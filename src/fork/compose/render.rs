//! `compose_render` (E3 / E4 / E5): raw read-scope check in Rust → sandboxed two-pass render → policy view + hash + the agent's own verdict → upload of the VIEW.
//! The full render (it contains interpolated secrets) lives in memory only and is never kept between tasks; `restore_db` / `compose_up` re-render and compare hashes.
use super::{ComposeRef, Job, RenderBody, RenderSink, SecretGuard, open_job};
use crate::fork::crypto::{Pin, sha256_hex};
use crate::fork::policy::raw::{RawResult, check_raw};
use crate::fork::policy::rendered::{Verdict, evaluate};
use crate::fork::policy::rules::{is_canon_path, is_under_roots, rules_sha256_ts};
use crate::fork::policy::view::{ViewError, policy_view};
use crate::fork::restore::docker_ops::{LABEL_AGENT, LABEL_RESTORE, RenderError, RenderSpec};
use crate::fork::restore::stage::write_0600;
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, paths, split};
use crate::fork::restore::docker_ops::DockerOps;
use base64::Engine;
use serde_json::{Map, Value, json};
use std::path::Path;

pub struct Rendered {
    pub full: Vec<u8>,
    pub doc: Value,
    pub view: Vec<u8>,
    pub sha: String,
    pub raw: RawResult,
    pub verdict: Verdict,
}

fn service_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 128 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}
fn under(p: &str, w: &str) -> bool {
    p == w || (p.starts_with(w) && p.as_bytes().get(w.len()) == Some(&b'/'))
}

/// production `read`: a regular, non-symlink file strictly inside the workspace, ≤ 256 KiB.
fn read_inside(ws: &str, roots: &[std::path::PathBuf], state_dir: &Path, p: &str) -> Option<String> {
    if !under(p, ws) || paths::check_task_path(roots, state_dir, p).is_err() {
        return None;
    }
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.len() > 262_144 {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

fn base_args(job: &Job, extra: &[String]) -> Vec<String> {
    let dir = &job.cref.dir;
    let mut a = vec!["--project-name".to_string(), job.h.project.clone(), "--project-directory".to_string(), dir.clone()];
    for f in &job.files {
        a.extend(["-f".to_string(), format!("{dir}/{f}")]);
    }
    for e in extra {
        a.extend(["-f".to_string(), e.clone()]);
    }
    a
}

async fn pass(job: &Job<'_>, extra: &[String]) -> R<Vec<u8>> {
    let mut cmd = base_args(job, extra);
    cmd.extend(["config".to_string(), "--format".to_string(), "json".to_string()]);
    let mut env: Vec<(String, String)> = job.cref.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    env.push(("HOME".into(), "/tmp".into()));
    let spec = RenderSpec { image: job.ce.own_image.clone(), bin: super::COMPOSE_BIN.into(), workspace: job.ws.root.clone(), cmd, env };
    job.ops.render(&spec).await.map_err(|e| match e {
        RenderError::TooLarge => Failure::from(Code::RenderTooLarge),
        RenderError::Failed(line) => Failure::with(Code::RenderFailed, &line),
        RenderError::Docker => Failure::from(Code::DockerUnavailable),
    })
}

/// `services.<svc>.volumes: !override <list>` for every service with a bind source outside the workspace that a `path_map.from` covers (CLI `remap_binds`).
pub(crate) fn remap_yaml(doc: &Value, ws: &str, map: &ComposeRef) -> R<Option<String>> {
    let mut out = String::from("services:\n");
    let mut any = false;
    let Some(services) = doc.get("services").and_then(Value::as_object) else { return Ok(None) };
    for (svc, s) in services {
        if !service_ok(svc) {
            return Err(Failure::with(Code::RenderFailed, "service_name"));
        }
        let Some(vols) = s.get("volumes").and_then(Value::as_array) else { continue };
        let mut changed = false;
        let mapped: Vec<Value> = vols
            .iter()
            .map(|v| {
                let mut v = v.clone();
                if v.get("type").and_then(Value::as_str) == Some("bind") {
                    if let Some(src) = v.get("source").and_then(Value::as_str) {
                        if !under(src, ws) {
                            if let Some(m) = map.path_map.iter().filter(|m| under(src, &m.from)).max_by_key(|m| m.from.len()) {
                                v["source"] = json!(format!("{}{}", m.to, &src[m.from.len()..]));
                                changed = true;
                            }
                        }
                    }
                }
                v
            })
            .collect();
        if changed {
            any = true;
            out.push_str(&format!("  {svc}:\n    volumes: !override {}\n", serde_json::to_string(&mapped).map_err(|_| Failure::from(Code::RenderFailed))?));
        }
    }
    Ok(any.then_some(out))
}

/// `owner.yml`: owner labels on every service and every NON-external top-level volume / network of the pass-1 render (E7).
pub(crate) fn owner_yaml(doc: &Value, restore_id: &str, agent_id: &str) -> R<String> {
    let labels = json!({LABEL_RESTORE: restore_id, LABEL_AGENT: agent_id});
    let names = |sect: &str, only_internal: bool| -> R<Map<String, Value>> {
        let mut m = Map::new();
        if let Some(o) = doc.get(sect).and_then(Value::as_object) {
            for (k, d) in o {
                if !service_ok(k) {
                    return Err(Failure::with(Code::RenderFailed, "resource_name"));
                }
                let external = matches!(d.get("external"), Some(Value::Bool(true))) || d.get("external").is_some_and(Value::is_object);
                if !(only_internal && external) {
                    m.insert(k.clone(), json!({"labels": labels}));
                }
            }
        }
        Ok(m)
    };
    let mut o = Map::new();
    o.insert("services".into(), Value::Object(names("services", false)?));
    for sect in ["volumes", "networks"] {
        let m = names(sect, true)?;
        if !m.is_empty() {
            o.insert(sect.into(), Value::Object(m));
        }
    }
    serde_json::to_string(&Value::Object(o)).map_err(|_| Failure::from(Code::RenderFailed))
}

/// Raw check → pass 1 → remap / owner → pass 2 → view / hash / verdict. `secret/` content is written 0600 and removed by the caller's `SecretGuard`.
pub async fn render_full(job: &Job<'_>) -> R<Rendered> {
    let ws = job.ws_str();
    let secret = job.ws.secret();
    std::fs::create_dir_all(&secret).map_err(|_| Failure::from(Code::RestoreFailed))?;
    let mut extra: Vec<String> = vec![];
    let mut entry: Vec<String> = job.files.iter().map(|f| format!("{}/{f}", job.cref.dir)).collect();
    if let Some(y) = &job.cref.override_yml {
        let p = secret.join("override.yml");
        write_0600(&p, y.as_bytes())?;
        let ps = p.to_string_lossy().into_owned();
        extra.push(ps.clone());
        entry.push(ps);
    }
    let raw = check_raw(job.rules, &ws, &entry, &|p| read_inside(&ws, &job.env.roots, &job.env.state_dir, p)).map_err(|_| Failure::from(Code::PayloadInvalid))?;
    if raw.refused {
        let first = raw.violations.first().map(|v| v.kind).or(raw.reason).unwrap_or("refused");
        return Err(Failure::with(Code::RawRefused, first).with_extra(json!({"raw": raw})));
    }
    let pass1 = pass(job, &extra).await?;
    let doc1: Value = serde_json::from_slice(&pass1).map_err(|_| Failure::with(Code::RenderFailed, "not_json"))?;
    if let Some(y) = remap_yaml(&doc1, &ws, &job.cref)? {
        let p = secret.join("remap.yml");
        write_0600(&p, y.as_bytes())?;
        extra.push(p.to_string_lossy().into_owned());
    }
    let p = secret.join("owner.yml");
    write_0600(&p, owner_yaml(&doc1, &job.h.restore_id, &job.env.agent_id)?.as_bytes())?;
    extra.push(p.to_string_lossy().into_owned());
    let full = pass(job, &extra).await?;
    let doc: Value = serde_json::from_slice(&full).map_err(|_| Failure::with(Code::RenderFailed, "not_json"))?;
    let view = policy_view(&full).map_err(|e| match e {
        ViewError::TooLarge => Failure::from(Code::RenderTooLarge),
        ViewError::TooDeep => Failure::with(Code::RenderFailed, "too_deep"),
        ViewError::NotJson => Failure::with(Code::RenderFailed, "not_json"),
    })?;
    let verdict = evaluate(job.rules, &view, std::slice::from_ref(&ws), &raw);
    Ok(Rendered { sha: sha256_hex(&view), full, doc, view, raw, verdict })
}

fn summary(r: &Rendered, job: &Job<'_>) -> Value {
    let findings: Vec<Value> = r.verdict.findings.iter().take(50).map(|f| json!({"service": f.service, "rule": f.rule})).collect();
    json!({"rendered_sha256": r.sha, "bytes": r.view.len(), "verdict": r.verdict.verdict, "hard": r.verdict.hard.iter().map(|h| h.code).collect::<Vec<_>>(), "findings": findings,
        "files": job.files, "compose_version": job.ce.version, "rules_sha256": rules_sha256_ts()})
}

pub async fn run_render(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], sink: &dyn RenderSink, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, RenderBody) = split(payload)?;
    let job = open_job(env, ops, pins, t, h, &b.manifest_sha256, b.compose).await?;
    let mut j = job.journal()?;
    j.begin(t.id, t.ty);
    let _guard = SecretGuard::new(&job.ws);
    let r = async {
        let r = render_full(&job).await?;
        let body = json!({"restore_id": job.h.restore_id, "view_b64": base64::engine::general_purpose::STANDARD.encode(&r.view), "view_sha256": r.sha, "raw": r.raw, "roots": [job.ws_str()],
            "files": job.files, "compose_version": job.ce.version, "rules_sha256": rules_sha256_ts()});
        sink.put(body).await.map_err(|_| Failure::with(Code::RenderFailed, "upload"))?;
        j.step(t.id, t.ty, "render", true, Some(&r.sha));
        Ok(summary(&r, &job))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

/// roots helper shared with the realpath gate: lexically under the workspace?
pub fn lexically_under(ws: &str, p: &str) -> bool {
    is_canon_path(p) && is_under_roots(p, &[ws.to_string()])
}
