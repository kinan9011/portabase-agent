//! `mirror_finalize` (#199): the runner-side half of the W20 compiler. Order (normative, plan-W22a §3.3): load-or-create the revision seed → pass-2 render of the staged
//! compose exactly like `mirror_render` → `sha256(own policy view) == spec.source_view_sha256` (else `source_changed`) → `apply_mirror_spec` → per-service limits
//! (`min(existing, cap)`), owner labels on every service / network / volume → `out.json` (0600) → `docker compose -f out.json config` in the sandbox → policy view →
//! upload of the FINAL view. Nothing leaves this host except that value-free view and `{view_sha256, services}`.
use super::apply_spec::{ApplyError, MirrorSpec, apply_mirror_spec};
use super::payload::{FinalizeBody, Limits};
use super::{config_of_out, out_json, seed};
use crate::fork::compose::{RenderSink, SecretGuard, open_job, render::render_full};
use crate::fork::crypto::{Pin, sha256_hex};
use crate::fork::policy::rendered::evaluate;
use crate::fork::policy::rules::rules_sha256_ts;
use crate::fork::policy::view::policy_view;
use crate::fork::restore::docker_ops::{DockerOps, LABEL_AGENT, LABEL_RESTORE};
use crate::fork::restore::stage::write_0600;
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, split};
use base64::Engine;
use serde_json::{Map, Value, json};

/// Canonical JSON exactly like the dashboard's `canonicalJson` (keys sorted recursively by UTF-16 code unit, no whitespace): the hash input of `spec_sha256`.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Array(a) => format!("[{}]", a.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<u16>>());
            format!("{{{}}}", keys.iter().map(|k| format!("{}:{}", serde_json::to_string(k).unwrap_or_default(), canonical_json(&o[*k]))).collect::<Vec<_>>().join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn unit_bytes(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)),
        Value::String(s) => {
            let s = s.trim().to_ascii_lowercase();
            let t = s.strip_suffix('b').unwrap_or(&s);
            let (num, mult) = match t.chars().last() {
                Some('k') => (&t[..t.len() - 1], 1u64 << 10),
                Some('m') => (&t[..t.len() - 1], 1 << 20),
                Some('g') => (&t[..t.len() - 1], 1 << 30),
                _ => (t, 1),
            };
            num.parse::<u64>().ok().and_then(|n| n.checked_mul(mult))
        }
        _ => None,
    }
}
fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Limits (`min(existing, cap)`; absent or unlimited ⇒ the cap) and owner labels on every service, non-external network and volume. `limits_invalid` when an existing
/// value is present but unreadable (never guessed).
pub fn decorate(doc: &mut Value, limits: &Limits, restore_id: &str, agent_id: &str) -> R<()> {
    let owner = |m: &mut Map<String, Value>| {
        let labels = m.entry("labels").or_insert_with(|| json!({}));
        if !labels.is_object() {
            *labels = json!({});
        }
        if let Some(l) = labels.as_object_mut() {
            l.insert(LABEL_RESTORE.into(), json!(restore_id));
            l.insert(LABEL_AGENT.into(), json!(agent_id));
        }
    };
    let cpu_cap = limits.nano_cpus as f64 / 1e9;
    let services = doc.get_mut("services").and_then(Value::as_object_mut).ok_or(Failure::from(Code::ApplyFailed))?;
    for s in services.values_mut() {
        let Some(s) = s.as_object_mut() else { return Err(Code::ApplyFailed.into()) };
        let mem = match s.get("mem_limit").filter(|v| !v.is_null()) {
            None => limits.mem_bytes,
            Some(v) => unit_bytes(v).ok_or_else(|| Failure::with(Code::LimitsInvalid, "mem_limit"))?.min(limits.mem_bytes),
        };
        let mem = if mem == 0 { limits.mem_bytes } else { mem }; // 0 = unlimited in compose
        let pids = match s.get("pids_limit").filter(|v| !v.is_null()) {
            None => limits.pids,
            Some(v) => match as_f64(v) {
                Some(n) if n > 0.0 => (n as u64).min(limits.pids),
                Some(_) => limits.pids, // -1 / 0 = unlimited
                None => return Err(Failure::with(Code::LimitsInvalid, "pids_limit")),
            },
        };
        let cpus = match s.get("cpus").filter(|v| !v.is_null()) {
            None => cpu_cap,
            Some(v) => match as_f64(v) {
                Some(n) if n > 0.0 => n.min(cpu_cap),
                Some(_) => cpu_cap,
                None => return Err(Failure::with(Code::LimitsInvalid, "cpus")),
            },
        };
        s.insert("mem_limit".into(), json!(mem));
        s.insert("pids_limit".into(), json!(pids));
        s.insert("cpus".into(), json!(cpus));
        owner(s);
    }
    for sect in ["networks", "volumes"] {
        if let Some(defs) = doc.get_mut(sect).and_then(Value::as_object_mut) {
            for d in defs.values_mut() {
                match d.as_object_mut() {
                    Some(m) => owner(m),
                    None => *d = json!({"labels": {LABEL_RESTORE: restore_id, LABEL_AGENT: agent_id}}),
                }
            }
        }
    }
    Ok(())
}

pub async fn run(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], sink: &dyn RenderSink, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, FinalizeBody) = split(payload)?;
    b.check()?;
    if b.spec.project != h.project || b.spec.workspace != h.workspace {
        return Err(Code::PayloadInvalid.into());
    }
    // the spec hash binds the exact bytes the dashboard approved (the canonical form is the dashboard's own)
    let raw_spec = serde_json::from_slice::<Value>(payload).ok().and_then(|v| v.get("spec").cloned()).ok_or(Failure::from(Code::PayloadInvalid))?;
    if sha256_hex(canonical_json(&raw_spec).as_bytes()) != b.spec_sha256 {
        return Err(Failure::with(Code::ApplyFailed, "spec_sha256")); // well-formed but not the spec the dashboard approved: nothing is rendered or written
    }
    let FinalizeBody { manifest_sha256, compose, spec, limits, .. } = b;
    let job = open_job(env, ops, pins, t, h, &manifest_sha256, compose).await?;
    let mut j = job.journal()?;
    j.begin(t.id, t.ty);
    let _guard = SecretGuard::new(&job.ws);
    let r = async {
        let seed = seed::create_or_load(&job.ws.root).map_err(Failure::from)?;
        let rendered = render_full(&job).await?;
        if rendered.sha != spec.source_view_sha256 {
            return Err(Failure::from(Code::SourceChanged));
        }
        let mut doc = merge(&rendered.doc, &spec, seed.bytes())?;
        decorate(&mut doc, &limits, &job.h.restore_id, &job.env.agent_id)?;
        let meta = seed::meta_dir(&job.ws.root);
        std::fs::create_dir_all(&meta).map_err(|_| Failure::from(Code::RestoreFailed))?;
        write_0600(&out_json(&job.ws.root), &serde_json::to_vec(&doc).map_err(|_| Failure::from(Code::ApplyFailed))?)?;
        drop(doc);
        let cfg = config_of_out(job.ce, ops, &job.h.project, &job.ws.root).await?;
        let view = policy_view(&cfg).map_err(|_| Failure::with(Code::RenderFailed, "final_view"))?;
        let ws = job.ws_str();
        if let Some(hard) = evaluate(job.rules, &view, std::slice::from_ref(&ws), &rendered.raw).hard.first() {
            return Err(Failure::with(Code::PolicyRefused, hard.code));
        }
        let sha = sha256_hex(&view);
        let services = serde_json::from_slice::<Value>(&cfg).ok().and_then(|d| d.get("services").and_then(Value::as_object).map(Map::len)).unwrap_or(0);
        let body = json!({"restore_id": job.h.restore_id, "view_b64": base64::engine::general_purpose::STANDARD.encode(&view), "view_sha256": sha, "raw": rendered.raw, "roots": [ws],
            "files": ["out.json"], "compose_version": job.ce.version, "rules_sha256": rules_sha256_ts()});
        sink.put(body).await.map_err(|_| Failure::with(Code::RenderFailed, "upload"))?;
        j.step(t.id, t.ty, "finalize", true, Some(&sha));
        Ok(json!({"v": 1, "view_sha256": sha, "services": services}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

fn merge(full: &Value, spec: &MirrorSpec, seed: &[u8]) -> R<Value> {
    apply_mirror_spec(full, spec, seed).map_err(|e| match e {
        ApplyError::SeedInvalid => Failure::from(Code::SeedInvalid),
        other => Failure::with(Code::ApplyFailed, other.as_str()),
    })
}
