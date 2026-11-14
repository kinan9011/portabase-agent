//! Runner-side mirror engine (W22a-f1, ADR-008 §12, ADR-007 A17): `mirror_probe|stage|apply|render|finalize|db|up|check|wipe|stop`. A mirror is created ONLY on a designated
//! runner (`FORK_HOST_ROLE=runner` + `FORK_MIRROR_ROOT`), from a signed manifest + audited archives (the W17 executors, reused unchanged), compiled by the dashboard
//! (W20 `MirrorSpecV1`, value-free) and finalised HERE with runner-local secrets (`apply_spec` + `seed`): the dashboard never sees an env value. Every later step
//! (`db`, `up`, `check`) uses only `<ws>/.portabase/mirror/out.json` and refuses (`final_view_mismatch`) when the policy view of what it is about to run differs from
//! the hash the dashboard approved. Nothing here runs unless the task passed the channel verification AND the role gate (`runner.v1` + `mirror.v1`).
//! The master key IS loaded on a mirror-enabled runner (staging production archives needs it): the realised residual R-W21-1, recorded in ADR-008 §12 (#201).
pub mod apply_spec;
pub mod db;
pub mod finalize;
pub mod lifecycle;
pub mod payload;
pub mod seed;
pub mod smoke;

#[cfg(test)]
mod tests;

use crate::fork::compose::{ComposeEnv, RenderSink};
use crate::fork::crypto::Pin;
use crate::fork::policy::view::policy_view;
use crate::fork::restore::docker_ops::{DockerOps, RenderError, RenderSpec};
use crate::fork::restore::workspace::Workspace;
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, paths, split};
use crate::fork::state::Redacted;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const DEADLINE_PROBE: Duration = Duration::from_secs(5 * 60);
pub const DEADLINE_WIPE: Duration = Duration::from_secs(5 * 60);
pub const DEADLINE_STEP: Duration = Duration::from_secs(15 * 60);
pub const DEADLINE_STAGE: Duration = Duration::from_secs(60 * 60);

pub fn deadline_of(task_type: &str) -> Duration {
    match task_type {
        "mirror_probe" => DEADLINE_PROBE,
        "mirror_wipe" => DEADLINE_WIPE,
        "mirror_stage" | "mirror_apply" => DEADLINE_STAGE,
        _ => DEADLINE_STEP, // render / finalize / db / up / check
    }
}

/// The mirror engine of one runner: a `RestoreEnv` whose only root is `FORK_MIRROR_ROOT` and whose host role is `Runner`, plus Docker access.
pub struct MirrorRuntime {
    pub env: RestoreEnv,
    pub ops: Arc<dyn DockerOps>,
    pub smoke: Arc<dyn smoke::Smoke>,
}

/// Fail closed with ONE reason (the capability is then simply not reported; a probe-only runner keeps working).
/// `master_b64` = the instance master key decoded from `EDGE_KEY` (needed to decrypt production archives, R-W21-1).
#[allow(clippy::too_many_arguments)]
pub async fn detect(env: &(dyn Fn(&str) -> Option<String> + Sync), state_path: &Path, agent_id: &str, ops: Arc<dyn DockerOps>, smoke: Arc<dyn smoke::Smoke>, master_b64: Option<String>, mountinfo: &str, cgroup: &str) -> Result<MirrorRuntime, String> {
    let root = env("FORK_MIRROR_ROOT").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).ok_or("FORK_MIRROR_ROOT is not set")?;
    let state_dir = state_path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    let state_dir = std::fs::canonicalize(&state_dir).unwrap_or(state_dir);
    let roots = paths::parse_roots(&root, std::slice::from_ref(&state_dir)).map_err(|e| e.to_string())?;
    if roots.len() != 1 {
        return Err("FORK_MIRROR_ROOT must name exactly one directory".into());
    }
    let master = master_b64.filter(|m| !m.is_empty()).ok_or("the instance master key (EDGE_KEY) does not decode")?;
    let http_hosts = env("FORK_ARTIFACT_HTTP_HOSTS").unwrap_or_default().split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()).collect();
    let compose = ComposeEnv::detect(ops.as_ref(), env, PathBuf::from(crate::fork::compose::COMPOSE_BIN), mountinfo, cgroup).await.map_err(|e| e.to_string())?;
    if !crate::fork::restore::probe::root_shared(ops.as_ref(), &roots[0]).await.unwrap_or(false) {
        return Err("FORK_MIRROR_ROOT is not visible at the same path to the Docker daemon (root_not_shared)".into());
    }
    let renv = RestoreEnv { roots, host_role: crate::fork::restore::HostRole::Runner, http_hosts, state_dir, agent_id: agent_id.to_string(), master_b64: Some(Redacted(master)), compose: Some(compose) };
    Ok(MirrorRuntime { env: renv, ops, smoke })
}

// ---- shared helpers ------------------------------------------------------------------------------------------------------------------------
/// An opened mirror task that needs no manifest: header checked, mirror mode only, compose enabled, workspace owned by THIS revision.
pub struct Ctx<'a> {
    pub env: &'a RestoreEnv,
    pub ce: &'a ComposeEnv,
    pub ops: &'a dyn DockerOps,
    pub h: Header,
    pub ws: Workspace,
}

pub fn open_light<'a>(env: &'a RestoreEnv, ops: &'a dyn DockerOps, t: &Task<'_>, h: Header) -> R<Ctx<'a>> {
    h.check(env)?;
    let ce = env.compose.as_ref().ok_or(Failure::from(Code::ComposeUnavailable))?;
    let ws_path = paths::check_task_path(&env.roots, &env.state_dir, &h.workspace)?;
    let ws = Workspace::open_owned(&ws_path, &crate::fork::compose::claim(env, &h), t.now)?;
    Ok(Ctx { env, ce, ops, h, ws })
}

/// The signed manifest staged by `mirror_stage`, re-verified against the hash the dashboard bound into the payload (same rule as `compose::open_job`).
pub fn load_manifest(c: &Ctx<'_>, pins: &[Pin], sha256: &str) -> R<crate::fork::restore::manifest::ManifestV1> {
    use crate::fork::restore::manifest::{self, Expect};
    let json = std::fs::read(c.ws.stage().join("manifest.json")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    let sig = std::fs::read(c.ws.stage().join("manifest.sig")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    manifest::verify(&json, &sig, pins, &Expect { rp_id: &c.h.rp_id, stack_id: &c.h.stack_id, sequence: None, sha256, min_sequence: None })
}

pub fn out_json(ws: &Path) -> PathBuf {
    seed::meta_dir(ws).join("out.json")
}

/// The base of every `up` / `exec` / `config` invocation of a mirror: `out.json` is the ONLY compose file, the project directory is the empty one.
pub fn base_args(project: &str, ws: &Path) -> Vec<String> {
    vec!["--project-name".into(), project.into(), "--project-directory".into(), ws.join(".portabase/empty").to_string_lossy().into_owned(), "-f".into(), out_json(ws).to_string_lossy().into_owned()]
}

/// `docker compose -f out.json config --format json` in the sandboxed render helper (the same helper `compose_render` uses; stdout ≤ 2 MiB).
pub async fn config_of_out(ce: &ComposeEnv, ops: &dyn DockerOps, project: &str, ws: &Path) -> R<Vec<u8>> {
    let mut cmd = base_args(project, ws);
    cmd.extend(["config".to_string(), "--format".to_string(), "json".to_string()]);
    let spec = RenderSpec { image: ce.own_image.clone(), bin: crate::fork::compose::COMPOSE_BIN.into(), workspace: ws.to_path_buf(), cmd, env: vec![("HOME".into(), "/tmp".into())] };
    ops.render(&spec).await.map_err(|e| match e {
        RenderError::TooLarge => Failure::from(Code::RenderTooLarge),
        RenderError::Failed(line) => Failure::with(Code::RenderFailed, &line),
        RenderError::Docker => Failure::from(Code::DockerUnavailable),
    })
}

/// The `final_view_mismatch` guard of `db` / `up` / `check`: the file about to be run must still render to the policy view the dashboard approved.
/// Returns the FULL config document (secret-bearing: memory only, never reported).
pub async fn final_check(c: &Ctx<'_>, final_sha256: &str) -> R<Value> {
    if !out_json(&c.ws.root).is_file() {
        return Err(Failure::with(Code::FinalViewMismatch, "no_out_json"));
    }
    let cfg = config_of_out(c.ce, c.ops, &c.h.project, &c.ws.root).await?;
    let view = policy_view(&cfg).map_err(|_| Failure::with(Code::FinalViewMismatch, "view"))?;
    if crate::fork::crypto::sha256_hex(&view) != final_sha256 {
        return Err(Failure::from(Code::FinalViewMismatch));
    }
    serde_json::from_slice(&cfg).map_err(|_| Failure::with(Code::FinalViewMismatch, "not_json"))
}

/// Entry point for the ten mirror task types. The caller (`poll`) wraps this in `exec::run_with_heartbeat` with `deadline_of(type)`.
pub async fn execute(rt: &MirrorRuntime, pins: &[Pin], sink: &dyn RenderSink, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (env, ops) = (&rt.env, rt.ops.as_ref());
    match t.ty {
        "mirror_probe" => {
            let b: payload::MirrorProbeBody = serde_json::from_slice(payload).map_err(|_| Failure::from(Code::PayloadInvalid))?;
            let leaf = b.workspace.rsplit('/').next().unwrap_or("");
            if b.v != 1 || !paths::canon(&b.workspace) || !leaf.starts_with("pbm-") {
                return Err(Code::PayloadInvalid.into());
            }
            crate::fork::restore::probe::run(env, ops, t, payload).await
        }
        "mirror_stage" => crate::fork::restore::stage::run(env, ops, pins, t, payload).await,
        "mirror_apply" => crate::fork::restore::apply::run_apply(env, ops, pins, t, payload).await,
        "mirror_render" => {
            let (_, b): (Header, payload::RenderBody) = split(payload)?;
            b.check()?;
            crate::fork::compose::render::run_render(env, ops, pins, sink, t, payload).await
        }
        "mirror_finalize" => finalize::run(env, ops, pins, sink, t, payload).await,
        "mirror_db" => db::run(env, ops, pins, t, payload).await,
        "mirror_up" => lifecycle::run_up(env, ops, t, payload).await,
        "mirror_check" => lifecycle::run_check(env, ops, rt.smoke.as_ref(), t, payload).await,
        "mirror_wipe" => lifecycle::run_wipe(env, ops, t, payload).await,
        "mirror_stop" => lifecycle::run_stop(env, ops, t, payload).await,
        _ => Err(Failure::from(Code::PayloadInvalid)),
    }
}
