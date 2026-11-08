//! `compose_up` (E10): re-check chain → `docker compose up -d --no-build --pull missing` on the verified full render with a closed argument set. Never
//! `--remove-orphans`, `down`, `-v`, `build`, `-y`. Idempotent: a re-run converges.
use super::check::recheck;
use super::run;
use super::{UpBody, SecretGuard, open_job};
use crate::fork::crypto::Pin;
use crate::fork::restore::docker_ops::{DockerOps, owned_by};
use crate::fork::restore::stage::write_0600;
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, paths, split};
use serde_json::{Value, json};
use std::time::Duration;

/// the base of every `up` / `exec` invocation: the verified render is the only compose file, the project directory is the empty one
pub fn base_args(project: &str, ws: &std::path::Path) -> Vec<String> {
    vec!["--project-name".into(), project.into(), "--project-directory".into(), ws.join(".portabase/empty").to_string_lossy().into_owned(), "-f".into(), ws.join(".portabase/secret/rendered.json").to_string_lossy().into_owned()]
}
pub(crate) fn exit_failure(code: Code, out: &run::Out) -> Failure {
    Failure::with(code, &format!("exit_{}", out.code))
}

pub async fn run_up(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, UpBody) = split(payload)?;
    if !crate::fork::restore::is_hex64(&b.compose_sha256) || b.volumes.len() > 100 || b.volumes.iter().any(|v| !paths::is_name(v, 255)) {
        return Err(Code::PayloadInvalid.into());
    }
    let job = open_job(env, ops, pins, t, h, &b.manifest_sha256, b.compose).await?;
    let mut j = job.journal()?;
    j.begin(t.id, t.ty);
    let _guard = SecretGuard::new(&job.ws);
    let r = async {
        let r = recheck(&job, &b.compose_sha256, &b.approval, Some(&b.volumes)).await?;
        write_0600(&job.ws.secret().join("rendered.json"), &r.full)?;
        let mut args = base_args(&job.h.project, &job.ws.root);
        args.extend(["up", "-d", "--no-build", "--pull", "missing"].map(String::from));
        let home = job.ws.tmp().join("home");
        let out = run::compose(&job.ce.bin, &args, &home, None, super::DEADLINE_UP - Duration::from_secs(60)).await?;
        if out.code != 0 {
            return Err(exit_failure(Code::ComposeFailed, &out));
        }
        j.step(t.id, t.ty, &format!("up:{}", job.h.project), true, Some(&r.sha));
        let mut services = vec![];
        for c in ops.containers().await? {
            if owned_by(&c.labels, &job.h.restore_id, &env.agent_id) && c.labels.get("com.docker.compose.project").map(String::as_str) == Some(job.h.project.as_str()) {
                services.push(json!({"service": c.labels.get("com.docker.compose.service").cloned().unwrap_or_default(), "state": if c.running {"running"} else {"exited"}}));
            }
        }
        Ok(json!({"project": job.h.project, "services": services}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}
