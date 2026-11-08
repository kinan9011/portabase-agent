//! `restore_probe` (i-8): what this agent can do for a restore, without touching anything but one probe file per root.
use super::docker_ops::DockerOps;
use super::workspace::Workspace;
use super::{Code, Failure, ProbeBody, R, RestoreEnv, Task, paths};
use serde_json::{Value, json};
use std::path::Path;

/// Free bytes on the filesystem holding `p` (`statvfs`).
pub fn free_bytes(p: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| (s.f_bavail as u64).saturating_mul(s.f_frsize as u64))
}

/// Root identity probe (DD4): the agent writes `<root>/.portabase-probe-<nonce>`, a helper that binds `<root>:/probe:ro` must read the same bytes back.
/// Proves "agent view of the path == the Docker daemon's view" (compose bind sources are HOST paths).
pub async fn root_shared(ops: &dyn DockerOps, root: &Path) -> Result<bool, Code> {
    let nonce: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    let name = format!(".portabase-probe-{nonce}");
    let file = root.join(&name);
    std::fs::write(&file, nonce.as_bytes()).map_err(|_| Code::RootNotShared)?;
    let seen = ops.read_from_bind(root, &name).await;
    let _ = std::fs::remove_file(&file);
    Ok(seen?.is_some_and(|b| b == nonce.as_bytes()))
}

pub async fn run(env: &RestoreEnv, ops: &dyn DockerOps, _t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let b: ProbeBody = serde_json::from_slice(payload).map_err(|_| Failure::from(Code::PayloadInvalid))?;
    if b.v != 1 {
        return Err(Code::PayloadInvalid.into());
    }
    let mut roots = Vec::new();
    for r in &env.roots {
        let shared = root_shared(ops, r).await.unwrap_or(false);
        roots.push(json!({"path": r.to_string_lossy(), "shared": shared, "free_bytes": free_bytes(r)}));
    }
    let workspace_state = match &b.workspace {
        None => Value::Null,
        Some(w) => {
            if !paths::canon(w) {
                return Err(Code::PayloadInvalid.into());
            }
            let p = paths::check_task_path(&env.roots, &env.state_dir, w)?;
            json!(if !p.exists() {
                "absent"
            } else if Workspace::read_owner(&p).is_some() {
                "owned"
            } else {
                "foreign"
            })
        }
    };
    let (compose_version, rules_sha256) = match &env.compose {
        Some(c) => (json!(c.version), json!(crate::fork::policy::rules::rules_sha256_ts())),
        None => (Value::Null, Value::Null),
    };
    Ok(json!({"roots": roots, "workspace_state": workspace_state, "arch": std::env::consts::ARCH, "compose_version": compose_version, "rules_sha256": rules_sha256}))
}
