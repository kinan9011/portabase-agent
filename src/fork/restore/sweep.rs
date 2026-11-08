//! Startup sweep (DD16, SEC-14): called once before the channel loop. Removes what a crash may have left: `secret/`, `tmp/` and `verify/` of every owned workspace under a
//! valid root, `stage/` when the workspace has been idle for > 24 h (by `owner.json.updated_at` against the INJECTED clock, never file mtimes), helper
//! containers, and marks interrupted journals as aborted.
use super::docker_ops::DockerOps;
use super::journal::{self, Journal};
use super::workspace::Workspace;
use super::RestoreEnv;
use std::path::Path;

pub const STAGE_TTL_SECS: i64 = 24 * 3600;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub workspaces: usize,
    pub stage_removed: usize,
    pub helpers: usize,
    pub journals_aborted: usize,
}

fn find_workspaces(root: &Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
    if root.join(".portabase/owner.json").is_file() {
        out.push(root.to_path_buf());
        return;
    }
    if depth == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else { return };
    for e in rd.flatten() {
        if e.file_type().map(|t| t.is_dir() && !t.is_symlink()).unwrap_or(false) {
            find_workspaces(&e.path(), depth - 1, out);
        }
    }
}

pub async fn startup_sweep(env: &RestoreEnv, ops: Option<&dyn DockerOps>, now: i64) -> Swept {
    let mut s = Swept::default();
    for root in &env.roots {
        let mut found = Vec::new();
        find_workspaces(root, 4, &mut found);
        for w in found {
            s.workspaces += 1;
            let _ = std::fs::remove_dir_all(w.join(".portabase/secret"));
            let _ = std::fs::remove_dir_all(w.join(".portabase/tmp"));
            let _ = std::fs::remove_dir_all(w.join(".portabase/verify")); // W-TR: private copies of staged data for the engine check (SEC-14)
            if let Some(o) = Workspace::read_owner(&w) {
                if now - o.updated_at > STAGE_TTL_SECS && std::fs::remove_dir_all(w.join(".portabase/stage")).is_ok() {
                    s.stage_removed += 1;
                }
            }
        }
    }
    if let Some(ops) = ops {
        s.helpers = ops.remove_helpers().await;
    }
    if let Ok(rd) = std::fs::read_dir(journal::dir(&env.state_dir)) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let lines = journal::read_lines(&p);
            if let Some(last) = journal::interrupted(&lines) {
                if let Some(stem) = p.file_stem().and_then(|x| x.to_str()) {
                    if let Ok(mut j) = Journal::open(&env.state_dir, stem) {
                        j.abort(&last.task, &last.ty, "restart");
                        s.journals_aborted += 1;
                    }
                }
            }
        }
    }
    s
}
