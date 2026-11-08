//! Journal replay (D7): at agent boot — even with the channel disabled — after an executor deadline / panic, and for the operator's "Start now".
//! Starts exactly the journaled containers that were running before and are not running now; never anything else.
use super::journal::{self, QJournal};
use super::{QOps, Timing, start_phase, summary};
use crate::fork::restore::docker_ops::{DockerOps, RealDocker};
use crate::fork::state::{Outcome, State};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub fn replay_value(j: &QJournal) -> Value {
    j.replay.clone().unwrap_or_else(|| summary(j, "replay", false, None))
}

/// Replay one journal in place: containers that run already are only verified (never touched twice); everything else is started in START order.
/// Idempotent. Returns whether every container that was running before is verified now.
pub async fn replay_one(ops: &dyn QOps, t: Timing, dir: &Path, j: &mut QJournal) -> bool {
    // running already ⇒ nothing to start, just record it as verified after a plain look (start_container is idempotent: 304)
    let ok = start_phase(ops, t, dir, j).await;
    j.phase = if ok { "replayed" } else { "unresolved" }.into();
    j.replay = Some(summary(j, "replay", false, None));
    let _ = journal::save(dir, j);
    ok
}

/// Boot replay (D7). `env` as in `config::state_path`. A no-op without a journal (no Docker call). Never panics.
pub async fn boot(env: &(dyn Fn(&str) -> Option<String> + Sync)) {
    let state_path = crate::fork::config::state_path(env);
    let dir = journal::dir(state_path.parent().unwrap_or(Path::new("/config")));
    if !journal::has_any(&dir) {
        return;
    }
    tracing::warn!("Fork quiesce: journal(s) found at start — containers may still be stopped; replaying");
    let mut ops: Option<Arc<dyn DockerOps>> = None;
    for attempt in 0..6 {
        if let Ok(d) = RealDocker::connect() {
            let d: Arc<dyn DockerOps> = Arc::new(d);
            if d.ping().await {
                ops = Some(d);
                break;
            }
        }
        if attempt < 5 {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
    let Some(ops) = ops else {
        tracing::error!("Fork quiesce: the Docker daemon is not reachable; the journal is kept (replay again at the next start, or `docker start` the containers listed in it)");
        return;
    };
    replay_all(&super::Docker(ops), Timing::REAL, &dir).await;
}

pub async fn replay_all(ops: &dyn QOps, t: Timing, dir: &Path) -> usize {
    let mut n = 0;
    for mut j in journal::list(dir) {
        let ok = replay_one(ops, t, dir, &mut j).await;
        let touched = j.containers.iter().filter(|e| e.stop_intent && e.was_running).count();
        let verified = j.containers.iter().filter(|e| e.outcome.as_deref() == Some("verified")).count();
        tracing::warn!("Fork quiesce: quiesce replay — task {} project {}: {verified}/{touched} verified{}", j.task_id, j.project, if ok { "" } else { " (journal kept)" });
        n += 1;
    }
    n
}

/// After `Runtime::from_config`: an accepted task whose outcome is still `None` died with the agent. Record the honest outcome (`failed:quiesce_interrupted`
/// with the replay result) so the re-offered task hits `Duplicate` and reports it. Fully verified journals are then removed. Returns whether the state changed.
pub fn adopt(state: &mut State, dir: &Path) -> bool {
    let mut changed = false;
    for j in journal::list(dir) {
        let Some(replayed) = j.replay.clone() else { continue }; // not replayed yet (Docker was unreachable): keep it for the next start
        let verified = j.phase == "replayed";
        if state.known(&j.task_id).is_some_and(|a| a.outcome.is_none()) {
            state.set_outcome(&j.task_id, Outcome { status: "failed".into(), reason: Some("quiesce_interrupted".into()), result: Some(replayed) });
            changed = true;
        }
        if verified {
            journal::remove(dir, &j.task_id);
        }
    }
    changed
}

/// Executor deadline / panic path: replay the task's own journal, return its result (removed when verified).
pub async fn recover(ops: &dyn QOps, t: Timing, dir: &Path, task_id: &str) -> Option<Value> {
    let mut j = journal::load(dir, task_id).ok().flatten()?;
    let ok = replay_one(ops, t, dir, &mut j).await;
    let v = replay_value(&j);
    if ok {
        journal::remove(dir, task_id);
    }
    Some(v)
}
