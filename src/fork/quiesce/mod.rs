//! W17b composite quiesce task (ADR-007 A15, D29): stop the selected containers of the stack's OWN compose project, hold the window while the dashboard
//! captures files / volumes through the stock backup path, then start exactly what was stopped — journaled, agent-deadline-bound, verified, crash-safe.
//!
//! Safety invariants (never split): the journal is on disk BEFORE the first stop (and `stop_intent` before each stop call); the window deadline runs on the
//! agent's monotonic clock and does not depend on the dashboard; a boot replay restarts journaled containers even when the channel is disabled; only
//! containers named in the agent's OWN journal are ever started; targets are re-validated here by FULL id (project, protected ids, replicas, restore-owned).
//! No field of a payload is a command, image, path or name: ids are pointers that must resolve to exactly one container of the project.
pub mod journal;
pub mod plan;
pub mod replay;

#[cfg(test)]
mod tests;

use crate::fork::compose::guard;
use crate::fork::restore::docker_ops::{CState, ContainerFacts, DockerOps};
use crate::fork::restore::{Code, Failure, is_uuid};
use async_trait::async_trait;
use journal::{QEntry, QJournal};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

pub const POLL_EVERY: Duration = Duration::from_secs(5);
/// the serialized result must stay well under the dashboard's 8 KiB audit-detail limit (`redactDetails`)
const MAX_RESULT_BYTES: usize = 6 * 1024;

// ---- strict payloads (mirror of the dashboard's `payload.ts`) ---------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRef {
    pub service: String,
    pub container_id: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuiesceBody {
    pub v: u8,
    pub run_id: String,
    pub stack_id: String,
    pub project: String,
    pub targets: Vec<TargetRef>,
    pub max_stop_seconds: u32,
    pub stop_timeout_cap_seconds: u32,
    pub start_timeout_seconds: u32,
    pub dry_run: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartBody {
    pub v: u8,
    pub quiesce_task_id: String,
    pub project: String,
}

pub(crate) fn is_project(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.as_bytes()[0].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}
pub(crate) fn is_service(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.as_bytes()[0].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}
pub(crate) fn is_hex_id(s: &str) -> bool {
    (12..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---- Docker surface (narrow, fakeable) ----------------------------------------------------------------------------------------------
#[async_trait]
pub trait QOps: Send + Sync {
    async fn containers(&self) -> Result<Vec<ContainerFacts>, Code>;
    async fn inspect_state(&self, id: &str) -> Result<Option<CState>, Code>;
    async fn stop_container(&self, id: &str, timeout_s: u32) -> Result<(), Code>;
    async fn start_container(&self, id: &str) -> Result<(), Code>;
}
/// The production `QOps`: the fork's `DockerOps` (bollard).
pub struct Docker(pub Arc<dyn DockerOps>);
#[async_trait]
impl QOps for Docker {
    async fn containers(&self) -> Result<Vec<ContainerFacts>, Code> {
        self.0.containers().await
    }
    async fn inspect_state(&self, id: &str) -> Result<Option<CState>, Code> {
        self.0.inspect_state(id).await
    }
    async fn stop_container(&self, id: &str, t: u32) -> Result<(), Code> {
        self.0.stop_container(id, t).await
    }
    async fn start_container(&self, id: &str) -> Result<(), Code> {
        self.0.start_container(id).await
    }
}

// ---- environment --------------------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub poll_every: Duration,
    pub verify_poll: Duration,
    pub settle: Duration,
    /// tests only: replaces the journal's per-container start timeout (production keeps `None`)
    pub start_timeout: Option<Duration>,
}
impl Timing {
    pub const REAL: Timing = Timing { poll_every: POLL_EVERY, verify_poll: Duration::from_secs(1), settle: Duration::from_secs(3), start_timeout: None };
}

#[derive(Debug, Clone)]
pub struct QuiesceEnv {
    pub own_id: String,
    pub protected_extra: Vec<String>,
    /// host-side hard cap of the stop window (`FORK_QUIESCE_MAX_STOP_SECONDS`, 60..=3600, default 1800)
    pub max_stop_cap: u32,
    pub journal_dir: PathBuf,
    pub t: Timing,
    /// tests only: replaces the payload/cap window length (production keeps `None`)
    pub window_override: Option<Duration>,
}

impl QuiesceEnv {
    /// Fail closed with ONE reason (logged once, no capability): host-side opt-in, valid protected list, own container id. The caller proved Docker answers.
    pub fn detect(env: &dyn Fn(&str) -> Option<String>, mountinfo: &str, cgroup: &str, state_path: &Path) -> Result<QuiesceEnv, &'static str> {
        if !env("FORK_QUIESCE_ENABLED").map(|s| s.trim().eq_ignore_ascii_case("true")).unwrap_or(false) {
            return Err("FORK_QUIESCE_ENABLED is not true on this host");
        }
        let protected_extra = crate::fork::compose::protected_list(env)?;
        let own_id = crate::domain::docker_volume::docker::parse_container_id(mountinfo, cgroup).ok_or("the agent cannot determine its own container id")?;
        let max_stop_cap = match env("FORK_QUIESCE_MAX_STOP_SECONDS").filter(|s| !s.trim().is_empty()) {
            None => 1800,
            Some(s) => s.trim().parse::<u32>().ok().filter(|n| (60..=3600).contains(n)).ok_or("FORK_QUIESCE_MAX_STOP_SECONDS must be 60..3600")?,
        };
        let dir = journal::dir(state_path.parent().unwrap_or(Path::new("/config")));
        Ok(QuiesceEnv { own_id, protected_extra, max_stop_cap, journal_dir: dir, t: Timing::REAL, window_override: None })
    }
}

// ---- the dashboard side of the window -----------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Release,
    Wait,
    /// 404 / 409: the dashboard no longer knows the task ⇒ fail safe, release
    Gone,
    /// network error / 5xx / 429: NOT a release — the agent-local deadline decides
    Unreachable,
}
#[async_trait]
pub trait Port: Send + Sync {
    async fn report(&self, phase: &str, containers: Option<Value>) -> Reply;
}

/// Outer executor deadline (D5): the window + every container's stop and start + slack. The task's own deadlines fire long before this.
pub fn deadline_of(payload: &[u8]) -> Duration {
    match serde_json::from_slice::<QuiesceBody>(payload) {
        Ok(b) => Duration::from_secs(b.max_stop_seconds as u64 + b.targets.len() as u64 * (b.stop_timeout_cap_seconds + b.start_timeout_seconds) as u64 + 300),
        Err(_) => Duration::from_secs(70 * 60),
    }
}
pub const START_DEADLINE: Duration = Duration::from_secs(30 * 60);

// ---- restart of one container (D4) --------------------------------------------------------------------------------------------------
/// start → wait until running (and healthy when a healthcheck exists) → settle → re-inspect (still running, restart count unchanged).
/// Outcome: verified | unhealthy | still_starting | not_running | replaced.
pub(crate) async fn restart_one(ops: &dyn QOps, t: Timing, id: &str, project: &str, service: &str, start_timeout: Duration) -> &'static str {
    let mut started = false;
    for attempt in 0..2 {
        match ops.start_container(id).await {
            Ok(()) => {
                started = true;
                break;
            }
            Err(Code::ContainerChanged) => {
                // 404: the container was recreated (e.g. an orchestrator). A running container of the same project + service counts as running, the window is not intact.
                let all = ops.containers().await.unwrap_or_default();
                let found = all.iter().any(|c| c.running && c.labels.get(plan::PROJECT_LABEL).map(String::as_str) == Some(project) && c.labels.get(plan::SERVICE_LABEL).map(String::as_str) == Some(service));
                return if found { "replaced" } else { "not_running" };
            }
            Err(_) if attempt == 0 => tokio::time::sleep(t.verify_poll).await,
            Err(_) => {}
        }
    }
    if !started {
        return "not_running";
    }
    let base = ops.inspect_state(id).await.ok().flatten().map(|s| s.restart_count);
    let until = Instant::now() + start_timeout;
    let mut last: Option<CState> = None;
    loop {
        if let Ok(Some(s)) = ops.inspect_state(id).await {
            let ok = s.running && s.health.as_deref().is_none_or(|h| h == "healthy");
            last = Some(s);
            if ok {
                break;
            }
        }
        if Instant::now() >= until {
            return match last {
                Some(s) if s.running && s.health.as_deref() == Some("unhealthy") => "unhealthy",
                Some(s) if s.running => "still_starting",
                _ => "not_running",
            };
        }
        tokio::time::sleep(t.verify_poll).await;
    }
    tokio::time::sleep(t.settle).await;
    match ops.inspect_state(id).await {
        Ok(Some(s)) if s.running && base.is_none_or(|b| s.restart_count == b) && s.health.as_deref().is_none_or(|h| h != "unhealthy") => "verified",
        Ok(Some(s)) if s.running && s.health.as_deref() == Some("unhealthy") => "unhealthy",
        Ok(Some(s)) if s.running => "not_running", // restarted behind our back (crash loop): not a verified start
        _ => "not_running",
    }
}

/// Start every journaled container that was running before and was (or may have been) stopped, in START order (reverse of stop), verifying each before the next.
/// ALL of them are started even when an earlier one fails verification. Persists after each container. Returns whether all are verified.
pub(crate) async fn start_phase(ops: &dyn QOps, t: Timing, dir: &Path, j: &mut QJournal) -> bool {
    let start_timeout = t.start_timeout.unwrap_or(Duration::from_secs(j.start_timeout_s as u64));
    let order: Vec<usize> = (0..j.containers.len()).rev().filter(|i| j.containers[*i].stop_intent && j.containers[*i].was_running).collect();
    for i in order {
        let (id, service) = (j.containers[i].id.clone(), j.containers[i].service.clone());
        let outcome = restart_one(ops, t, &id, &j.project, &service, start_timeout).await;
        let e = &mut j.containers[i];
        e.started = matches!(outcome, "verified" | "replaced" | "unhealthy" | "still_starting");
        e.outcome = Some(outcome.to_string());
        let _ = journal::save(dir, j);
    }
    j.containers.iter().filter(|e| e.stop_intent && e.was_running).all(|e| e.outcome.as_deref() == Some("verified"))
}

/// The task result (also used by replay): top-level summary fields are authoritative for the dashboard, `containers` is trimmed to stay small.
pub(crate) fn summary(j: &QJournal, released_by: &str, window_intact: bool, downtime_ms: Option<u64>) -> Value {
    let touched = |e: &&QEntry| e.stop_intent && e.was_running;
    let stopped_count = j.containers.iter().filter(touched).count();
    let verified_count = j.containers.iter().filter(touched).filter(|e| e.outcome.as_deref() == Some("verified")).count();
    let mk = |n: usize| -> Value {
        let list: Vec<Value> = j.containers.iter().take(n).map(|e| json!({"service": e.service, "id12": e.id.chars().take(12).collect::<String>(), "was_running": e.was_running, "stopped": e.stopped, "started": e.started,
            "outcome": e.outcome.clone().unwrap_or_else(|| if e.was_running { "not_running".into() } else { "not_running_before".into() })})).collect();
        let mut m = json!({"project": j.project, "released_by": released_by, "window_intact": window_intact, "all_verified": stopped_count == verified_count, "stopped_count": stopped_count, "verified_count": verified_count, "containers": list});
        if n < j.containers.len() {
            m["containers_truncated"] = json!(true);
        }
        if let Some(d) = downtime_ms {
            m["downtime_ms"] = json!(d);
        }
        m
    };
    let mut n = j.containers.len();
    loop {
        let v = mk(n);
        if n == 0 || serde_json::to_vec(&v).map(|b| b.len()).unwrap_or(usize::MAX) <= MAX_RESULT_BYTES {
            return v;
        }
        n -= 1;
    }
}

fn dry_result(project: &str, targets: &[plan::Target], states: &HashMap<String, CState>) -> Value {
    let list: Vec<Value> = targets.iter().map(|t| json!({"service": t.service, "id12": t.id.chars().take(12).collect::<String>(), "status": states.get(&t.id).map(|s| s.status.clone()).unwrap_or_default(),
        "health": states.get(&t.id).and_then(|s| s.health.clone()), "was_running": t.was_running})).collect();
    json!({"dry_run": true, "project": project, "targets": list})
}

fn fail_with(code: Code, result: Value) -> Failure {
    Failure::from(code).with_extra(result)
}

// ---- execute ------------------------------------------------------------------------------------------------------------------------
pub async fn execute(q: &QuiesceEnv, ops: &dyn QOps, port: &dyn Port, task_id: &str, payload: &[u8]) -> Result<Value, Failure> {
    let body: QuiesceBody = serde_json::from_slice(payload).map_err(|_| Failure::from(Code::PayloadInvalid))?;
    plan::validate(&body)?;
    if !is_uuid(task_id) {
        return Err(Code::PayloadInvalid.into());
    }
    // D8 rule 6: an unresolved journal of this project blocks a new quiesce unless every container of it is running again (then it is stale: resolve it)
    if let Some(pj) = journal::pending_for(&q.journal_dir, &body.project) {
        let mut all_up = true;
        for e in pj.containers.iter().filter(|e| e.stop_intent && e.was_running) {
            all_up &= matches!(ops.inspect_state(&e.id).await, Ok(Some(s)) if s.running);
        }
        if all_up {
            journal::remove(&q.journal_dir, &pj.task_id);
        } else {
            return Err(Code::QuiescePending.into());
        }
    }
    let all = ops.containers().await?;
    let protected: HashSet<String> = guard::protected_ids(&all, &q.own_id, &q.protected_extra);
    let mut states: HashMap<String, CState> = HashMap::new();
    for c in all.iter().filter(|c| c.labels.get(plan::PROJECT_LABEL).map(String::as_str) == Some(body.project.as_str())) {
        if let Some(s) = ops.inspect_state(&c.id).await? {
            states.insert(c.id.clone(), s);
        }
    }
    let targets = plan::resolve(&body, &all, &states, &protected, body.stop_timeout_cap_seconds)?;
    if body.dry_run {
        return Ok(dry_result(&body.project, &targets, &states));
    }

    let mut j = QJournal {
        v: 1,
        task_id: task_id.to_string(),
        run_id: body.run_id.clone(),
        project: body.project.clone(),
        created_unix: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0),
        phase: "stopping".into(),
        containers: targets.iter().map(|t| QEntry { id: t.id.clone(), service: t.service.clone(), name: t.name.clone(), was_running: t.was_running, stop_intent: false, stopped: false, started: false, outcome: None }).collect(),
        released_by: None,
        replay: None,
        start_timeout_s: body.start_timeout_seconds,
    };
    // the journal exists on disk BEFORE the first stop; if it cannot be written nothing is stopped
    journal::save(&q.journal_dir, &j)?;
    tracing::info!("Fork quiesce: task {task_id} project {} — stopping {} container(s)", body.project, targets.iter().filter(|t| t.was_running).count());

    let first_stop = Instant::now();
    let window = q.window_override.unwrap_or_else(|| Duration::from_secs(body.max_stop_seconds.min(q.max_stop_cap) as u64));
    let deadline = first_stop + window;
    let mut released_by: &str;
    let mut stop_err: Option<Code> = None;

    for (i, t) in targets.iter().enumerate() {
        if !t.was_running {
            continue;
        }
        j.containers[i].stop_intent = true;
        if let Err(c) = journal::save(&q.journal_dir, &j) {
            j.containers[i].stop_intent = false;
            stop_err = Some(c);
            break;
        }
        match ops.stop_container(&t.id, t.stop_timeout).await {
            Ok(()) => {
                // a stop that returned Ok must really have stopped it
                if matches!(ops.inspect_state(&t.id).await, Ok(Some(s)) if s.running) {
                    stop_err = Some(Code::StopFailed);
                    break;
                }
                j.containers[i].stopped = true;
                let _ = journal::save(&q.journal_dir, &j);
            }
            Err(_) => {
                stop_err = Some(Code::StopFailed);
                break;
            }
        }
    }

    if stop_err.is_some() {
        released_by = "stop_failed";
    } else {
        j.phase = "stopped".into();
        let _ = journal::save(&q.journal_dir, &j);
        let report: Vec<Value> = j.containers.iter().map(|e| json!({"service": e.service, "id12": e.id.chars().take(12).collect::<String>(), "was_running": e.was_running})).collect();
        let first = tokio::time::timeout_at(deadline, port.report("stopped", Some(Value::Array(report)))).await;
        released_by = match first {
            Err(_) => "deadline",
            Ok(Reply::Release) => "dashboard",
            Ok(Reply::Gone) => "lost_dashboard",
            Ok(Reply::Wait | Reply::Unreachable) => "",
        };
        while released_by.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                released_by = "deadline";
                break;
            }
            tokio::time::sleep(q.t.poll_every.min(deadline - now)).await;
            if Instant::now() >= deadline {
                released_by = "deadline";
                break;
            }
            // a stopped container that runs again (someone / something restarted it) means the copy is no longer quiesced
            let mut broken = false;
            for e in j.containers.iter().filter(|e| e.stopped) {
                if matches!(ops.inspect_state(&e.id).await, Ok(Some(s)) if s.running) {
                    broken = true;
                }
            }
            if broken {
                released_by = "window_broken";
                break;
            }
            match tokio::time::timeout_at(deadline, port.report("waiting", None)).await {
                Err(_) => released_by = "deadline",
                Ok(Reply::Release) => released_by = "dashboard",
                Ok(Reply::Gone) => released_by = "lost_dashboard",
                Ok(Reply::Wait | Reply::Unreachable) => {}
            }
        }
    }

    // start phase — always, whatever ended the window
    j.phase = "starting".into();
    j.released_by = Some(released_by.to_string());
    let _ = journal::save(&q.journal_dir, &j);
    let all_ok = start_phase(ops, q.t, &q.journal_dir, &mut j).await;
    let downtime_ms = first_stop.elapsed().as_millis() as u64;
    // intact = the dashboard released it AND no stopped container was seen running (that would have ended the window as `window_broken`)
    let window_intact = released_by == "dashboard";
    let result = summary(&j, released_by, window_intact, Some(downtime_ms));
    if let Some(code) = stop_err {
        if all_ok {
            journal::remove(&q.journal_dir, task_id);
        } else {
            j.phase = "unresolved".into();
            let _ = journal::save(&q.journal_dir, &j);
        }
        return Err(fail_with(if code == Code::JournalUnavailable { code } else { Code::StopFailed }, result));
    }
    if all_ok {
        journal::remove(&q.journal_dir, task_id);
        tracing::info!("Fork quiesce: task {task_id} finished ({released_by}), downtime {downtime_ms} ms");
        Ok(result)
    } else {
        j.phase = "unresolved".into();
        let _ = journal::save(&q.journal_dir, &j);
        tracing::error!("Fork quiesce: task {task_id}: not every container was verified after the start (journal kept)");
        Err(fail_with(Code::RestartUnverified, result))
    }
}

/// "Start now" retry (OD-W17b-13): replay the agent's OWN journal of an earlier quiesce task. No ids come from the payload.
pub async fn execute_start(q: &QuiesceEnv, ops: &dyn QOps, payload: &[u8]) -> Result<Value, Failure> {
    let body: StartBody = serde_json::from_slice(payload).map_err(|_| Failure::from(Code::PayloadInvalid))?;
    if body.v != 1 || !is_uuid(&body.quiesce_task_id) || !is_project(&body.project) {
        return Err(Code::PayloadInvalid.into());
    }
    let Some(mut j) = journal::load(&q.journal_dir, &body.quiesce_task_id).map_err(Failure::from)? else {
        return Ok(json!({"nothing_to_start": true}));
    };
    if j.project != body.project {
        return Err(Code::PayloadInvalid.into());
    }
    if replay::replay_one(ops, q.t, &q.journal_dir, &mut j).await {
        journal::remove(&q.journal_dir, &body.quiesce_task_id);
        Ok(replay::replay_value(&j))
    } else {
        Err(fail_with(Code::RestartUnverified, replay::replay_value(&j)))
    }
}
