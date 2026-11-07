//! Persisted replay / rollback state (ADR-007 D3): `last_seq` per enrolment generation + a bounded ring of accepted task ids with their outcome.
//! Fail closed: an unreadable or corrupt file stops the channel (never a silent reset — a reset would re-open every replay). The only reset is a
//! new enrolment generation (`enroll_id` changes = operator re-enrolled the agent after a dashboard rollback or compromise).
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub const MAX_ACCEPTED: usize = 256;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("channel state file is unreadable or corrupt")]
    Corrupt,
    #[error("channel state file cannot be written")]
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    pub status: String,
    pub reason: Option<String>,
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Accepted {
    pub task_id: String,
    pub seq: u64,
    pub outcome: Option<Outcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub enroll_id: String,
    pub last_seq: u64,
    pub accepted: Vec<Accepted>,
}

impl State {
    pub fn fresh(enroll_id: &str) -> Self {
        State { enroll_id: enroll_id.to_string(), last_seq: 0, accepted: Vec::new() }
    }
    pub fn known(&self, task_id: &str) -> Option<&Accepted> {
        self.accepted.iter().find(|a| a.task_id == task_id)
    }
    /// Records acceptance BEFORE execution (so a crash mid-task can never re-run it).
    pub fn accept(&mut self, task_id: &str, seq: u64) {
        self.last_seq = self.last_seq.max(seq);
        self.accepted.push(Accepted { task_id: task_id.to_string(), seq, outcome: None });
        if self.accepted.len() > MAX_ACCEPTED {
            self.accepted.remove(0);
        }
    }
    pub fn set_outcome(&mut self, task_id: &str, outcome: Outcome) {
        if let Some(a) = self.accepted.iter_mut().find(|a| a.task_id == task_id) {
            a.outcome = Some(outcome);
        }
    }
}

pub fn load(path: &Path, enroll_id: &str) -> Result<State, StateError> {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::fresh(enroll_id)),
        Err(_) => Err(StateError::Corrupt),
        Ok(text) => {
            let s: State = serde_json::from_str(&text).map_err(|_| StateError::Corrupt)?;
            // a different generation = the operator re-enrolled: the old counters belong to a dashboard that no longer exists
            Ok(if s.enroll_id == enroll_id { s } else { State::fresh(enroll_id) })
        }
    }
}

/// Atomic write (temp file, 0600, fsync, rename).
pub fn save(path: &Path, state: &State) -> Result<(), StateError> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec(state).map_err(|_| StateError::Write)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|_| StateError::Write)?;
    f.write_all(&data).and_then(|_| f.sync_all()).map_err(|_| StateError::Write)?;
    std::fs::rename(&tmp, path).map_err(|_| StateError::Write)
}
