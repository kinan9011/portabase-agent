//! W17b quiesce journal (D6): `<state_dir>/fork-quiesce/<task_id>.json`, dir 0700, file 0600, atomic rewrite (tmp + fsync + rename) on every state change,
//! written BEFORE the first stop. Holds ids / service + container names / flags only (no secrets), never lives inside a volume. A corrupt file is logged and
//! skipped, never deleted.
use crate::fork::restore::{Code, is_uuid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

fn default_start_timeout() -> u32 {
    180
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QEntry {
    /// FULL container id
    pub id: String,
    pub service: String,
    pub name: String,
    pub was_running: bool,
    pub stop_intent: bool,
    pub stopped: bool,
    pub started: bool,
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QJournal {
    pub v: u8,
    pub task_id: String,
    pub run_id: String,
    pub project: String,
    pub created_unix: i64,
    /// stopping | stopped | starting | unresolved | replayed
    pub phase: String,
    /// STOP order
    pub containers: Vec<QEntry>,
    pub released_by: Option<String>,
    pub replay: Option<Value>,
    #[serde(default = "default_start_timeout")]
    pub start_timeout_s: u32,
}

pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("fork-quiesce")
}

fn file(dir: &Path, task_id: &str) -> Result<PathBuf, Code> {
    if !is_uuid(task_id) {
        return Err(Code::JournalUnavailable);
    }
    Ok(dir.join(format!("{task_id}.json")))
}

pub fn save(dir: &Path, j: &QJournal) -> Result<(), Code> {
    let path = file(dir, &j.task_id)?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|_| Code::JournalUnavailable)?;
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec(j).map_err(|_| Code::JournalUnavailable)?;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).map_err(|_| Code::JournalUnavailable)?;
    f.write_all(&data).and_then(|_| f.sync_all()).map_err(|_| Code::JournalUnavailable)?;
    std::fs::rename(&tmp, &path).map_err(|_| Code::JournalUnavailable)?;
    // make the rename itself durable
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn load(dir: &Path, task_id: &str) -> Result<Option<QJournal>, Code> {
    let path = file(dir, task_id)?;
    match std::fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Code::JournalUnavailable),
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|_| Code::JournalUnavailable),
    }
}

/// Every readable journal; a corrupt or foreign file is logged and skipped (never deleted).
pub fn list(dir: &Path) -> Vec<QJournal> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        let Some(stem) = p.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".json")) else { continue };
        if !is_uuid(stem) {
            continue;
        }
        match std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<QJournal>(&b).ok()) {
            Some(j) if j.task_id == stem => out.push(j),
            _ => tracing::error!("Fork quiesce: journal file {stem}.json is corrupt; it is kept for the operator (docker start the stopped containers by hand)"),
        }
    }
    out.sort_by_key(|j| j.created_unix);
    out
}

pub fn remove(dir: &Path, task_id: &str) {
    if let Ok(p) = file(dir, task_id) {
        let _ = std::fs::remove_file(p);
    }
}

pub fn pending_for(dir: &Path, project: &str) -> Option<QJournal> {
    list(dir).into_iter().find(|j| j.project == project)
}

pub fn has_any(dir: &Path) -> bool {
    std::fs::read_dir(dir).map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().ends_with(".json"))).unwrap_or(false)
}
