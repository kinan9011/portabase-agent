//! Restore journal (DD16): one JSON line per event, fsync per line, kept in the agent STATE dir (never inside a restored/backed-up volume, RK6).
//! `done(step)` makes a re-run of the same `restore_id` skip finished steps; `abort` marks a run that a restart interrupted.
use super::Code;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Line {
    pub t: i64,
    pub task: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub ev: String,
    pub step: Option<String>,
    pub ok: Option<bool>,
    pub sha256: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

pub struct Journal {
    path: PathBuf,
    file: File,
}

pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("fork-restore")
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Journal {
    /// `restore_id` must be uuid-shaped (checked by the payload validation; re-checked here because it becomes a file name).
    pub fn open(state_dir: &Path, restore_id: &str) -> Result<Self, Code> {
        if !super::is_uuid(restore_id) {
            return Err(Code::RestoreFailed);
        }
        let d = dir(state_dir);
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&d).map_err(|_| Code::RestoreFailed)?;
        let path = d.join(format!("{restore_id}.jsonl"));
        let file = OpenOptions::new().create(true).append(true).mode(0o600).open(&path).map_err(|_| Code::RestoreFailed)?;
        Ok(Self { path, file })
    }

    fn put(&mut self, l: &Line) {
        // a journal write failure must not abort a restore that is otherwise fine, but the step is then not resumable
        if let Ok(mut s) = serde_json::to_string(l) {
            s.push('\n');
            if self.file.write_all(s.as_bytes()).is_ok() {
                let _ = self.file.sync_all();
            }
        }
    }
    fn line(task: &str, ty: &str, ev: &str, step: Option<&str>, ok: Option<bool>, sha: Option<&str>) -> Line {
        Line { t: now(), task: task.into(), ty: ty.into(), ev: ev.into(), step: step.map(Into::into), ok, sha256: sha.map(Into::into), reason: None }
    }
    pub fn begin(&mut self, task: &str, ty: &str) {
        self.put(&Self::line(task, ty, "begin", None, None, None));
    }
    pub fn step(&mut self, task: &str, ty: &str, step: &str, ok: bool, sha: Option<&str>) {
        self.put(&Self::line(task, ty, "step", Some(step), Some(ok), sha));
    }
    pub fn end(&mut self, task: &str, ty: &str, ok: bool) {
        self.put(&Self::line(task, ty, "end", None, Some(ok), None));
    }
    pub fn abort(&mut self, task: &str, ty: &str, reason: &str) {
        let mut l = Self::line(task, ty, "abort", None, None, None);
        l.reason = Some(reason.into());
        self.put(&l);
    }

    pub fn lines(&self) -> Vec<Line> {
        read_lines(&self.path)
    }
    /// Latest successful `step` record of this run: `Some(sha)` (empty string when the step carried none).
    pub fn done(&self, step: &str) -> Option<String> {
        self.lines().into_iter().rev().find(|l| l.ev == "step" && l.ok == Some(true) && l.step.as_deref() == Some(step)).map(|l| l.sha256.unwrap_or_default())
    }
}

pub fn read_lines(path: &Path) -> Vec<Line> {
    let Ok(f) = File::open(path) else { return vec![] };
    BufReader::new(f).lines().map_while(Result::ok).filter_map(|s| serde_json::from_str::<Line>(&s).ok()).collect()
}

/// `true` when the last event of the run is a `begin` / `step` (a task started and never ended or aborted).
pub fn interrupted(lines: &[Line]) -> Option<&Line> {
    lines.last().filter(|l| l.ev == "begin" || l.ev == "step")
}

#[cfg(test)]
mod tests {
    use super::*;
    const RID: &str = "77777777-7777-4777-8777-777777777777";

    #[test]
    fn steps_resume_and_abort_marks_interruption() {
        let d = tempfile::tempdir().unwrap();
        let mut j = Journal::open(d.path(), RID).unwrap();
        j.begin("t1", "restore_stage");
        j.step("t1", "restore_stage", "artifact:0", true, Some("abc"));
        j.step("t1", "restore_stage", "artifact:1", false, None);
        assert_eq!(j.done("artifact:0").as_deref(), Some("abc"));
        assert_eq!(j.done("artifact:1"), None, "a failed step is not done");
        assert!(interrupted(&j.lines()).is_some());
        j.abort("t1", "restore_stage", "restart");
        assert!(interrupted(&j.lines()).is_none());
        // re-open (new process) sees the same history
        let j2 = Journal::open(d.path(), RID).unwrap();
        assert_eq!(j2.done("artifact:0").as_deref(), Some("abc"));
        assert_eq!(std::fs::metadata(d.path().join("fork-restore").join(format!("{RID}.jsonl"))).unwrap().permissions().mode() & 0o777, 0o600);
    }
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn file_name_is_never_attacker_shaped() {
        let d = tempfile::tempdir().unwrap();
        for bad in ["../x", "a/b", "", "not-a-uuid", "77777777-7777-4777-8777-77777777777/"] {
            assert!(Journal::open(d.path(), bad).is_err(), "{bad}");
        }
    }
}
