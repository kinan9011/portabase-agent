//! Workspace ownership (DD3, DD5): `W = <root>/<project>` with `.portabase/` (0700) holding `owner.json` (0600) and the `tmp|stage|secret|empty` dirs.
//! A workspace is claimed by exactly one `restore_id`; a later task of the SAME run resumes it, any other run is refused. A foreign non-empty directory
//! is never claimed.
use super::Code;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Owner {
    pub v: u8,
    pub restore_id: String,
    pub stack_id: String,
    pub rp_id: String,
    pub project: String,
    pub agent_id: String,
    pub created_at: i64,
    /// Rewritten at every task begin; the startup sweep compares it with its injected clock (never file mtimes).
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct Workspace {
    pub root: PathBuf,
}

pub struct Claim<'a> {
    pub restore_id: &'a str,
    pub stack_id: &'a str,
    pub rp_id: &'a str,
    pub project: &'a str,
    pub agent_id: &'a str,
}

impl Workspace {
    pub fn meta(&self) -> PathBuf {
        self.root.join(".portabase")
    }
    pub fn tmp(&self) -> PathBuf {
        self.meta().join("tmp")
    }
    pub fn stage(&self) -> PathBuf {
        self.meta().join("stage")
    }
    pub fn secret(&self) -> PathBuf {
        self.meta().join("secret")
    }
    pub fn empty(&self) -> PathBuf {
        self.meta().join("empty")
    }
    fn owner_path(&self) -> PathBuf {
        self.meta().join("owner.json")
    }

    pub fn read_owner(root: &Path) -> Option<Owner> {
        serde_json::from_slice(&std::fs::read(root.join(".portabase/owner.json")).ok()?).ok()
    }

    fn write_owner(&self, o: &Owner) -> Result<(), Code> {
        let tmp = self.meta().join("owner.json.tmp");
        let body = serde_json::to_vec(o).map_err(|_| Code::RestoreFailed)?;
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&tmp).map_err(|_| Code::RestoreFailed)?;
            f.write_all(&body).and_then(|_| f.sync_all()).map_err(|_| Code::RestoreFailed)?;
        }
        std::fs::rename(&tmp, self.owner_path()).map_err(|_| Code::RestoreFailed)
    }

    /// Claim or resume. `root` must already have passed `check_task_path`. `now` is epoch seconds.
    pub fn open_or_create(root: &Path, c: &Claim, now: i64) -> Result<Workspace, Code> {
        let ws = Workspace { root: root.to_path_buf() };
        let existing = Self::read_owner(root);
        match (root.exists(), existing) {
            (true, Some(o)) => {
                if o.restore_id != c.restore_id || o.agent_id != c.agent_id || o.rp_id != c.rp_id || o.project != c.project {
                    return Err(Code::WorkspaceNotOwned);
                }
                ws.make_dirs()?;
                ws.write_owner(&Owner { updated_at: now, ..o })?;
            }
            (true, None) => {
                let empty = std::fs::read_dir(root).map_err(|_| Code::WorkspaceNotOwned)?.next().is_none();
                if !empty {
                    return Err(Code::WorkspaceNotOwned);
                }
                ws.claim(c, now)?;
            }
            (false, _) => {
                std::fs::DirBuilder::new().recursive(true).mode(0o750).create(root).map_err(|_| Code::RestoreFailed)?;
                ws.claim(c, now)?;
            }
        }
        Ok(ws)
    }

    /// `restore_apply` / `restore_cleanup`: the workspace must already exist AND belong to this run (never creates, never claims).
    pub fn open_owned(root: &Path, c: &Claim, now: i64) -> Result<Workspace, Code> {
        let o = Self::read_owner(root).ok_or(Code::WorkspaceNotOwned)?;
        if o.restore_id != c.restore_id || o.agent_id != c.agent_id || o.rp_id != c.rp_id || o.project != c.project {
            return Err(Code::WorkspaceNotOwned);
        }
        let ws = Workspace { root: root.to_path_buf() };
        ws.make_dirs()?;
        ws.write_owner(&Owner { updated_at: now, ..o })?;
        Ok(ws)
    }

    fn claim(&self, c: &Claim, now: i64) -> Result<(), Code> {
        self.make_dirs()?;
        self.write_owner(&Owner { v: 1, restore_id: c.restore_id.into(), stack_id: c.stack_id.into(), rp_id: c.rp_id.into(), project: c.project.into(), agent_id: c.agent_id.into(), created_at: now, updated_at: now })
    }

    fn make_dirs(&self) -> Result<(), Code> {
        for d in [self.meta(), self.tmp(), self.stage(), self.secret(), self.empty()] {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&d).map_err(|_| Code::RestoreFailed)?;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).map_err(|_| Code::RestoreFailed)?;
        }
        Ok(())
    }

    /// Empty `tmp/` (downloads) at the end of a task, recreated empty.
    pub fn clear_tmp(&self) {
        let _ = std::fs::remove_dir_all(self.tmp());
        let _ = std::fs::DirBuilder::new().mode(0o700).create(self.tmp());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const R1: &str = "77777777-7777-4777-8777-777777777777";
    const R2: &str = "99999999-9999-4999-8999-999999999999";
    fn claim<'a>(r: &'a str) -> Claim<'a> {
        Claim { restore_id: r, stack_id: "s", rp_id: "rp", project: "app", agent_id: A }
    }

    #[test]
    fn create_resume_and_refuse_foreign() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path().join("restore/app");
        let ws = Workspace::open_or_create(&w, &claim(R1), 1000).unwrap();
        assert_eq!(std::fs::metadata(ws.meta()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(ws.secret()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(ws.meta().join("owner.json")).unwrap().permissions().mode() & 0o777, 0o600);
        // the same run resumes and bumps updated_at
        Workspace::open_or_create(&w, &claim(R1), 2000).unwrap();
        let o = Workspace::read_owner(&w).unwrap();
        assert_eq!((o.created_at, o.updated_at), (1000, 2000));
        // another run on the same workspace is refused
        assert_eq!(Workspace::open_or_create(&w, &claim(R2), 3000).unwrap_err(), Code::WorkspaceNotOwned);
        assert_eq!(Workspace::read_owner(&w).unwrap().restore_id, R1, "owner.json untouched by the refused run");
    }

    #[test]
    fn foreign_non_empty_directory_is_never_claimed_but_an_empty_one_is() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path().join("app");
        std::fs::create_dir_all(&w).unwrap();
        std::fs::write(w.join("precious.txt"), b"x").unwrap();
        assert_eq!(Workspace::open_or_create(&w, &claim(R1), 1).unwrap_err(), Code::WorkspaceNotOwned);
        assert!(w.join("precious.txt").exists() && !w.join(".portabase").exists());
        std::fs::remove_file(w.join("precious.txt")).unwrap();
        assert!(Workspace::open_or_create(&w, &claim(R1), 1).is_ok());
    }
}
