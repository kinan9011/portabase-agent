//! Path model (ADR-007 R6, plan-W17 DD4, SEC-24, #142): allowed roots, the shared lexical grammar (`canon`, the dashboard's `absPath`), and the
//! realpath check that refuses a symlink anywhere on the EXISTING part of a task path. Pure apart from `symlink_metadata` / `canonicalize`.
use super::Code;
use std::path::{Component, Path, PathBuf};

/// A path may not equal, lie under, or contain any of these (fail closed: the root list is rejected as a whole).
pub const FORBIDDEN: &[&str] = &["/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/root", "/var/lib/docker"];
pub const DOCKER_SOCK: &str = "/var/run/docker.sock";
pub const MAX_PATH: usize = 1024;

/// Lexical grammar shared with the dashboard (`payload-schema.ts::absPath`): absolute, no `$`, `~`, control chars, `//`, `.`/`..` segments, no trailing `/`.
pub fn canon(p: &str) -> bool {
    p.len() >= 2
        && p.len() <= MAX_PATH
        && p.starts_with('/')
        && !p.ends_with('/')
        && !p.contains("//")
        && !p.chars().any(|c| c.is_control() || c == '$' || c == '~')
        && p.split('/').skip(1).all(|s| s != "." && s != "..")
}

fn under(p: &Path, root: &Path) -> bool {
    p != root && p.starts_with(root)
}

/// `FORK_ALLOWED_PATH_ROOTS` (colon list). Empty ⇒ no roots (`restore.target.v1` is then not reported). Any invalid root rejects the whole list.
/// `extra_forbidden` = the agent's own state / bundle directories.
pub fn parse_roots(list: &str, extra_forbidden: &[PathBuf]) -> Result<Vec<PathBuf>, &'static str> {
    let mut out: Vec<PathBuf> = Vec::new();
    for raw in list.split(':').map(str::trim).filter(|s| !s.is_empty()) {
        if !canon(raw) {
            return Err("an allowed root is not a canonical absolute path");
        }
        let root = PathBuf::from(raw);
        let md = std::fs::symlink_metadata(&root).map_err(|_| "an allowed root does not exist")?;
        if !md.is_dir() {
            return Err("an allowed root is not a directory");
        }
        if std::fs::canonicalize(&root).map_err(|_| "an allowed root cannot be resolved")? != root {
            return Err("an allowed root is a symlink or contains one");
        }
        let forbidden = FORBIDDEN.iter().map(PathBuf::from).chain(std::iter::once(PathBuf::from(DOCKER_SOCK))).chain(extra_forbidden.iter().cloned());
        for f in forbidden {
            if root == f || root.starts_with(&f) || f.starts_with(&root) {
                return Err("an allowed root overlaps a system or agent directory");
            }
        }
        if !out.contains(&root) {
            out.push(root);
        }
    }
    Ok(out)
}

/// The realpath of the longest EXISTING prefix must equal its lexical form: no symlink (and no bind-mount trick visible as one) anywhere on the existing part.
pub fn no_symlink_on_existing_prefix(p: &Path) -> bool {
    let mut cur = p.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&cur) {
            Ok(_) => return std::fs::canonicalize(&cur).map(|c| c == cur).unwrap_or(false),
            Err(_) => {
                if !cur.pop() || cur.as_os_str().is_empty() {
                    return false;
                }
            }
        }
    }
}

/// Task path check: grammar → strictly under one root (never the root itself) → not in the agent state dir → no symlink on the existing prefix.
pub fn check_task_path(roots: &[PathBuf], state_dir: &Path, p: &str) -> Result<PathBuf, Code> {
    if !canon(p) {
        return Err(Code::PathNotAllowed);
    }
    let path = PathBuf::from(p);
    if !path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))) {
        return Err(Code::PathNotAllowed);
    }
    if !roots.iter().any(|r| under(&path, r)) || path.starts_with(state_dir) || state_dir.starts_with(&path) {
        return Err(Code::PathNotAllowed);
    }
    if !no_symlink_on_existing_prefix(&path) {
        return Err(Code::SymlinkEscape);
    }
    Ok(path)
}

/// `path` (already checked) is `under` `ws` (the workspace) — payload paths must all live there.
pub fn within(ws: &Path, path: &Path) -> bool {
    under(path, ws)
}

pub fn is_name(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.as_bytes()[0].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// Relative path inside a volume (sqlite placement): no leading `/`, no `.`/`..`, no `//`, no control chars.
pub fn rel_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_PATH && !s.starts_with('/') && !s.ends_with('/') && !s.contains("//") && !s.chars().any(|c| c.is_control() || c == '$' || c == '~' || c == '\\') && s.split('/').all(|x| x != "." && x != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn root() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(d.path()).unwrap();
        (d, r)
    }

    #[test]
    fn canon_table() {
        for ok in ["/srv/restore/app", "/a/b.c/d-e_f"] {
            assert!(canon(ok), "{ok}");
        }
        let long = format!("/{}", "a".repeat(1024));
        let bad = ["", "/", "rel/x", "/a/../b", "/a/./b", "/a//b", "/a/b/", "/a/$HOME", "/a/~r", "/a/\u{7f}", "/a/\u{7}b", long.as_str()];
        for b in bad {
            assert!(!canon(b), "{b:?}");
        }
        assert!(!canon(&"a".repeat(1025)));
    }

    #[test]
    fn roots_are_validated_whole_list_or_nothing() {
        let (_d, r) = root();
        assert_eq!(parse_roots(r.to_str().unwrap(), &[]).unwrap(), vec![r.clone()]);
        assert!(parse_roots("", &[]).unwrap().is_empty());
        for bad in ["/", "/etc", "/etc/x", "/var/run/docker.sock", "/var/lib/docker/volumes", "/var", "/usr/local", "relative", "/does/not/exist/xyz"] {
            assert!(parse_roots(bad, &[]).is_err(), "{bad}");
        }
        assert!(parse_roots(&format!("{}:/etc", r.display()), &[]).is_err(), "one bad root rejects the whole list");
        // a symlinked root
        let link = r.join("link");
        symlink(&r, &link).unwrap();
        assert!(parse_roots(link.to_str().unwrap(), &[]).is_err());
        // state dir overlap
        assert!(parse_roots(r.to_str().unwrap(), &[r.join("state")]).is_err(), "root containing the state dir");
        assert!(parse_roots(r.to_str().unwrap(), std::slice::from_ref(&r)).is_err());
    }

    #[test]
    fn task_paths() {
        let (_d, r) = root();
        let roots = vec![r.clone()];
        let state = PathBuf::from("/nonexistent-state-dir");
        let p = |s: &str| check_task_path(&roots, &state, s);
        assert!(p(&format!("{}/restore/app", r.display())).is_ok());
        assert_eq!(p(r.to_str().unwrap()), Err(Code::PathNotAllowed), "the root itself");
        assert_eq!(p("/etc/passwd"), Err(Code::PathNotAllowed));
        assert_eq!(p("/var/run/docker.sock"), Err(Code::PathNotAllowed));
        assert_eq!(p(&format!("{}/a/../b", r.display())), Err(Code::PathNotAllowed));
        assert_eq!(p(&format!("{}/$X", r.display())), Err(Code::PathNotAllowed));
        assert_eq!(p(&format!("{}/{}", r.display(), "a".repeat(1025))), Err(Code::PathNotAllowed));
        assert_eq!(p(&format!("{}/\u{7f}", r.display())), Err(Code::PathNotAllowed));
        assert_eq!(p("relative/x"), Err(Code::PathNotAllowed));
        assert_eq!(p(&format!("{}x/y", r.display())), Err(Code::PathNotAllowed), "prefix without a separator is not under the root");
        // state dir inside the root
        let st = r.join("state");
        assert_eq!(check_task_path(&roots, &st, st.join("x").to_str().unwrap()), Err(Code::PathNotAllowed));
    }

    #[test]
    fn symlinks_anywhere_on_the_existing_part_are_refused() {
        let (_d, r) = root();
        let roots = vec![r.clone()];
        let state = PathBuf::from("/nonexistent-state-dir");
        std::fs::create_dir_all(r.join("real/inner")).unwrap();
        symlink("/etc", r.join("evil")).unwrap();
        symlink(r.join("real"), r.join("alias")).unwrap();
        symlink("/nonexistent-target", r.join("dangling")).unwrap();
        for bad in ["evil", "evil/passwd", "alias/inner", "alias", "dangling", "dangling/x/y"] {
            assert_eq!(check_task_path(&roots, &state, &format!("{}/{bad}", r.display())), Err(Code::SymlinkEscape), "{bad}");
        }
        assert!(check_task_path(&roots, &state, &format!("{}/real/inner/new/deeper", r.display())).is_ok());
    }

    #[test]
    fn names_and_relative_paths() {
        assert!(is_name("app_data", 255) && is_name("a.b-c", 8));
        assert!(!is_name("", 8) && !is_name("-x", 8) && !is_name("a/b", 8) && !is_name("a b", 8) && !is_name(&"a".repeat(300), 255));
        assert!(rel_ok("data/x.db") && !rel_ok("/x") && !rel_ok("../x") && !rel_ok("a/../x") && !rel_ok("a//b") && !rel_ok("") && !rel_ok("a\\b"));
    }
}
