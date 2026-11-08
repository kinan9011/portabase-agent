//! `restore_verify` (W-TR, ADR-007 A16): engine integrity check of the staged artifacts of a data-only TEST restore. Each check re-hashes the staged plaintext archive
//! against the signed manifest, extracts it into a private directory under the workspace (`.portabase/verify/a<i>/`, 0700 / 0600, never outside the workspace), and
//! runs the engine's own reader in a hardened helper container (no network, caps dropped, read-only rootfs, helper label): `sqlite3 … PRAGMA integrity_check` or
//! `pg_restore -f /dev/null` (reads and decompresses every TOC entry and data block, writes nothing, needs no server). The result carries codes and counts only:
//! never stdout content, a path or a stderr line.
use super::artifact;
use super::docker_ops::DockerOps;
use super::journal::Journal;
use super::manifest::{self, Expect, Role};
use super::stage::{role_name, staged_file};
use super::workspace::{Claim, Workspace};
use super::{CheckRef, Code, Engine, Failure, Purpose, R, RestoreEnv, Task, VerifyBody, paths, split};
use crate::fork::crypto::Pin;
use serde_json::{Value, json};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const SQLITE_BIN: &str = "/usr/bin/sqlite3";
const PG_BASE: &str = "/usr/lib/postgresql";
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// Per helper run (one file / one dump). The task deadline (`DEADLINE_VERIFY`) bounds the sum.
const HELPER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Highest `<base>/<n>/bin/pg_restore` (numeric sort of `<n>`), as an absolute path.
pub fn pg_restore_bin_in(base: &Path) -> Option<String> {
    let mut best: Option<(u32, PathBuf)> = None;
    for e in std::fs::read_dir(base).ok()?.flatten() {
        let Some(n) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let bin = e.path().join("bin/pg_restore");
        if bin.is_file() && best.as_ref().is_none_or(|(b, _)| n > *b) {
            best = Some((n, bin));
        }
    }
    best.map(|(_, p)| p.display().to_string())
}
pub fn pg_restore_bin() -> Option<String> {
    pg_restore_bin_in(Path::new(PG_BASE))
}
/// The checkers exist in THIS filesystem (the helper container runs the agent's own image).
pub fn tools_present() -> bool {
    Path::new(SQLITE_BIN).is_file() && pg_restore_bin().is_some()
}

fn make_private_dir(p: &Path) -> R<()> {
    let _ = std::fs::remove_dir_all(p);
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p).map_err(|_| Failure::from(Code::RestoreFailed))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).map_err(|_| Failure::from(Code::RestoreFailed))
}

/// After extraction: owner-only modes, and (when the agent runs as root) the tree owned by the agent so the helper (same uid) can read AND write without any capability.
fn normalize(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        let _ = std::os::unix::fs::lchown(&p, Some(unsafe { libc::geteuid() }), Some(unsafe { libc::getegid() }));
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
            normalize(&p);
        } else {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
    }
}

/// Regular files below `dir` (symlinks never followed), sorted, as paths relative to `dir`.
fn regular_files(dir: &Path) -> Vec<PathBuf> {
    fn walk(base: &Path, p: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(p) else { return };
        for e in rd.flatten() {
            let q = e.path();
            let Ok(md) = std::fs::symlink_metadata(&q) else { continue };
            if md.is_dir() {
                walk(base, &q, out);
            } else if md.is_file() {
                out.push(q.strip_prefix(base).unwrap_or(&q).to_path_buf());
            }
        }
    }
    let mut v = Vec::new();
    walk(dir, dir, &mut v);
    v.sort();
    v
}

fn is_sqlite(path: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut b)).is_ok() && &b == SQLITE_MAGIC
}

fn classify(engine: &str, out: &super::docker_ops::CheckOut, expect_ok_stdout: bool) -> R<()> {
    match out.code {
        126 | 127 => Err(Code::EngineUnavailable.into()),
        0 if !expect_ok_stdout || String::from_utf8_lossy(&out.stdout).trim() == "ok" => Ok(()),
        _ => Err(Failure::with(Code::IntegrityFailed, engine)),
    }
}

fn vpath(rel: &Path) -> String {
    format!("/v/{}", rel.display())
}

pub(crate) async fn check_sqlite(ops: &dyn DockerOps, dir: &Path) -> R<usize> {
    let files: Vec<PathBuf> = regular_files(dir).into_iter().filter(|r| is_sqlite(&dir.join(r))).collect();
    if files.is_empty() {
        return Err(Failure::with(Code::IntegrityFailed, "no_sqlite_file"));
    }
    for rel in &files {
        let argv = vec![SQLITE_BIN.to_string(), vpath(rel), "PRAGMA temp_store=MEMORY; PRAGMA integrity_check;".to_string()];
        classify("sqlite", &ops.helper_check(dir, argv, HELPER_TIMEOUT).await?, true)?;
    }
    Ok(files.len())
}

/// The staged archive holds one `-Fc` file, or one gzip'd tar of a `-Fd` directory (`artifact::check_pg_dump`): find what `pg_restore` must be pointed at.
pub(crate) fn pg_target(dir: &Path) -> R<(Vec<String>, PathBuf)> {
    let files = regular_files(dir);
    let [only] = files.as_slice() else { return Err(Failure::with(Code::IntegrityFailed, "no_dump")) };
    let mut head = [0u8; 5];
    {
        use std::io::Read;
        std::fs::File::open(dir.join(only)).and_then(|mut f| f.read_exact(&mut head)).map_err(|_| Failure::with(Code::IntegrityFailed, "no_dump"))?;
    }
    if &head == b"PGDMP" {
        return Ok((vec![], only.clone()));
    }
    if head[0] == 0x1f && head[1] == 0x8b {
        let inner_dir = dir.join("inner-dir");
        artifact::extract(&dir.join(only), &inner_dir).map_err(|c| Failure::from(c))?;
        normalize(&inner_dir);
        let found = regular_files(&inner_dir).into_iter().find(|r| r.file_name().is_some_and(|n| n == "toc.dat"));
        let Some(toc) = found else { return Err(Failure::with(Code::IntegrityFailed, "no_dump")) };
        let parent = toc.parent().map(Path::to_path_buf).unwrap_or_default();
        return Ok((vec!["-Fd".to_string()], Path::new("inner-dir").join(parent)));
    }
    Err(Failure::with(Code::IntegrityFailed, "no_dump"))
}

async fn check_pg(ops: &dyn DockerOps, dir: &Path, pg_bin: Option<&str>) -> R<usize> {
    let bin = pg_bin.ok_or_else(|| Failure::from(Code::EngineUnavailable))?.to_string();
    let (fmt, target) = pg_target(dir)?;
    let mut argv = vec![bin];
    argv.extend(fmt);
    argv.extend(["-f".to_string(), "/dev/null".to_string(), vpath(&target)]);
    classify("postgresql", &ops.helper_check(dir, argv, HELPER_TIMEOUT).await?, false)?;
    Ok(1)
}

fn bounds_ok(checks: &[CheckRef]) -> bool {
    let mut seen = std::collections::HashSet::new();
    (1..=100).contains(&checks.len()) && checks.iter().all(|c| seen.insert(c.index))
}

pub async fn run(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8]) -> R<Value> {
    run_with(env, ops, pins, t, payload, pg_restore_bin()).await
}

/// `pg_bin` injected so unit tests do not depend on the host's PostgreSQL client installation.
pub(crate) async fn run_with(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8], pg_bin: Option<String>) -> R<Value> {
    let (h, b): (super::Header, VerifyBody) = split(payload)?;
    h.check(env)?;
    if h.purpose != Purpose::TestRestore {
        return Err(Code::ModeUnsupported.into()); // only a data-only test restore is engine-checked
    }
    if !super::is_hex64(&b.manifest_sha256) || !bounds_ok(&b.checks) {
        return Err(Code::PayloadInvalid.into());
    }
    let ws_path = paths::check_task_path(&env.roots, &env.state_dir, &h.workspace)?;
    let mut j = Journal::open(&env.state_dir, &h.restore_id)?;
    j.begin(t.id, t.ty);
    let r = inner(env, ops, pins, t, &h, &b, &ws_path, &mut j, pg_bin.as_deref()).await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

#[allow(clippy::too_many_arguments)]
async fn inner(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, h: &super::Header, b: &VerifyBody, ws_path: &Path, j: &mut Journal, pg_bin: Option<&str>) -> R<Value> {
    let started = Instant::now();
    let claim = Claim { restore_id: &h.restore_id, stack_id: &h.stack_id, rp_id: &h.rp_id, project: &h.project, agent_id: &env.agent_id };
    let ws = Workspace::open_owned(ws_path, &claim, t.now)?;
    let json = std::fs::read(ws.stage().join("manifest.json")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    let sig = std::fs::read(ws.stage().join("manifest.sig")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    let m = manifest::verify(&json, &sig, pins, &Expect { rp_id: &h.rp_id, stack_id: &h.stack_id, sequence: None, sha256: &b.manifest_sha256, min_sequence: None })?;
    let verify_root = ws.meta().join("verify");
    let r = checks(ops, &ws, &m, b, t, j, pg_bin, &verify_root).await;
    let _ = std::fs::remove_dir_all(&verify_root); // every outcome: nothing of the private copies outlives the task
    r.map(|done| json!({"checks": done, "seconds": started.elapsed().as_secs()}))
}

#[allow(clippy::too_many_arguments)]
async fn checks(ops: &dyn DockerOps, ws: &Workspace, m: &manifest::ManifestV1, b: &VerifyBody, t: &Task<'_>, j: &mut Journal, pg_bin: Option<&str>, verify_root: &Path) -> R<Vec<Value>> {
    let mut done = Vec::new();
    let mut ordered: Vec<&CheckRef> = b.checks.iter().collect();
    ordered.sort_by_key(|c| c.index);
    for c in ordered {
        let a = m.artifacts.get(c.index).ok_or_else(|| Failure::from(Code::ManifestMismatch).at(c.index))?;
        let role = manifest::role(a);
        let want = if c.engine == Engine::Sqlite { Role::Sqlite } else { Role::PgDump };
        if role != want {
            return Err(Failure::with(Code::ManifestMismatch, role_name(role)).at(c.index));
        }
        let (Some(sha), Some(size)) = (a.plaintext_sha256.clone(), a.plaintext_size) else { return Err(Failure::with(Code::ChecksumMismatch, "no_expected_hash").at(c.index)) };
        let staged = staged_file(ws, c.index);
        if !staged.is_file() {
            return Err(Failure::with(Code::RestoreFailed, "not_staged").at(c.index));
        }
        // close the gap between stage and verify: the staged bytes must still be the signed plaintext
        match crate::fork::hash::plaintext_hash(&staged).await {
            Ok((s, n)) if s == sha && n == size => {}
            _ => return Err(Failure::from(Code::ChecksumMismatch).at(c.index)),
        }
        let dir = verify_root.join(format!("a{}", c.index));
        let r: R<usize> = async {
            make_private_dir(&dir)?;
            artifact::extract(&staged, &dir).map_err(Failure::from)?;
            normalize(&dir);
            match c.engine {
                Engine::Sqlite => check_sqlite(ops, &dir).await,
                Engine::Postgresql => check_pg(ops, &dir, pg_bin).await,
            }
        }
        .await;
        let _ = std::fs::remove_dir_all(&dir); // every outcome: the private copy never outlives the check
        let n = r.map_err(|f| f.at(c.index))?;
        let step = format!("verify:{}", c.index);
        j.step(t.id, t.ty, &step, true, Some(&sha));
        done.push(json!({"index": c.index, "engine": if c.engine == Engine::Sqlite { "sqlite" } else { "postgresql" }, "status": "ok", "files": n}));
    }
    Ok(done)
}
