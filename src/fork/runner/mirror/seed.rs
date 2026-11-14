//! Seed custody (W20 D-6, W22a-f1): 32 random bytes per mirror revision, generated and kept ON THE RUNNER, never uploaded, never logged. The rotated env values
//! are `H(seed, …)`, so the seed is what lets a retried `mirror_finalize` reproduce the very same values the database role was already set to.
//! Layout `<workspace>/.portabase/mirror/seed`: dirs 0700 (`DirBuilder::mode`), file 0600 (`create_new`), symlinks refused, wrong size / group-other bits refused.
//! (It does NOT live in `secret/`: a `SecretGuard` empties that directory at the end of every compose task and the startup sweep removes it.)
use crate::fork::restore::Code;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const SEED_LEN: usize = 32;

/// The holder never prints its bytes (`Debug` is redacted), so a stray `{:?}` can never leak the seed into a log or a result.
pub struct Seed([u8; SEED_LEN]);
impl Seed {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

pub fn meta_dir(ws: &Path) -> PathBuf {
    ws.join(".portabase/mirror")
}
pub fn seed_path(ws: &Path) -> PathBuf {
    meta_dir(ws).join("seed")
}

fn ensure_dir(p: &Path) -> Result<(), Code> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => return Err(Code::SeedInvalid),
        Ok(_) => {}
        Err(_) => std::fs::DirBuilder::new().mode(0o700).create(p).map_err(|_| Code::SeedInvalid)?,
    }
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).map_err(|_| Code::SeedInvalid)
}

/// Read an existing seed file. Anything unexpected (symlink, not a regular file, size ≠ 32, mode with group/other bits) is `seed_invalid`.
fn read_seed(path: &Path) -> Result<[u8; SEED_LEN], Code> {
    let m = std::fs::symlink_metadata(path).map_err(|_| Code::SeedInvalid)?;
    if m.file_type().is_symlink() || !m.is_file() || m.len() != SEED_LEN as u64 || m.mode() & 0o077 != 0 {
        return Err(Code::SeedInvalid);
    }
    let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(|_| Code::SeedInvalid)?;
    let mut b = [0u8; SEED_LEN];
    f.read_exact(&mut b).map_err(|_| Code::SeedInvalid)?;
    Ok(b)
}

fn write_new(path: &Path, b: &[u8; SEED_LEN]) -> Result<(), Code> {
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path).map_err(|_| Code::SeedInvalid)?;
    f.write_all(b).and_then(|_| f.sync_all()).map_err(|_| Code::SeedInvalid)
}

/// Load the revision's seed, or create it. Anything unexpected about an existing file is `seed_invalid`.
pub fn create_or_load(ws: &Path) -> Result<Seed, Code> {
    ensure_dir(&ws.join(".portabase"))?;
    ensure_dir(&meta_dir(ws))?;
    let path = seed_path(ws);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => read_seed(&path).map(Seed),
        Err(_) => {
            let b: [u8; SEED_LEN] = rand::random();
            write_new(&path, &b)?;
            Ok(Seed(b))
        }
    }
}

/// W24 (DD-8): a refresh revision starts from the ACTIVE revision's seed (the test credentials survive a refresh). The source is validated exactly like a loaded seed; the
/// target is written `create_new` 0600 and an EXISTING target seed is never overwritten (it simply stays). No silent fallback to a new seed: any failure is `seed_invalid`.
pub fn copy_from(prev_ws: &Path, ws: &Path) -> Result<(), Code> {
    let b = read_seed(&seed_path(prev_ws))?;
    ensure_dir(&ws.join(".portabase"))?;
    ensure_dir(&meta_dir(ws))?;
    if std::fs::symlink_metadata(seed_path(ws)).is_ok() {
        return Ok(());
    }
    write_new(&seed_path(ws), &b)
}
