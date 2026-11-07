//! Artifact pipeline (DD14, i-7): download (SSRF-hardened) → decrypt → plaintext SHA-256/size == the signed manifest → complete gzip → tar audit
//! (port of `decrypt-archive::audit_tar`, the same untrusted-archive rules) → extract. Nothing is extracted before every earlier step passed.
use super::manifest::DumpFormat;
use super::Code;
use flate2::read::GzDecoder;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;
use tar::EntryType;
use tokio::io::AsyncWriteExt;

pub const MAX_ENTRIES: usize = 5_000_000;
pub const MAX_NAME: usize = 4096;
pub const MAX_COMPONENT: usize = 255;
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_inflated: u64,
    pub max_entries: usize,
}
impl Limits {
    pub fn with_inflated(max_inflated: u64) -> Self {
        Limits { max_inflated, max_entries: MAX_ENTRIES }
    }
}

// ---- download ----------------------------------------------------------------------------------------------------------------------------
/// URL policy: `https`, or `http` only for a host listed in `FORK_ARTIFACT_HTTP_HOSTS` (exact match); no userinfo; a host is required.
pub fn url_allowed(url: &str, http_hosts: &[String]) -> Result<url::Url, Code> {
    let u = url::Url::parse(url).map_err(|_| Code::ArtifactUnavailable)?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err(Code::ArtifactUnavailable);
    }
    let host = u.host_str().ok_or(Code::ArtifactUnavailable)?.to_ascii_lowercase();
    match u.scheme() {
        "https" => Ok(u),
        "http" if http_hosts.iter().any(|h| *h == host) => Ok(u),
        _ => Err(Code::ArtifactUnavailable),
    }
}

/// Fetch one presigned object into `dest` (0600). No redirects (the redirect target is never contacted), a byte cap, host-only logging (the URL carries the signature).
pub async fn download(url: &str, cap: u64, http_hosts: &[String], dest: &Path) -> Result<u64, Code> {
    let u = url_allowed(url, http_hosts)?;
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).connect_timeout(Duration::from_secs(30)).timeout(Duration::from_secs(30 * 60)).build().map_err(|_| Code::ArtifactUnavailable)?;
    tracing::info!("Fork restore: fetching an artifact from {}", u.host_str().unwrap_or("?"));
    let mut resp = client.get(u).send().await.map_err(|_| Code::ArtifactUnavailable)?;
    if resp.status().as_u16() != 200 || resp.content_length().is_some_and(|n| n > cap) {
        return Err(Code::ArtifactUnavailable);
    }
    let file = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(dest).map_err(|_| Code::RestoreFailed)?;
    let mut out = tokio::fs::File::from_std(file);
    let mut total = 0u64;
    while let Some(chunk) = resp.chunk().await.map_err(|_| Code::ArtifactUnavailable)? {
        total += chunk.len() as u64;
        if total > cap {
            let _ = std::fs::remove_file(dest);
            return Err(Code::ArtifactUnavailable);
        }
        out.write_all(&chunk).await.map_err(|_| Code::DiskFull)?;
    }
    out.flush().await.map_err(|_| Code::DiskFull)?;
    Ok(total)
}

// ---- decrypt + checksum --------------------------------------------------------------------------------------------------------------------
/// `enc` → plaintext `out` (an `archive_plain` artifact is its own plaintext: `out` is then just `enc`). The plaintext SHA-256 and size must equal the VERIFIED
/// manifest's, else `checksum_mismatch` (a flipped/truncated/swapped object fails the GCM tag or this comparison).
pub async fn decrypt_verify(enc: &Path, out: &Path, master_b64: &str, encrypted: bool, expect_sha: &str, expect_size: u64) -> Result<(), Code> {
    let target = if encrypted {
        crate::utils::file::decrypt_file_stream_gcm(enc.to_path_buf(), out.to_path_buf(), master_b64.to_string()).await.map_err(|_| Code::ChecksumMismatch)?;
        out
    } else {
        enc
    };
    let (sha, size) = crate::fork::hash::plaintext_hash(target).await.map_err(|_| Code::RestoreFailed)?;
    if sha != expect_sha || size != expect_size {
        return Err(Code::ChecksumMismatch);
    }
    Ok(())
}

// ---- gzip ---------------------------------------------------------------------------------------------------------------------------------
/// The `gzip -t` equivalent: the whole stream inflates to EOF within `max_inflated` and nothing follows it. Returns the inflated size.
pub fn gzip_complete(path: &Path, max_inflated: u64) -> Result<u64, Code> {
    let f = std::fs::File::open(path).map_err(|_| Code::RestoreFailed)?;
    let mut d = flate2::bufread::GzDecoder::new(BufReader::new(f)); // bufread: `into_inner` gives back the reader that still holds trailing bytes
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = d.read(&mut buf).map_err(|_| Code::ArchiveInvalid)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max_inflated {
            return Err(Code::ArchiveInvalid);
        }
    }
    let mut rest = d.into_inner();
    if !rest.fill_buf().map_err(|_| Code::ArchiveInvalid)?.is_empty() {
        return Err(Code::ArchiveInvalid);
    }
    Ok(total)
}

// ---- tar audit ------------------------------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
    pub entries: usize,
    pub declared: u64,
}

fn clean(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_NAME && !s.chars().any(|c| (c as u32) < 32 || c as u32 == 127)
}
fn parts(name: &str) -> Result<Vec<String>, Code> {
    if !clean(name) || name.starts_with('/') {
        return Err(Code::ArchiveInvalid);
    }
    let p: Vec<String> = name.split('/').filter(|s| !s.is_empty() && *s != ".").map(String::from).collect();
    if p.iter().any(|s| s == "..") || p.len() > MAX_DEPTH || p.iter().any(|s| s.len() > MAX_COMPONENT) {
        return Err(Code::ArchiveInvalid);
    }
    Ok(p)
}

/// Reads headers only (never extracts). Rules: no absolute / `..` / control characters; nothing written THROUGH an earlier symlink; no setuid/setgid/sticky;
/// no sparse files; hard links only to EARLIER regular members; no devices / fifos / other specials; a member never changes type; entry / depth / name limits.
/// `expect_top`: every member lives under that top-level directory (docker-volume archives: `vol`).
pub fn audit_tar(path: &Path, expect_top: Option<&str>, lim: &Limits) -> Result<Audit, Code> {
    let f = std::fs::File::open(path).map_err(|_| Code::RestoreFailed)?;
    let mut ar = tar::Archive::new(GzDecoder::new(BufReader::new(f)).take(lim.max_inflated + 1));
    let (mut kinds, mut symlinks): (HashMap<String, char>, HashSet<String>) = (HashMap::new(), HashSet::new());
    let (mut entries, mut declared) = (0usize, 0u64);
    for e in ar.entries().map_err(|_| Code::ArchiveInvalid)? {
        let e = e.map_err(|_| Code::ArchiveInvalid)?;
        entries += 1;
        if entries > lim.max_entries {
            return Err(Code::ArchiveInvalid);
        }
        let name = String::from_utf8(e.path_bytes().to_vec()).map_err(|_| Code::ArchiveInvalid)?;
        let p = parts(&name)?;
        let ty = e.header().entry_type();
        if p.is_empty() {
            if !ty.is_dir() {
                return Err(Code::ArchiveInvalid);
            }
            continue;
        }
        if expect_top.is_some_and(|t| p[0] != t) {
            return Err(Code::ArchiveInvalid);
        }
        for i in 1..p.len() {
            if symlinks.contains(&p[..i].join("/")) {
                return Err(Code::ArchiveInvalid);
            }
        }
        if e.header().mode().map_err(|_| Code::ArchiveInvalid)? & 0o7000 != 0 || ty == EntryType::GNUSparse {
            return Err(Code::ArchiveInvalid);
        }
        let key = p.join("/");
        let kind = if ty.is_dir() {
            'd'
        } else if ty.is_file() || ty == EntryType::Continuous {
            declared = declared.saturating_add(e.header().size().map_err(|_| Code::ArchiveInvalid)?);
            'f'
        } else if ty.is_symlink() {
            let t = e.link_name_bytes().ok_or(Code::ArchiveInvalid)?;
            if !clean(&String::from_utf8_lossy(&t)) {
                return Err(Code::ArchiveInvalid);
            }
            'l'
        } else if ty.is_hard_link() {
            let t = String::from_utf8(e.link_name_bytes().ok_or(Code::ArchiveInvalid)?.to_vec()).map_err(|_| Code::ArchiveInvalid)?;
            if kinds.get(&parts(&t)?.join("/")) != Some(&'f') {
                return Err(Code::ArchiveInvalid);
            }
            'f'
        } else {
            return Err(Code::ArchiveInvalid);
        };
        if kinds.get(&key).is_some_and(|k| *k != kind) {
            return Err(Code::ArchiveInvalid);
        }
        kinds.insert(key.clone(), kind);
        if kind == 'l' {
            symlinks.insert(key);
        } else {
            symlinks.remove(&key);
        }
    }
    Ok(Audit { entries, declared })
}

/// Extract an ALREADY AUDITED archive under `dest` (created). `tar` refuses `..`, absolute names and writes through a symlinked parent; permissions are
/// preserved, ownership only when running as root.
pub fn extract(path: &Path, dest: &Path) -> Result<(), Code> {
    std::fs::create_dir_all(dest).map_err(|_| Code::RestoreFailed)?;
    let f = std::fs::File::open(path).map_err(|_| Code::RestoreFailed)?;
    let mut ar = tar::Archive::new(GzDecoder::new(BufReader::new(f)));
    ar.set_preserve_permissions(true);
    ar.set_preserve_mtime(true);
    ar.set_unpack_xattrs(false);
    ar.set_overwrite(false);
    #[cfg(unix)]
    ar.set_preserve_ownerships(unsafe { libc::geteuid() } == 0);
    ar.unpack(dest).map_err(|e| if e.raw_os_error() == Some(28) { Code::DiskFull } else { Code::ArchiveInvalid })
}

// ---- PostgreSQL dump staging check ---------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgDump {
    Custom,
    Directory,
}

/// The stage archive of a PostgreSQL artifact holds exactly one file: a `pg_dump -Fc` file (`PGDMP`) or the gzip'd tar of a `-Fd` directory (inner archive audited too).
/// The detected format must equal the manifest's `dump_format` (`dump_format_mismatch`).
pub fn check_pg_dump(path: &Path, manifest_format: Option<DumpFormat>, lim: &Limits, tmp: &Path) -> Result<PgDump, Code> {
    let f = std::fs::File::open(path).map_err(|_| Code::RestoreFailed)?;
    let mut ar = tar::Archive::new(GzDecoder::new(BufReader::new(f)));
    let mut found: Option<PgDump> = None;
    for e in ar.entries().map_err(|_| Code::ArchiveInvalid)? {
        let mut e = e.map_err(|_| Code::ArchiveInvalid)?;
        if e.header().entry_type().is_dir() {
            continue;
        }
        if !e.header().entry_type().is_file() || found.is_some() {
            return Err(Code::DumpFormatMismatch);
        }
        let mut magic = [0u8; 5];
        let n = e.read(&mut magic).map_err(|_| Code::ArchiveInvalid)?;
        found = Some(if &magic[..n.min(5)] == b"PGDMP" {
            PgDump::Custom
        } else if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
            // inner -Fd archive: write it out (magic + rest) and audit it like any untrusted archive
            let inner = tmp.join("pg-inner.tar.gz");
            let mut out = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&inner).map_err(|_| Code::RestoreFailed)?;
            std::io::Write::write_all(&mut out, &magic[..n]).map_err(|_| Code::DiskFull)?;
            std::io::copy(&mut e.take(lim.max_inflated), &mut out).map_err(|_| Code::ArchiveInvalid)?;
            let r = gzip_complete(&inner, lim.max_inflated).and_then(|_| audit_tar(&inner, None, lim));
            let _ = std::fs::remove_file(&inner);
            r?;
            PgDump::Directory
        } else {
            return Err(Code::DumpFormatMismatch);
        });
    }
    let got = found.ok_or(Code::DumpFormatMismatch)?;
    match (manifest_format, got) {
        (Some(DumpFormat::PgCustom), PgDump::Custom) | (Some(DumpFormat::PgDirectory), PgDump::Directory) | (None, _) => Ok(got),
        _ => Err(Code::DumpFormatMismatch),
    }
}
