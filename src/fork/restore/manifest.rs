//! Manifest verification on the agent (DD12, ADR-013, ADR-014 §3). Rust mirror of the dashboard's `ManifestV1` (strict: an unknown key is a rejection),
//! RSA PKCS#1 v1.5 / SHA-256 over the RAW bytes with a PINNED key (effective pins), then the binding to the planned RP and the plan's bound hash.
//! Expected plaintext hashes / sizes / formats come ONLY from here, never from the payload. No canonical-JSON check on the agent: the signature covers
//! the exact bytes (A1 rule), the dashboard checked canonical form before it enqueued.
use super::{Code, R};
use crate::fork::crypto::{Pin, sha256_hex, verify_manifest};
use serde::Deserialize;
use serde_json::Value;

pub const MAX_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ARTIFACTS: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveKind {
    ResticSnapshot,
    ArchiveEnc,
    ArchivePlain,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DumpFormat {
    PgCustom,
    PgDirectory,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Artifact {
    pub source_name: String,
    pub engine: String,
    pub archive_kind: ArchiveKind,
    pub dump_format: Option<DumpFormat>,
    pub archive_format_version: Option<u64>,
    pub encrypted: bool,
    pub channel_id: Option<String>,
    pub channel_kind: Option<String>,
    pub location: Option<String>,
    pub generated_id: Option<String>,
    pub size_bytes: Option<u64>,
    pub ciphertext_sha256: Option<String>,
    pub plaintext_sha256: Option<String>,
    pub plaintext_size: Option<u64>,
    pub plaintext_hash_source: String,
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Rp {
    pub id: String,
    pub stack_id: String,
    pub stack_name: String,
    pub sequence: u64,
    pub created_at: String,
    pub finalized_at: Option<String>,
    pub verified_at: String,
    pub consistency_level: String,
    pub inventory_version: Option<u64>,
    pub inventory_hash: Option<String>,
    pub required_artifact_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ManifestV1 {
    pub manifest_version: u8,
    pub kid: String,
    pub signed_at: String,
    pub rp: Rp,
    pub artifacts: Vec<Artifact>,
    /// Kept opaque (it is signed; the engine reads nothing from it in W17-i).
    pub inventory: Option<Value>,
}

/// What the artifact is, from the VERIFIED manifest only (engine + format), never from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Files,
    Volume,
    PgDump,
    Sqlite,
    DbOther,
}
pub fn role(a: &Artifact) -> Role {
    if a.engine == "docker-volume" || a.source_name.starts_with("volume_") {
        Role::Volume
    } else if a.dump_format.is_some() || a.engine == "postgresql" {
        Role::PgDump
    } else if a.engine == "sqlite" {
        Role::Sqlite
    } else if a.source_name.starts_with("db_") {
        Role::DbOther
    } else {
        Role::Files
    }
}

pub struct Expect<'a> {
    pub rp_id: &'a str,
    pub stack_id: &'a str,
    /// `None` at `restore_apply` (the sequence is implied by the bound hash).
    pub sequence: Option<u64>,
    /// The hash the plan bound (payload `manifest.sha256` / `manifest_sha256`).
    pub sha256: &'a str,
    pub min_sequence: Option<u64>,
}

fn hex64(s: &str) -> bool {
    super::is_hex64(s)
}

/// Order: size → strict parse → pinned kid → signature → bound hash → RP / stack / sequence → floor. Fail closed; the code says WHY, never what was inside.
pub fn verify(bytes: &[u8], sig: &[u8], pins: &[Pin], e: &Expect) -> R<ManifestV1> {
    if bytes.len() > MAX_BYTES {
        return Err(Code::ManifestInvalid.into());
    }
    let m: ManifestV1 = serde_json::from_slice(bytes).map_err(|_| super::Failure::from(Code::ManifestInvalid))?;
    if m.manifest_version != 1 || m.artifacts.len() > MAX_ARTIFACTS || m.kid.len() != 12 {
        return Err(Code::ManifestInvalid.into());
    }
    let bad = m.artifacts.iter().any(|a| {
        a.source_name.is_empty() || a.source_name.len() > 256 || [&a.ciphertext_sha256, &a.plaintext_sha256].iter().any(|h| h.as_deref().is_some_and(|h| !hex64(h)))
    });
    if bad {
        return Err(Code::ManifestInvalid.into());
    }
    let Some(pin) = pins.iter().find(|p| p.kid == m.kid) else { return Err(Code::ManifestUnknownKid.into()) };
    if !verify_manifest(pin, bytes, sig) {
        return Err(Code::ManifestSignature.into());
    }
    // ---- authentic from here ----
    if sha256_hex(bytes) != e.sha256 || m.rp.id != e.rp_id || m.rp.stack_id != e.stack_id || e.sequence.is_some_and(|q| m.rp.sequence != q) {
        return Err(Code::ManifestMismatch.into());
    }
    if e.min_sequence.is_some_and(|min| m.rp.sequence < min) {
        return Err(Code::ManifestMismatch.into());
    }
    Ok(m)
}
