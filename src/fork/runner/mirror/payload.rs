//! Strict payload bodies of the mirror task types (W22a contract §3.3; the dashboard's `mirror/payload-schema.ts` is the other half and the shared vectors prove both
//! agree row by row). The header is the W17 header (`restore::Header`, `purpose mirror`, `host_role runner`); everything after it must fit these structs exactly.
use super::apply_spec::{CredentialReset, MirrorSpec};
use crate::fork::compose::ComposeRef;
use crate::fork::restore::{Code, Failure, R, is_hex64, paths};
use serde::Deserialize;

pub const MEM_MIN: u64 = 32 << 20;
pub const MEM_CAP: u64 = 8 << 30;
pub const PIDS_MIN: u64 = 16;
pub const PIDS_CAP: u64 = 4096;
pub const CPU_MIN: u64 = 100_000_000;
pub const CPU_CAP: u64 = 4_000_000_000;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub mem_bytes: u64,
    pub pids: u64,
    pub nano_cpus: u64,
}
impl Limits {
    pub fn check(&self) -> R<()> {
        let ok = (MEM_MIN..=MEM_CAP).contains(&self.mem_bytes) && (PIDS_MIN..=PIDS_CAP).contains(&self.pids) && (CPU_MIN..=CPU_CAP).contains(&self.nano_cpus);
        ok.then_some(()).ok_or_else(|| Failure::from(Code::PayloadInvalid))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorProbeBody {
    pub v: u8,
    pub workspace: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderBody {
    pub manifest_sha256: String,
    pub compose: ComposeRef,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeBody {
    pub manifest_sha256: String,
    pub compose: ComposeRef,
    pub spec: MirrorSpec,
    pub spec_sha256: String,
    pub limits: Limits,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbRef {
    pub index: usize,
    pub service: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbBody {
    pub manifest_sha256: String,
    pub final_sha256: String,
    pub dbs: Vec<DbRef>,
    pub resets: Vec<CredentialReset>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpBody {
    pub final_sha256: String,
    pub volumes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckAccess {
    pub service: String,
    pub target: u32,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckBody {
    pub final_sha256: String,
    pub access: CheckAccess,
    pub http_path: Option<String>,
    pub wait_s: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WipeBody {}

/// W23 `mirror_stop`: no fields (the revision, project and workspace are in the header, like `mirror_wipe`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopBody {}

fn svc_ok(s: &str) -> bool {
    paths::is_name(s, 128)
}
fn key_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}
/// `^/[A-Za-z0-9._~/-]{0,127}$`
pub fn http_path_ok(p: &str) -> bool {
    p.starts_with('/') && p.len() <= 128 && p.bytes().skip(1).all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'-'))
}

fn bad<T>() -> R<T> {
    Err(Code::PayloadInvalid.into())
}

impl RenderBody {
    /// Mirror mode has NO overrides (W20 D-2): no override file, no env.
    pub fn check(&self) -> R<()> {
        if !is_hex64(&self.manifest_sha256) || self.compose.override_yml.is_some() || !self.compose.env.is_empty() {
            return bad();
        }
        Ok(())
    }
}
impl FinalizeBody {
    pub fn check(&self) -> R<()> {
        if !is_hex64(&self.manifest_sha256) || !is_hex64(&self.spec_sha256) || self.compose.override_yml.is_some() || !self.compose.env.is_empty() {
            return bad();
        }
        let s = &self.spec;
        let access_ok = s.access.as_ref().is_none_or(|a| svc_ok(&a.service) && (1..=65535).contains(&a.target) && (1024..=65535).contains(&a.host_port));
        if !access_ok || s.v != 1 || s.compiler != 1 || !is_hex64(&s.source_view_sha256) || !is_hex64(&s.rules_sha256) || s.credential_resets.len() > 20 || s.kept_production_secrets.len() > 100 {
            return bad();
        }
        self.limits.check()
    }
}
impl DbBody {
    pub fn check(&self) -> R<()> {
        let ok = is_hex64(&self.manifest_sha256) && is_hex64(&self.final_sha256) && self.dbs.len() <= 20 && self.resets.len() <= 20 && !(self.dbs.is_empty() && self.resets.is_empty())
            && self.dbs.iter().all(|d| svc_ok(&d.service))
            && self.resets.iter().all(|r| svc_ok(&r.service) && key_ok(&r.password_key) && r.user_key.as_deref().is_none_or(key_ok));
        ok.then_some(()).ok_or_else(|| Failure::from(Code::PayloadInvalid))
    }
}
impl UpBody {
    pub fn check(&self) -> R<()> {
        let ok = is_hex64(&self.final_sha256) && self.volumes.len() <= 100 && self.volumes.iter().all(|v| paths::is_name(v, 255));
        ok.then_some(()).ok_or_else(|| Failure::from(Code::PayloadInvalid))
    }
}
impl CheckBody {
    pub fn check(&self) -> R<()> {
        let ok = is_hex64(&self.final_sha256) && svc_ok(&self.access.service) && (1..=65535).contains(&self.access.target) && (10..=300).contains(&self.wait_s) && self.http_path.as_deref().is_none_or(http_path_ok);
        ok.then_some(()).ok_or_else(|| Failure::from(Code::PayloadInvalid))
    }
}
