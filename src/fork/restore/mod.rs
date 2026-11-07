//! Restore-to-target engine, data only (W17-i, plan-W17, ADR-007 A13): `restore_probe`, `restore_stage`, `restore_apply`, `restore_cleanup`.
//! Everything here runs ONLY for a task that already passed the channel verification (signature, pin, target binding, replay, capability): the executors
//! below re-validate every payload field (strict serde + the shared path/name grammars), verify the signed manifest and every checksum BEFORE any data
//! is touched, work inside one workspace claimed by a `restore_id`, and clean up only what carries that id. W17-ii adds compose render / policy / up.
pub mod apply;
pub mod artifact;
pub mod docker_ops;
pub mod journal;
pub mod manifest;
pub mod paths;
pub mod probe;
pub mod stage;
pub mod sweep;
pub mod workspace;

use super::crypto::Pin;
use super::state::Redacted;
use docker_ops::DockerOps;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::path::PathBuf;
use std::time::Duration;

/// Closed failure / rejection codes (== dashboard `RESTORE_REASONS` + `payload_invalid`). A code the dashboard does not know makes the result POST fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    PathNotAllowed,
    SymlinkEscape,
    RootNotShared,
    WorkspaceNotOwned,
    ModeUnsupported,
    HostRoleMismatch,
    ApprovalMissing,
    ManifestInvalid,
    ManifestUnknownKid,
    ManifestSignature,
    ManifestMismatch,
    ArtifactUnavailable,
    ChecksumMismatch,
    ArchiveInvalid,
    DumpFormatMismatch,
    VolumeExists,
    VolumeNotOwned,
    DiskFull,
    DockerUnavailable,
    DeadlineExceeded,
    RestoreFailed,
    PayloadInvalid,
}

impl Code {
    /// The restore-specific list, in the dashboard's order (the vectors assert equality).
    #[cfg_attr(not(test), allow(dead_code))]
    pub const RESTORE: [Code; 21] = [
        Code::PathNotAllowed, Code::SymlinkEscape, Code::RootNotShared, Code::WorkspaceNotOwned, Code::ModeUnsupported, Code::HostRoleMismatch, Code::ApprovalMissing,
        Code::ManifestInvalid, Code::ManifestUnknownKid, Code::ManifestSignature, Code::ManifestMismatch, Code::ArtifactUnavailable, Code::ChecksumMismatch, Code::ArchiveInvalid,
        Code::DumpFormatMismatch, Code::VolumeExists, Code::VolumeNotOwned, Code::DiskFull, Code::DockerUnavailable, Code::DeadlineExceeded, Code::RestoreFailed,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Code::PathNotAllowed => "path_not_allowed",
            Code::SymlinkEscape => "symlink_escape",
            Code::RootNotShared => "root_not_shared",
            Code::WorkspaceNotOwned => "workspace_not_owned",
            Code::ModeUnsupported => "mode_unsupported",
            Code::HostRoleMismatch => "host_role_mismatch",
            Code::ApprovalMissing => "approval_missing",
            Code::ManifestInvalid => "manifest_invalid",
            Code::ManifestUnknownKid => "manifest_unknown_kid",
            Code::ManifestSignature => "manifest_signature",
            Code::ManifestMismatch => "manifest_mismatch",
            Code::ArtifactUnavailable => "artifact_unavailable",
            Code::ChecksumMismatch => "checksum_mismatch",
            Code::ArchiveInvalid => "archive_invalid",
            Code::DumpFormatMismatch => "dump_format_mismatch",
            Code::VolumeExists => "volume_exists",
            Code::VolumeNotOwned => "volume_not_owned",
            Code::DiskFull => "disk_full",
            Code::DockerUnavailable => "docker_unavailable",
            Code::DeadlineExceeded => "deadline_exceeded",
            Code::RestoreFailed => "restore_failed",
            Code::PayloadInvalid => "payload_invalid",
        }
    }
}

/// A failed task: the closed code, an optional sanitized detail (≤ 64 chars `[a-z0-9_:.-]`) and the manifest artifact index it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: Code,
    pub detail: Option<String>,
    pub artifact: Option<usize>,
}
impl From<Code> for Failure {
    fn from(code: Code) -> Self {
        Failure { code, detail: None, artifact: None }
    }
}
impl Failure {
    pub fn with(code: Code, detail: &str) -> Self {
        Failure { code, detail: Some(sanitize_detail(detail)), artifact: None }
    }
    pub fn at(mut self, artifact: usize) -> Self {
        self.artifact = Some(artifact);
        self
    }
    /// The `result` object of the failed outcome (inside the existing result map, so the dashboard's `ResultInput` is unchanged).
    pub fn result(&self) -> Option<Value> {
        if self.detail.is_none() && self.artifact.is_none() {
            return None;
        }
        let mut m = Map::new();
        if let Some(d) = &self.detail {
            m.insert("detail".into(), json!(d));
        }
        if let Some(a) = self.artifact {
            m.insert("artifact".into(), json!(a));
        }
        Some(Value::Object(m))
    }
}
pub type R<T> = Result<T, Failure>;

pub fn sanitize_detail(s: &str) -> String {
    s.chars().take(64).map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | ':' | '.' | '-') { c } else { '_' }).collect()
}

pub fn is_uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() })
}
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---- deadlines (DD6) -------------------------------------------------------------------------------------------------------------------
pub const DEADLINE_PROBE: Duration = Duration::from_secs(2 * 60);
pub const DEADLINE_STAGE: Duration = Duration::from_secs(30 * 60);
pub const DEADLINE_APPLY: Duration = Duration::from_secs(60 * 60);
pub const DEADLINE_CLEANUP: Duration = Duration::from_secs(10 * 60);

pub fn deadline_of(task_type: &str) -> Duration {
    match task_type {
        "restore_probe" => DEADLINE_PROBE,
        "restore_stage" => DEADLINE_STAGE,
        "restore_apply" => DEADLINE_APPLY,
        _ => DEADLINE_CLEANUP,
    }
}

// ---- environment -------------------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostRole {
    Production,
    Test,
}

#[derive(Clone)]
pub struct RestoreEnv {
    pub roots: Vec<PathBuf>,
    pub host_role: HostRole,
    /// Exact artifact hosts that may be fetched over plain http (default empty = https only, OD-W17-7).
    pub http_hosts: Vec<String>,
    pub state_dir: PathBuf,
    pub agent_id: String,
    /// Edge-key master key (decrypts agent archives). `None` ⇒ stage refuses (`restore_failed`). Never logged.
    pub master_b64: Option<Redacted>,
}
impl std::fmt::Debug for RestoreEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreEnv").field("roots", &self.roots).field("host_role", &self.host_role).field("agent_id", &self.agent_id).finish_non_exhaustive()
    }
}

impl RestoreEnv {
    /// `FORK_ALLOWED_PATH_ROOTS` (colon list), `FORK_HOST_ROLE` (`test` default | `production`), `FORK_ARTIFACT_HTTP_HOSTS` (comma list).
    /// Invalid configuration ⇒ `Err` (the capability is then not reported: honest degrade, DD20).
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>, state_path: &std::path::Path, agent_id: &str) -> Result<RestoreEnv, &'static str> {
        let state_dir = state_path.parent().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        let state_dir = std::fs::canonicalize(&state_dir).unwrap_or(state_dir);
        let host_role = match env("FORK_HOST_ROLE").as_deref().map(str::trim) {
            None | Some("") | Some("test") => HostRole::Test,
            Some("production") => HostRole::Production,
            Some(_) => return Err("FORK_HOST_ROLE must be test or production"),
        };
        let roots = paths::parse_roots(&env("FORK_ALLOWED_PATH_ROOTS").unwrap_or_default(), std::slice::from_ref(&state_dir))?;
        let http_hosts = env("FORK_ARTIFACT_HTTP_HOSTS").unwrap_or_default().split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()).collect();
        Ok(RestoreEnv { roots, host_role, http_hosts, state_dir, agent_id: agent_id.to_string(), master_b64: None })
    }
}

// ---- payloads (strict, DD1/§4.0) -------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Restore,
    TestRestore,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    NewStack,
    Selective,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    ProductionTarget,
    DestructiveReplace,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub v: u8,
    pub restore_id: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub stack_id: String,
    pub rp_id: String,
    pub purpose: Purpose,
    #[allow(dead_code)]
    pub mode: Mode,
    pub host_role: HostRole,
    pub approvals: Vec<Approval>,
    pub workspace: String,
    pub project: String,
}
const HEADER_KEYS: [&str; 12] = ["v", "restore_id", "plan_id", "plan_hash", "stack_id", "rp_id", "purpose", "mode", "host_role", "approvals", "workspace", "project"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRef {
    pub json_b64: String,
    pub sig_b64: String,
    pub sha256: String,
    #[serde(default)]
    pub min_sequence: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub index: usize,
    pub source: String,
    pub url: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRef {
    pub index: usize,
    pub dest: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageBody {
    pub manifest: ManifestRef,
    pub artifacts: Vec<ArtifactRef>,
    pub paths: Vec<PathRef>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolRef {
    pub index: usize,
    pub name: String,
    pub compose_volume: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteRef {
    pub index: usize,
    pub volume: String,
    pub relative_path: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetRef {
    pub name: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnpackRef {
    pub index: usize,
    pub service: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyBody {
    pub manifest_sha256: String,
    pub volumes: Vec<VolRef>,
    pub sqlite: Vec<SqliteRef>,
    pub networks: Vec<NetRef>,
    pub unpack: Vec<UnpackRef>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupBody {
    pub workspace_remove: bool,
    pub volumes: bool,
    pub networks: bool,
    pub containers: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeBody {
    pub v: u8,
    #[serde(default)]
    pub workspace: Option<String>,
}

/// Header + type body: the header keys are taken out of the object (strict), what is left must fit the body struct exactly (`deny_unknown_fields`).
pub fn split<B: serde::de::DeserializeOwned>(payload: &[u8]) -> R<(Header, B)> {
    let Ok(Value::Object(mut m)) = serde_json::from_slice::<Value>(payload) else { return Err(Code::PayloadInvalid.into()) };
    let mut h = Map::new();
    for k in HEADER_KEYS {
        match m.remove(k) {
            Some(v) => {
                h.insert(k.to_string(), v);
            }
            None => return Err(Code::PayloadInvalid.into()),
        }
    }
    let header: Header = serde_json::from_value(Value::Object(h)).map_err(|_| Failure::from(Code::PayloadInvalid))?;
    let body: B = serde_json::from_value(Value::Object(m)).map_err(|_| Failure::from(Code::PayloadInvalid))?;
    Ok((header, body))
}

impl Header {
    /// Shape + policy checks that need no I/O: ids, grammar, host role (DD17).
    pub fn check(&self, env: &RestoreEnv) -> R<()> {
        let ok = self.v == 1 && [&self.restore_id, &self.plan_id, &self.stack_id, &self.rp_id].iter().all(|s| is_uuid(s)) && is_hex64(&self.plan_hash) && paths::is_name(&self.project, 64)
            && self.project.bytes().all(|b| !b.is_ascii_uppercase() && b != b'.')
            && paths::canon(&self.workspace) && self.workspace.ends_with(&format!("/{}", self.project)) && self.approvals.len() <= 2;
        if !ok {
            return Err(Code::PayloadInvalid.into());
        }
        if self.host_role != env.host_role {
            return Err(Code::HostRoleMismatch.into());
        }
        if self.host_role == HostRole::Production && !self.approvals.contains(&Approval::ProductionTarget) {
            return Err(Code::ApprovalMissing.into());
        }
        Ok(())
    }
}

pub struct Task<'a> {
    pub id: &'a str,
    pub ty: &'a str,
    /// Unix seconds (injected: tests never compare against the real clock).
    pub now: i64,
}

/// Entry point for the four W17-i task types. The caller (`poll`) wraps this in `exec::run_with_heartbeat` with `deadline_of(type)`.
pub async fn execute(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8]) -> R<Value> {
    match t.ty {
        "restore_probe" => probe::run(env, ops, t, payload).await,
        "restore_stage" => stage::run(env, ops, pins, t, payload).await,
        "restore_apply" => apply::run_apply(env, ops, pins, t, payload).await,
        "restore_cleanup" => apply::run_cleanup(env, ops, t, payload).await,
        _ => Err(Failure::from(Code::PayloadInvalid)),
    }
}

#[cfg(test)]
mod tests;
