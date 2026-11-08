//! Compose render, policy re-check, `compose up` and PostgreSQL restore (W17-ii, plan-W17-ii, ADR-007 A14). Runs ONLY for tasks that passed the channel
//! verification; every payload field is re-validated, the signed manifest is re-verified, the compose is rendered in a sandboxed helper container, judged by the
//! agent's OWN policy engine (`fork::policy`, ported from the dashboard and proven on the shared corpus) and only then handed to `docker compose up`.
//! Process spawning lives in `run.rs` only; nothing here ever builds a shell string from payload data.
pub mod check;
pub mod db;
pub mod guard;
pub mod render;
pub mod run;
pub mod up;

#[cfg(test)]
pub(crate) mod tests;

use crate::fork::crypto::Pin;
use crate::fork::policy::rules::Rules;
use crate::fork::restore::docker_ops::DockerOps;
use crate::fork::restore::journal::Journal;
use crate::fork::restore::manifest::{self, Expect, ManifestV1};
use crate::fork::restore::workspace::{Claim, Workspace};
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, paths};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the Compose CLI lives inside the fork image (E16). Not configurable by any environment variable.
pub const COMPOSE_BIN: &str = "/usr/local/bin/docker-compose";
pub const COMPOSE_VERSION: &str = "5.4.0";
pub const DEADLINE_RENDER: Duration = Duration::from_secs(5 * 60);
pub const DEADLINE_DB: Duration = Duration::from_secs(60 * 60);
pub const DEADLINE_UP: Duration = Duration::from_secs(30 * 60);
pub fn deadline_of(task_type: &str) -> Duration {
    match task_type {
        "compose_render" => DEADLINE_RENDER,
        "restore_db" => DEADLINE_DB,
        _ => DEADLINE_UP,
    }
}

/// What `compose.render.v1` needs besides a working restore target (E17).
#[derive(Clone, Debug)]
pub struct ComposeEnv {
    /// the Compose CLI the agent PROCESS runs for `up` / `exec` (tests point it at a fake script; never an env var)
    pub bin: PathBuf,
    pub version: String,
    pub own_id: String,
    pub own_image: String,
    pub protected_extra: Vec<String>,
}

fn protected_list(env: &dyn Fn(&str) -> Option<String>) -> Result<Vec<String>, &'static str> {
    let ok = |s: &str| crate::fork::restore::is_hex64(s) || (!s.is_empty() && s.len() <= 128 && s.as_bytes()[0].is_ascii_alphanumeric() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')));
    let list: Vec<String> = env("FORK_PROTECTED_CONTAINERS").unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if list.iter().all(|s| ok(s)) { Ok(list) } else { Err("FORK_PROTECTED_CONTAINERS has an invalid entry") }
}

impl ComposeEnv {
    /// Fail closed, one reason: own container id, own image id, the pinned CLI version, the embedded rule file, a valid `FORK_PROTECTED_CONTAINERS`.
    pub async fn detect(ops: &dyn DockerOps, env: &(dyn Fn(&str) -> Option<String> + Sync), bin: PathBuf, mountinfo: &str, cgroup: &str) -> Result<ComposeEnv, &'static str> {
        let protected_extra = protected_list(env)?;
        Rules::embedded()?;
        let own_id = crate::domain::docker_volume::docker::parse_container_id(mountinfo, cgroup).ok_or("the agent cannot determine its own container id")?;
        let own_image = ops.image_of_container(&own_id).await.map_err(|_| "the agent cannot inspect its own container")?;
        let version = run::version(&bin).await.ok_or("the Compose CLI is missing")?;
        if version != COMPOSE_VERSION {
            return Err("the Compose CLI is not the pinned version");
        }
        Ok(ComposeEnv { bin, version, own_id, own_image, protected_extra })
    }
}

// ---- payloads (strict) ----------------------------------------------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathMap {
    pub from: String,
    pub to: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeRef {
    pub dir: String,
    pub override_yml: Option<String>,
    pub env: BTreeMap<String, String>,
    pub path_map: Vec<PathMap>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderBody {
    pub manifest_sha256: String,
    pub compose: ComposeRef,
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
    pub compose: ComposeRef,
    pub compose_sha256: String,
    pub approval: Value,
    pub dbs: Vec<DbRef>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpBody {
    pub manifest_sha256: String,
    pub compose: ComposeRef,
    pub compose_sha256: String,
    pub approval: Value,
    pub volumes: Vec<String>,
}

fn env_key_ok(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty() && b.len() <= 128 && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && !["COMPOSE_", "DOCKER_", "BUILDKIT_"].iter().any(|p| k.starts_with(p)) && !["PATH", "HOME", "HOSTNAME"].contains(&k)
}

impl ComposeRef {
    /// E2 grammar: every violation of the override / env bounds is `override_invalid`; paths follow the shared path rules (`path_not_allowed` / `symlink_escape`).
    pub fn validate(&self, ws: &Path, env: &RestoreEnv) -> R<()> {
        if self.env.len() > 200 || self.path_map.len() > 200 || self.override_yml.as_ref().is_some_and(|y| y.len() > 64 * 1024) {
            return Err(Code::OverrideInvalid.into());
        }
        for (k, v) in &self.env {
            if !env_key_ok(k) || v.len() > 4096 || v.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
                return Err(Code::OverrideInvalid.into());
            }
        }
        if !paths::canon(&self.dir) {
            return Err(Code::PayloadInvalid.into());
        }
        let dir = paths::check_task_path(&env.roots, &env.state_dir, &self.dir)?;
        if !paths::within(ws, &dir) {
            return Err(Code::PathNotAllowed.into());
        }
        for m in &self.path_map {
            if !paths::canon(&m.from) || !paths::canon(&m.to) {
                return Err(Code::PayloadInvalid.into());
            }
            let to = paths::check_task_path(&env.roots, &env.state_dir, &m.to)?;
            if !paths::within(ws, &to) {
                return Err(Code::PathNotAllowed.into());
            }
        }
        Ok(())
    }
}

/// Where `compose_render` hands the policy view to the dashboard (production: the channel transport; tests: a recorder).
#[async_trait]
pub trait RenderSink: Send + Sync {
    async fn put(&self, body: Value) -> Result<(), ()>;
}

/// An opened, verified compose job: workspace owned by this restore, staged manifest re-verified, payload bounds checked, compose files derived.
pub struct Job<'a> {
    pub env: &'a RestoreEnv,
    pub ce: &'a ComposeEnv,
    pub ops: &'a dyn DockerOps,
    pub rules: &'static Rules,
    pub h: Header,
    pub ws: Workspace,
    pub cref: ComposeRef,
    pub files: Vec<String>,
    pub manifest: ManifestV1,
}

pub fn claim<'a>(env: &'a RestoreEnv, h: &'a Header) -> Claim<'a> {
    Claim { restore_id: &h.restore_id, stack_id: &h.stack_id, rp_id: &h.rp_id, project: &h.project, agent_id: &env.agent_id }
}

fn is_yaml_name(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() <= 128 && (s.ends_with(".yml") || s.ends_with(".yaml")) && !b.is_empty() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}
fn regular(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.is_file()).unwrap_or(false)
}
/// Compose files like the CLI's `find_compose_files`: basenames of the signed `inventory.stack.config_files_hint` that exist in `dir` as regular, non-symlink
/// files (in order); else the first existing default name, then the first existing default override name.
pub fn discover(dir: &Path, inventory: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let hints = inventory.and_then(|i| i.get("stack")).and_then(|s| s.get("config_files_hint")).and_then(Value::as_array);
    for h in hints.into_iter().flatten().filter_map(Value::as_str) {
        let base = h.rsplit('/').next().unwrap_or("");
        if is_yaml_name(base) && regular(&dir.join(base)) && !out.iter().any(|o| o == base) {
            out.push(base.to_string());
        }
    }
    if out.is_empty() {
        if let Some(f) = ["compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"].iter().find(|f| regular(&dir.join(f))) {
            out.push((*f).to_string());
        }
        if let Some(f) = ["compose.override.yaml", "compose.override.yml", "docker-compose.override.yml"].iter().find(|f| regular(&dir.join(f))) {
            out.push((*f).to_string());
        }
    }
    out
}

/// header → compose enabled → workspace → manifest re-verify → payload bounds → compose file discovery.
pub async fn open_job<'a>(env: &'a RestoreEnv, ops: &'a dyn DockerOps, pins: &[Pin], t: &Task<'_>, h: Header, manifest_sha: &str, cref: ComposeRef) -> R<Job<'a>> {
    h.check(env)?;
    let ce = env.compose.as_ref().ok_or(Failure::from(Code::ComposeUnavailable))?;
    let rules = Rules::embedded().map_err(|_| Failure::from(Code::ComposeUnavailable))?;
    if !crate::fork::restore::is_hex64(manifest_sha) {
        return Err(Code::PayloadInvalid.into());
    }
    let ws_path = paths::check_task_path(&env.roots, &env.state_dir, &h.workspace)?;
    cref.validate(&ws_path, env)?; // payload bounds first: a forged payload is refused before any I/O on the workspace
    let ws = Workspace::open_owned(&ws_path, &claim(env, &h), t.now)?;
    let json = std::fs::read(ws.stage().join("manifest.json")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    let sig = std::fs::read(ws.stage().join("manifest.sig")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    let m = manifest::verify(&json, &sig, pins, &Expect { rp_id: &h.rp_id, stack_id: &h.stack_id, sequence: None, sha256: manifest_sha, min_sequence: None })?;
    let dir = PathBuf::from(&cref.dir);
    let files = discover(&dir, m.inventory.as_ref());
    if files.is_empty() {
        return Err(Failure::with(Code::RenderFailed, "no_compose_file"));
    }
    Ok(Job { env, ce, ops, rules, h, ws, cref, files, manifest: m })
}

impl Job<'_> {
    pub fn ws_str(&self) -> String {
        self.ws.root.to_string_lossy().into_owned()
    }
    pub fn journal(&self) -> R<Journal> {
        Ok(Journal::open(&self.env.state_dir, &self.h.restore_id)?)
    }
}

/// Removes every file of `secret/` (override.yml, remap.yml, owner.yml, rendered.json) when dropped: normal end, error, AND a deadline that drops the future.
pub struct SecretGuard(PathBuf);
impl SecretGuard {
    pub fn new(ws: &Workspace) -> Self {
        let p = ws.secret();
        let _ = std::fs::create_dir_all(&p);
        SecretGuard(p)
    }
}
impl Drop for SecretGuard {
    fn drop(&mut self) {
        if let Ok(rd) = std::fs::read_dir(&self.0) {
            for e in rd.flatten() {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Entry point for the three compose task types (E1). Same contract as `restore::execute`.
pub async fn execute(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], sink: &dyn RenderSink, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    match t.ty {
        "compose_render" => render::run_render(env, ops, pins, sink, t, payload).await,
        "restore_db" => db::run_db(env, ops, pins, t, payload).await,
        "compose_up" => up::run_up(env, ops, pins, t, payload).await,
        _ => Err(Failure::from(Code::PayloadInvalid)),
    }
}

