//! W24 `mirror_route` (DD-3 / DD-13): the stable per-mirror private access route. ONE runner-local forwarder container `pbm-route-<mirror_id>` (the agent's own image,
//! entrypoint `app pbm-route /route/upstream`, see `proxy.rs`) publishes ONLY `127.0.0.1:<route_port>` and is attached to exactly ONE network: the target revision's
//! `<project>_pbm_access`. `switch` = atomic `rename(2)` of the upstream file → (re)create the forwarder ON the target network when it is not already exactly there → inspect →
//! smoke THROUGH the forwarder from a helper on the target network. A container is never re-attached with `docker network connect`: Docker refuses that once the container's
//! CREATION-time network was removed (verified in the W24 lab: `could not find a network matching network mode …`), and a retired revision's network IS removed by `mirror_wipe`.
//! The price is a brief (about a second) gap for NEW connections at a switch and open tunnel connections ending (deviation from DD-3, ADR-017 addendum).
//! `remove` (delete) removes the forwarder (so the revision networks can be wiped) and its directory.
//! Only resources carrying `route=<mirror_id>` + this agent's id (container) / a matching marker file (directory) are ever touched; a foreign object is left alone.
pub mod docker;
pub mod proxy;

#[cfg(test)]
pub(crate) mod tests;

use super::mirror::lifecycle::{ACCESS_NETWORK, SERVICE_LABEL, judge_smoke, mine};
use super::mirror::payload::{RouteAction, RouteBody};
use super::mirror::smoke::{Labels, Smoke, smoke_cmd};
use super::mirror::open_light;
use crate::fork::restore::docker_ops::{DockerOps, LABEL_AGENT, LABEL_HELPER, owner_labels};
use crate::fork::restore::journal::Journal;
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, paths, split};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const LABEL_ROUTE: &str = "com.portabase.fork.route";
pub const NAME_PREFIX: &str = "pbm-route-";
pub const FORWARDER_PORT: u16 = 8080;
pub const MARKER: &str = "route.json";
pub const UPSTREAM: &str = "upstream";
const SMOKE_TRIES: usize = 6;
const SMOKE_PAUSE: Duration = Duration::from_secs(2);

/// What the executor needs to know about the forwarder container (never more).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFacts {
    pub running: bool,
    /// the image reference the container was created from
    pub image: String,
    pub labels: Labels,
    pub networks: Vec<String>,
    /// (host_ip, host_port, container_port)
    pub ports: Vec<(String, u16, u16)>,
}

#[derive(Debug, Clone)]
pub struct RouteSpec {
    pub name: String,
    pub image: String,
    pub network: String,
    pub route_port: u16,
    /// host directory bound read-only at `/route`
    pub dir: PathBuf,
    pub labels: Labels,
}

#[async_trait]
pub trait RouteOps: Send + Sync {
    async fn inspect(&self, name: &str) -> Result<Option<RouteFacts>, Code>;
    /// create (hardened, see `docker.rs`) + start on `spec.network`
    async fn create_start(&self, spec: &RouteSpec) -> Result<(), Code>;
    /// stop + remove (volumes none)
    async fn remove(&self, name: &str) -> Result<(), Code>;
}

pub fn route_name(mirror_id: &str) -> String {
    format!("{NAME_PREFIX}{mirror_id}")
}
fn bad_state<T>(c: Code) -> R<T> {
    Err(Failure::from(c))
}

pub(crate) fn route_labels(mirror_id: &str, agent_id: &str) -> Labels {
    Labels::from([(LABEL_ROUTE.to_string(), mirror_id.to_string()), (LABEL_AGENT.to_string(), agent_id.to_string())])
}
fn is_ours(l: &Labels, mirror_id: &str, agent_id: &str) -> bool {
    l.get(LABEL_ROUTE).map(String::as_str) == Some(mirror_id) && l.get(LABEL_AGENT).map(String::as_str) == Some(agent_id) && !l.contains_key(LABEL_HELPER)
}

/// `<root>/pbm-route-<mirror_id>` — a sibling of the revision workspaces, never inside one (and without `.portabase/`, so the startup sweep ignores it).
fn route_dir(env: &RestoreEnv, mirror_id: &str) -> R<PathBuf> {
    let root = env.roots.first().ok_or(Failure::from(Code::PathNotAllowed))?;
    let p = root.join(route_name(mirror_id));
    paths::check_task_path(&env.roots, &env.state_dir, &p.to_string_lossy()).map_err(Failure::from)
}

/// Marker `route.json {mirror_id, agent_id}`: `Ok(true)` ours, `Ok(false)` the directory does not exist, `Err(route_not_owned)` anything else.
fn marker_state(dir: &Path, mirror_id: &str, agent_id: &str) -> R<bool> {
    match std::fs::symlink_metadata(dir) {
        Err(_) => Ok(false),
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => bad_state(Code::RouteNotOwned),
        Ok(_) => {
            let v: Option<Value> = std::fs::read(dir.join(MARKER)).ok().and_then(|b| serde_json::from_slice(&b).ok());
            let ours = v.is_some_and(|v| v.get("mirror_id").and_then(Value::as_str) == Some(mirror_id) && v.get("agent_id").and_then(Value::as_str) == Some(agent_id));
            if ours { Ok(true) } else { bad_state(Code::RouteNotOwned) }
        }
    }
}

fn prepare_dir(dir: &Path, mirror_id: &str, agent_id: &str) -> R<()> {
    if !marker_state(dir, mirror_id, agent_id)? {
        std::fs::DirBuilder::new().mode(0o755).create(dir).map_err(|_| Failure::from(Code::RouteIncomplete))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(|_| Failure::from(Code::RouteIncomplete))?;
        write_file(&dir.join(MARKER), &serde_json::to_vec(&json!({"mirror_id": mirror_id, "agent_id": agent_id})).unwrap_or_default())?;
    }
    Ok(())
}

fn write_file(p: &Path, b: &[u8]) -> R<()> {
    use std::io::Write;
    let tmp = p.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&tmp).map_err(|_| Failure::from(Code::RouteIncomplete))?;
    f.write_all(b).and_then(|_| f.sync_all()).map_err(|_| Failure::from(Code::RouteIncomplete))?;
    std::fs::rename(&tmp, p).map_err(|_| Failure::from(Code::RouteIncomplete))
}

fn ports_exact(f: &RouteFacts, route_port: u16) -> bool {
    f.ports.len() == 1 && f.ports[0] == ("127.0.0.1".to_string(), route_port, FORWARDER_PORT)
}

pub async fn run(env: &RestoreEnv, ops: &dyn DockerOps, route: &dyn RouteOps, smoke: &dyn Smoke, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    run_with(env, ops, route, smoke, SMOKE_PAUSE, t, payload).await
}

pub async fn run_with(env: &RestoreEnv, ops: &dyn DockerOps, route: &dyn RouteOps, smoke: &dyn Smoke, pause: Duration, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, RouteBody) = split(payload)?;
    b.check()?;
    match b.action {
        RouteAction::Switch => switch(env, ops, route, smoke, pause, t, h, &b).await,
        RouteAction::Remove => remove(env, route, t, h, &b).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn switch(env: &RestoreEnv, ops: &dyn DockerOps, route: &dyn RouteOps, smoke: &dyn Smoke, pause: Duration, t: &Task<'_>, h: Header, b: &RouteBody) -> R<Value> {
    let c = open_light(env, ops, t, h)?;
    let mut j = Journal::open(&env.state_dir, &c.h.restore_id)?;
    j.begin(t.id, t.ty);
    let r: R<Value> = async {
        let agent = env.agent_id.as_str();
        let (name, port) = (route_name(&b.mirror_id), b.route_port as u16);
        // the target: the running access container of THIS revision (owner labels, own agent id, compose project)
        let target = mine(&c).await?.into_iter().find(|x| x.running && x.labels.get(SERVICE_LABEL).map(String::as_str) == Some(b.service.as_str())).ok_or(Failure::from(Code::RouteTargetNotRunning))?;
        let upstream = format!("{}:{}\n", target.names.first().ok_or(Failure::from(Code::RouteTargetNotRunning))?.trim_start_matches('/'), b.target);
        let net = format!("{}_{ACCESS_NETWORK}", c.h.project);
        let dir = route_dir(env, &b.mirror_id)?;
        prepare_dir(&dir, &b.mirror_id, agent)?;
        let spec = RouteSpec { name: name.clone(), image: c.ce.own_image.clone(), network: net.clone(), route_port: port, dir: dir.clone(), labels: route_labels(&b.mirror_id, agent) };
        // 1. atomic upstream swap (the forwarder reads the file per NEW connection)
        write_file(&dir.join(UPSTREAM), upstream.as_bytes())?;
        // 2. ensure the forwarder is exactly on the target network: absent → create; not ours → refuse (never touch a foreign one); any other shape or network → recreate
        let facts = route.inspect(&name).await?;
        let keep = match &facts {
            Some(f) if !is_ours(&f.labels, &b.mirror_id, agent) => return bad_state(Code::RouteNotOwned),
            Some(f) => f.running && ports_exact(f, port) && f.image == spec.image && f.networks == [net.clone()],
            None => false,
        };
        if !keep {
            if facts.is_some() {
                route.remove(&name).await?;
            }
            route.create_start(&spec).await?;
        }
        // 3. verify what the runner actually has now
        let after = route.inspect(&name).await?.ok_or(Failure::from(Code::RouteIncomplete))?;
        if !after.running || after.networks != [net.clone()] || !ports_exact(&after, port) || !is_ours(&after.labels, &b.mirror_id, agent) {
            return bad_state(Code::RouteIncomplete);
        }
        // 4. smoke THROUGH the forwarder, from a helper on the target network (the forwarder may need a moment to listen: a few tries)
        let mut labels = owner_labels(&c.h.restore_id, agent);
        labels.insert(LABEL_HELPER.into(), "true".into());
        let hname = format!("pbm-smoke-route-{}", &c.h.restore_id[..8]);
        let cmd = smoke_cmd(&name, FORWARDER_PORT as u32, b.http_path.as_deref());
        let mut http = None;
        for i in 0..SMOKE_TRIES {
            if i > 0 {
                tokio::time::sleep(pause).await;
            }
            match smoke.run(&hname, &net, &labels, &cmd, Duration::from_secs(40)).await {
                Ok((code, out)) => {
                    let (ok, st) = judge_smoke(code, &String::from_utf8_lossy(&out), b.http_path.is_some());
                    if ok {
                        http = Some(st);
                        break;
                    }
                }
                Err(Code::SmokeFailedInternal) => return bad_state(Code::SmokeFailedInternal),
                Err(_) => {}
            }
        }
        let st = http.ok_or(Failure::from(Code::RouteSmokeFailed))?;
        j.step(t.id, t.ty, &format!("route:{}", c.h.project), true, None);
        Ok(json!({"v": 1, "route_port": b.route_port, "switched": true, "smoke": {"status": "ok", "http_status": st}}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

/// `remove`: only the header is checked (the revision workspace is NOT opened: delete may run after the newest revision's workspace is gone).
async fn remove(env: &RestoreEnv, route: &dyn RouteOps, t: &Task<'_>, h: Header, b: &RouteBody) -> R<Value> {
    h.check(env)?;
    let mut j = Journal::open(&env.state_dir, &h.restore_id)?;
    j.begin(t.id, t.ty);
    let r: R<Value> = async {
        let agent = env.agent_id.as_str();
        let name = route_name(&b.mirror_id);
        let mut removed_container = 0;
        // a foreign container of that name is left alone and is not ours to count
        if route.inspect(&name).await?.is_some_and(|f| is_ours(&f.labels, &b.mirror_id, agent)) {
            route.remove(&name).await?;
            removed_container = 1;
        }
        let dir = route_dir(env, &b.mirror_id)?;
        let mut removed_dir = false;
        if marker_state(&dir, &b.mirror_id, agent).unwrap_or(false) {
            removed_dir = std::fs::remove_dir_all(&dir).is_ok();
        }
        let left_container = route.inspect(&name).await?.is_some_and(|f| is_ours(&f.labels, &b.mirror_id, agent));
        let left_dir = marker_state(&dir, &b.mirror_id, agent).unwrap_or(false);
        if left_container || left_dir {
            return Err(Failure::from(Code::RouteIncomplete).with_extra(json!({"remaining": usize::from(left_container) + usize::from(left_dir)})));
        }
        j.step(t.id, t.ty, "route_remove", true, None);
        Ok(json!({"v": 1, "removed": {"container": removed_container, "dir": removed_dir}, "remaining": 0}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}
