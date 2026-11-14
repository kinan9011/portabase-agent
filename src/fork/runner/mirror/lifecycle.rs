//! `mirror_up`, `mirror_check`, `mirror_stop` and `mirror_wipe`. `up` and `check` run only after the `final_view_mismatch` guard (the file about to run must still render to the view the
//! dashboard approved) and the D29 container guard; `check` reports honest container states + health and an app smoke from the mirror's own access network; `wipe`
//! removes everything of THIS revision (owner labels + own agent id) and then RE-LISTS: any leftover is `wipe_incomplete`, never a silent success.
use super::payload::{CheckBody, StopBody, UpBody, WipeBody};
use super::smoke::{Smoke, smoke_cmd};
use super::{Ctx, base_args, final_check, open_light};
use crate::fork::compose::guard::{check_resources, check_up, protected_ids};
use crate::fork::compose::run;
use crate::fork::compose::up::exit_failure;
use crate::fork::restore::docker_ops::{DockerOps, LABEL_HELPER, owned_by, owner_labels};
use crate::fork::restore::journal::Journal;
use crate::fork::restore::workspace::Workspace;
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, paths, split};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::Instant;

const PROJECT_LABEL: &str = "com.docker.compose.project";
const SERVICE_LABEL: &str = "com.docker.compose.service";
pub const ACCESS_NETWORK: &str = "pbm_access";
const CHECK_POLL: Duration = Duration::from_secs(2);

async fn guard(c: &Ctx<'_>, doc: &Value) -> R<()> {
    let all = c.ops.containers().await?;
    let protected = protected_ids(&all, &c.ce.own_id, &c.ce.protected_extra);
    check_up(doc, &c.h.project, &c.h.restore_id, &c.env.agent_id, &all, &protected)?;
    check_resources(c.ops, doc, &c.h.restore_id, &c.env.agent_id).await
}

/// the containers of THIS revision's project that carry its owner labels
async fn mine(c: &Ctx<'_>) -> R<Vec<crate::fork::restore::docker_ops::ContainerFacts>> {
    Ok(c.ops.containers().await?.into_iter().filter(|x| owned_by(&x.labels, &c.h.restore_id, &c.env.agent_id) && x.labels.get(PROJECT_LABEL).map(String::as_str) == Some(c.h.project.as_str())).collect())
}

pub async fn run_up(env: &RestoreEnv, ops: &dyn DockerOps, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, UpBody) = split(payload)?;
    b.check()?;
    let c = open_light(env, ops, t, h)?;
    let mut j = Journal::open(&env.state_dir, &c.h.restore_id)?;
    j.begin(t.id, t.ty);
    let r = async {
        let doc = final_check(&c, &b.final_sha256).await?;
        let names: Vec<&str> = doc.get("volumes").and_then(Value::as_object).map(|o| o.values().filter_map(|v| v.get("name").and_then(Value::as_str)).collect()).unwrap_or_default();
        if b.volumes.iter().any(|v| !names.contains(&v.as_str())) {
            return Err(Code::VolumeNotInCompose.into());
        }
        guard(&c, &doc).await?;
        let mut args = base_args(&c.h.project, &c.ws.root);
        args.extend(["up", "-d", "--no-build", "--pull", "missing"].map(String::from));
        let home = c.ws.tmp().join("home");
        let out = run::compose(&c.ce.bin, &args, &home, None, super::DEADLINE_STEP - Duration::from_secs(60)).await?;
        if out.code != 0 {
            return Err(exit_failure(Code::ComposeFailed, &out));
        }
        j.step(t.id, t.ty, &format!("up:{}", c.h.project), true, Some(&b.final_sha256));
        let services: Vec<Value> = mine(&c).await?.iter().map(|x| json!({"service": x.labels.get(SERVICE_LABEL).cloned().unwrap_or_default(), "state": if x.running {"running"} else {"exited"}})).collect();
        Ok(json!({"v": 1, "services": services}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

/// stdout of the smoke helper → `(ok, http_status)`; with a path the status must be 100–499 (a 5xx / garbage is an honest `failed`).
pub fn judge_smoke(code: i64, stdout: &str, with_path: bool) -> (bool, Option<u16>) {
    let status = stdout.lines().find_map(|l| l.strip_prefix("HTTP ")).and_then(|s| s.trim().parse::<u16>().ok());
    let ok = code == 0 && stdout.lines().any(|l| l == "OK") && (!with_path || status.is_some_and(|s| (100..=499).contains(&s)));
    (ok, status)
}

pub async fn run_check(env: &RestoreEnv, ops: &dyn DockerOps, smoke: &dyn Smoke, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, CheckBody) = split(payload)?;
    b.check()?;
    let c = open_light(env, ops, t, h)?;
    let mut j = Journal::open(&env.state_dir, &c.h.restore_id)?;
    j.begin(t.id, t.ty);
    let r = async {
        let doc = final_check(&c, &b.final_sha256).await?;
        if !doc.get("services").and_then(Value::as_object).is_some_and(|s| s.contains_key(&b.access.service)) {
            return Err(Failure::with(Code::FinalViewMismatch, "access_service"));
        }
        let end = Instant::now() + Duration::from_secs(b.wait_s as u64);
        let mut report;
        loop {
            report = vec![];
            for x in mine(&c).await? {
                let st = ops.inspect_state(&x.id).await?;
                let health = st.as_ref().and_then(|s| s.health.clone()).unwrap_or_else(|| "none".into());
                report.push((x.labels.get(SERVICE_LABEL).cloned().unwrap_or_default(), st.as_ref().is_some_and(|s| s.running), health));
            }
            let settled = !report.is_empty() && report.iter().all(|(_, _, health)| health != "starting"); // an exited / unhealthy service will not progress: report it now
            if settled || Instant::now() >= end {
                break;
            }
            tokio::time::sleep(CHECK_POLL).await;
        }
        let access_up = report.iter().any(|(s, running, _)| *s == b.access.service && *running);
        let (ok, http_status) = if access_up {
            let mut labels = owner_labels(&c.h.restore_id, &c.env.agent_id);
            labels.insert(LABEL_HELPER.into(), "true".into());
            let name = format!("pbm-smoke-{}", &c.h.restore_id[..8]);
            let network = format!("{}_{ACCESS_NETWORK}", c.h.project);
            match smoke.run(&name, &network, &labels, &smoke_cmd(&b.access.service, b.access.target, b.http_path.as_deref()), Duration::from_secs(40)).await {
                Ok((code, out)) => judge_smoke(code, &String::from_utf8_lossy(&out), b.http_path.is_some()),
                Err(Code::DeadlineExceeded) => (false, None),
                Err(Code::SmokeFailedInternal) => return Err(Code::SmokeFailedInternal.into()),
                Err(_) => (false, None),
            }
        } else {
            (false, None)
        };
        j.step(t.id, t.ty, "check", true, None);
        let services: Vec<Value> = report.iter().map(|(s, running, health)| json!({"service": s, "state": if *running {"running"} else {"exited"}, "health": health})).collect();
        Ok(json!({"v": 1, "services": services, "smoke": {"status": if ok {"ok"} else {"failed"}, "http_status": http_status}}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

pub async fn run_wipe(env: &RestoreEnv, ops: &dyn DockerOps, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, _b): (Header, WipeBody) = split(payload)?;
    h.check(env)?;
    let ce = env.compose.as_ref().ok_or(Failure::from(Code::ComposeUnavailable))?;
    let ws_path = paths::check_task_path(&env.roots, &env.state_dir, &h.workspace)?;
    // a directory that is not THIS revision's workspace is never touched (no owner.json, or another run's)
    let ws_exists = ws_path.exists();
    if ws_exists && !Workspace::read_owner(&ws_path).is_some_and(|o| o.restore_id == h.restore_id && o.agent_id == env.agent_id) {
        return Err(Code::WorkspaceNotOwned.into());
    }
    let mut j = Journal::open(&env.state_dir, &h.restore_id)?;
    j.begin(t.id, t.ty);
    let own = |l: &crate::fork::restore::docker_ops::Labels| owned_by(l, &h.restore_id, &env.agent_id);
    let r: R<Value> = async {
        let all = ops.containers().await?;
        let protected = protected_ids(&all, &ce.own_id, &ce.protected_extra);
        let (mut cs, mut ns, mut vs) = (0usize, 0usize, 0usize);
        // individual removal errors are not fatal on their own: the re-list below is the judge
        for x in all.iter().filter(|x| own(&x.labels) && !protected.contains(&x.id)) {
            if ops.stop_remove(&x.id).await.is_ok() {
                cs += 1;
            }
        }
        for (name, l) in ops.list_networks().await?.into_iter().filter(|(_, l)| own(l)) {
            let _ = &l;
            if ops.remove_network(&name).await.is_ok() {
                ns += 1;
            }
        }
        for (name, _) in ops.list_volumes().await?.into_iter().filter(|(_, l)| own(l)) {
            if ops.remove_volume(&name).await.is_ok() {
                vs += 1;
            }
        }
        let removed_ws = ws_exists && std::fs::remove_dir_all(&ws_path).is_ok();
        let left = ops.containers().await?.iter().filter(|x| own(&x.labels)).count()
            + ops.list_networks().await?.iter().filter(|(_, l)| own(l)).count()
            + ops.list_volumes().await?.iter().filter(|(_, l)| own(l)).count()
            + usize::from(ws_path.exists());
        if left > 0 {
            return Err(Failure::from(Code::WipeIncomplete).with_extra(json!({"remaining": left})));
        }
        Ok(json!({"v": 1, "containers": cs, "networks": ns, "volumes": vs, "workspace_removed": removed_ws, "remaining": 0}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

/// W23: stop (NOT remove) the running containers of THIS revision's project (owner labels + own agent id, via `mine`) and RE-LIST: any container still running is
/// `stop_incomplete`, never a silent success. Data (volumes, workspace) stays; `mirror_up` brings the same containers back. Foreign and production containers are never touched.
pub async fn run_stop(env: &RestoreEnv, ops: &dyn DockerOps, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, _b): (Header, StopBody) = split(payload)?;
    let c = open_light(env, ops, t, h)?;
    let mut j = Journal::open(&env.state_dir, &c.h.restore_id)?;
    j.begin(t.id, t.ty);
    let r: R<Value> = async {
        let mut stopped = 0usize;
        for x in mine(&c).await?.iter().filter(|x| x.running) {
            ops.stop_container(&x.id, 30).await?;
            stopped += 1;
        }
        let after = mine(&c).await?;
        let remaining = after.iter().filter(|x| x.running).count();
        if remaining > 0 {
            return Err(Failure::from(Code::StopIncomplete).with_extra(json!({"remaining": remaining})));
        }
        j.step(t.id, t.ty, &format!("stop:{}", c.h.project), true, None);
        let services: Vec<Value> = after.iter().map(|x| json!({"service": x.labels.get(SERVICE_LABEL).cloned().unwrap_or_default(), "state": "exited"})).collect();
        Ok(json!({"v": 1, "stopped": stopped, "services": services, "remaining": 0}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}
