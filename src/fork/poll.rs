//! The channel's own loop (independent of the stock 5 s ping: one failing stock ping cannot starve fork tasks, and vice versa).
use super::capabilities;
use super::config::ChannelConfig;
use super::crypto::Pin;
use super::exec::{self, Ended};
use super::maint;
use super::restore::{self, docker_ops::DockerOps};
use super::state::{self, Outcome, State};
use super::tasks;
use super::transport::{CallError, Leased, Transport};
use super::verify::{Ctx, Decision, Reject, evaluate};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub struct Runtime {
    pub agent_id: String,
    pub enroll_id: String,
    /// Effective pins (bundle − revoked + runtime-added, see `maint::effective_pins`).
    pub pins: Vec<Pin>,
    /// Pins and credential exactly as the bundle file states them; effective values are derived from these + the persisted state.
    pub bundle_pins: Vec<Pin>,
    pub bundle_credential: String,
    pub task_key: [u8; 32],
    pub capabilities: Vec<String>,
    pub state: State,
    pub state_path: PathBuf,
    pub transport: Transport,
    /// W17-i: restore configuration + Docker access. `None` until `init_restore` proved the host is configured (then `restore.target.v1` is reported).
    pub renv: Option<restore::RestoreEnv>,
    pub ops: Option<Arc<dyn DockerOps>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Handled {
    Executed(String),
    Duplicate,
    Rejected(&'static str),
}

/// A disabled channel refuses EVERYTHING it is handed, before any parsing, signature check, state access or network call.
#[allow(dead_code)] // the real guarantee is "a disabled channel never polls"; this is the explicit refusal path, pinned by tests
pub fn process_when_disabled(_leased: &Leased) -> Handled {
    Handled::Rejected(Reject::ChannelDisabled.code())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Runtime {
    pub fn from_config(cfg: ChannelConfig) -> Result<Self, String> {
        let state = state::load(&cfg.state_path, &cfg.enroll_id).map_err(|e| e.to_string())?;
        let pins = maint::effective_pins(&cfg.pins, &state).map_err(|e| e.to_string())?;
        let transport = Transport::new(&cfg.server_url, &cfg.agent_id, maint::effective_credential(&cfg.credential, &state), cfg.insecure_lab).map_err(|_| "cannot build the http client".to_string())?;
        Ok(Self { agent_id: cfg.agent_id, enroll_id: cfg.enroll_id, pins, bundle_pins: cfg.pins, bundle_credential: cfg.credential, task_key: cfg.task_key, capabilities: capabilities::reported(false, false), state, state_path: cfg.state_path, transport, renv: None, ops: None })
    }

    /// W17-i (DD20): decide, once at start-up, whether this host can be a restore target — valid `FORK_ALLOWED_PATH_ROOTS` (non-empty) AND a Docker daemon that answers.
    /// Only then `restore.target.v1` is reported; then the crash leftovers are swept (SEC-14). Misconfiguration degrades honestly (one log line, no capability).
    pub async fn init_restore(&mut self, now: i64) {
        let env = |k: &str| std::env::var(k).ok();
        let mut renv = match restore::RestoreEnv::from_env(&env, &self.state_path, &self.agent_id) {
            Ok(r) if !r.roots.is_empty() => r,
            Ok(_) => {
                info!("Fork channel: restore target not enabled (FORK_ALLOWED_PATH_ROOTS is empty)");
                return;
            }
            Err(e) => {
                error!("Fork channel: restore target NOT enabled: {e}");
                return;
            }
        };
        let ops: Arc<dyn DockerOps> = match restore::docker_ops::RealDocker::connect() {
            Ok(d) => Arc::new(d),
            Err(_) => {
                error!("Fork channel: restore target NOT enabled: the Docker daemon is not reachable");
                return;
            }
        };
        if !ops.ping().await {
            error!("Fork channel: restore target NOT enabled: the Docker daemon does not answer");
            return;
        }
        renv.master_b64 = crate::utils::edge_key::decode_edge_key(&crate::settings::CONFIG.edge_key).ok().map(|k| super::state::Redacted(k.master_key_b64));
        let swept = restore::sweep::startup_sweep(&renv, Some(ops.as_ref()), now).await;
        info!("Fork channel: restore target enabled ({} root(s), host role {:?}); startup sweep: {:?}", renv.roots.len(), renv.host_role, swept);
        // W17-ii (E17): `compose.render.v1` only when the agent knows its own container + image, runs the pinned Compose CLI and loaded its rule file.
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        let compose_ok = match super::compose::ComposeEnv::detect(ops.as_ref(), &env, PathBuf::from(super::compose::COMPOSE_BIN), &mountinfo, &cgroup).await {
            Ok(ce) => {
                info!("Fork channel: compose.render.v1 enabled (Compose {}, own image resolved)", ce.version);
                renv.compose = Some(ce);
                true
            }
            Err(why) => {
                info!("Fork channel: compose.render.v1 NOT enabled: {why}");
                false
            }
        };
        self.renv = Some(renv);
        self.ops = Some(ops);
        self.capabilities = capabilities::reported(true, compose_ok);
    }

    /// Run one restore-class task under the heartbeat loop and its deadline. Never panics; every failure is a closed code.
    async fn run_restore(&self, v: &super::verify::Verified, leased: &Leased, now: i64) -> Outcome {
        let failed = |code: &str, result: Option<serde_json::Value>| Outcome { status: "failed".into(), reason: Some(code.into()), result };
        let (Some(renv), Some(ops)) = (&self.renv, &self.ops) else { return failed("execution_error", None) };
        let ty = v.envelope.task_type.as_str();
        let task = restore::Task { id: &v.envelope.task_id, ty, now };
        let sink = Sink { transport: &self.transport, task_id: &leased.task_id, lease_id: &leased.lease_id };
        let is_compose = matches!(ty, "compose_render" | "restore_db" | "compose_up");
        let fut = async {
            if is_compose { super::compose::execute(renv, ops.as_ref(), &self.pins, &sink, &task, &v.payload).await } else { restore::execute(renv, ops.as_ref(), &self.pins, &task, &v.payload).await }
        };
        let deadline = if is_compose { super::compose::deadline_of(ty) } else { restore::deadline_of(ty) };
        match exec::run_with_heartbeat(&self.transport, &leased.task_id, &leased.lease_id, deadline, fut).await {
            Ended::Done(Ok(result)) => Outcome { status: "succeeded".into(), reason: None, result: Some(result) },
            Ended::Done(Err(f)) => failed(f.code.as_str(), f.result()),
            Ended::Deadline => failed(restore::Code::DeadlineExceeded.as_str(), None),
        }
    }

    async fn report(&self, leased: &Leased, o: &Outcome) {
        if let Err(e) = self.transport.result(&leased.task_id, &leased.lease_id, o).await {
            warn!("Fork channel: could not report the result of task {} ({e:?}); the dashboard will offer it again", leased.task_id);
        }
    }

    /// Maintenance task (pin_add / pin_revoke / rotate_credential): compute the new state, SAVE it, and only then swap pins / credential in memory (DD6).
    /// A save failure leaves memory and transport untouched and reports `failed:state_unavailable`; a rule violation reports `failed:<code>`.
    pub(crate) fn apply_maint(&mut self, task_id: &str, signing_kid: &str, ty: &str, payload: &[u8]) -> Outcome {
        let failed = |code: &str| Outcome { status: "failed".into(), reason: Some(code.into()), result: None };
        let outcome = match maint::apply(&self.state, &self.bundle_pins, &self.bundle_credential, &self.agent_id, signing_kid, ty, payload) {
            Ok((mut ns, result)) => {
                let ok = Outcome { status: "succeeded".into(), reason: None, result: Some(result) };
                ns.set_outcome(task_id, ok.clone());
                if state::save(&self.state_path, &ns).is_ok() {
                    match maint::effective_pins(&self.bundle_pins, &ns) {
                        Ok(p) => self.pins = p,
                        Err(e) => error!("Fork channel: pinned key set invalid after {ty} ({e}); it will refuse to start at the next restart"),
                    }
                    if let Some(c) = &ns.credential {
                        let _ = self.transport.set_credential(&c.0);
                    }
                    self.state = ns;
                    return ok;
                }
                error!("Fork channel: cannot persist the effect of {ty}; nothing was applied");
                failed("state_unavailable")
            }
            Err(code) => failed(code),
        };
        self.state.set_outcome(task_id, outcome.clone());
        let _ = state::save(&self.state_path, &self.state);
        outcome
    }

    /// Verify → (accept → persist → execute → persist → report) | (reject → report). Never executes anything that did not pass every check.
    pub async fn process(&mut self, leased: &Leased, now: i64) -> Handled {
        let decision = {
            let c = Ctx { agent_id: &self.agent_id, enroll_id: &self.enroll_id, pins: &self.pins, task_key: &self.task_key, capabilities: &self.capabilities, state: &self.state, now };
            evaluate(&c, &leased.envelope, &leased.signature, leased.payload_enc.as_deref())
        };
        match decision {
            Decision::Reject(r) => {
                warn!("Fork channel: refused task {} ({})", leased.task_id, r.code());
                self.report(leased, &Outcome { status: "rejected".into(), reason: Some(r.code().into()), result: None }).await;
                Handled::Rejected(r.code())
            }
            Decision::Duplicate(a) => {
                // never run again; re-report what happened (or that the agent restarted mid-task)
                let o = a.outcome.clone().unwrap_or(Outcome { status: "failed".into(), reason: Some("execution_error".into()), result: None });
                info!("Fork channel: task {} already handled, re-reporting its outcome", leased.task_id);
                self.report(leased, &o).await;
                Handled::Duplicate
            }
            Decision::Accept(v) => {
                self.state.accept(&v.envelope.task_id, v.envelope.seq);
                if state::save(&self.state_path, &self.state).is_err() {
                    // without durable replay state nothing may run
                    error!("Fork channel: cannot persist replay state; refusing task {}", leased.task_id);
                    self.report(leased, &Outcome { status: "rejected".into(), reason: Some(Reject::StateUnavailable.code().into()), result: None }).await;
                    return Handled::Rejected(Reject::StateUnavailable.code());
                }
                let _ = self.transport.heartbeat(&leased.task_id, &leased.lease_id).await;
                let ty = v.envelope.task_type.as_str();
                let outcome = if maint::is_maint(ty) {
                    self.apply_maint(&v.envelope.task_id, &v.envelope.kid, ty, &v.payload)
                } else {
                    let outcome = if capabilities::is_targeted(ty) {
                        self.run_restore(&v, leased, now).await
                    } else {
                        match tasks::execute(ty, &v.payload) {
                            Ok(result) => Outcome { status: "succeeded".into(), reason: None, result: Some(result) },
                            Err(code) => Outcome { status: "failed".into(), reason: Some(code.into()), result: None },
                        }
                    };
                    self.state.set_outcome(&v.envelope.task_id, outcome.clone());
                    if state::save(&self.state_path, &self.state).is_err() {
                        warn!("Fork channel: cannot persist the outcome of task {}", leased.task_id);
                    }
                    outcome
                };
                self.report(leased, &outcome).await;
                info!("Fork channel: task {} ({}) {}", leased.task_id, v.envelope.task_type, outcome.status);
                Handled::Executed(outcome.status)
            }
        }
    }

    /// One iteration. Returns how long to wait before the next one.
    pub async fn poll_once(&mut self, poll: Duration, now: i64) -> Duration {
        match self.transport.lease(&self.capabilities).await {
            Ok(None) => poll,
            Ok(Some(leased)) => {
                self.process(&leased, now).await;
                Duration::from_millis(200) // more may be queued
            }
            Err(CallError::RateLimited(s)) => Duration::from_secs(s.clamp(1, 300)),
            Err(CallError::Unauthorized) => {
                error!("Fork channel: the dashboard rejected this agent's credential (revoked, rotated or wrong bundle). Re-enrol the agent.");
                Duration::from_secs(60)
            }
            Err(CallError::Disabled) => {
                info!("Fork channel: switched off for this agent by the operator");
                Duration::from_secs(60)
            }
            Err(e) => {
                warn!("Fork channel: lease failed ({e:?})");
                (poll * 3).min(Duration::from_secs(120))
            }
        }
    }
}

pub async fn run(cfg: ChannelConfig) {
    let poll = Duration::from_secs(cfg.poll_seconds);
    let mut rt = match Runtime::from_config(cfg) {
        Ok(r) => r,
        Err(e) => {
            error!("Fork task channel NOT started: {e}");
            return;
        }
    };
    info!("Fork channel: pinned dashboard keys (kid): {}", rt.pins.iter().map(|p| p.kid.as_str()).collect::<Vec<_>>().join(", "));
    rt.init_restore(now_secs()).await;
    super::set_active(Arc::new(super::Active { client: rt.transport.clone(), capabilities: rt.capabilities.clone() }));
    loop {
        let wait = rt.poll_once(poll, now_secs()).await;
        tokio::time::sleep(wait).await;
    }
}

/// W17-ii: hands the policy view of a `compose_render` task to the dashboard's render route (bound to this task + lease).
struct Sink<'a> {
    transport: &'a Transport,
    task_id: &'a str,
    lease_id: &'a str,
}
#[async_trait::async_trait]
impl super::compose::RenderSink for Sink<'_> {
    async fn put(&self, body: serde_json::Value) -> Result<(), ()> {
        self.transport.render(self.task_id, self.lease_id, body).await.map_err(|_| ())
    }
}
