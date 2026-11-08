//! W17b agent tests: fake Docker (QOps) + fake Port; timings are milliseconds (`Timing`/`window_override`), never the real 5 s / 180 s clocks.
use super::journal::{self, QEntry, QJournal};
use super::*;
use crate::fork::restore::docker_ops::{LABEL_HELPER, LABEL_RESTORE};
use crate::fork::state::State;
use std::collections::VecDeque;
use std::sync::Mutex;

const UUID_T: &str = "11111111-1111-4111-8111-111111111111";
const UUID_T2: &str = "22222222-2222-4222-8222-222222222222";
const UUID_R: &str = "33333333-3333-4333-8333-333333333333";
const PROJECT: &str = "forklab-quiesce";

fn id(n: u8) -> String {
    format!("{:02x}", n).repeat(32)
}
fn id12(n: u8) -> String {
    id(n)[..12].to_string()
}

#[derive(Clone, Copy, PartialEq)]
enum StartMode {
    Normal,
    NeverRuns,
    Unhealthy,
    CrashLoop,
    Gone,
}
struct FQ {
    containers: Vec<ContainerFacts>,
    states: HashMap<String, CState>,
    log: Vec<String>,
    start_mode: HashMap<String, StartMode>,
    stop_err: HashSet<String>,
    healthcheck: HashSet<String>,
    /// journal dir + "did the journal exist (with stop_intent) when stop was called"
    watch: Option<PathBuf>,
    journal_at_stop: Vec<bool>,
    restart_after_stop: HashSet<String>,
}
struct Fake(Mutex<FQ>);
impl Fake {
    fn new() -> Self {
        Fake(Mutex::new(FQ { containers: vec![], states: HashMap::new(), log: vec![], start_mode: HashMap::new(), stop_err: HashSet::new(), healthcheck: HashSet::new(), watch: None, journal_at_stop: vec![], restart_after_stop: HashSet::new() }))
    }
    fn add(&self, n: u8, project: &str, service: &str, image: &str, running: bool) -> String {
        let mut s = self.0.lock().unwrap();
        let full = id(n);
        let labels = HashMap::from([(plan::PROJECT_LABEL.to_string(), project.to_string()), (plan::SERVICE_LABEL.to_string(), service.to_string())]);
        s.containers.push(ContainerFacts { id: full.clone(), names: vec![format!("{project}-{service}-1")], image: image.into(), labels, mounts_docker_sock: false, running });
        s.states.insert(full.clone(), CState { status: if running { "running" } else { "exited" }.into(), running, health: None, restart_count: 0, stop_timeout: None });
        full
    }
    fn label(&self, n: u8, k: &str, v: &str) {
        let mut s = self.0.lock().unwrap();
        s.containers.iter_mut().find(|c| c.id == id(n)).unwrap().labels.insert(k.into(), v.into());
    }
    fn set_status(&self, n: u8, status: &str) {
        let mut s = self.0.lock().unwrap();
        let st = s.states.get_mut(&id(n)).unwrap();
        st.status = status.into();
        st.running = status == "running";
        s.containers.iter_mut().find(|c| c.id == id(n)).unwrap().running = status == "running";
    }
    fn running(&self, n: u8) -> bool {
        self.0.lock().unwrap().states[&id(n)].running
    }
    fn log(&self) -> Vec<String> {
        self.0.lock().unwrap().log.clone()
    }
    fn mutating(&self) -> usize {
        self.log().iter().filter(|l| l.starts_with("stop:") || l.starts_with("start:")).count()
    }
}
#[async_trait]
impl QOps for Fake {
    async fn containers(&self) -> Result<Vec<ContainerFacts>, Code> {
        Ok(self.0.lock().unwrap().containers.clone())
    }
    async fn inspect_state(&self, i: &str) -> Result<Option<CState>, Code> {
        let mut s = self.0.lock().unwrap();
        if s.start_mode.get(i) == Some(&StartMode::CrashLoop) && s.states.get(i).is_some_and(|x| x.running) {
            s.states.get_mut(i).unwrap().restart_count += 1;
        }
        let hc = s.healthcheck.contains(i);
        Ok(s.states.get(i).cloned().map(|mut x| {
            if hc && x.health.is_none() {
                x.health = Some("healthy".into());
            }
            x
        }))
    }
    async fn stop_container(&self, i: &str, _t: u32) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        let existed = s.watch.as_ref().and_then(|d| journal::list(d).first().map(|j| j.containers.iter().any(|e| e.stop_intent))).unwrap_or(false);
        s.journal_at_stop.push(existed);
        s.log.push(format!("stop:{}", &i[..2]));
        if s.stop_err.contains(i) {
            return Err(Code::DockerUnavailable);
        }
        if let Some(st) = s.states.get_mut(i) {
            st.running = false;
            st.status = "exited".into();
        }
        s.containers.iter_mut().find(|c| c.id == i).unwrap().running = false;
        Ok(())
    }
    async fn start_container(&self, i: &str) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.log.push(format!("start:{}", &i[..2]));
        let mode = s.start_mode.get(i).copied().unwrap_or(StartMode::Normal);
        if mode == StartMode::Gone {
            return Err(Code::ContainerChanged);
        }
        if mode != StartMode::NeverRuns {
            let st = s.states.get_mut(i).unwrap();
            st.running = true;
            st.status = "running".into();
            if mode == StartMode::Unhealthy {
                st.health = Some("unhealthy".into());
            }
            s.containers.iter_mut().find(|c| c.id == i).unwrap().running = true;
        }
        Ok(())
    }
}

struct FakePort {
    replies: Mutex<VecDeque<Reply>>,
    default: Reply,
    calls: Mutex<Vec<String>>,
}
impl FakePort {
    fn new(replies: Vec<Reply>, default: Reply) -> Self {
        FakePort { replies: Mutex::new(replies.into()), default, calls: Mutex::new(vec![]) }
    }
}
#[async_trait]
impl Port for FakePort {
    async fn report(&self, phase: &str, _c: Option<Value>) -> Reply {
        self.calls.lock().unwrap().push(phase.to_string());
        self.replies.lock().unwrap().pop_front().unwrap_or(self.default)
    }
}

fn env(dir: &Path) -> QuiesceEnv {
    QuiesceEnv {
        own_id: id(0xaa),
        protected_extra: vec![],
        max_stop_cap: 1800,
        journal_dir: dir.join("fork-quiesce"),
        t: Timing { poll_every: Duration::from_millis(15), verify_poll: Duration::from_millis(5), settle: Duration::from_millis(5), start_timeout: Some(Duration::from_millis(120)) },
        window_override: Some(Duration::from_millis(400)),
    }
}
fn payload(targets: &[(&str, u8)]) -> Vec<u8> {
    let t: Vec<Value> = targets.iter().map(|(s, n)| json!({"service": s, "container_id": id12(*n)})).collect();
    serde_json::to_vec(&json!({"v": 1, "run_id": UUID_R, "stack_id": UUID_R, "project": PROJECT, "targets": t, "max_stop_seconds": 600, "stop_timeout_cap_seconds": 30, "start_timeout_seconds": 60, "dry_run": false})).unwrap()
}
/// web (depends on db) = 1, db = 2; stop order web, db
fn demo() -> Fake {
    let f = Fake::new();
    f.add(1, PROJECT, "web", "nginx:1", true);
    f.add(2, PROJECT, "db", "postgres:17", true);
    f
}
async fn run(f: &Fake, q: &QuiesceEnv, port: &FakePort, p: &[u8]) -> Result<Value, Failure> {
    execute(q, f, port, UUID_T, p).await
}
fn code(r: &Result<Value, Failure>) -> &'static str {
    r.as_ref().err().map(|e| e.code.as_str()).unwrap_or("ok")
}

// ---- plan (D8) ---------------------------------------------------------------------------------------------------------------------
#[tokio::test]
async fn refuses_own_container_manager_image_socket_mounter_and_listed_names() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let port = FakePort::new(vec![], Reply::Release);
    // target IS the agent's own container (also in the project)
    let f = demo();
    f.add(0xaa, PROJECT, "agent", "busybox", true);
    let r = run(&f, &q, &port, &payload(&[("web", 1), ("db", 2)])).await;
    assert_eq!(code(&r), "protected_in_project");
    assert_eq!(f.mutating(), 0);
    // a manager image in the project (even unselected)
    let f = demo();
    f.add(3, PROJECT, "pb", "ghcr.io/portabase/portabase:1.35.2", true);
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1)])).await), "protected_in_project");
    // arcane
    let f = demo();
    f.add(3, PROJECT, "arc", "ghcr.io/getarcaneapp/arcane:latest", true);
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1)])).await), "protected_in_project");
    // a docker.sock mounter
    let f = demo();
    f.add(3, PROJECT, "watch", "containrrr/watchtower", true);
    f.0.lock().unwrap().containers.iter_mut().find(|c| c.id == id(3)).unwrap().mounts_docker_sock = true;
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1)])).await), "protected_in_project");
    // FORK_PROTECTED_CONTAINERS by name and by 64-hex id
    for extra in [vec![format!("{PROJECT}-db-1")], vec![id(2)]] {
        let f = demo();
        let mut q2 = env(d.path());
        q2.protected_extra = extra;
        assert_eq!(code(&run(&f, &q2, &port, &payload(&[("web", 1), ("db", 2)])).await), "protected_in_project");
        assert_eq!(f.mutating(), 0);
    }
    // the target prefix names the protected container of ANOTHER project
    let f = demo();
    f.add(4, "other", "mgr", "ghcr.io/portabase/portabase:1", true);
    let r = run(&f, &q, &port, &payload(&[("web", 1), ("mgr", 4)])).await;
    assert_eq!(code(&r), "protected_container");
}

#[tokio::test]
async fn refuses_foreign_ambiguous_changed_replica_unstable_restore_owned() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let port = FakePort::new(vec![], Reply::Release);
    // foreign project container
    let f = demo();
    f.add(5, "other", "x", "busybox", true);
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1), ("x", 5)])).await), "not_in_project");
    // unknown id
    let f = demo();
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 9)])).await), "container_changed");
    // service label mismatch
    let f = demo();
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("db", 1)])).await), "container_changed");
    // ambiguous prefix (two containers share the 12-hex prefix)
    let f = demo();
    let mut dup = id(1);
    dup.replace_range(40..42, "ff");
    let labels = f.0.lock().unwrap().containers[0].labels.clone();
    f.0.lock().unwrap().containers.push(ContainerFacts { id: dup.clone(), names: vec!["dup".into()], image: "x".into(), labels, mounts_docker_sock: false, running: true });
    f.0.lock().unwrap().states.insert(dup, CState { status: "running".into(), running: true, health: None, restart_count: 0, stop_timeout: None });
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1)])).await), "container_changed");
    // replica of a selected service running but not listed
    let f = demo();
    f.add(6, PROJECT, "web", "nginx:1", true);
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1)])).await), "replica_not_listed");
    // paused / restarting
    for st in ["paused", "restarting", "dead", "removing"] {
        let f = demo();
        f.set_status(1, st);
        assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1)])).await), "container_unstable", "{st}");
    }
    // restore-owned / helper label
    for l in [LABEL_RESTORE, LABEL_HELPER] {
        let f = demo();
        f.label(1, l, "x");
        assert_eq!(code(&run(&f, &q, &port, &payload(&[("web", 1)])).await), "restore_owned", "{l}");
        assert_eq!(f.mutating(), 0);
    }
}

#[tokio::test]
async fn exited_container_is_never_stopped_or_started() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    f.add(7, PROJECT, "job", "busybox", false);
    let port = FakePort::new(vec![], Reply::Release);
    let r = run(&f, &q, &port, &payload(&[("web", 1), ("job", 7), ("db", 2)])).await.unwrap();
    assert_eq!(r["stopped_count"], 2);
    assert!(!f.log().iter().any(|l| l.contains(&id(7)[..2].to_string())), "log {:?}", f.log());
    assert!(!f.running(7));
    assert_eq!(r["containers"][1]["outcome"], "not_running_before");
}

#[test]
fn payload_grammar_and_bounds() {
    let ok = payload(&[("web", 1)]);
    let body: QuiesceBody = serde_json::from_slice(&ok).unwrap();
    assert!(plan::validate(&body).is_ok());
    let mut v: Value = serde_json::from_slice(&ok).unwrap();
    // unknown field (free-form command / image / path would be one)
    for k in ["command", "image", "path", "container_name"] {
        let mut x = v.clone();
        x[k] = json!("x");
        assert!(serde_json::from_value::<QuiesceBody>(x).is_err(), "{k}");
    }
    let bad = |f: &dyn Fn(&mut Value)| {
        let mut x = v.clone();
        f(&mut x);
        serde_json::from_value::<QuiesceBody>(x).map(|b| plan::validate(&b).is_err()).unwrap_or(true)
    };
    assert!(bad(&|x| x["targets"] = json!([])));
    assert!(bad(&|x| x["targets"] = Value::Array((0..33).map(|i| json!({"service": format!("s{i}"), "container_id": id12(1)})).collect())));
    assert!(bad(&|x| x["targets"] = json!([{"service": "a", "container_id": id12(1)}, {"service": "a", "container_id": id12(2)}])));
    assert!(bad(&|x| x["targets"] = json!([{"service": "a", "container_id": id12(1)}, {"service": "b", "container_id": id12(1)}])));
    assert!(bad(&|x| x["targets"][0]["container_id"] = json!("abc")));
    assert!(bad(&|x| x["targets"][0]["container_id"] = json!("ABCDEF012345")));
    assert!(bad(&|x| x["targets"][0]["service"] = json!("a b; rm -rf /")));
    assert!(bad(&|x| x["project"] = json!("Bad Project")));
    assert!(bad(&|x| x["max_stop_seconds"] = json!(59)));
    assert!(bad(&|x| x["max_stop_seconds"] = json!(3601)));
    assert!(bad(&|x| x["stop_timeout_cap_seconds"] = json!(9)));
    assert!(bad(&|x| x["start_timeout_seconds"] = json!(601)));
    assert!(bad(&|x| x["v"] = json!(2)));
    assert!(bad(&|x| x["run_id"] = json!("nope")));
    v["extra"] = json!(1);
    assert!(serde_json::from_value::<QuiesceBody>(v).is_err());
    assert!(serde_json::from_slice::<StartBody>(br#"{"v":1,"quiesce_task_id":"11111111-1111-4111-8111-111111111111","project":"p","ids":["x"]}"#).is_err());
}

#[tokio::test]
async fn dry_run_makes_no_mutating_call_and_no_journal() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    let mut v: Value = serde_json::from_slice(&payload(&[("web", 1), ("db", 2)])).unwrap();
    v["dry_run"] = json!(true);
    let r = execute(&q, &f, &FakePort::new(vec![], Reply::Release), UUID_T, &serde_json::to_vec(&v).unwrap()).await.unwrap();
    assert_eq!(r["dry_run"], true);
    assert_eq!(f.mutating(), 0);
    assert!(!journal::has_any(&q.journal_dir));
}

// ---- execute -----------------------------------------------------------------------------------------------------------------------
#[tokio::test]
async fn happy_path_orders_journal_and_result() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    f.0.lock().unwrap().watch = Some(q.journal_dir.clone());
    f.0.lock().unwrap().healthcheck.insert(id(2));
    let port = FakePort::new(vec![Reply::Wait, Reply::Wait, Reply::Release], Reply::Wait);
    let r = run(&f, &q, &port, &payload(&[("web", 1), ("db", 2)])).await.unwrap();
    // m7: the journal (with stop_intent) is on disk at EVERY stop call
    assert_eq!(f.0.lock().unwrap().journal_at_stop, vec![true, true]);
    // stop order = payload order, start order = reverse; verified one by one
    let log = f.log();
    assert_eq!(log.iter().filter(|l| l.starts_with("stop:") || l.starts_with("start:")).cloned().collect::<Vec<_>>(), vec!["stop:01", "stop:02", "start:02", "start:01"]);
    assert_eq!(r["released_by"], "dashboard");
    assert_eq!(r["window_intact"], true);
    assert_eq!(r["all_verified"], true);
    assert_eq!(r["stopped_count"], 2);
    assert!(r["downtime_ms"].as_u64().unwrap() > 0);
    assert!(f.running(1) && f.running(2));
    assert!(!journal::has_any(&q.journal_dir), "a fully verified task deletes its journal");
    assert!(serde_json::to_vec(&r).unwrap().len() < 6 * 1024);
    assert_eq!(port.calls.lock().unwrap().first().map(String::as_str), Some("stopped"));
    for k in r.as_object().unwrap().keys() {
        assert!(!["key", "token", "secret", "password", "credential", "cookie", "session"].iter().any(|bad| k.contains(bad)), "{k}");
    }
}

#[tokio::test]
async fn gone_means_release_and_unreachable_does_not() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    let port = FakePort::new(vec![Reply::Wait, Reply::Gone], Reply::Wait);
    let r = run(&f, &q, &port, &payload(&[("web", 1), ("db", 2)])).await.unwrap();
    assert_eq!(r["released_by"], "lost_dashboard");
    assert_eq!(r["window_intact"], false);
    // m9: Unreachable is NOT a release — only the agent-local deadline ends the window, and the containers come back
    let f = demo();
    let started = Instant::now();
    let r = run(&f, &q, &FakePort::new(vec![], Reply::Unreachable), &payload(&[("web", 1), ("db", 2)])).await.unwrap();
    assert_eq!(r["released_by"], "deadline");
    assert!(started.elapsed() >= Duration::from_millis(390), "waited for the deadline, not for the first answer");
    assert_eq!(r["window_intact"], false);
    assert!(f.running(1) && f.running(2));
}

#[tokio::test]
async fn deadline_holds_even_when_the_dashboard_call_hangs() {
    struct Hang;
    #[async_trait]
    impl Port for Hang {
        async fn report(&self, _p: &str, _c: Option<Value>) -> Reply {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Reply::Wait
        }
    }
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    let r = execute(&q, &f, &Hang, UUID_T, &payload(&[("web", 1), ("db", 2)])).await.unwrap();
    assert_eq!(r["released_by"], "deadline");
    assert!(f.running(1) && f.running(2));
}

#[tokio::test]
async fn window_broken_when_a_stopped_container_runs_again() {
    struct Wake<'a>(&'a Fake);
    #[async_trait]
    impl Port for Wake<'_> {
        async fn report(&self, p: &str, _c: Option<Value>) -> Reply {
            if p == "waiting" {
                let _ = self.0.start_container(&id(1)).await; // someone restarts web inside the window
            }
            Reply::Wait
        }
    }
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    let r = execute(&q, &f, &Wake(&f), UUID_T, &payload(&[("web", 1), ("db", 2)])).await.unwrap();
    assert_eq!(r["released_by"], "window_broken");
    assert_eq!(r["window_intact"], false);
}

#[tokio::test]
async fn stop_failure_restarts_what_was_stopped() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    f.0.lock().unwrap().stop_err.insert(id(2));
    let r = run(&f, &q, &FakePort::new(vec![], Reply::Release), &payload(&[("web", 1), ("db", 2)])).await;
    assert_eq!(code(&r), "stop_failed");
    assert!(f.running(1), "web was stopped first and must be back");
    let res = r.unwrap_err().result().unwrap();
    assert_eq!(res["released_by"], "stop_failed");
    assert!(!journal::has_any(&q.journal_dir), "everything is back ⇒ the journal is resolved");
}

#[tokio::test]
async fn restart_failures_are_reported_and_everything_else_still_starts() {
    for (mode, outcome) in [(StartMode::NeverRuns, "not_running"), (StartMode::Unhealthy, "unhealthy"), (StartMode::CrashLoop, "not_running"), (StartMode::Gone, "not_running")] {
        let d = tempfile::tempdir().unwrap();
        let mut q = env(d.path());
        q.t.verify_poll = Duration::from_millis(2);
        let f = demo();
        f.add(8, PROJECT, "flaky", "busybox", true);
        f.0.lock().unwrap().start_mode.insert(id(8), mode);
        if mode == StartMode::Unhealthy {
            f.0.lock().unwrap().healthcheck.insert(id(8));
        }
        let r = tokio::time::timeout(Duration::from_secs(60), run(&f, &q, &FakePort::new(vec![], Reply::Release), &payload(&[("web", 1), ("db", 2), ("flaky", 8)]))).await;
        let r = r.expect("finished");
        assert_eq!(code(&r), "restart_unverified", "{outcome}");
        let res = r.unwrap_err().result().unwrap();
        let flaky = res["containers"].as_array().unwrap().iter().find(|c| c["service"] == "flaky").unwrap();
        assert_eq!(flaky["outcome"], outcome);
        assert_eq!(res["all_verified"], false);
        assert!(f.running(1) && f.running(2), "the others still start and verify");
        assert!(journal::has_any(&q.journal_dir), "unresolved ⇒ journal kept");
        assert_eq!(journal::list(&q.journal_dir)[0].phase, "unresolved");
    }
}

#[tokio::test]
async fn quiesce_pending_blocks_and_auto_resolves() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    let pending = QJournal { v: 1, task_id: UUID_T2.into(), run_id: UUID_R.into(), project: PROJECT.into(), created_unix: 1, phase: "unresolved".into(),
        containers: vec![QEntry { id: id(1), service: "web".into(), name: "n".into(), was_running: true, stop_intent: true, stopped: true, started: false, outcome: None }], released_by: None, replay: None, start_timeout_s: 30 };
    journal::save(&q.journal_dir, &pending).unwrap();
    f.set_status(1, "exited");
    let port = FakePort::new(vec![], Reply::Release);
    assert_eq!(code(&run(&f, &q, &port, &payload(&[("db", 2)])).await), "quiesce_pending");
    f.set_status(1, "running"); // all journaled containers are running again: stale ⇒ auto-resolved
    assert!(run(&f, &q, &port, &payload(&[("db", 2)])).await.is_ok());
    assert!(journal::load(&q.journal_dir, UUID_T2).unwrap().is_none());
}

#[tokio::test]
async fn journal_failure_stops_nothing() {
    let d = tempfile::tempdir().unwrap();
    let mut q = env(d.path());
    // the journal dir is a FILE ⇒ create fails
    std::fs::write(d.path().join("blocker"), b"x").unwrap();
    q.journal_dir = d.path().join("blocker").join("fork-quiesce");
    let f = demo();
    let r = run(&f, &q, &FakePort::new(vec![], Reply::Release), &payload(&[("web", 1)])).await;
    assert_eq!(code(&r), "journal_unavailable");
    assert_eq!(f.mutating(), 0);
}

// ---- replay ------------------------------------------------------------------------------------------------------------------------
fn jr(task: &str, entries: Vec<QEntry>) -> QJournal {
    QJournal { v: 1, task_id: task.into(), run_id: UUID_R.into(), project: PROJECT.into(), created_unix: 1, phase: "stopped".into(), containers: entries, released_by: None, replay: None, start_timeout_s: 30 }
}
fn entry(n: u8, service: &str, was_running: bool, intent: bool) -> QEntry {
    QEntry { id: id(n), service: service.into(), name: service.into(), was_running, stop_intent: intent, stopped: intent, started: false, outcome: None }
}

#[tokio::test]
async fn replay_starts_only_journaled_stop_intent_was_running_and_is_idempotent() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("fork-quiesce");
    let f = demo(); // web 1, db 2
    f.add(3, PROJECT, "bystander", "busybox", false); // stopped by the operator, NOT journaled: must stay stopped (m8)
    f.add(4, PROJECT, "notrunning", "busybox", false);
    f.set_status(1, "exited");
    f.set_status(2, "exited");
    journal::save(&dir, &jr(UUID_T, vec![entry(1, "web", true, true), entry(2, "db", true, true), entry(4, "notrunning", false, false)])).unwrap();
    let t = env(d.path()).t;
    assert_eq!(replay::replay_all(&f, t, &dir).await, 1);
    assert!(f.running(1) && f.running(2));
    assert!(!f.running(3) && !f.running(4), "only journaled stop_intent && was_running containers are started");
    let log = f.log();
    assert_eq!(log.iter().filter(|l| l.starts_with("start:")).cloned().collect::<Vec<_>>(), vec!["start:02", "start:01"], "reverse of the stop order");
    let j = journal::load(&dir, UUID_T).unwrap().unwrap();
    assert_eq!(j.phase, "replayed");
    // twice: still fine, nothing breaks
    assert_eq!(replay::replay_all(&f, t, &dir).await, 1);
    assert!(f.running(1) && f.running(2));
}

#[tokio::test]
async fn corrupt_journal_is_skipped_and_kept() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("fork-quiesce");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{UUID_T}.json")), b"{not json").unwrap();
    std::fs::write(dir.join("notes.txt"), b"hi").unwrap();
    let f = demo();
    assert_eq!(replay::replay_all(&f, env(d.path()).t, &dir).await, 0);
    assert!(dir.join(format!("{UUID_T}.json")).exists(), "never deleted");
    assert_eq!(f.mutating(), 0);
}

#[tokio::test]
async fn adopt_fills_the_outcome_only_when_none_and_removes_verified_journals() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("fork-quiesce");
    let f = demo();
    f.set_status(1, "exited");
    journal::save(&dir, &jr(UUID_T, vec![entry(1, "web", true, true)])).unwrap();
    journal::save(&dir, &jr(UUID_T2, vec![entry(2, "db", true, true)])).unwrap();
    // T2 is NOT replayed yet (no `replay`): adopt must leave it alone
    let mut j1 = journal::load(&dir, UUID_T).unwrap().unwrap();
    assert!(replay::replay_one(&f, env(d.path()).t, &dir, &mut j1).await);
    let mut st = State::fresh("e");
    st.accept(UUID_T, 1);
    st.accept(UUID_T2, 2);
    st.accept(UUID_R, 3);
    st.set_outcome(UUID_R, crate::fork::state::Outcome { status: "succeeded".into(), reason: None, result: None });
    assert!(replay::adopt(&mut st, &dir));
    let o = st.known(UUID_T).unwrap().outcome.clone().unwrap();
    assert_eq!((o.status.as_str(), o.reason.as_deref()), ("failed", Some("quiesce_interrupted")));
    assert_eq!(o.result.unwrap()["all_verified"], true);
    assert!(st.known(UUID_T2).unwrap().outcome.is_none());
    assert_eq!(st.known(UUID_R).unwrap().outcome.as_ref().unwrap().status, "succeeded");
    assert!(journal::load(&dir, UUID_T).unwrap().is_none(), "verified journal removed after adoption");
    assert!(journal::load(&dir, UUID_T2).unwrap().is_some());
    // an already-set outcome is never overwritten
    st.set_outcome(UUID_T2, crate::fork::state::Outcome { status: "failed".into(), reason: Some("x".into()), result: None });
    assert!(!replay::adopt(&mut st, &dir));
}

#[tokio::test]
async fn recover_after_a_simulated_executor_deadline() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    // abort the task mid-window (what `abort.abort()` does on the outer deadline)
    let (f2, q2) = (std::sync::Arc::new(f), q.clone());
    let f3 = f2.clone();
    let h = tokio::spawn(async move { execute(&q2, &*f3, &FakePort::new(vec![], Reply::Wait), UUID_T, &payload(&[("web", 1), ("db", 2)])).await });
    tokio::time::sleep(Duration::from_millis(60)).await;
    h.abort();
    assert!(!f2.running(1) && !f2.running(2), "aborted inside the window: still stopped");
    assert!(journal::load(&q.journal_dir, UUID_T).unwrap().is_some());
    let r = replay::recover(&*f2, q.t, &q.journal_dir, UUID_T).await.unwrap();
    assert_eq!(r["all_verified"], true);
    assert!(f2.running(1) && f2.running(2));
    assert!(journal::load(&q.journal_dir, UUID_T).unwrap().is_none());
    assert!(replay::recover(&*f2, q.t, &q.journal_dir, UUID_T).await.is_none());
}

#[tokio::test]
async fn quiesce_start_is_journal_bound() {
    let d = tempfile::tempdir().unwrap();
    let q = env(d.path());
    let f = demo();
    f.set_status(2, "exited");
    journal::save(&q.journal_dir, &jr(UUID_T, vec![entry(2, "db", true, true)])).unwrap();
    let body = |t: &str, p: &str| serde_json::to_vec(&json!({"v": 1, "quiesce_task_id": t, "project": p})).unwrap();
    // wrong project ⇒ refused, nothing started
    assert_eq!(execute_start(&q, &f, &body(UUID_T, "other")).await.unwrap_err().code.as_str(), "payload_invalid");
    assert_eq!(f.mutating(), 0);
    // unknown task ⇒ nothing to start
    assert_eq!(execute_start(&q, &f, &body(UUID_T2, PROJECT)).await.unwrap()["nothing_to_start"], true);
    // the real one
    let r = execute_start(&q, &f, &body(UUID_T, PROJECT)).await.unwrap();
    assert_eq!(r["all_verified"], true);
    assert!(f.running(2));
    assert!(journal::load(&q.journal_dir, UUID_T).unwrap().is_none());
    // not a uuid ⇒ no path traversal through the file name
    assert!(execute_start(&q, &f, &body("../../etc/passwd", PROJECT)).await.is_err());
}

#[test]
fn detect_requires_the_host_opt_in_and_valid_config() {
    let mi = format!("0 0 0:0 /docker/containers/{}/hostname /etc/hostname rw - ext4 x rw", id(0xaa));
    let e = |m: &'static [(&'static str, &'static str)]| move |k: &str| m.iter().find(|(a, _)| *a == k).map(|(_, v)| v.to_string());
    let sp = Path::new("/config/fork-channel-state.json");
    assert!(QuiesceEnv::detect(&e(&[]), &mi, "", sp).is_err());
    assert!(QuiesceEnv::detect(&e(&[("FORK_QUIESCE_ENABLED", "false")]), &mi, "", sp).is_err());
    let ok = QuiesceEnv::detect(&e(&[("FORK_QUIESCE_ENABLED", "true")]), &mi, "", sp).unwrap();
    assert_eq!((ok.max_stop_cap, ok.own_id.as_str(), ok.journal_dir.to_str().unwrap()), (1800, id(0xaa).as_str(), "/config/fork-quiesce"));
    assert!(QuiesceEnv::detect(&e(&[("FORK_QUIESCE_ENABLED", "true"), ("FORK_PROTECTED_CONTAINERS", "bad name;")]), &mi, "", sp).is_err());
    assert!(QuiesceEnv::detect(&e(&[("FORK_QUIESCE_ENABLED", "true"), ("FORK_QUIESCE_MAX_STOP_SECONDS", "59")]), &mi, "", sp).is_err());
    assert!(QuiesceEnv::detect(&e(&[("FORK_QUIESCE_ENABLED", "true")]), "", "", sp).is_err(), "no own container id ⇒ no capability");
    assert_eq!(super::deadline_of(b"garbage"), Duration::from_secs(70 * 60));
}

#[test]
fn capability_is_reported_only_with_the_flag_and_types_are_targeted() {
    use crate::fork::capabilities as c;
    assert!(!c::reported(true, true, false, false).iter().any(|x| x == "quiesce.v1"));
    assert!(c::reported(false, false, true, false).iter().any(|x| x == "quiesce.v1"));
    assert!(c::is_targeted("quiesce") && c::is_targeted("quiesce_start"));
    assert_eq!(c::task_requires("quiesce"), Some(&["quiesce.v1"][..]));
    assert_eq!(c::task_requires("quiesce_start"), Some(&["quiesce.v1"][..]));
}

#[test]
fn dashboard_vectors() {
    // `quiesce_vectors.json` is generated by the dashboard test w17b-quiesce-vectors: the agent must reach the SAME verdict (serde strictness + `validate`)
    let v: Value = serde_json::from_str(include_str!("../tests/quiesce_vectors.json")).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 12);
    for c in cases {
        let (name, ty, accept) = (c["name"].as_str().unwrap(), c["type"].as_str().unwrap(), c["accept"].as_bool().unwrap());
        let raw = serde_json::to_vec(&c["payload"]).unwrap();
        let ok = if ty == "quiesce" {
            serde_json::from_slice::<QuiesceBody>(&raw).map(|b| plan::validate(&b).is_ok()).unwrap_or(false)
        } else {
            serde_json::from_slice::<StartBody>(&raw).map(|b| b.v == 1 && is_uuid(&b.quiesce_task_id) && is_project(&b.project)).unwrap_or(false)
        };
        assert_eq!(ok, accept, "{name}");
    }
}
