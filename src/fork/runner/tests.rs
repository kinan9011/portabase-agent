//! W21 runner tests: role gating (signed vectors produced by the dashboard code), capability sets, payload validation incl. forged inputs, the pure classifier, the pinned
//! helper script, the hardened request bodies, the executor against a fake Docker (wipe always, verified) and the runner init.
use super::docker::{HelperSpec, LABEL_AGENT, LABEL_PROBE, Labels, Owned, RunnerDocker, has_label, real};
use super::probe::{self, Kind, Outcome, ProbePayload, Target};
use super::wipe::wipe_owned;
use super::{Code, role_is_runner};
use crate::fork::capabilities;
use crate::fork::crypto::{parse_pin, sha256_hex};
use crate::fork::state::State;
use crate::fork::verify::{Ctx, Decision, evaluate};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Deserialize)]
struct VPin {
    kid: String,
    pem: String,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    envelope: String,
    signature: String,
    payload_enc: Option<String>,
    expect: String,
}
#[derive(Deserialize)]
struct PCase {
    name: String,
    payload: serde_json::Value,
    valid: bool,
}
#[derive(Deserialize)]
struct RunnerVec {
    capabilities: Vec<String>,
    cases: Vec<Case>,
    payload_cases: Vec<PCase>,
}
#[derive(Deserialize)]
struct Vecs {
    now: i64,
    agent_id: String,
    enroll_id: String,
    own_capabilities: Vec<String>,
    pins: Vec<VPin>,
    task_key_b64: String,
    cases: Vec<Case>,
    runner: RunnerVec,
}
fn vecs() -> Vecs {
    serde_json::from_str(include_str!("../tests/restore_vectors.json")).expect("restore_vectors.json")
}

fn decide(v: &Vecs, caps: &[String], c: &Case) -> Decision {
    let pins: Vec<_> = v.pins.iter().map(|p| parse_pin(&p.kid, &p.pem).unwrap()).collect();
    let key: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &v.task_key_b64).unwrap().try_into().unwrap();
    let state = State::fresh(&v.enroll_id);
    let ctx = Ctx { agent_id: &v.agent_id, enroll_id: &v.enroll_id, pins: &pins, task_key: &key, capabilities: caps, state: &state, now: v.now };
    evaluate(&ctx, &c.envelope, &c.signature, c.payload_enc.as_deref())
}
fn expect(v: &Vecs, caps: &[String], c: &Case) {
    match (c.expect.as_str(), decide(v, caps, c)) {
        ("ok", Decision::Accept(_)) => {}
        (code, Decision::Reject(r)) => assert_eq!(r.code(), code, "{}", c.name),
        (e, g) => panic!("{}: expected {e}, got {g:?}", c.name),
    }
}

// ---- role gating -----------------------------------------------------------------------------------------------------------------------
#[test]
fn runner_role_matrix_with_signed_dashboard_vectors() {
    let v = vecs();
    assert_eq!(v.runner.capabilities, capabilities::runner_reported(), "the dashboard fixture and the agent agree on the runner capability set");
    assert!(v.runner.cases.len() >= 10);
    for c in &v.runner.cases {
        expect(&v, &v.runner.capabilities, c);
    }
}
#[test]
fn a_non_runner_refuses_runner_probe_with_role_forbidden() {
    let v = vecs();
    let c = v.cases.iter().find(|c| c.name == "runner_probe_on_non_runner").unwrap();
    expect(&v, &v.own_capabilities, c);
    // also with the plain minimal capability set
    let minimal = capabilities::reported(false, false, false, false);
    assert!(matches!(decide(&v, &minimal, c), Decision::Reject(r) if r.code() == "role_forbidden"));
}
#[test]
fn every_restore_vector_still_gets_its_decision_for_a_non_runner() {
    let v = vecs();
    for c in &v.cases {
        expect(&v, &v.own_capabilities, c);
    }
}
#[test]
fn a_runner_that_somehow_also_has_restore_capabilities_still_refuses_restore_tasks() {
    let v = vecs();
    let mut caps = v.own_capabilities.clone();
    caps.push(capabilities::RUNNER.to_string());
    let c = v.runner.cases.iter().find(|c| c.name == "restore_probe_on_runner").unwrap();
    assert!(matches!(decide(&v, &caps, c), Decision::Reject(r) if r.code() == "role_forbidden"));
}
#[test]
fn runner_reports_exactly_four_capabilities_and_none_of_the_data_ones() {
    let r = capabilities::runner_reported();
    assert_eq!(r, vec!["channel.v1", "noop.v1", "channel-maint.v1", "runner.v1"]);
    for forbidden in ["restore.target.v1", "compose.render.v1", "quiesce.v1", "test-restore.v1", "plaintext-hash.v1"] {
        assert!(!r.iter().any(|c| c == forbidden), "{forbidden}");
    }
    assert_eq!(capabilities::task_requires("runner_probe"), Some(&[capabilities::RUNNER][..]));
    assert!(capabilities::is_targeted("runner_probe") && capabilities::is_runner_only("runner_probe") && !capabilities::is_common("runner_probe"));
    // no type is both runner-only and common; every common type exists in the closed list
    for t in capabilities::RUNNER_ONLY {
        assert!(!capabilities::is_common(t));
    }
    for t in capabilities::COMMON {
        assert!(capabilities::task_requires(t).is_some(), "{t}");
    }
}
#[test]
fn role_is_runner_is_exact() {
    let e = |v: &'static str| move |k: &str| (k == "FORK_HOST_ROLE").then(|| v.to_string());
    assert!(role_is_runner(&e("runner")));
    assert!(role_is_runner(&e(" runner ")));
    for no in ["", "production", "test", "Runner", "runner2", "runners"] {
        assert!(!role_is_runner(&e(no)), "{no}");
    }
    assert!(!role_is_runner(&|_: &str| None));
}
#[test]
fn runner_codes_are_the_dashboard_reasons() {
    let got: Vec<&str> = [Code::PayloadInvalid, Code::DockerUnavailable, Code::HelperFailed, Code::WipeIncomplete, Code::DeadlineExceeded].iter().map(|c| c.as_str()).collect();
    assert_eq!(got, ["payload_invalid", "docker_unavailable", "helper_failed", "wipe_incomplete", "deadline_exceeded"]);
    assert_eq!(crate::fork::verify::Reject::RoleForbidden.code(), "role_forbidden");
}

// ---- payload validation (shared forged-input corpus with the dashboard schema) ------------------------------------------------------------
#[test]
fn payload_cases_agree_with_the_dashboard_schema_row_by_row() {
    let v = vecs();
    assert!(v.runner.payload_cases.len() >= 35);
    for c in &v.runner.payload_cases {
        let bytes = serde_json::to_vec(&c.payload).unwrap();
        assert_eq!(probe::parse(&bytes).is_ok(), c.valid, "{}", c.name);
        if !c.valid {
            assert_eq!(probe::parse(&bytes).unwrap_err(), Code::PayloadInvalid, "{}", c.name);
        }
    }
}
fn payload(targets: Vec<Target>) -> ProbePayload {
    ProbePayload { v: 1, probe_id: "99999999-9999-4999-8999-999999999999".into(), targets_sha256: "d".repeat(64), timeout_ms: 1500, targets }
}
fn t(id: &str, kind: Kind, host: &str, port: Option<u32>) -> Target {
    Target { id: id.into(), kind, host: host.into(), port }
}
fn sample() -> ProbePayload {
    payload(vec![t("t01", Kind::Tcp, "10.20.30.40", Some(25)), t("t02", Kind::DnsTcp, "10.20.30.53", Some(53)), t("t03", Kind::DnsName, "example.com", None)])
}

#[test]
fn classify_table_covers_every_branch() {
    use Kind::*;
    use Outcome::*;
    for k in [Tcp, DnsTcp] {
        assert_eq!(probe::classify(k, 0, "none"), Reachable);
        assert_eq!(probe::classify(k, 1, "refused"), Reachable, "a RST proves a path exists");
        assert_eq!(probe::classify(k, 124, "none"), Blocked);
        assert_eq!(probe::classify(k, 137, "none"), Blocked);
        assert_eq!(probe::classify(k, 1, "noroute"), Blocked);
        assert_eq!(probe::classify(k, 1, "unreach"), Blocked);
        assert_eq!(probe::classify(k, 1, "other"), Error);
        assert_eq!(probe::classify(k, 7, "none"), Error);
    }
    assert_eq!(probe::classify(DnsName, 0, "none"), Reachable);
    assert_eq!(probe::classify(DnsName, 2, "none"), Blocked);
    assert_eq!(probe::classify(DnsName, 124, "none"), Blocked);
    assert_eq!(probe::classify(DnsName, 137, "none"), Blocked);
    assert_eq!(probe::classify(DnsName, 1, "none"), Error);
    assert_eq!(probe::classify(DnsName, 1, "refused"), Error, "refused is a TCP notion; a DNS name never reads it as reachable");
}
#[test]
fn probe_script_hash_is_pinned() {
    // changing the helper script is a security-relevant change: update this hash only together with ADR-008 §Probe
    assert_eq!(sha256_hex(probe::PROBE_SCRIPT.as_bytes()), PINNED_SCRIPT_SHA256);
    assert!(!probe::PROBE_SCRIPT.contains("eval") && !probe::PROBE_SCRIPT.contains("sh -c \"$"));
}
const PINNED_SCRIPT_SHA256: &str = "edbf55a003bb7796f537574f25c30542462931748c350010a21a0aa1cf4613d0";

#[test]
fn deadline_formula() {
    assert_eq!(probe::deadline_of(&sample()), Duration::from_secs(3 * 3 + 60));
    let many = payload((0..32).map(|i| t(&format!("t{i:02}"), Kind::Tcp, "10.0.0.1", Some(1 + i))).collect());
    assert_eq!(probe::deadline_of(&many), Duration::from_secs((32 * 3 + 60).min(300)));
    let mut slow = many.clone();
    slow.timeout_ms = 5000;
    assert_eq!(probe::deadline_of(&slow), Duration::from_secs(32 * 6 + 60), "32 targets at 5 s stay under the 300 s cap");
}
#[test]
fn targets_env_has_one_line_per_target_and_dash_for_no_port() {
    assert_eq!(probe::targets_env(&sample()), "t01 tcp 10.20.30.40 25\nt02 dns_tcp 10.20.30.53 53\nt03 dns_name example.com -");
}

fn out(lines: &[&str]) -> String {
    lines.join("\n") + "\n"
}
#[test]
fn parse_output_accepts_the_exact_shape_and_maps_outcomes() {
    let p = sample();
    let s = out(&["PBM-PROBE-START", "S ok", "R t01 124 none", "R t02 1 refused", "R t03 2 none", "PBM-PROBE-END"]);
    let (dns, r) = probe::parse_output(&s, &p).unwrap();
    assert!(dns);
    assert_eq!(r, vec![("t01".into(), Outcome::Blocked), ("t02".into(), Outcome::Reachable), ("t03".into(), Outcome::Blocked)]);
    let (dns, _) = probe::parse_output(&out(&["PBM-PROBE-START", "S fail", "R t01 124 none", "R t02 124 none", "R t03 124 none", "PBM-PROBE-END"]), &p).unwrap();
    assert!(!dns);
}
#[test]
fn parse_output_refuses_everything_unexpected_as_helper_failed() {
    let p = sample();
    let ok = ["PBM-PROBE-START", "S ok", "R t01 124 none", "R t02 124 none", "R t03 2 none", "PBM-PROBE-END"];
    assert!(probe::parse_output(&out(&ok), &p).is_ok());
    let without = |i: usize| -> Vec<&str> { ok.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, l)| *l).collect() };
    for (name, s) in [
        ("no start", out(&without(0))),
        ("no S", out(&without(1))),
        ("missing id t01", out(&without(2))),
        ("missing id t03", out(&without(4))),
        ("no end", out(&without(5))),
        ("empty", String::new()),
        ("unknown id", out(&["PBM-PROBE-START", "S ok", "R t01 124 none", "R t02 124 none", "R t03 2 none", "R t99 0 none", "PBM-PROBE-END"])),
        ("duplicate id", out(&["PBM-PROBE-START", "S ok", "R t01 124 none", "R t01 0 none", "R t02 124 none", "R t03 2 none", "PBM-PROBE-END"])),
        ("two S", out(&["PBM-PROBE-START", "S ok", "S ok", "R t01 124 none", "R t02 124 none", "R t03 2 none", "PBM-PROBE-END"])),
        ("bad class", out(&["PBM-PROBE-START", "S ok", "R t01 124 weird", "R t02 124 none", "R t03 2 none", "PBM-PROBE-END"])),
        ("bad rc", out(&["PBM-PROBE-START", "S ok", "R t01 x none", "R t02 124 none", "R t03 2 none", "PBM-PROBE-END"])),
        ("garbage line", out(&["PBM-PROBE-START", "S ok", "hello", "R t01 124 none", "R t02 124 none", "R t03 2 none", "PBM-PROBE-END"])),
    ] {
        assert_eq!(probe::parse_output(&s, &p).unwrap_err(), Code::HelperFailed, "{name}");
    }
}

// ---- hardened requests ---------------------------------------------------------------------------------------------------------------------
#[test]
fn probe_network_is_not_internal_and_takes_its_subnet_from_the_daemon_pool() {
    let labels = Labels::from([(LABEL_PROBE.to_string(), "p".to_string())]);
    let r = real::network_request("pbr-probe-x", &labels);
    assert_eq!(r.internal, Some(false), "internal: true would hide the very leak the probe looks for");
    assert!(r.ipam.is_none(), "no IPAM: the subnet comes from default-address-pools exactly like a mirror's");
    assert!(r.options.is_none());
    assert_eq!(r.driver.as_deref(), Some("bridge"));
    assert_eq!(r.labels.unwrap(), labels);
}
#[test]
fn probe_helper_is_hardened() {
    let spec = HelperSpec { name: "pbr-probe-x-h".into(), network: "pbr-probe-x".into(), labels: Labels::from([(LABEL_PROBE.to_string(), "p".to_string())]), env: vec![("PBM_TARGETS".into(), "t01 tcp 10.0.0.1 25".into()), ("PBM_T".into(), "1.5".into()), ("PBM_SELF".into(), "pbr-probe-x-h".into())], timeout: Duration::from_secs(60) };
    let b = real::helper_body("img:1", &spec);
    let hc = b.host_config.clone().unwrap();
    assert_eq!(b.user.as_deref(), Some("65534:65534"));
    assert_eq!(hc.cap_drop.unwrap(), vec!["ALL"]);
    assert!(hc.cap_add.is_none());
    assert_eq!(hc.security_opt.unwrap(), vec!["no-new-privileges"]);
    assert_eq!(hc.readonly_rootfs, Some(true));
    assert!(hc.binds.is_none(), "no bind mount of any kind");
    assert_eq!(hc.memory, Some(64 << 20));
    assert_eq!(hc.pids_limit, Some(64));
    assert_eq!(hc.network_mode.as_deref(), Some("pbr-probe-x"));
    assert!(hc.dns.is_none(), "daemon DNS, like a mirror");
    assert_eq!(hc.log_config.unwrap().typ.as_deref(), Some("none"));
    assert_eq!(hc.privileged, None);
    assert_eq!(b.network_disabled, None);
    assert_eq!(b.entrypoint.unwrap(), vec!["bash"]);
    let cmd = b.cmd.unwrap();
    assert_eq!(cmd[0], "-c");
    assert_eq!(cmd[1], probe::PROBE_SCRIPT);
    assert_eq!(cmd.len(), 3, "values reach the script only through env, never through argv");
    assert!(b.env.unwrap().iter().all(|e| e.starts_with("PBM_")));
}

// ---- fake Docker + executor ---------------------------------------------------------------------------------------------------------------
#[derive(Default)]
struct FakeState {
    networks: BTreeMap<String, Labels>,
    containers: BTreeMap<String, Labels>,
    volumes: BTreeMap<String, Labels>,
    created_networks: Vec<String>,
    specs: Vec<HelperSpec>,
    helper: Option<Result<(i64, Vec<u8>), Code>>,
    stdout: Option<String>,
    undeletable: bool,
    ping: bool,
    image: bool,
    events: Vec<String>,
    list_fails_after_remove: bool,
    removed_once: bool,
}
struct Fake(Mutex<FakeState>);
impl Fake {
    fn new() -> Arc<Self> {
        Arc::new(Fake(Mutex::new(FakeState { ping: true, image: true, ..Default::default() })))
    }
}
#[async_trait]
impl RunnerDocker for Fake {
    async fn ping(&self) -> bool {
        self.0.lock().unwrap().ping
    }
    async fn helper_image(&self) -> Result<String, Code> {
        if self.0.lock().unwrap().image { Ok("img:1".into()) } else { Err(Code::DockerUnavailable) }
    }
    async fn create_probe_network(&self, name: &str, labels: &Labels) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.events.push(format!("net+{name}"));
        s.created_networks.push(name.into());
        s.networks.insert(name.into(), labels.clone());
        Ok(())
    }
    async fn run_probe_helper(&self, spec: &HelperSpec) -> Result<(i64, Vec<u8>), Code> {
        let mut s = self.0.lock().unwrap();
        s.events.push(format!("run {}", spec.name));
        s.specs.push(spec.clone());
        s.containers.insert(spec.name.clone(), spec.labels.clone());
        if let Some(r) = s.helper.clone() {
            return r;
        }
        let targets = &spec.env.iter().find(|(k, _)| k == "PBM_TARGETS").unwrap().1;
        let body = s.stdout.clone().unwrap_or_else(|| {
            let mut o = String::from("PBM-PROBE-START\nS ok\n");
            for l in targets.lines() {
                o += &format!("R {} 124 none\n", l.split(' ').next().unwrap());
            }
            o + "PBM-PROBE-END\n"
        });
        Ok((0, body.into_bytes()))
    }
    async fn list_owned(&self, key: &str, value: Option<&str>) -> Result<Owned, Code> {
        let mut s = self.0.lock().unwrap();
        if s.list_fails_after_remove && s.removed_once {
            return Err(Code::DockerUnavailable);
        }
        s.events.push("list".into());
        let pick = |m: &BTreeMap<String, Labels>| m.iter().filter(|(_, l)| has_label(l, key, value)).map(|(n, _)| n.clone()).collect::<Vec<_>>();
        Ok(Owned { containers: pick(&s.containers), networks: pick(&s.networks), volumes: pick(&s.volumes) })
    }
    async fn remove_container(&self, id: &str) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.events.push(format!("rm-c {id}"));
        s.removed_once = true;
        if !s.undeletable {
            s.containers.remove(id);
        }
        Ok(())
    }
    async fn remove_network(&self, name: &str) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.events.push(format!("rm-n {name}"));
        s.removed_once = true;
        s.networks.remove(name);
        Ok(())
    }
    async fn remove_volume(&self, name: &str) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.volumes.remove(name);
        Ok(())
    }
}
fn bytes(p: &ProbePayload) -> Vec<u8> {
    serde_json::json!({"v": p.v, "probe_id": p.probe_id, "targets_sha256": p.targets_sha256, "timeout_ms": p.timeout_ms,
        "targets": p.targets.iter().map(|t| match t.port { Some(port) => serde_json::json!({"id": t.id, "kind": match t.kind { Kind::Tcp => "tcp", Kind::DnsTcp => "dns_tcp", Kind::DnsName => "dns_name" }, "host": t.host, "port": port}),
            None => serde_json::json!({"id": t.id, "kind": "dns_name", "host": t.host}) }).collect::<Vec<_>>()})
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn execute_creates_one_network_runs_the_helper_wipes_and_reports_ids_and_outcomes_only() {
    let f = Fake::new();
    let p = sample();
    let r = probe::execute(f.as_ref(), "agent-1", &bytes(&p)).await.unwrap();
    assert_eq!(r["v"], 1);
    assert_eq!(r["probe_id"], p.probe_id);
    assert_eq!(r["targets_sha256"], p.targets_sha256);
    assert_eq!(r["self_dns"], "ok");
    assert_eq!(r["results"], serde_json::json!([{"id": "t01", "outcome": "blocked"}, {"id": "t02", "outcome": "blocked"}, {"id": "t03", "outcome": "blocked"}]));
    assert_eq!(r["wiped"], serde_json::json!({"containers": 1, "networks": 1}));
    let text = r.to_string();
    for secret in ["10.20.30.40", "example.com", "agent-1"] {
        assert!(!text.contains(secret), "the result carries no hosts / IPs / agent ids: {secret}");
    }
    let s = f.0.lock().unwrap();
    assert_eq!(s.created_networks, vec!["pbr-probe-99999999"]);
    assert_eq!(s.specs[0].name, "pbr-probe-99999999-h");
    assert_eq!(s.specs[0].labels.get(LABEL_AGENT).map(String::as_str), Some("agent-1"));
    assert!(s.networks.is_empty() && s.containers.is_empty(), "nothing left behind");
    let env: BTreeMap<_, _> = s.specs[0].env.iter().cloned().collect();
    assert_eq!(env["PBM_T"], "1.5");
    assert_eq!(env["PBM_SELF"], "pbr-probe-99999999-h");
}
#[tokio::test]
async fn execute_wipes_even_when_the_helper_or_the_parse_fails() {
    for (name, helper, stdout, want) in [
        ("helper error", Some(Err(Code::DockerUnavailable)), None, Code::DockerUnavailable),
        ("helper timeout", Some(Err(Code::DeadlineExceeded)), None, Code::DeadlineExceeded),
        ("non-zero exit", Some(Ok((1, b"x".to_vec()))), None, Code::HelperFailed),
        ("bad output", None, Some("nonsense\n".to_string()), Code::HelperFailed),
    ] {
        let f = Fake::new();
        {
            let mut s = f.0.lock().unwrap();
            s.helper = helper;
            s.stdout = stdout;
        }
        let e = probe::execute(f.as_ref(), "a", &bytes(&sample())).await.unwrap_err();
        assert_eq!(e.0, want, "{name}");
        let s = f.0.lock().unwrap();
        assert!(s.networks.is_empty() && s.containers.is_empty(), "{name}: wiped");
        assert!(s.events.iter().any(|e| e.starts_with("rm-n")), "{name}: network removal attempted");
    }
}
#[tokio::test]
async fn execute_reports_wipe_incomplete_when_a_container_survives_and_that_wins_over_the_result() {
    let f = Fake::new();
    f.0.lock().unwrap().undeletable = true;
    let e = probe::execute(f.as_ref(), "a", &bytes(&sample())).await.unwrap_err();
    assert_eq!(e.0, Code::WipeIncomplete);
    // the verifying re-list failing is also incomplete (never a silent success)
    let f = Fake::new();
    f.0.lock().unwrap().list_fails_after_remove = true;
    assert_eq!(probe::execute(f.as_ref(), "a", &bytes(&sample())).await.unwrap_err().0, Code::WipeIncomplete);
}
#[tokio::test]
async fn execute_refuses_an_invalid_payload_before_touching_docker() {
    let f = Fake::new();
    let mut p = sample();
    p.targets[0].host = "1.2.3.4;id".into();
    let e = probe::execute(f.as_ref(), "a", &bytes(&p)).await.unwrap_err();
    assert_eq!(e.0, Code::PayloadInvalid);
    assert!(f.0.lock().unwrap().events.is_empty());
    assert_eq!(probe::execute(f.as_ref(), "a", b"not json").await.unwrap_err().0, Code::PayloadInvalid);
}
#[tokio::test]
async fn wipe_owned_only_touches_objects_with_the_label_and_value() {
    let f = Fake::new();
    {
        let mut s = f.0.lock().unwrap();
        let l = |v: &str| Labels::from([(LABEL_PROBE.to_string(), v.to_string())]);
        s.networks.insert("mine".into(), l("p1"));
        s.networks.insert("other-probe".into(), l("p2"));
        s.networks.insert("unrelated".into(), Labels::new());
        s.containers.insert("c-mine".into(), l("p1"));
        s.volumes.insert("v-mine".into(), l("p1"));
    }
    let r = wipe_owned(f.as_ref(), LABEL_PROBE, Some("p1")).await.unwrap();
    assert_eq!((r.containers, r.networks, r.volumes), (1, 1, 1));
    {
        let s = f.0.lock().unwrap();
        assert!(s.networks.contains_key("other-probe") && s.networks.contains_key("unrelated"));
    }
    let r = wipe_owned(f.as_ref(), LABEL_PROBE, None).await.unwrap();
    assert_eq!(r.networks, 1, "the startup sweep takes every probe-labelled object, whatever its value");
    assert!(f.0.lock().unwrap().networks.contains_key("unrelated"), "an unlabelled network is never touched");
}

// ---- runner init --------------------------------------------------------------------------------------------------------------------------
fn runtime() -> (crate::fork::poll::Runtime, tempfile::TempDir) {
    use crate::fork::transport::Transport;
    let v = vecs();
    let dir = tempfile::tempdir().unwrap();
    let key: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &v.task_key_b64).unwrap().try_into().unwrap();
    let pins: Vec<_> = v.pins.iter().map(|p| parse_pin(&p.kid, &p.pem).unwrap()).collect();
    let cfg = crate::fork::config::ChannelConfig { agent_id: v.agent_id.clone(), enroll_id: v.enroll_id.clone(), server_url: "https://dashboard.invalid".into(), credential: "fork.00000000-0000-4000-8000-000000000000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(), task_key: key, pins, pin_fingerprint: String::new(), insecure_lab: false, poll_seconds: 5, state_path: dir.path().join("state.json") };
    let _ = Transport::new; // the real constructor is exercised by from_config
    (crate::fork::poll::Runtime::from_config(cfg).unwrap(), dir)
}
#[tokio::test]
async fn init_runner_sweeps_leftovers_and_reports_exactly_the_runner_capabilities() {
    let (mut rt, _d) = runtime();
    let f = Fake::new();
    {
        let mut s = f.0.lock().unwrap();
        s.networks.insert("leftover".into(), Labels::from([(LABEL_PROBE.to_string(), "old".to_string())]));
        s.containers.insert("leftover-h".into(), Labels::from([(LABEL_PROBE.to_string(), "old".to_string())]));
    }
    rt.init_runner_with(f.clone()).await;
    assert_eq!(rt.capabilities, capabilities::runner_reported());
    assert!(rt.runner.is_some());
    assert!(rt.renv.is_none() && rt.ops.is_none() && rt.qenv.is_none() && !rt.restore_ok, "the restore path is never entered, so the master key is never loaded");
    let s = f.0.lock().unwrap();
    assert!(s.networks.is_empty() && s.containers.is_empty(), "startup sweep removed the leftovers");
}
#[tokio::test]
async fn init_runner_without_docker_or_image_reports_no_runner_capability() {
    for (ping, image) in [(false, true), (true, false)] {
        let (mut rt, _d) = runtime();
        let before = rt.capabilities.clone();
        let f = Fake::new();
        {
            let mut s = f.0.lock().unwrap();
            s.ping = ping;
            s.image = image;
        }
        rt.init_runner_with(f).await;
        assert_eq!(rt.capabilities, before);
        assert!(!rt.capabilities.iter().any(|c| c == capabilities::RUNNER));
        assert!(rt.runner.is_none());
    }
    // an incomplete startup sweep also keeps the role off
    let (mut rt, _d) = runtime();
    let f = Fake::new();
    {
        let mut s = f.0.lock().unwrap();
        s.undeletable = true;
        s.containers.insert("stuck".into(), Labels::from([(LABEL_PROBE.to_string(), "old".to_string())]));
    }
    rt.init_runner_with(f).await;
    assert!(rt.runner.is_none());
}
