//! The REAL channel code (transport + verify + state + executor) against an in-process mock dashboard.
use super::*;
use crate::fork::capabilities;
use crate::fork::poll::{Handled, Runtime, process_when_disabled};
use crate::fork::state::{self, State};
use crate::fork::transport::{CallError, Leased, Transport};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const AGENT_CRED: &str = "fork.11111111-1111-4111-8111-111111111111.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn leased(c: &VCase) -> Leased {
    let id = serde_json::from_str::<Value>(&c.envelope).ok().and_then(|v| v["task_id"].as_str().map(String::from)).unwrap_or_else(|| "00000000-0000-4000-8000-000000000000".into());
    Leased { task_id: id, envelope: c.envelope.clone(), signature: c.signature.clone(), kid: String::new(), payload_enc: c.payload_enc.clone(), lease_id: "99999999-9999-4999-8999-999999999999".into(), lease_until: "2030-01-01T00:00:00Z".into() }
}
fn lease_json(c: &VCase) -> Value {
    let l = leased(c);
    serde_json::json!({"task_id": l.task_id, "envelope": l.envelope, "signature": l.signature, "kid": "x", "payload_enc": l.payload_enc, "lease_id": l.lease_id, "lease_until": l.lease_until})
}

struct Rig {
    server: MockServer,
    rt: Runtime,
    dir: tempfile::TempDir,
    v: Vectors,
}
fn runtime(v: &Vectors, server_url: &str, state_path: PathBuf, insecure_lab: bool) -> Runtime {
    Runtime {
        agent_id: v.agent_id.clone(),
        enroll_id: v.enroll_id.clone(),
        pins: pins(v),
        bundle_pins: pins(v),
        bundle_credential: AGENT_CRED.to_string(),
        task_key: task_key(v),
        capabilities: capabilities::reported(false, false),
        state: state::load(&state_path, &v.enroll_id).unwrap(),
        state_path,
        transport: Transport::new(server_url, &v.agent_id, AGENT_CRED, insecure_lab).unwrap(),
        renv: None,
        ops: None,
    }
}
async fn rig() -> Rig {
    let v = vectors();
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let rt = runtime(&v, &server.uri(), dir.path().join("state.json"), true);
    Rig { server, rt, dir, v }
}
async fn mount_ok(server: &MockServer) {
    Mock::given(method("POST")).and(path_regex(r"^/api/fork/agent/[^/]+/tasks/[^/]+/(heartbeat|result)$")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))).mount(server).await;
}
async fn bodies(server: &MockServer, suffix: &str) -> Vec<Value> {
    server.received_requests().await.unwrap().iter().filter(|r| r.url.path().ends_with(suffix)).map(|r| serde_json::from_slice(&r.body).unwrap()).collect()
}

#[tokio::test]
async fn signed_noop_round_trip_lease_heartbeat_result() {
    let mut r = rig().await;
    let c = case(&r.v, "valid").clone();
    Mock::given(method("POST")).and(path(format!("/api/fork/agent/{}/lease", r.v.agent_id))).respond_with(ResponseTemplate::new(200).set_body_json(lease_json(&c))).mount(&r.server).await;
    mount_ok(&r.server).await;
    let wait = r.rt.poll_once(Duration::from_secs(5), r.v.now).await;
    assert_eq!(wait, Duration::from_millis(200));
    let reqs = r.server.received_requests().await.unwrap();
    // every call carries the bearer credential and nothing else is sent to the dashboard
    for q in &reqs {
        assert_eq!(q.headers.get("authorization").unwrap().to_str().unwrap(), format!("Bearer {AGENT_CRED}"));
    }
    let lease = &bodies(&r.server, "/lease").await[0];
    assert_eq!(lease["capabilities"], serde_json::json!(["channel.v1", "noop.v1", "plaintext-hash.v1", "channel-maint.v1"]));
    assert_eq!(bodies(&r.server, "/heartbeat").await.len(), 1);
    let res = bodies(&r.server, "/result").await;
    assert_eq!(res.len(), 1);
    assert_eq!(res[0]["status"], "succeeded");
    assert_eq!(res[0]["result"]["echo"], "hi");
    assert_eq!(res[0]["lease_id"], "99999999-9999-4999-8999-999999999999");
    // state persisted BEFORE the outcome was reported: seq 1 accepted, file is private
    let st = state::load(&r.dir.path().join("state.json"), &r.v.enroll_id).unwrap();
    assert_eq!(st.last_seq, 1);
    assert_eq!(st.accepted[0].outcome.as_ref().unwrap().status, "succeeded");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(r.dir.path().join("state.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[tokio::test]
async fn every_refusal_fixture_is_rejected_reported_and_never_executed() {
    let v = vectors();
    for c in v.cases.iter().filter(|c| c.expect != "ok" && c.expect != "duplicate") {
        let server = MockServer::start().await;
        mount_ok(&server).await;
        let dir = tempfile::tempdir().unwrap();
        let mut rt = runtime(&v, &server.uri(), dir.path().join("state.json"), true);
        rt.state.last_seq = c.last_seq.unwrap_or(0);
        let h = rt.process(&leased(c), v.now).await;
        assert_eq!(h, Handled::Rejected(Box::leak(c.expect.clone().into_boxed_str())), "{}", c.name);
        let res = bodies(&server, "/result").await;
        assert_eq!(res.len(), 1, "{}", c.name);
        assert_eq!(res[0]["status"], "rejected", "{}", c.name);
        assert_eq!(res[0]["reason"], c.expect.as_str(), "{}", c.name);
        assert!(bodies(&server, "/heartbeat").await.is_empty(), "{}: nothing may start", c.name);
        assert!(!dir.path().join("state.json").exists(), "{}: a refused task leaves no replay state", c.name);
        assert_eq!(rt.state.accepted.len(), 0, "{}", c.name);
    }
}

#[tokio::test]
async fn replay_is_re_reported_but_never_re_executed_and_survives_a_restart() {
    let mut r = rig().await;
    mount_ok(&r.server).await;
    let c = case(&r.v, "valid").clone();
    assert_eq!(r.rt.process(&leased(&c), r.v.now).await, Handled::Executed("succeeded".into()));
    assert_eq!(r.rt.process(&leased(&c), r.v.now).await, Handled::Duplicate);
    assert_eq!(bodies(&r.server, "/heartbeat").await.len(), 1, "executed once");
    let res = bodies(&r.server, "/result").await;
    assert_eq!(res.len(), 2);
    assert_eq!(res[1]["status"], "succeeded", "the stored outcome is re-reported");
    // restart: state comes from disk; the same task is still a duplicate, an older seq is a rollback
    let mut rt2 = runtime(&r.v, &r.server.uri(), r.dir.path().join("state.json"), true);
    assert_eq!(rt2.process(&leased(&c), r.v.now).await, Handled::Duplicate);
    let older = case(&r.v, "valid_within_skew").clone(); // seq 2, unknown id: accepted (2 > 1)…
    assert_eq!(rt2.process(&leased(&older), r.v.now).await, Handled::Executed("succeeded".into()));
    let rolled = case(&r.v, "seq_below_last").clone(); // seq 3 now < last? last=2 → accepted would be fine, so force:
    rt2.state.last_seq = 50;
    assert_eq!(rt2.process(&leased(&rolled), r.v.now).await, Handled::Rejected("seq_rollback"));
}

#[tokio::test]
async fn a_new_enrolment_generation_resets_state_but_a_corrupt_file_fails_closed() {
    let v = vectors();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("s.json");
    let mut s = State::fresh(&v.enroll_id);
    s.accept("t", 5);
    state::save(&p, &s).unwrap();
    assert_eq!(state::load(&p, &v.enroll_id).unwrap().last_seq, 5);
    assert_eq!(state::load(&p, "33333333-3333-4333-8333-333333333333").unwrap().last_seq, 0); // re-enrolled
    std::fs::write(&p, "{not json").unwrap();
    assert!(state::load(&p, &v.enroll_id).is_err());
    std::fs::write(&p, "").unwrap();
    assert!(state::load(&p, &v.enroll_id).is_err());
}

#[tokio::test]
async fn if_the_replay_state_cannot_be_persisted_nothing_runs() {
    let mut r = rig().await;
    mount_ok(&r.server).await;
    r.rt.state_path = r.dir.path().join("no-such-dir").join("state.json");
    let c = case(&r.v, "valid").clone();
    assert_eq!(r.rt.process(&leased(&c), r.v.now).await, Handled::Rejected("state_unavailable"));
    assert!(bodies(&r.server, "/heartbeat").await.is_empty());
    assert_eq!(bodies(&r.server, "/result").await[0]["reason"], "state_unavailable");
}

#[tokio::test]
async fn disabled_channel_refuses_everything_and_a_disabled_agent_makes_no_requests() {
    let r = rig().await;
    let c = case(&r.v, "valid").clone();
    assert_eq!(process_when_disabled(&leased(&c)), Handled::Rejected("channel_disabled"));
    // a disabled agent never builds a runtime, so the mock dashboard sees no traffic at all
    use crate::fork::config::{Startup, load};
    assert!(matches!(load(&|_| None), Ok(Startup::Disabled(_))));
    assert!(r.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn http_is_refused_by_the_client_and_redirects_are_never_followed() {
    let v = vectors();
    let server = MockServer::start().await;
    mount_ok(&server).await;
    // lab exemption OFF: plain http must not even be attempted
    let t = Transport::new(&server.uri(), &v.agent_id, AGENT_CRED, false).unwrap();
    assert_eq!(t.lease(&[]).await.err(), Some(CallError::Network));
    assert!(server.received_requests().await.unwrap().is_empty());
    // redirect (e.g. to an attacker or a downgrade) is an error, not followed
    let evil = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(307).insert_header("location", format!("{}/steal", evil.uri()))).mount(&server).await;
    let t = Transport::new(&server.uri(), &v.agent_id, AGENT_CRED, true).unwrap();
    assert_eq!(t.lease(&[]).await.err(), Some(CallError::Http(307)));
    assert!(evil.received_requests().await.unwrap().is_empty(), "the bearer never reaches the redirect target");
}

#[tokio::test]
async fn dashboard_answers_are_handled_without_panics_or_credential_loss() {
    let mut r = rig().await;
    let p = Duration::from_secs(5);
    let lease = format!("/api/fork/agent/{}/lease", r.v.agent_id);
    for (status, expect) in [(204u16, Duration::from_secs(5)), (401, Duration::from_secs(60)), (403, Duration::from_secs(60)), (500, Duration::from_secs(15))] {
        r.server.reset().await;
        Mock::given(method("POST")).and(path(lease.clone())).respond_with(ResponseTemplate::new(status)).mount(&r.server).await;
        assert_eq!(r.rt.poll_once(p, r.v.now).await, expect, "{status}");
    }
    r.server.reset().await;
    Mock::given(method("POST")).and(path(lease.clone())).respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7")).mount(&r.server).await;
    assert_eq!(r.rt.poll_once(p, r.v.now).await, Duration::from_secs(7));
    r.server.reset().await;
    Mock::given(method("POST")).and(path(lease)).respond_with(ResponseTemplate::new(200).set_body_string("not json")).mount(&r.server).await;
    assert_eq!(r.rt.poll_once(p, r.v.now).await, Duration::from_secs(15));
    assert!(r.rt.state.accepted.is_empty());
}

#[tokio::test]
async fn plaintext_hash_matches_sha256_and_is_reported_with_size() {
    use crate::fork::hash::plaintext_hash;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.tar.gz");
    std::fs::write(&f, b"hello world").unwrap();
    let (h, n) = plaintext_hash(&f).await.unwrap();
    assert_eq!(h, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    assert_eq!(n, 11);
    // a multi-chunk file (> 1 MiB read buffer) hashes identically to a one-shot digest
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&f, &big).unwrap();
    assert_eq!(plaintext_hash(&f).await.unwrap(), (crate::fork::crypto::sha256_hex(&big), 3_000_000));
    assert!(plaintext_hash(&dir.path().join("missing")).await.is_err());
    // the report body
    let v = vectors();
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(path(format!("/api/fork/agent/{}/hash-report", v.agent_id))).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))).mount(&server).await;
    let t = Transport::new(&server.uri(), &v.agent_id, AGENT_CRED, true).unwrap();
    t.hash_report("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", &h, n).await.unwrap();
    let b = bodies(&server, "/hash-report").await;
    assert_eq!(b[0], serde_json::json!({"backup_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sha256": h, "size_bytes": 3_000_000 - 3_000_000 + 11}));
}

/// D45 end to end on REAL agent artifacts: the plaintext the agent hashes BEFORE encryption is exactly what the dashboard's verify job recovers by
/// decrypting the stored object (W02b fixture = a real stock-agent archive, TEST-ONLY lab key).
const FIXTURE_MASTER_B64: &str = "7V2197O7oHu676baTe285S2RzxNDPaHGvVvNV9lrsec=";

#[tokio::test]
async fn plaintext_hash_before_encryption_equals_what_decrypting_a_real_agent_archive_yields() {
    use crate::fork::hash::plaintext_hash;
    use crate::utils::file::decrypt_file_stream_gcm;
    let dir = tempfile::tempdir().unwrap();
    // (1) a real archive written by the stock agent (lab fixture): decrypt → hash == the committed plaintext hash/size
    let out = dir.path().join("real.tar.gz");
    decrypt_file_stream_gcm(PathBuf::from("src/fork/tests/lab-postgres.tar.gz.enc"), out.clone(), FIXTURE_MASTER_B64.into()).await.unwrap();
    assert_eq!(plaintext_hash(&out).await.unwrap(), ("48fdb387abd55cc600618de19886f4d78e75605d392e61d7497f4969619456aa".to_string(), 20668));
    // (2) the agent's own encrypt path: hash the plaintext first, encrypt through the real upload stream, decrypt → same hash
    let plain = dir.path().join("a.tar.gz");
    let data: Vec<u8> = (0..2_500_000u32).map(|i| (i.wrapping_mul(31) % 253) as u8).collect();
    std::fs::write(&plain, &data).unwrap();
    let before = plaintext_hash(&plain).await.unwrap();
    use futures::StreamExt;
    let mut stream = crate::utils::stream::build_stream(&plain, true, &FIXTURE_MASTER_B64.to_string()).await.unwrap().stream;
    let mut enc = Vec::new();
    while let Some(chunk) = stream.next().await {
        enc.extend_from_slice(&chunk.unwrap());
    }
    assert_ne!(enc, data);
    let enc_path = dir.path().join("a.tar.gz.enc");
    std::fs::write(&enc_path, &enc).unwrap();
    let dec = dir.path().join("a.dec");
    decrypt_file_stream_gcm(enc_path, dec.clone(), FIXTURE_MASTER_B64.into()).await.unwrap();
    assert_eq!(plaintext_hash(&dec).await.unwrap(), before);
    assert_eq!(before.1, 2_500_000);
}

// ---- W15b: signed channel maintenance (pin_add / pin_revoke / rotate_credential) ----

fn plain(c: &VCase) -> Value {
    serde_json::from_str(c.payload_plain.as_deref().unwrap()).unwrap()
}
fn channel_config(v: &Vectors, server_url: &str, state_path: PathBuf) -> crate::fork::config::ChannelConfig {
    crate::fork::config::ChannelConfig {
        agent_id: v.agent_id.clone(),
        enroll_id: v.enroll_id.clone(),
        server_url: server_url.to_string(),
        credential: AGENT_CRED.to_string(),
        task_key: task_key(v),
        pins: pins(v),
        pin_fingerprint: String::new(),
        insecure_lab: true,
        poll_seconds: 5,
        state_path,
    }
}
fn auth_headers(reqs: &[wiremock::Request], suffix: &str) -> Vec<String> {
    reqs.iter().filter(|q| q.url.path().ends_with(suffix)).map(|q| q.headers.get("authorization").unwrap().to_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn pin_add_round_trip_then_a_task_signed_by_the_new_key_is_accepted_and_persisted() {
    let mut r = rig().await;
    mount_ok(&r.server).await;
    let second = case(&r.v, "signed_by_second_key").clone();
    // before the pin: refused
    assert_eq!(r.rt.process(&leased(&second), r.v.now).await, Handled::Rejected("unknown_kid"));
    let add = case(&r.v, "maint_pin_add").clone();
    assert_eq!(r.rt.process(&leased(&add), r.v.now).await, Handled::Executed("succeeded".into()));
    let res = bodies(&r.server, "/result").await;
    let added = plain(&add)["kid"].as_str().unwrap().to_string();
    assert!(res[1]["result"]["pinned"].as_array().unwrap().iter().any(|k| k == added.as_str()), "{res:?}");
    assert!(!res[1].to_string().contains("BEGIN"), "no key material in a result");
    assert_eq!(r.rt.process(&leased(&second), r.v.now).await, Handled::Executed("succeeded".into()));
    // a restart (fresh runtime from the same config + state file) still trusts the added key
    let rt2 = Runtime::from_config(channel_config(&r.v, &r.server.uri(), r.dir.path().join("state.json"))).unwrap();
    assert_eq!(rt2.pins.len(), 2);
}

#[tokio::test]
async fn pin_revoke_makes_the_revoked_key_unknown_again() {
    let mut r = rig().await;
    mount_ok(&r.server).await;
    let add = case(&r.v, "maint_pin_add").clone();
    let revoke = case(&r.v, "maint_pin_revoke").clone();
    let second = case(&r.v, "signed_by_second_key").clone();
    assert_eq!(r.rt.process(&leased(&add), r.v.now).await, Handled::Executed("succeeded".into()));
    assert_eq!(r.rt.process(&leased(&revoke), r.v.now).await, Handled::Executed("succeeded".into()));
    assert_eq!(r.rt.process(&leased(&second), r.v.now).await, Handled::Rejected("unknown_kid"));
    assert_eq!(r.rt.pins.len(), 1);
}

#[tokio::test]
async fn rotate_credential_switches_every_later_request_and_every_clone_to_the_new_bearer_and_survives_a_restart() {
    let mut r = rig().await;
    mount_ok(&r.server).await;
    Mock::given(method("POST")).and(path(format!("/api/fork/agent/{}/hash-report", r.v.agent_id))).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))).mount(&r.server).await;
    let active_clone = r.rt.transport.clone(); // what the D45 hook holds
    let rotate = case(&r.v, "maint_rotate").clone();
    let new = plain(&rotate)["credential"].as_str().unwrap().to_string();
    assert_eq!(r.rt.process(&leased(&rotate), r.v.now).await, Handled::Executed("succeeded".into()));
    let res = bodies(&r.server, "/result").await;
    assert_eq!(res[0]["result"], serde_json::json!({"rotated": true}));
    assert!(!res[0].to_string().contains(&new[new.len() - 43..]), "the credential is never reported back");
    let reqs = r.server.received_requests().await.unwrap();
    assert_eq!(auth_headers(&reqs, "/heartbeat"), vec![format!("Bearer {AGENT_CRED}")], "accepted under the old bearer");
    assert_eq!(auth_headers(&reqs, "/result"), vec![format!("Bearer {new}")], "the result already proves the new one");
    // every later request, including the clone the D45 hook uses
    active_clone.hash_report("b", &"0".repeat(64), 1).await.unwrap();
    let _ = r.rt.transport.lease(&[]).await;
    let reqs = r.server.received_requests().await.unwrap();
    assert_eq!(auth_headers(&reqs, "/hash-report"), vec![format!("Bearer {new}")]);
    assert_eq!(auth_headers(&reqs, "/lease"), vec![format!("Bearer {new}")]);
    // persisted, and a restart uses it
    let text = std::fs::read_to_string(r.dir.path().join("state.json")).unwrap();
    assert!(text.contains(&new));
    let rt2 = Runtime::from_config(channel_config(&r.v, &r.server.uri(), r.dir.path().join("state.json"))).unwrap();
    let _ = rt2.transport.lease(&[]).await;
    let reqs = r.server.received_requests().await.unwrap();
    assert_eq!(auth_headers(&reqs, "/lease").last().unwrap(), &format!("Bearer {new}"));
    // the state file is private
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(r.dir.path().join("state.json")).unwrap().permissions().mode() & 0o077, 0);
    }
}

#[tokio::test]
async fn rotate_with_an_unwritable_state_applies_nothing_and_keeps_the_old_bearer() {
    let mut r = rig().await;
    mount_ok(&r.server).await;
    r.rt.state_path = r.dir.path().join("no-such-dir").join("state.json");
    let rotate = case(&r.v, "maint_rotate").clone();
    let payload = plain(&rotate).to_string();
    let out = r.rt.apply_maint("task-1", &r.v.pins[0].kid, "rotate_credential", payload.as_bytes());
    assert_eq!((out.status.as_str(), out.reason.as_deref()), ("failed", Some("state_unavailable")));
    assert!(r.rt.state.credential.is_none());
    let _ = r.rt.transport.lease(&[]).await;
    let reqs = r.server.received_requests().await.unwrap();
    assert_eq!(auth_headers(&reqs, "/lease"), vec![format!("Bearer {AGENT_CRED}")]);
}

#[tokio::test]
async fn a_rule_violation_reports_failed_payload_invalid_and_changes_nothing() {
    let mut r = rig().await;
    mount_ok(&r.server).await;
    // revoking the only pin
    let out = r.rt.apply_maint("task-2", "someone-else", "pin_revoke", serde_json::json!({"kid": r.v.pins[0].kid}).to_string().as_bytes());
    assert_eq!((out.status.as_str(), out.reason.as_deref()), ("failed", Some("payload_invalid")));
    assert_eq!(r.rt.pins.len(), 1);
    assert!(r.rt.state.revoked_kids.is_empty());
}
