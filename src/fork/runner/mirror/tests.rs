//! W22a-f1 mirror engine tests. No docker, no network, no clock dependence: the daemon is the shared `Fake`, the Compose CLI is a recording shell script, the smoke
//! helper is a fake. Oracles: the dashboard's signed role-gating vectors + payload / header corpus (`tests/restore_vectors.json`, byte-identical to the dashboard fixture)
//! and the 72 + 10 `applyMirrorSpec` vectors (`corpus/compose-mirror-vectors.json`).
use super::apply_spec::*;
use super::finalize::{canonical_json, decorate};
use super::lifecycle::judge_smoke;
use super::payload::Limits;
use super::smoke::{self, Labels, SMOKE_SCRIPT, Smoke};
use super::*;
use crate::fork::capabilities;
use crate::fork::compose::tests::{NullSink, compose_env};
use crate::fork::crypto::{parse_pin, sha256_hex};
use crate::fork::restore::docker_ops::{CState, ContainerFacts, LABEL_AGENT, LABEL_RESTORE, owner_labels};
use crate::fork::restore::tests::{Fake, NOW, RID, Rig, merge, rig, task};
use crate::fork::restore::{HostRole, Purpose};
use crate::fork::state::State;
use crate::fork::verify::{Ctx as VCtx, Decision, evaluate};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, OnceLock};

const VECTORS: &str = include_str!("../../tests/restore_vectors.json");
const MIRROR_VECTORS: &[u8] = include_bytes!("../corpus/compose-mirror-vectors.json");
const SOURCE: &[u8] = include_bytes!("../corpus/SOURCE.json");
const TYPES: [&str; 9] = ["mirror_probe", "mirror_stage", "mirror_apply", "mirror_render", "mirror_finalize", "mirror_db", "mirror_up", "mirror_check", "mirror_wipe"];
const CANARY: &str = "W20_CANARY_7f3a9c51d2e84b6a_pgpw";
/// the lab compose project used by the apply vectors; tests move it under a real temp root
const VEC_WS: &str = "/srv/mirrors/pbm-lab";
const PROJECT: &str = "pbm-lab";
const PINNED_SMOKE_SHA256: &str = "0e794c3b063e5b748436c7d6561ef928a9ac23a5477ed19a17f73e258ca3d1b9";

// ---- vector plumbing -------------------------------------------------------------------------------------------------------------------
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
    #[serde(rename = "type")]
    ty: String,
    name: String,
    payload: Value,
    agent: String,
}
#[derive(Deserialize)]
struct HCase {
    name: String,
    header: Value,
    valid: bool,
}
#[derive(Deserialize)]
struct MV {
    root: String,
    capabilities: Vec<String>,
    cases: Vec<Case>,
    no_mirror_cap_capabilities: Vec<String>,
    no_mirror_cap_cases: Vec<Case>,
    payload_cases: Vec<PCase>,
    header_cases: Vec<HCase>,
    agent_codes: Vec<String>,
}
#[derive(Deserialize)]
struct Vecs {
    now: i64,
    agent_id: String,
    enroll_id: String,
    pins: Vec<VPin>,
    task_key_b64: String,
    codes: Vec<String>,
    mirror: MV,
}
fn vecs() -> Vecs {
    serde_json::from_str(VECTORS).expect("restore_vectors.json")
}
fn decide(v: &Vecs, caps: &[String], c: &Case) -> Decision {
    let pins: Vec<_> = v.pins.iter().map(|p| parse_pin(&p.kid, &p.pem).unwrap()).collect();
    let key: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &v.task_key_b64).unwrap().try_into().unwrap();
    let state = State::fresh(&v.enroll_id);
    let ctx = VCtx { agent_id: &v.agent_id, enroll_id: &v.enroll_id, pins: &pins, task_key: &key, capabilities: caps, state: &state, now: v.now };
    evaluate(&ctx, &c.envelope, &c.signature, c.payload_enc.as_deref())
}
fn expect(v: &Vecs, caps: &[String], c: &Case) {
    match (c.expect.as_str(), decide(v, caps, c)) {
        ("ok", Decision::Accept(_)) => {}
        (code, Decision::Reject(r)) => assert_eq!(r.code(), code, "{}", c.name),
        (e, g) => panic!("{}: expected {e}, got {g:?}", c.name),
    }
}

// ---- role gating, capability sets, codes ---------------------------------------------------------------------------------------------------
#[test]
fn mirror_role_matrix_with_signed_dashboard_vectors() {
    let v = vecs();
    assert_eq!(v.mirror.capabilities, capabilities::runner_reported(true), "the dashboard fixture and the agent agree on the mirror runner capability set");
    assert_eq!(v.mirror.no_mirror_cap_capabilities, capabilities::runner_reported(false));
    assert!(v.mirror.cases.len() >= 15 && v.mirror.no_mirror_cap_cases.len() >= 2);
    for c in &v.mirror.cases {
        expect(&v, &v.mirror.capabilities, c);
    }
    for c in &v.mirror.no_mirror_cap_cases {
        expect(&v, &v.mirror.no_mirror_cap_capabilities, c); // a probe-only runner refuses mirror tasks (capability_missing) but still probes
    }
}

#[test]
fn capability_sets_dispatch_classes_and_codes() {
    let v = vecs();
    assert_eq!(capabilities::runner_reported(true), ["channel.v1", "noop.v1", "channel-maint.v1", "runner.v1", "mirror.v1"]);
    for t in TYPES {
        assert_eq!(capabilities::task_requires(t), Some(&[capabilities::RUNNER, capabilities::MIRROR][..]), "{t}");
        assert!(capabilities::is_targeted(t) && capabilities::is_runner_only(t) && capabilities::is_mirror(t) && !capabilities::is_common(t), "{t}");
    }
    assert!(!capabilities::is_mirror("runner_probe") && !capabilities::is_mirror("restore_stage") && !capabilities::is_mirror("mirror_unknown"));
    // the agent codes are the dashboard's `MIRROR_AGENT_CODES`, appended after the 47 W17/W-TR codes, same order
    let got: Vec<&str> = Code::RESTORE[47..].iter().map(|c| c.as_str()).collect();
    assert_eq!(got, v.mirror.agent_codes);
    assert_eq!(Code::RESTORE.iter().map(|c| c.as_str().to_string()).collect::<Vec<_>>(), v.codes);
    assert_eq!(Code::WipeIncomplete.as_str(), "wipe_incomplete");
    assert!(!v.codes.iter().any(|c| c == "wipe_incomplete") || v.codes.iter().filter(|c| *c == "wipe_incomplete").count() == 1);
}

/// M19 guard: every `mirror_*` type is targeted, so the generic targeted branch (`run_restore`) would swallow it; the mirror branch must come first.
#[test]
fn the_mirror_branch_is_dispatched_before_the_generic_targeted_branch() {
    let src = include_str!("../../poll.rs");
    let mirror = src.find("capabilities::is_mirror(ty)").expect("mirror dispatch");
    let generic = src.find("} else if capabilities::is_targeted(ty) {").expect("generic targeted dispatch");
    let probe = src.find("ty == \"runner_probe\"").expect("runner_probe dispatch");
    assert!(probe < generic && mirror < generic, "runner_probe and mirror dispatch precede the generic targeted branch");
}

#[test]
fn deadlines_per_type() {
    assert_eq!(deadline_of("mirror_probe"), DEADLINE_PROBE);
    assert_eq!(deadline_of("mirror_wipe"), DEADLINE_WIPE);
    assert_eq!(deadline_of("mirror_stage"), DEADLINE_STAGE);
    assert_eq!(deadline_of("mirror_apply"), DEADLINE_STAGE);
    for t in ["mirror_render", "mirror_finalize", "mirror_db", "mirror_up", "mirror_check"] {
        assert_eq!(deadline_of(t), DEADLINE_STEP, "{t}");
    }
}

// ---- header + payload corpus -----------------------------------------------------------------------------------------------------------------
fn mirror_rig() -> Rig {
    let mut r = rig(HostRole::Runner, &["127.0.0.1"]);
    r.env.compose = Some(compose_env());
    r
}
#[test]
fn header_cases_agree_with_the_dashboard_schema() {
    let v = vecs();
    let r = mirror_rig();
    assert!(v.mirror.header_cases.len() >= 10);
    for c in &v.mirror.header_cases {
        let text = serde_json::to_string(&c.header).unwrap().replace(&v.mirror.root, &r.root.display().to_string());
        let ok = serde_json::from_str::<Header>(&text).ok().is_some_and(|h| h.check(&r.env).is_ok());
        assert_eq!(ok, c.valid, "{}", c.name);
    }
}
#[test]
fn a_mirror_header_never_passes_on_a_restore_env_and_a_restore_header_never_on_a_runner() {
    let v = vecs();
    let runner = mirror_rig();
    let test_env = rig(HostRole::Test, &[]);
    let ok = &v.mirror.header_cases[0].header;
    let text = serde_json::to_string(ok).unwrap().replace(&v.mirror.root, &test_env.root.display().to_string());
    let h: Header = serde_json::from_str(&text).unwrap();
    assert_eq!(h.purpose, Purpose::Mirror);
    assert_eq!(h.check(&test_env.env).unwrap_err().code, Code::ModeUnsupported, "restore-class executors refuse a mirror header");
    let mut restore = h.clone();
    restore.purpose = Purpose::Restore;
    restore.host_role = HostRole::Test;
    assert_eq!(restore.check(&runner.env).unwrap_err().code, Code::HostRoleMismatch);
    // M20: a mirror purpose with a non-runner host role is a payload error, never accepted
    let mut bad = h.clone();
    bad.host_role = HostRole::Production;
    assert_eq!(bad.check(&test_env.env).unwrap_err().code, Code::PayloadInvalid);
}

fn runtime(r: &Rig, fake: &std::sync::Arc<Fake>, sm: &std::sync::Arc<FakeSmoke>, bin: Option<PathBuf>) -> MirrorRuntime {
    let mut env = r.env.clone();
    let mut ce = compose_env();
    if let Some(b) = bin {
        ce.bin = b;
    }
    env.compose = Some(ce);
    MirrorRuntime { env, ops: fake.clone(), smoke: sm.clone() }
}

#[tokio::test]
async fn payload_vectors_get_the_expected_agent_decision() {
    let v = vecs();
    assert!(v.mirror.payload_cases.len() >= 50);
    for c in &v.mirror.payload_cases {
        let r = mirror_rig();
        let (fake, sm) = (std::sync::Arc::new(Fake::new()), std::sync::Arc::new(FakeSmoke::default()));
        let rt = runtime(&r, &fake, &sm, None);
        let text = serde_json::to_string(&c.payload).unwrap().replace(&v.mirror.root, &r.root.display().to_string());
        let got = execute(&rt, &r.pins, &NullSink, &task(&c.ty), text.as_bytes()).await;
        if c.agent == "ok" {
            if let Err(f) = got {
                assert!(!matches!(f.code, Code::PayloadInvalid | Code::PathNotAllowed | Code::ModeUnsupported | Code::HostRoleMismatch | Code::ApprovalMissing | Code::OverrideInvalid), "{}: {:?}", c.name, f);
            }
        } else {
            assert_eq!(got.unwrap_err().code.as_str(), c.agent, "{}", c.name);
        }
    }
}

// ---- the 72 + 10 applyMirrorSpec vectors + corpus provenance -------------------------------------------------------------------------------
fn corpus() -> Value {
    serde_json::from_slice(MIRROR_VECTORS).unwrap()
}
fn seed_of(hex_seed: &str) -> Vec<u8> {
    hex::decode(hex_seed).unwrap()
}
fn action_of(s: &str) -> EnvAction {
    serde_json::from_value(json!(s)).unwrap()
}

#[test]
fn corpus_is_the_dashboards() {
    let src: Value = serde_json::from_slice(SOURCE).unwrap();
    assert_eq!(src["files"]["compose-mirror-vectors.json"].as_str().unwrap(), sha256_hex(MIRROR_VECTORS));
    assert_eq!(src["dashboard_commit"].as_str().unwrap().len(), 40);
}

#[test]
fn env_value_vectors() {
    let c = corpus();
    let cases = c["env"].as_array().unwrap();
    assert_eq!(cases.len(), 72);
    for (i, e) in cases.iter().enumerate() {
        let action = action_of(e["action"].as_str().unwrap());
        let got = mirror_env_value(action, e["in"].as_str(), &seed_of(e["seed_hex"].as_str().unwrap()));
        match (&e["out"], got) {
            (Value::Null, Some(None)) => {}
            (Value::Null, None) if action == EnvAction::Drop => {} // TS `undefined` serialises as null in the vector file
            (Value::String(s), Some(Some(g))) => assert_eq!(&g, s, "env vector {i}: {} {:?}", e["action"], e["in"]),
            (want, got) => panic!("env vector {i}: want {want:?}, got {got:?}"),
        }
    }
}
#[test]
fn drop_removes_the_key_and_null_stays_null() {
    let seed = [7u8; 32];
    assert_eq!(mirror_env_value(EnvAction::Drop, Some("x"), &seed), None);
    assert_eq!(mirror_env_value(EnvAction::Drop, None, &seed), None);
    for a in [EnvAction::Keep, EnvAction::KeepExact, EnvAction::Rotate, EnvAction::Disable] {
        assert_eq!(mirror_env_value(a, None, &seed), Some(None), "{a:?}");
    }
}

fn spec_of(v: &Value) -> MirrorSpec {
    serde_json::from_value(v.clone()).expect("spec")
}
#[test]
fn apply_vectors() {
    let c = corpus();
    let cases = c["apply"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for a in cases {
        let name = a["name"].as_str().unwrap();
        let got = apply_mirror_spec(&a["full"], &spec_of(&a["spec"]), &seed_of(a["seed_hex"].as_str().unwrap()));
        match (a.get("out"), a.get("error").and_then(Value::as_str), got) {
            (Some(out), None, Ok(doc)) => assert!(deep_eq(&doc, out), "{name}: {doc}"),
            (None, Some(err), Err(e)) => assert_eq!(e.as_str(), err, "{name}"),
            (_, _, g) => panic!("{name}: unexpected {g:?}"),
        }
    }
}
fn deep_eq(a: &Value, b: &Value) -> bool {
    a == b
}
#[test]
fn a_seed_that_is_not_32_bytes_is_refused_and_the_hash_is_keyed_by_the_seed() {
    let c = corpus();
    let a = &c["apply"][0];
    assert_eq!(apply_mirror_spec(&a["full"], &spec_of(&a["spec"]), &[1u8; 31]).unwrap_err(), ApplyError::SeedInvalid);
    assert_ne!(mirror_hash(&[1u8; 32], "x"), mirror_hash(&[2u8; 32], "x"));
    assert_eq!(mirror_hash(&[1u8; 32], "x").len(), 32);
}

#[test]
fn canonical_json_matches_the_dashboard_canonical_json() {
    // sha256(canonicalJson(spec)) of the dashboard's own `mirror_finalize_valid` vector, computed by the TS function (node) when the vectors were written
    let v = vecs();
    let spec = v.mirror.payload_cases.iter().find(|c| c.name == "mirror_finalize_valid").unwrap().payload["spec"].clone();
    assert_eq!(sha256_hex(canonical_json(&spec).as_bytes()), "f0a7a55f0d70c2124dec189de26b4578e00e42a6e0702f8c6e7f64efa129b25f");
    assert_eq!(canonical_json(&json!({"b": [1, {"z": null, "a": "é\n"}], "a": true})), "{\"a\":true,\"b\":[1,{\"a\":\"é\\n\",\"z\":null}]}");
}

// ---- seed custody ----------------------------------------------------------------------------------------------------------------------
#[test]
fn seed_is_created_0600_in_0700_dirs_reloaded_and_never_printed() {
    let d = tempfile::tempdir().unwrap();
    let ws = d.path().join("pbm-x");
    std::fs::create_dir_all(ws.join(".portabase")).unwrap();
    let a = seed::create_or_load(&ws).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&seed::seed_path(&ws)), 0o600);
    assert_eq!(mode(&seed::meta_dir(&ws)), 0o700);
    let b = seed::create_or_load(&ws).unwrap();
    assert_eq!(a.bytes(), b.bytes(), "a retried finalize reproduces the very same rotated values");
    assert_eq!(a.bytes().len(), 32);
    assert_eq!(format!("{a:?}"), "Seed(<redacted>)");
    // two revisions never share a seed
    let ws2 = d.path().join("pbm-y");
    std::fs::create_dir_all(ws2.join(".portabase")).unwrap();
    assert_ne!(seed::create_or_load(&ws2).unwrap().bytes(), a.bytes());
}
#[test]
fn a_seed_with_group_or_other_bits_the_wrong_size_or_a_symlink_is_refused() {
    // M17: a 0644 seed file is never accepted
    let d = tempfile::tempdir().unwrap();
    let ws = d.path().join("pbm-x");
    std::fs::create_dir_all(ws.join(".portabase")).unwrap();
    seed::create_or_load(&ws).unwrap();
    let p = seed::seed_path(&ws);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(seed::create_or_load(&ws).unwrap_err(), Code::SeedInvalid);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&p, [1u8; 31]).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(seed::create_or_load(&ws).unwrap_err(), Code::SeedInvalid);
    std::fs::remove_file(&p).unwrap();
    let other = d.path().join("elsewhere");
    std::fs::write(&other, [1u8; 32]).unwrap();
    std::os::unix::fs::symlink(&other, &p).unwrap();
    assert_eq!(seed::create_or_load(&ws).unwrap_err(), Code::SeedInvalid, "a symlinked seed");
    // a symlinked mirror dir
    let ws2 = d.path().join("pbm-z");
    std::fs::create_dir_all(ws2.join(".portabase")).unwrap();
    std::os::unix::fs::symlink(d.path(), seed::meta_dir(&ws2)).unwrap();
    assert_eq!(seed::create_or_load(&ws2).unwrap_err(), Code::SeedInvalid);
}

// ---- smoke helper ----------------------------------------------------------------------------------------------------------------------
#[test]
fn smoke_script_is_pinned_takes_values_as_arguments_only_and_the_helper_is_hardened() {
    assert_eq!(sha256_hex(SMOKE_SCRIPT.as_bytes()), PINNED_SMOKE_SHA256);
    assert!(!SMOKE_SCRIPT.contains("eval") && !SMOKE_SCRIPT.contains("sh -c \"$"));
    let cmd = smoke::smoke_cmd("web", 8080, Some("/health"));
    assert_eq!(&cmd[..6], ["-k", "1", "20", "bash", "-c", SMOKE_SCRIPT]);
    assert_eq!(&cmd[6..], ["pbm-smoke", "web", "8080", "/health"]);
    assert_eq!(smoke::smoke_cmd("web", 80, None).last().unwrap(), "");
    let body = smoke::real::helper_body("img:1", "pbm-lab_pbm_access", &Labels::from([("k".into(), "v".into())]), &cmd);
    let hc = body.host_config.unwrap();
    assert_eq!(body.user.as_deref(), Some("65534:65534"));
    assert_eq!(hc.network_mode.as_deref(), Some("pbm-lab_pbm_access"));
    assert_eq!(hc.cap_drop, Some(vec!["ALL".to_string()]));
    assert_eq!(hc.security_opt, Some(vec!["no-new-privileges".to_string()]));
    assert_eq!((hc.readonly_rootfs, hc.memory, hc.pids_limit, hc.binds), (Some(true), Some(64 << 20), Some(64), None));
    assert_eq!(hc.log_config.unwrap().typ.as_deref(), Some("none"));
}
#[test]
fn smoke_judgement() {
    assert_eq!(judge_smoke(0, "OK\n", false), (true, None));
    assert_eq!(judge_smoke(0, "HTTP 200\nOK\n", true), (true, Some(200)));
    assert_eq!(judge_smoke(0, "HTTP 404\nOK\n", true), (true, Some(404)));
    // M15: a 5xx is an honest failure even though the connection worked
    assert_eq!(judge_smoke(0, "HTTP 500\nOK\n", true), (false, Some(500)));
    assert!(!judge_smoke(0, "HTTP 99\nOK\n", true).0);
    assert_eq!(judge_smoke(0, "OK\n", true), (false, None), "a path was asked for but no status line arrived");
    assert_eq!(judge_smoke(3, "", false), (false, None));
    assert_eq!(judge_smoke(0, "", false), (false, None));
}

// ---- the fakes -------------------------------------------------------------------------------------------------------------------------
#[derive(Default)]
struct FakeSmoke {
    result: Mutex<Option<Result<(i64, Vec<u8>), Code>>>,
    calls: Mutex<Vec<(String, String, Labels, Vec<String>)>>,
}
#[async_trait]
impl Smoke for FakeSmoke {
    async fn run(&self, name: &str, network: &str, labels: &Labels, args: &[String], _t: std::time::Duration) -> Result<(i64, Vec<u8>), Code> {
        self.calls.lock().unwrap().push((name.into(), network.into(), labels.clone(), args.to_vec()));
        self.result.lock().unwrap().clone().unwrap_or(Ok((0, b"OK\n".to_vec())))
    }
}

/// A recording stand-in for `docker-compose` that keeps the FULL stdin of every call (`stdin.<pid>`) and fails any call whose argv has a word `w` with a `fail_<w>` marker in `$HOME`.
fn mirror_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("w22af1-fakebin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("docker-compose");
        let script = "#!/bin/sh\n{ printf 'ARGS:'; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; printf '\\nENV:\\n'; env | sort; echo ---; } >> \"$HOME/log\"\ncat > \"$HOME/stdin.$$\"\nfor a in \"$@\"; do [ -f \"$HOME/fail_$a\" ] && exit 7; done\nexit 0\n";
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    })
    .clone()
}

const CLEAN_YML: &str = "services:\n  web:\n    image: nginx:1\n  db:\n    image: postgres:17\n";

struct MW {
    r: Rig,
    ws: PathBuf,
    fake: std::sync::Arc<Fake>,
    smoke: std::sync::Arc<FakeSmoke>,
    rt: MirrorRuntime,
}
impl MW {
    fn new() -> MW {
        let r = rig(HostRole::Runner, &[]);
        let ws = r.root.join(PROJECT);
        let (fake, smoke) = (std::sync::Arc::new(Fake::new()), std::sync::Arc::new(FakeSmoke::default()));
        let rt = runtime(&r, &fake, &smoke, Some(mirror_bin()));
        let h: Header = serde_json::from_value(Self::hdr_of(&r, &ws)).unwrap();
        let w = crate::fork::restore::workspace::Workspace::open_or_create(&ws, &crate::fork::compose::claim(&rt.env, &h), NOW).unwrap();
        std::fs::create_dir_all(w.stage()).unwrap();
        std::fs::write(w.stage().join("manifest.json"), &r.v.stage_world.json).unwrap();
        std::fs::write(w.stage().join("manifest.sig"), base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &r.v.stage_world.sig_b64).unwrap()).unwrap();
        std::fs::create_dir_all(ws.join("compose")).unwrap();
        std::fs::write(ws.join("compose/compose.yml"), CLEAN_YML).unwrap();
        MW { r, ws, fake, smoke, rt }
    }
    fn hdr_of(r: &Rig, ws: &Path) -> Value {
        json!({"v":1,"restore_id":RID,"plan_id":r.v.ids["plan_id"],"plan_hash":"a".repeat(64),"stack_id":r.v.ids["stack_id"],"rp_id":r.v.ids["rp_id"],"purpose":"mirror","mode":"new_stack",
            "host_role":"runner","approvals":[],"workspace":ws.display().to_string(),"project":PROJECT})
    }
    fn payload(&self, body: Value) -> Vec<u8> {
        merge(Self::hdr_of(&self.r, &self.ws), body)
    }
    fn home(&self) -> PathBuf {
        self.ws.join(".portabase/tmp/home")
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.home().join("log")).unwrap_or_default()
    }
    fn stdins(&self) -> Vec<String> {
        std::fs::read_dir(self.home()).map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("stdin.")).filter_map(|e| std::fs::read_to_string(e.path()).ok()).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
    }
    fn fail(&self, word: &str) {
        std::fs::create_dir_all(self.home()).unwrap();
        std::fs::write(self.home().join(format!("fail_{word}")), b"").unwrap();
    }
    fn out_json(&self) -> Value {
        serde_json::from_slice(&std::fs::read(out_json(&self.ws)).unwrap()).unwrap()
    }
    fn vec_case(&self, i: usize) -> (Value, Value) {
        let c = corpus();
        let text = serde_json::to_string(&c["apply"][i]).unwrap().replace(VEC_WS, &self.ws.display().to_string());
        let a: Value = serde_json::from_str(&text).unwrap();
        (a["full"].clone(), a["spec"].clone())
    }
    /// the `mirror_finalize` payload for the lab vector: the spec is bound to THIS runner's own view of the canned pass-2 render and hashed like the dashboard does
    fn finalize_payload(&self, full: &Value, mut spec: Value, limits: Value) -> Vec<u8> {
        let view = crate::fork::policy::view::policy_view(&serde_json::to_vec(full).unwrap()).unwrap();
        spec["source_view_sha256"] = json!(sha256_hex(&view));
        let sha = sha256_hex(canonical_json(&spec).as_bytes());
        self.payload(json!({"manifest_sha256": self.r.v.stage_world.sha256, "compose": {"dir": format!("{}/compose", self.ws.display()), "override_yml": null, "env": {}, "path_map": []}, "spec": spec, "spec_sha256": sha, "limits": limits}))
    }
    fn can_render(&self, doc: &Value, passes: usize) {
        let mut s = self.fake.0.lock().unwrap();
        for _ in 0..passes {
            s.render_out.push_back(Ok(serde_json::to_vec(doc).unwrap()));
        }
    }
    async fn finalize(&self, sink: &dyn RenderSink, limits: Value) -> R<Value> {
        let (full, spec) = self.vec_case(0);
        self.can_render(&full, 2);
        execute(&self.rt, &self.r.pins, sink, &task("mirror_finalize"), &self.finalize_payload(&full, spec, limits)).await
    }
}
const LIMITS: fn() -> Value = || json!({"mem_bytes": 1073741824u64, "pids": 512, "nano_cpus": 1_000_000_000u64});

#[derive(Default)]
struct Rec(Mutex<Vec<Value>>);
#[async_trait]
impl RenderSink for Rec {
    async fn put(&self, b: Value) -> Result<(), ()> {
        self.0.lock().unwrap().push(b);
        Ok(())
    }
}

// ---- finalize --------------------------------------------------------------------------------------------------------------------------
#[test]
fn limits_are_min_of_existing_and_cap_and_owner_labels_land_everywhere() {
    let lim = Limits { mem_bytes: 1 << 30, pids: 512, nano_cpus: 1_000_000_000 };
    let mut d = json!({"services": {
        "none": {"image": "a"},
        "lower": {"image": "a", "mem_limit": "268435456", "pids_limit": 100, "cpus": 0.5},
        "higher": {"image": "a", "mem_limit": 8589934592u64, "pids_limit": 9000, "cpus": 2},
        "unlimited": {"image": "a", "mem_limit": 0, "pids_limit": -1},
        "unit": {"image": "a", "mem_limit": "512m"}},
        "networks": {"n": {"name": "pbm-lab_n", "internal": true}}, "volumes": {"v": {"name": "pbm-lab_v"}}});
    decorate(&mut d, &lim, "rid", "aid").unwrap();
    let s = &d["services"];
    assert_eq!((s["none"]["mem_limit"].as_u64(), s["none"]["pids_limit"].as_u64(), s["none"]["cpus"].as_f64()), (Some(1 << 30), Some(512), Some(1.0)));
    assert_eq!((s["lower"]["mem_limit"].as_u64(), s["lower"]["pids_limit"].as_u64(), s["lower"]["cpus"].as_f64()), (Some(268435456), Some(100), Some(0.5)));
    assert_eq!((s["higher"]["mem_limit"].as_u64(), s["higher"]["pids_limit"].as_u64(), s["higher"]["cpus"].as_f64()), (Some(1 << 30), Some(512), Some(1.0)), "an existing value above the cap is lowered to the cap");
    assert_eq!((s["unlimited"]["mem_limit"].as_u64(), s["unlimited"]["pids_limit"].as_u64()), (Some(1 << 30), Some(512)), "unlimited (0 / -1) gets the cap");
    assert_eq!(s["unit"]["mem_limit"].as_u64(), Some(512 << 20));
    for name in ["none", "lower", "higher", "unlimited", "unit"] {
        assert_eq!((s[name]["labels"][LABEL_RESTORE].as_str(), s[name]["labels"][LABEL_AGENT].as_str()), (Some("rid"), Some("aid")), "{name}");
    }
    assert_eq!(d["networks"]["n"]["labels"][LABEL_RESTORE], "rid");
    assert_eq!(d["volumes"]["v"]["labels"][LABEL_AGENT], "aid");
    // an unreadable existing limit is never guessed
    let mut bad = json!({"services": {"x": {"image": "a", "mem_limit": "lots"}}});
    assert_eq!(decorate(&mut bad, &lim, "r", "a").unwrap_err().code, Code::LimitsInvalid);
}

#[tokio::test]
async fn finalize_writes_out_json_uploads_only_the_final_view_and_no_value_leaves_the_runner() {
    let w = MW::new();
    let sink = Rec::default();
    let res = w.finalize(&sink, LIMITS()).await.unwrap();
    assert_eq!(res["v"], 1);
    assert_eq!(res["services"], 2);
    let sha = res["view_sha256"].as_str().unwrap();
    assert!(crate::fork::restore::is_hex64(sha));
    // out.json: 0600, owner labels + limits, the production secret is gone (rotated), the seed is not in it
    let mode = std::fs::metadata(out_json(&w.ws)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let out = w.out_json();
    let text = out.to_string();
    assert!(!text.contains(CANARY), "the production password is rotated");
    for s in ["db", "web"] {
        assert_eq!(out["services"][s]["labels"][LABEL_RESTORE], RID);
        assert_eq!(out["services"][s]["mem_limit"], 1073741824u64);
        assert_eq!(out["services"][s]["pids_limit"], 512);
    }
    assert_eq!(out["services"]["db"]["environment"]["POSTGRES_PASSWORD"].as_str().unwrap().len(), 32);
    assert_eq!(out["services"]["db"]["environment"]["POSTGRES_PASSWORD"], out["services"]["web"]["environment"]["POSTGRES_PASSWORD"], "db and app share the rotated value");
    let sd = seed::create_or_load(&w.ws).unwrap();
    assert!(!text.contains(&hex::encode(sd.bytes())));
    // what went to the dashboard: ONE view upload, value-free, bound to the revision id, naming no host path
    let bodies = sink.0.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["restore_id"], RID);
    assert_eq!(bodies[0]["view_sha256"], sha);
    let view = String::from_utf8(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bodies[0]["view_b64"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(sha256_hex(view.as_bytes()), sha);
    assert!(!view.contains(CANARY) && !view.contains(&hex::encode(sd.bytes())));
    assert!(!bodies[0].to_string().contains(CANARY) && !res.to_string().contains(CANARY));
    assert_eq!(w.fake.0.lock().unwrap().renders.len(), 3, "pass 1, pass 2, config of out.json");
    assert_eq!(std::fs::read_dir(w.ws.join(".portabase/secret")).map(|d| d.count()).unwrap_or(0), 0, "secret/ is emptied; the seed lives elsewhere and survives");
}

#[tokio::test]
async fn finalize_is_idempotent_a_retry_reproduces_the_same_rotated_values() {
    let w = MW::new();
    let a = w.finalize(&NullSink, LIMITS()).await.unwrap();
    let first = w.out_json();
    let b = w.finalize(&NullSink, LIMITS()).await.unwrap();
    assert_eq!(a["view_sha256"], b["view_sha256"]);
    assert_eq!(first, w.out_json());
}

#[tokio::test]
async fn finalize_refuses_a_changed_source_a_wrong_spec_hash_a_broken_seed_and_a_structure_mismatch() {
    // source_changed: the staged compose now renders differently from what the dashboard compiled
    let w = MW::new();
    let (full, spec) = w.vec_case(0);
    let p = w.finalize_payload(&full, spec.clone(), LIMITS());
    let mut other = full.clone();
    other["services"]["web"]["restart"] = json!("always");
    w.can_render(&other, 2);
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_finalize"), &p).await.unwrap_err().code, Code::SourceChanged);
    assert!(!out_json(&w.ws).exists(), "nothing is written when the source changed");
    // spec_sha256 does not bind the spec
    let w = MW::new();
    let (full, spec) = w.vec_case(0);
    let mut v: Value = serde_json::from_slice(&w.finalize_payload(&full, spec.clone(), LIMITS())).unwrap();
    v["spec_sha256"] = json!("d".repeat(64));
    w.can_render(&full, 2);
    let f = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_finalize"), &serde_json::to_vec(&v).unwrap()).await.unwrap_err();
    assert_eq!((f.code, f.detail.as_deref()), (Code::ApplyFailed, Some("spec_sha256")));
    // a world-readable seed
    let w = MW::new();
    seed::create_or_load(&w.ws).unwrap();
    std::fs::set_permissions(seed::seed_path(&w.ws), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(w.finalize(&NullSink, LIMITS()).await.unwrap_err().code, Code::SeedInvalid);
    // apply_failed: the full render's command no longer fits the skeleton (command length vector)
    let w = MW::new();
    let (mut full, spec) = w.vec_case(0);
    full["services"]["web"]["command"] = json!(["a"]);
    w.can_render(&full, 2);
    let p = w.finalize_payload(&full, spec, LIMITS());
    let f = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_finalize"), &p).await.unwrap_err();
    assert_eq!((f.code, f.detail.as_deref()), (Code::ApplyFailed, Some("structure_mismatch")));
    assert!(!out_json(&w.ws).exists());
}

#[tokio::test]
async fn finalize_refuses_a_spec_for_another_project_or_workspace() {
    let w = MW::new();
    let (full, mut spec) = w.vec_case(0);
    spec["project"] = json!("pbm-other");
    let p = w.finalize_payload(&full, spec, LIMITS());
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_finalize"), &p).await.unwrap_err().code, Code::PayloadInvalid);
}

// ---- up / db / check -------------------------------------------------------------------------------------------------------------------
async fn finalized() -> (MW, String) {
    let w = MW::new();
    let res = w.finalize(&NullSink, LIMITS()).await.unwrap();
    let sha = res["view_sha256"].as_str().unwrap().to_string();
    (w, sha)
}
fn dump_tar_gz(path: &Path) {
    let f = std::fs::File::create(path).unwrap();
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
    let mut b = tar::Builder::new(gz);
    let data = b"PGDMP-synthetic";
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o600);
    h.set_cksum();
    b.append_data(&mut h, "dump.pgdump", &data[..]).unwrap();
    b.into_inner().unwrap().finish().unwrap();
}
fn db_payload(w: &MW, sha: &str, resets: Value) -> Vec<u8> {
    w.payload(json!({"manifest_sha256": w.r.v.stage_world.sha256, "final_sha256": sha, "dbs": [{"index": w.r.v.stage_world.db_index, "service": "db"}], "resets": resets}))
}
fn pg_reset() -> Value {
    json!([{"service": "db", "engine": "postgresql", "user_key": "POSTGRES_USER", "password_key": "POSTGRES_PASSWORD"}])
}

#[test]
fn reset_sql_quotes_identifier_and_literal() {
    assert_eq!(db::reset_sql("app", "pw"), "ALTER ROLE \"app\" WITH PASSWORD 'pw';\n");
    assert_eq!(db::reset_sql("a\"b", "p'w"), "ALTER ROLE \"a\"\"b\" WITH PASSWORD 'p''w';\n");
}

#[tokio::test]
async fn db_starts_only_db_services_resets_over_stdin_then_restores_and_no_secret_reaches_argv_or_env() {
    let (w, sha) = finalized().await;
    dump_tar_gz(&crate::fork::restore::stage::staged_file(&crate::fork::restore::workspace::Workspace { root: w.ws.clone() }, w.r.v.stage_world.db_index));
    let res = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_db"), &db_payload(&w, &sha, pg_reset())).await.unwrap();
    assert_eq!(res["dbs"], json!([{"index": w.r.v.stage_world.db_index, "service": "db", "status": "restored"}]));
    assert_eq!(res["resets"], json!([{"service": "db", "status": "done"}]));
    let log = w.log();
    let args: Vec<&str> = log.lines().filter(|l| l.starts_with("ARGS:")).collect();
    assert_eq!(args.len(), 4, "{log}");
    assert!(args[0].contains("[up] [-d] [--no-deps] [--no-build] [--pull] [missing] [db]"), "only the database service is started");
    assert!(!args[0].contains("[web]"));
    assert!(args[1].contains("[exec] [-T] [db] [sh] [-c]") && args[1].contains("pg_isready"));
    assert!(args[2].contains("[exec] [-T] [db] [psql] [-v] [ON_ERROR_STOP=1] [-U] [app] [-d] [postgres]"));
    assert!(args[3].contains("pg_restore"));
    for a in &args {
        assert!(a.contains(&format!("[-f] [{}]", out_json(&w.ws).display())), "out.json is the only compose file: {a}");
    }
    // the statement travelled on stdin and carries the value the container is configured with; it is nowhere else
    let pw = w.out_json()["services"]["db"]["environment"]["POSTGRES_PASSWORD"].as_str().unwrap().to_string();
    assert!(w.stdins().iter().any(|s| s == &db::reset_sql("app", &pw)));
    assert!(!log.contains(&pw) && !log.contains(CANARY), "no password in argv or in the process environment");
    assert!(!w.ws.join(".portabase/secret/reset.sql").exists());
}

#[tokio::test]
async fn db_refuses_mysql_a_failed_reset_a_changed_final_view_and_a_missing_service() {
    let (w, sha) = finalized().await;
    let mysql = json!([{"service": "db", "engine": "mysql", "user_key": null, "password_key": "MYSQL_ROOT_PASSWORD"}]);
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_db"), &db_payload(&w, &sha, mysql)).await.unwrap_err().code, Code::CredentialResetUnsupported);
    assert!(w.log().is_empty(), "nothing is started when a reset cannot be done");
    w.fail("psql");
    let f = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_db"), &db_payload(&w, &sha, pg_reset())).await.unwrap_err();
    assert_eq!((f.code, f.detail.as_deref()), (Code::CredentialResetFailed, Some("exit_7")));
    // M18: a tampered out.json is refused before anything starts
    let (w, sha) = finalized().await;
    let mut o = w.out_json();
    o["services"]["web"]["ports"] = json!([{"mode": "ingress", "host_ip": "0.0.0.0", "target": 80, "published": "80", "protocol": "tcp"}]);
    std::fs::write(out_json(&w.ws), serde_json::to_vec(&o).unwrap()).unwrap();
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_db"), &db_payload(&w, &sha, pg_reset())).await.unwrap_err().code, Code::FinalViewMismatch);
    assert!(w.log().is_empty());
    let (w, sha) = finalized().await;
    let ghost = json!([{"service": "ghost", "engine": "postgresql", "user_key": null, "password_key": "POSTGRES_PASSWORD"}]);
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_db"), &db_payload(&w, &sha, ghost)).await.unwrap_err().code, Code::ManifestMismatch);
}

fn mirror_container(id: &str, service: &str, running: bool) -> ContainerFacts {
    let mut labels = owner_labels(RID, "11111111-1111-4111-8111-111111111111");
    labels.insert("com.docker.compose.project".into(), PROJECT.into());
    labels.insert("com.docker.compose.service".into(), service.into());
    ContainerFacts { id: format!("{:0<64}", format!("c0ffee{id}")), names: vec![format!("{PROJECT}-{service}-1")], image: "postgres:17".into(), labels, mounts_docker_sock: false, running }
}
fn state(running: bool, health: Option<&str>) -> CState {
    CState { status: if running { "running" } else { "exited" }.into(), running, health: health.map(Into::into), restart_count: 0, stop_timeout: None }
}
fn up_payload(w: &MW, sha: &str, volumes: Value) -> Vec<u8> {
    w.payload(json!({"final_sha256": sha, "volumes": volumes}))
}

#[tokio::test]
async fn up_runs_the_closed_argument_set_reports_service_states_and_refuses_a_changed_file() {
    let (w, sha) = finalized().await;
    let names: Vec<String> = w.out_json()["volumes"].as_object().unwrap().values().filter_map(|v| v["name"].as_str().map(String::from)).collect();
    assert!(!names.is_empty());
    {
        let mut s = w.fake.0.lock().unwrap();
        s.containers.push(mirror_container("a", "db", true));
        s.containers.push(mirror_container("b", "web", false));
    }
    let res = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_up"), &up_payload(&w, &sha, json!(names))).await.unwrap();
    assert_eq!(res["services"], json!([{"service": "db", "state": "running"}, {"service": "web", "state": "exited"}]));
    let log = w.log();
    let line = log.lines().find(|l| l.starts_with("ARGS:")).unwrap();
    assert!(line.ends_with("[up] [-d] [--no-build] [--pull] [missing]"), "{line}");
    for banned in ["--remove-orphans", "[down]", "[-v]", "[build]", "[-y]"] {
        assert!(!line.contains(banned), "{banned}");
    }
    // a volume the final project does not know
    let f = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_up"), &up_payload(&w, &sha, json!(["pbm-lab_nope"]))).await.unwrap_err();
    assert_eq!(f.code, Code::VolumeNotInCompose);
    // a different file than the one approved
    let mut o = w.out_json();
    o["services"]["web"]["image"] = json!("evil:1");
    std::fs::write(out_json(&w.ws), serde_json::to_vec(&o).unwrap()).unwrap();
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_up"), &up_payload(&w, &sha, json!([]))).await.unwrap_err().code, Code::FinalViewMismatch);
    // a compose failure is reported with its exit code only
    let (w, sha) = finalized().await;
    w.fail("up");
    let f = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_up"), &up_payload(&w, &sha, json!([]))).await.unwrap_err();
    assert_eq!((f.code, f.detail.as_deref()), (Code::ComposeFailed, Some("exit_7")));
}

#[tokio::test]
async fn up_refuses_a_foreign_container_in_the_project_d29() {
    let (w, sha) = finalized().await;
    let mut foreign = mirror_container("c", "db", true);
    foreign.labels.insert(LABEL_RESTORE.into(), "99999999-9999-4999-8999-999999999999".into());
    w.fake.0.lock().unwrap().containers.push(foreign);
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_up"), &up_payload(&w, &sha, json!([]))).await.unwrap_err().code, Code::ContainerConflict);
    assert!(w.log().is_empty());
}

fn check_payload(w: &MW, sha: &str, path: Value) -> Vec<u8> {
    w.payload(json!({"final_sha256": sha, "access": {"service": "web", "target": 8080}, "http_path": path, "wait_s": 10}))
}

#[tokio::test]
async fn check_reports_states_health_and_the_smoke_from_the_access_network() {
    let (w, sha) = finalized().await;
    {
        let mut s = w.fake.0.lock().unwrap();
        s.containers.push(mirror_container("a", "db", true));
        s.containers.push(mirror_container("b", "web", true));
        s.states.insert(mirror_container("a", "db", true).id, state(true, Some("healthy")));
        s.states.insert(mirror_container("b", "web", true).id, state(true, None));
    }
    *w.smoke.result.lock().unwrap() = Some(Ok((0, b"HTTP 200\nOK\n".to_vec())));
    let res = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_check"), &check_payload(&w, &sha, json!("/"))).await.unwrap();
    assert_eq!(res["services"], json!([{"service": "db", "state": "running", "health": "healthy"}, {"service": "web", "state": "running", "health": "none"}]));
    assert_eq!(res["smoke"], json!({"status": "ok", "http_status": 200}));
    let calls = w.smoke.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "pbm-lab_pbm_access", "the helper joins ONLY the mirror's own access network");
    assert_eq!(calls[0].2.get(LABEL_RESTORE).map(String::as_str), Some(RID), "owner labels: a leaked helper is found by the wipe");
    assert_eq!(&calls[0].3[6..], ["pbm-smoke", "web", "8080", "/"]);
    // M15: a 500 is not a pass
    *w.smoke.result.lock().unwrap() = Some(Ok((0, b"HTTP 500\nOK\n".to_vec())));
    let res = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_check"), &check_payload(&w, &sha, json!("/"))).await.unwrap();
    assert_eq!(res["smoke"], json!({"status": "failed", "http_status": 500}));
    // a helper that could not be removed is an internal failure, not a pass or a quiet fail
    *w.smoke.result.lock().unwrap() = Some(Err(Code::SmokeFailedInternal));
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_check"), &check_payload(&w, &sha, Value::Null)).await.unwrap_err().code, Code::SmokeFailedInternal);
}

#[tokio::test]
async fn check_reports_unhealthy_and_exited_services_honestly_and_skips_the_smoke_when_the_access_service_is_down() {
    let (w, sha) = finalized().await;
    {
        let mut s = w.fake.0.lock().unwrap();
        s.containers.push(mirror_container("a", "db", true));
        s.containers.push(mirror_container("b", "web", false));
        s.states.insert(mirror_container("a", "db", true).id, state(true, Some("unhealthy")));
        s.states.insert(mirror_container("b", "web", false).id, state(false, None));
    }
    let res = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_check"), &check_payload(&w, &sha, Value::Null)).await.unwrap();
    assert_eq!(res["services"][0]["health"], "unhealthy");
    assert_eq!(res["services"][1]["state"], "exited");
    assert_eq!(res["smoke"], json!({"status": "failed", "http_status": null}));
    assert!(w.smoke.calls.lock().unwrap().is_empty(), "no helper is started against a service that is not running");
}

// ---- wipe ------------------------------------------------------------------------------------------------------------------------------
fn wipe_payload(w: &MW) -> Vec<u8> {
    w.payload(json!({}))
}
#[tokio::test]
async fn wipe_removes_exactly_this_revisions_objects_and_the_workspace_and_verifies() {
    let (w, _) = finalized().await;
    let agent = "11111111-1111-4111-8111-111111111111";
    let other = "99999999-9999-4999-8999-999999999999";
    {
        let mut s = w.fake.0.lock().unwrap();
        s.containers.push(mirror_container("a", "db", true));
        let mut foreign = mirror_container("f", "web", true);
        foreign.labels.insert(LABEL_RESTORE.into(), other.into());
        s.containers.push(foreign);
        s.volumes.insert("pbm-lab_pgdata".into(), owner_labels(RID, agent));
        s.volumes.insert("someone_elses".into(), owner_labels(other, agent));
        s.networks.insert("pbm-lab_default".into(), owner_labels(RID, agent));
        s.networks.insert("bridge".into(), Default::default());
    }
    let res = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_wipe"), &wipe_payload(&w)).await.unwrap();
    assert_eq!(res, json!({"v": 1, "containers": 1, "networks": 1, "volumes": 1, "workspace_removed": true, "remaining": 0}));
    assert!(!w.ws.exists(), "the workspace (and the seed with it) is gone");
    let s = w.fake.0.lock().unwrap();
    assert_eq!(s.containers.len(), 1, "the foreign container is untouched");
    assert!(s.volumes.contains_key("someone_elses") && s.networks.contains_key("bridge"));
    assert!(!s.volumes.contains_key("pbm-lab_pgdata") && !s.networks.contains_key("pbm-lab_default"));
}
#[tokio::test]
async fn wipe_is_idempotent_and_a_leftover_is_wipe_incomplete_never_a_silent_success() {
    let (w, _) = finalized().await;
    execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_wipe"), &wipe_payload(&w)).await.unwrap();
    // second run: nothing exists any more (the dashboard's independent probe reads `absent`)
    let again = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_wipe"), &wipe_payload(&w)).await.unwrap();
    assert_eq!(again["remaining"], 0);
    // a container that refuses to go away
    let (w, _) = finalized().await;
    {
        let mut s = w.fake.0.lock().unwrap();
        s.containers.push(mirror_container("a", "db", true));
        s.keep_containers = true;
    }
    let f = execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_wipe"), &wipe_payload(&w)).await.unwrap_err();
    assert_eq!(f.code, Code::WipeIncomplete);
    assert_eq!(f.result().unwrap()["remaining"].as_u64(), Some(1));
}
#[tokio::test]
async fn wipe_never_touches_a_workspace_that_is_not_this_revisions() {
    let w = MW::new();
    // another run's workspace under the same name
    let owner = w.ws.join(".portabase/owner.json");
    let mut o: Value = serde_json::from_slice(&std::fs::read(&owner).unwrap()).unwrap();
    o["restore_id"] = json!("99999999-9999-4999-8999-999999999999");
    std::fs::write(&owner, serde_json::to_vec(&o).unwrap()).unwrap();
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_wipe"), &wipe_payload(&w)).await.unwrap_err().code, Code::WorkspaceNotOwned);
    assert!(w.ws.exists());
    // a plain directory without owner.json
    std::fs::remove_file(&owner).unwrap();
    std::fs::write(w.ws.join("precious"), b"x").unwrap();
    assert_eq!(execute(&w.rt, &w.r.pins, &NullSink, &task("mirror_wipe"), &wipe_payload(&w)).await.unwrap_err().code, Code::WorkspaceNotOwned);
    assert!(w.ws.join("precious").exists());
}

// ---- detect ----------------------------------------------------------------------------------------------------------------------------
#[tokio::test]
async fn detect_fails_closed_with_one_reason_each() {
    let r = mirror_rig();
    let fake: std::sync::Arc<Fake> = std::sync::Arc::new(Fake::new());
    let smoke: std::sync::Arc<FakeSmoke> = std::sync::Arc::new(FakeSmoke::default());
    let state = r._state_dir.path().join("state.json");
    let root = r.root.display().to_string();
    let env = |pairs: Vec<(&'static str, String)>| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
    let go = |e: Box<dyn Fn(&str) -> Option<String> + Sync>, master: Option<String>| {
        let (fake, smoke, state) = (fake.clone(), smoke.clone(), state.clone());
        async move { detect(e.as_ref(), &state, "a", fake, smoke, master, "", "").await.map(|_| ()) }
    };
    assert_eq!(go(Box::new(env(vec![])), Some("k".to_string())).await.unwrap_err(), "FORK_MIRROR_ROOT is not set");
    assert!(go(Box::new(env(vec![("FORK_MIRROR_ROOT", "/etc".into())])), Some("k".to_string())).await.unwrap_err().contains("overlaps"));
    assert!(go(Box::new(env(vec![("FORK_MIRROR_ROOT", format!("{root}:/tmp"))])), Some("k".to_string())).await.is_err(), "exactly one root");
    assert!(go(Box::new(env(vec![("FORK_MIRROR_ROOT", root.clone())])), None).await.unwrap_err().contains("master key"));
    // own container id unknown (empty mountinfo / cgroup) ⇒ the compose gate answers, the capability is not reported
    assert!(go(Box::new(env(vec![("FORK_MIRROR_ROOT", root)])), Some("k".to_string())).await.unwrap_err().contains("container id"));
}

#[test]
fn the_mirror_engine_never_spawns_a_process_outside_the_one_spawner() {
    // the compose runner (`compose::run`) is the only process spawner of the fork agent; mirror code must not add one
    for (name, src) in [("finalize", include_str!("finalize.rs")), ("db", include_str!("db.rs")), ("lifecycle", include_str!("lifecycle.rs")), ("mod", include_str!("mod.rs")), ("seed", include_str!("seed.rs")), ("apply_spec", include_str!("apply_spec.rs"))] {
        for banned in ["std::process", "tokio::process", "Command::new"] {
            assert!(!src.contains(banned), "{name}: {banned}");
        }
    }
}
