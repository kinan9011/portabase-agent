//! W17-i engine tests: cross-language vectors signed by the dashboard code, a fake Docker (ownership / idempotency / cleanup rules), the artifact pipeline against
//! real stock-agent fixtures served by wiremock, hostile tars, the startup sweep. No test depends on the real clock vs a fixed past one (`now` is injected).
use super::artifact::{self, Limits};
use super::docker_ops::{DockerOps, Labels, owner_labels};
use super::*;
use crate::fork::crypto::parse_pin;
use crate::fork::state::Redacted;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

// ---- vectors -----------------------------------------------------------------------------------------------------------------------------
#[derive(Deserialize, Clone)]
struct VPin {
    kid: String,
    pem: String,
}
#[derive(Deserialize, Clone)]
struct EnvCase {
    name: String,
    envelope: String,
    signature: String,
    payload_enc: Option<String>,
    expect: String,
}
#[derive(Deserialize, Clone)]
struct PCase {
    #[serde(rename = "type")]
    ty: String,
    name: String,
    payload: Value,
    agent: String,
}
#[derive(Deserialize, Clone)]
struct MCase {
    name: String,
    json: String,
    sig_b64: String,
    expect: String,
    rp_id: String,
    stack_id: String,
    sequence: u64,
    manifest_sha256: String,
    #[serde(default)]
    min_sequence: Option<u64>,
}
#[derive(Deserialize, Clone)]
pub(crate) struct StageWorld {
    pub(crate) json: String,
    pub(crate) sig_b64: String,
    pub(crate) sha256: String,
    pub(crate) rp_id: String,
    pub(crate) stack_id: String,
    pub(crate) volume_index: usize,
    pub(crate) db_index: usize,
}
#[derive(Deserialize, Clone)]
pub(crate) struct RV {
    pub(crate) now: i64,
    pub(crate) agent_id: String,
    pub(crate) enroll_id: String,
    pub(crate) own_capabilities: Vec<String>,
    pub(crate) pins: Vec<VPin>,
    task_key_b64: String,
    pub(crate) ids: BTreeMap<String, String>,
    pub(crate) codes: Vec<String>,
    pub(crate) types: BTreeMap<String, Vec<String>>,
    pub(crate) targeted: Vec<String>,
    pub(crate) cases: Vec<EnvCase>,
    pub(crate) payload_cases: Vec<PCase>,
    pub(crate) manifests: Vec<MCase>,
    pub(crate) stage_world: StageWorld,
}
pub(crate) fn rv() -> RV {
    serde_json::from_str(include_str!("../tests/restore_vectors.json")).expect("restore_vectors.json")
}
fn pins_of(v: &RV) -> Vec<Pin> {
    v.pins.iter().map(|p| parse_pin(&p.kid, &p.pem).unwrap()).collect()
}

#[test]
fn codes_types_and_targeted_list_equal_the_dashboards() {
    let v = rv();
    assert_eq!(Code::RESTORE.iter().map(|c| c.as_str().to_string()).collect::<Vec<_>>(), v.codes);
    let mut got: Vec<_> = v.types.keys().cloned().collect();
    got.sort();
    let mut want: Vec<_> = crate::fork::capabilities::TARGETED.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(got, want);
    assert_eq!(v.targeted, crate::fork::capabilities::TARGETED.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    for (t, req) in &v.types {
        assert_eq!(crate::fork::capabilities::task_requires(t).unwrap().iter().map(|s| s.to_string()).collect::<Vec<_>>(), *req, "{t}");
    }
    assert_eq!(deadline_of("restore_stage"), DEADLINE_STAGE);
}

#[test]
fn envelope_vectors_every_case_gets_the_expected_decision() {
    use crate::fork::verify::{Ctx, Decision, evaluate};
    let v = rv();
    let pins = pins_of(&v);
    let key: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &v.task_key_b64).unwrap().try_into().unwrap();
    let state = crate::fork::state::State::fresh(&v.enroll_id);
    for c in &v.cases {
        let ctx = Ctx { agent_id: &v.agent_id, enroll_id: &v.enroll_id, pins: &pins, task_key: &key, capabilities: &v.own_capabilities, state: &state, now: v.now };
        match (c.expect.as_str(), evaluate(&ctx, &c.envelope, &c.signature, c.payload_enc.as_deref())) {
            ("ok", Decision::Accept(_)) => {}
            (code, Decision::Reject(r)) => assert_eq!(r.code(), code, "{}", c.name),
            (e, g) => panic!("{}: expected {e}, got {g:?}", c.name),
        }
    }
    // a build without the capability refuses the whole class (honest degrade)
    let no_restore: Vec<String> = v.own_capabilities.iter().filter(|c| *c != "restore.target.v1").cloned().collect();
    let c = v.cases.iter().find(|c| c.name == "restore_stage_targeted_ok").unwrap();
    let ctx = Ctx { agent_id: &v.agent_id, enroll_id: &v.enroll_id, pins: &pins, task_key: &key, capabilities: &no_restore, state: &state, now: v.now };
    assert!(matches!(evaluate(&ctx, &c.envelope, &c.signature, c.payload_enc.as_deref()), Decision::Reject(r) if r.code() == "capability_missing"));
}

#[test]
fn manifest_vectors() {
    let v = rv();
    let pins = pins_of(&v);
    for c in &v.manifests {
        let sig = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &c.sig_b64).unwrap();
        let r = manifest::verify(c.json.as_bytes(), &sig, &pins, &manifest::Expect { rp_id: &c.rp_id, stack_id: &c.stack_id, sequence: Some(c.sequence), sha256: &c.manifest_sha256, min_sequence: c.min_sequence });
        match (c.expect.as_str(), r) {
            ("ok", Ok(_)) => {}
            (code, Err(f)) => assert_eq!(f.code.as_str(), code, "{}", c.name),
            (e, g) => panic!("{}: expected {e}, got {:?}", c.name, g.map(|_| ())),
        }
    }
    // a task signature never verifies as a manifest signature (domain separation): the envelope of a valid case is not a manifest
    let t = &v.cases[0];
    let sig = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &t.signature).unwrap();
    assert!(!crate::fork::crypto::verify_manifest(&pins[0], t.envelope.as_bytes(), &sig));
}

// ---- fake Docker -----------------------------------------------------------------------------------------------------------------------
#[derive(Default)]
pub(crate) struct FakeState {
    pub(crate) volumes: BTreeMap<String, Labels>,
    pub(crate) networks: BTreeMap<String, Labels>,
    pub(crate) extracted: Vec<String>,
    pub(crate) wiped: Vec<String>,
    pub(crate) puts: Vec<(String, String, Vec<u8>)>,
    pub(crate) put_metas: Vec<super::docker_ops::FileMeta>,
    pub(crate) fail_extract_for: Option<String>,
    pub(crate) shared: bool,
    /// W17-ii: existing file metadata per (volume, relative path), `helper_rm` calls (in order with puts), render specs + canned render outputs, containers
    pub(crate) file_metas: BTreeMap<(String, String), super::docker_ops::FileMeta>,
    pub(crate) events: Vec<String>,
    pub(crate) renders: Vec<super::docker_ops::RenderSpec>,
    pub(crate) render_out: std::collections::VecDeque<Result<Vec<u8>, super::docker_ops::RenderError>>,
    pub(crate) containers: Vec<super::docker_ops::ContainerFacts>,
    pub(crate) removed_containers: Vec<String>,
    pub(crate) own_image: String,
}
pub(crate) struct Fake(pub(crate) Mutex<FakeState>);
impl Fake {
    pub(crate) fn new() -> Self {
        Fake(Mutex::new(FakeState { shared: true, own_image: "sha256:".to_string() + &"1".repeat(64), ..Default::default() }))
    }
}
#[async_trait]
impl DockerOps for Fake {
    async fn ping(&self) -> bool {
        true
    }
    async fn read_from_bind(&self, dir: &Path, file: &str) -> Result<Option<Vec<u8>>, Code> {
        Ok(if self.0.lock().unwrap().shared { std::fs::read(dir.join(file)).ok() } else { None })
    }
    async fn volume_labels(&self, n: &str) -> Result<Option<Labels>, Code> {
        Ok(self.0.lock().unwrap().volumes.get(n).cloned())
    }
    async fn create_volume(&self, n: &str, l: &Labels) -> Result<(), Code> {
        self.0.lock().unwrap().volumes.insert(n.into(), l.clone());
        Ok(())
    }
    async fn remove_volume(&self, n: &str) -> Result<(), Code> {
        self.0.lock().unwrap().volumes.remove(n);
        Ok(())
    }
    async fn list_volumes(&self) -> Result<Vec<(String, Labels)>, Code> {
        Ok(self.0.lock().unwrap().volumes.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
    async fn network_labels(&self, n: &str) -> Result<Option<Labels>, Code> {
        Ok(self.0.lock().unwrap().networks.get(n).cloned())
    }
    async fn create_network(&self, n: &str, l: &Labels) -> Result<(), Code> {
        self.0.lock().unwrap().networks.insert(n.into(), l.clone());
        Ok(())
    }
    async fn remove_network(&self, n: &str) -> Result<(), Code> {
        self.0.lock().unwrap().networks.remove(n);
        Ok(())
    }
    async fn list_networks(&self) -> Result<Vec<(String, Labels)>, Code> {
        Ok(self.0.lock().unwrap().networks.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
    async fn helper_wipe(&self, v: &str) -> Result<(), Code> {
        self.0.lock().unwrap().wiped.push(v.into());
        Ok(())
    }
    async fn helper_extract(&self, v: &str, _f: &Path) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        if s.fail_extract_for.as_deref() == Some(v) {
            s.fail_extract_for = None; // fails once: the simulated crash
            return Err(Code::DockerUnavailable);
        }
        s.extracted.push(v.into());
        Ok(())
    }
    async fn helper_put_file(&self, v: &str, rel: &str, f: &Path, meta: super::docker_ops::FileMeta) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.events.push(format!("put:{v}:{rel}"));
        s.put_metas.push(meta);
        s.puts.push((v.into(), rel.into(), std::fs::read(f).unwrap()));
        Ok(())
    }
    async fn file_meta(&self, v: &str, rel: &str) -> Result<Option<super::docker_ops::FileMeta>, Code> {
        Ok(self.0.lock().unwrap().file_metas.get(&(v.to_string(), rel.to_string())).copied())
    }
    async fn helper_rm(&self, v: &str, paths: &[String]) -> Result<(), Code> {
        self.0.lock().unwrap().events.push(format!("rm:{v}:{}", paths.join(",")));
        Ok(())
    }
    async fn render(&self, spec: &super::docker_ops::RenderSpec) -> Result<Vec<u8>, super::docker_ops::RenderError> {
        let mut s = self.0.lock().unwrap();
        s.renders.push(spec.clone());
        s.render_out.pop_front().unwrap_or(Err(super::docker_ops::RenderError::Failed("no canned render".into())))
    }
    async fn containers(&self) -> Result<Vec<super::docker_ops::ContainerFacts>, Code> {
        Ok(self.0.lock().unwrap().containers.clone())
    }
    async fn stop_remove(&self, id: &str) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.removed_containers.push(id.to_string());
        s.containers.retain(|c| c.id != id);
        Ok(())
    }
    async fn image_of_container(&self, _own_id: &str) -> Result<String, Code> {
        Ok(self.0.lock().unwrap().own_image.clone())
    }
    async fn remove_helpers(&self) -> usize {
        3
    }
}

// ---- rig -------------------------------------------------------------------------------------------------------------------------------
pub(crate) struct Rig {
    pub(crate) _root_dir: tempfile::TempDir,
    pub(crate) _state_dir: tempfile::TempDir,
    pub(crate) root: PathBuf,
    pub(crate) env: RestoreEnv,
    pub(crate) v: RV,
    pub(crate) pins: Vec<Pin>,
}
fn fixtures_key() -> String {
    let j: Value = serde_json::from_str(include_str!("../tests/fixtures.json")).unwrap();
    j["master_key_b64"].as_str().unwrap().to_string()
}
pub(crate) fn rig(host_role: HostRole, http_hosts: &[&str]) -> Rig {
    let v = rv();
    let rd = tempfile::tempdir().unwrap();
    let sd = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(rd.path()).unwrap();
    let env = RestoreEnv { roots: vec![root.clone()], host_role, http_hosts: http_hosts.iter().map(|s| s.to_string()).collect(), state_dir: std::fs::canonicalize(sd.path()).unwrap(), agent_id: v.agent_id.clone(), master_b64: Some(Redacted(fixtures_key())), compose: None };
    let pins = pins_of(&v);
    Rig { _root_dir: rd, _state_dir: sd, root, env, v, pins }
}
pub(crate) const NOW: i64 = 1_794_052_800;
pub(crate) fn task<'a>(ty: &'a str) -> Task<'a> {
    Task { id: "00000000-0000-4000-8000-000000000001", ty, now: NOW }
}
pub(crate) fn header(r: &Rig, restore_id: &str) -> Value {
    json!({"v":1,"restore_id":restore_id,"plan_id":r.v.ids["plan_id"],"plan_hash":"a".repeat(64),"stack_id":r.v.ids["stack_id"],"rp_id":r.v.ids["rp_id"],"purpose":"restore","mode":"selective",
        "host_role": if r.env.host_role == HostRole::Test {"test"} else {"production"}, "approvals": if r.env.host_role == HostRole::Test {json!([])} else {json!(["production_target"])},
        "workspace": format!("{}/restore/app", r.root.display()), "project":"app"})
}
pub(crate) fn merge(mut a: Value, b: Value) -> Vec<u8> {
    a.as_object_mut().unwrap().extend(b.as_object().unwrap().clone());
    serde_json::to_vec(&a).unwrap()
}
pub(crate) const RID: &str = "77777777-7777-4777-8777-777777777777";
const RID2: &str = "99999999-9999-4999-8999-999999999999";

fn stage_payload(r: &Rig, rid: &str, vol_url: &str, db_url: &str, sha_override: Option<&str>) -> Vec<u8> {
    let w = &r.v.stage_world;
    merge(header(r, rid), json!({
        "manifest": {"json_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, w.json.as_bytes()), "sig_b64": w.sig_b64, "sha256": sha_override.unwrap_or(&w.sha256)},
        "artifacts": [{"index": w.volume_index, "source": "archive", "url": vol_url}, {"index": w.db_index, "source": "archive", "url": db_url}],
        "paths": [{"index": w.volume_index, "dest": format!("{}/restore/app/files/vol", r.root.display())}],
    }))
}
fn apply_payload(r: &Rig, rid: &str, volumes: Value) -> Vec<u8> {
    merge(header(r, rid), json!({"manifest_sha256": r.v.stage_world.sha256, "volumes": volumes, "sqlite": [], "networks": [{"name": "app_default"}], "unpack": []}))
}
fn cleanup_payload(r: &Rig, rid: &str) -> Vec<u8> {
    merge(header(r, rid), json!({"workspace_remove": true, "volumes": true, "networks": true, "containers": false}))
}

use wiremock::matchers::{method, path as wpath};
use wiremock::{Mock, MockServer, ResponseTemplate};
const VOL_ENC: &[u8] = include_bytes!("../tests/lab-volume.tar.gz.enc");
const PG_ENC: &[u8] = include_bytes!("../tests/lab-postgres.tar.gz.enc");

async fn serve(srv: &MockServer, p: &str, body: Vec<u8>, times: u64) {
    Mock::given(method("GET")).and(wpath(p)).respond_with(ResponseTemplate::new(200).set_body_bytes(body)).expect(times).mount(srv).await;
}

#[tokio::test]
async fn stage_good_then_resume_skips_done_artifacts_then_apply_and_cleanup() {
    let r = rig(HostRole::Test, &["127.0.0.1"]);
    let srv = MockServer::start().await;
    serve(&srv, "/vol", VOL_ENC.to_vec(), 1).await; // exactly ONE download each, even though stage runs twice (resume)
    serve(&srv, "/db", PG_ENC.to_vec(), 1).await;
    let ops = Fake::new();
    let p = stage_payload(&r, RID, &format!("{}/vol?X-Amz-Signature=SECRET", srv.uri()), &format!("{}/db?X-Amz-Signature=SECRET", srv.uri()), None);
    let out = execute(&r.env, &ops, &r.pins, &task("restore_stage"), &p).await.unwrap();
    assert_eq!(out["extracted"], 1);
    assert_eq!(out["staged"].as_array().unwrap().len(), 2);
    let ws = r.root.join("restore/app");
    for i in 1..=10 {
        assert!(ws.join(format!("files/vol/file-{i}.txt")).is_file(), "file-{i}");
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(ws.join(".portabase")).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(std::fs::read_dir(ws.join(".portabase/tmp")).unwrap().next().is_none(), "tmp/ emptied at the end");
    assert!(ws.join(".portabase/stage/a0.tar.gz").is_file() && ws.join(".portabase/stage/a1.tar.gz").is_file());
    // same restore_id, second stage: resumes (no second download — the mock asserts it on drop)
    let again = execute(&r.env, &ops, &r.pins, &task("restore_stage"), &p).await.unwrap();
    assert_eq!(again["extracted"], 1);
    // another run on the same workspace is refused
    let p2 = stage_payload(&r, RID2, "http://127.0.0.1:1/x", "http://127.0.0.1:1/y", None);
    assert_eq!(execute(&r.env, &ops, &r.pins, &task("restore_stage"), &p2).await.unwrap_err().code, Code::WorkspaceNotOwned);

    // ---- apply: volume created with ownership labels, consumed archive removed, PG dump stays staged ----
    let vols = json!([{"index": 0, "name": "app_appdata", "compose_volume": "appdata"}]);
    let a = execute(&r.env, &ops, &r.pins, &task("restore_apply"), &apply_payload(&r, RID, vols.clone())).await.unwrap();
    assert_eq!(a["volumes"][0]["status"], "created");
    {
        let s = ops.0.lock().unwrap();
        let l = &s.volumes["app_appdata"];
        assert_eq!(l["com.portabase.fork.restore_id"], RID);
        assert_eq!(l["com.portabase.fork.agent_id"], r.v.agent_id);
        assert_eq!(l["com.docker.compose.volume"], "appdata");
        assert_eq!(l["com.docker.compose.project"], "app");
        assert!(s.networks.contains_key("app_default"));
    }
    assert!(!ws.join(".portabase/stage/a0.tar.gz").exists() && ws.join(".portabase/stage/a1.tar.gz").exists());
    // idempotent: running apply again reuses
    let a2 = execute(&r.env, &ops, &r.pins, &task("restore_apply"), &apply_payload(&r, RID, vols)).await.unwrap();
    assert_eq!(a2["volumes"][0]["status"], "reused");
    assert_eq!(ops.0.lock().unwrap().extracted, vec!["app_appdata"]);

    // ---- cleanup: foreign volumes survive, owned ones and the workspace are gone ----
    {
        let mut s = ops.0.lock().unwrap();
        s.volumes.insert("app_foreign".into(), Labels::new());
        s.volumes.insert("app_other_run".into(), owner_labels(RID2, &r.v.agent_id));
        s.volumes.insert("unrelated".into(), Labels::new());
        s.networks.insert("app_foreign_net".into(), Labels::new());
    }
    let c = execute(&r.env, &ops, &r.pins, &task("restore_cleanup"), &cleanup_payload(&r, RID)).await.unwrap();
    assert_eq!(c["removed"], json!({"volumes": 1, "networks": 1, "containers": 0, "workspace": true}));
    assert_eq!(c["kept_foreign"], 3, "app_foreign, app_other_run, app_foreign_net match the project but are not ours");
    let s = ops.0.lock().unwrap();
    assert!(s.volumes.contains_key("app_foreign") && s.volumes.contains_key("app_other_run") && s.volumes.contains_key("unrelated") && !s.volumes.contains_key("app_appdata"));
    assert!(!ws.exists());
}

#[tokio::test]
async fn cleanup_never_removes_a_workspace_of_another_run_or_a_foreign_directory() {
    let r = rig(HostRole::Test, &["127.0.0.1"]);
    let ops = Fake::new();
    let ws = r.root.join("restore/app");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("precious"), b"x").unwrap();
    let c = execute(&r.env, &ops, &r.pins, &task("restore_cleanup"), &cleanup_payload(&r, RID)).await.unwrap();
    assert_eq!(c["removed"]["workspace"], false);
    assert!(ws.join("precious").exists());
    // owned by another run
    workspace::Workspace::open_or_create(&ws.join("sub"), &workspace::Claim { restore_id: RID2, stack_id: "s", rp_id: "r", project: "app", agent_id: &r.v.agent_id }, NOW).ok();
    std::fs::remove_file(ws.join("precious")).unwrap();
    std::fs::remove_dir_all(ws.join("sub")).ok();
    workspace::Workspace::open_or_create(&ws, &workspace::Claim { restore_id: RID2, stack_id: &r.v.ids["stack_id"], rp_id: &r.v.ids["rp_id"], project: "app", agent_id: &r.v.agent_id }, NOW).unwrap();
    let c = execute(&r.env, &ops, &r.pins, &task("restore_cleanup"), &cleanup_payload(&r, RID)).await.unwrap();
    assert_eq!(c["removed"]["workspace"], false);
    assert!(ws.join(".portabase/owner.json").exists());
    // containers:true is W17-ii
    let p = merge(header(&r, RID), json!({"workspace_remove": true, "volumes": true, "networks": true, "containers": true}));
    assert_eq!(execute(&r.env, &ops, &r.pins, &task("restore_cleanup"), &p).await.unwrap_err().code, Code::ModeUnsupported);
}

#[tokio::test]
async fn apply_refuses_foreign_volumes_and_resumes_after_a_crash_redoing_only_the_unfinished_volume() {
    let r = rig(HostRole::Test, &["127.0.0.1"]);
    let srv = MockServer::start().await;
    serve(&srv, "/vol", VOL_ENC.to_vec(), 1).await;
    serve(&srv, "/db", PG_ENC.to_vec(), 1).await;
    let ops = Fake::new();
    // stage with the volume artifact twice mapped (two volumes from the same staged archive is not planner output, but exercises the loop)
    let p = stage_payload(&r, RID, &format!("{}/vol", srv.uri()), &format!("{}/db", srv.uri()), None);
    execute(&r.env, &ops, &r.pins, &task("restore_stage"), &p).await.unwrap();
    let vols = json!([{"index": 0, "name": "app_one", "compose_volume": "one"}]);
    // a foreign (unlabelled) volume with the same name ⇒ volume_exists, untouched
    ops.0.lock().unwrap().volumes.insert("app_one".into(), Labels::new());
    let e = execute(&r.env, &ops, &r.pins, &task("restore_apply"), &apply_payload(&r, RID, vols.clone())).await.unwrap_err();
    assert_eq!(e.code, Code::VolumeExists);
    assert!(ops.0.lock().unwrap().wiped.is_empty() && ops.0.lock().unwrap().extracted.is_empty(), "nothing touched");
    // labelled by ANOTHER run ⇒ volume_not_owned
    ops.0.lock().unwrap().volumes.insert("app_one".into(), owner_labels(RID2, &r.v.agent_id));
    assert_eq!(execute(&r.env, &ops, &r.pins, &task("restore_apply"), &apply_payload(&r, RID, vols.clone())).await.unwrap_err().code, Code::VolumeNotOwned);
    // crash during the extraction of an OWNED volume ⇒ the retry (same restore_id) wipes and redoes it
    ops.0.lock().unwrap().volumes.insert("app_one".into(), owner_labels(RID, &r.v.agent_id));
    ops.0.lock().unwrap().fail_extract_for = Some("app_one".into());
    assert!(execute(&r.env, &ops, &r.pins, &task("restore_apply"), &apply_payload(&r, RID, vols.clone())).await.is_err());
    let ok = execute(&r.env, &ops, &r.pins, &task("restore_apply"), &apply_payload(&r, RID, vols)).await.unwrap();
    assert_eq!(ok["volumes"][0]["status"], "redone");
    assert_eq!(ops.0.lock().unwrap().wiped.len(), 2);
    assert_eq!(ops.0.lock().unwrap().extracted, vec!["app_one"]);
}

#[tokio::test]
async fn stage_refuses_forged_manifest_before_any_download_and_writes_nothing() {
    let r = rig(HostRole::Test, &["127.0.0.1"]);
    let srv = MockServer::start().await;
    serve(&srv, "/vol", VOL_ENC.to_vec(), 0).await; // never contacted
    serve(&srv, "/db", PG_ENC.to_vec(), 0).await;
    let ops = Fake::new();
    // sha bound by the plan differs from the manifest bytes
    let p = stage_payload(&r, RID, &format!("{}/vol", srv.uri()), &format!("{}/db", srv.uri()), Some(&"0".repeat(64)));
    assert_eq!(execute(&r.env, &ops, &r.pins, &task("restore_stage"), &p).await.unwrap_err().code, Code::ManifestMismatch);
    // tampered manifest byte
    let mut v = r.v.clone();
    v.stage_world.json = v.stage_world.json.replace("\"app\"", "\"apq\"");
    let r2 = Rig { v, ..rig(HostRole::Test, &["127.0.0.1"]) };
    let p = stage_payload(&r2, RID, &format!("{}/vol", srv.uri()), &format!("{}/db", srv.uri()), None);
    assert_eq!(execute(&r2.env, &ops, &r2.pins, &task("restore_stage"), &p).await.unwrap_err().code, Code::ManifestSignature);
    assert!(!r2.root.join("restore/app/files").exists());
}

#[tokio::test]
async fn stage_hostile_artifacts_swapped_flipped_truncated_redirect_http_oversize() {
    let r = rig(HostRole::Test, &["127.0.0.1"]);
    let ops = Fake::new();
    let dest = r.root.join("restore/app/files");
    async fn run(r: &Rig, ops: &Fake, vol: String) -> Failure {
        let p = stage_payload(r, RID, &vol, &vol, None);
        execute(&r.env, ops, &r.pins, &task("restore_stage"), &p).await.unwrap_err()
    }
    // flipped ciphertext byte (GCM tag) and a swapped object (the other fixture) ⇒ checksum_mismatch, nothing extracted
    let mut flipped = VOL_ENC.to_vec();
    let n = flipped.len() / 2;
    flipped[n] ^= 1;
    for (name, body) in [("flipped", flipped), ("swapped", PG_ENC.to_vec()), ("truncated", VOL_ENC[..VOL_ENC.len() - 7].to_vec())] {
        let srv = MockServer::start().await;
        serve(&srv, "/o", body, 1).await;
        let e = run(&r, &ops, format!("{}/o", srv.uri())).await;
        assert_eq!(e.code, Code::ChecksumMismatch, "{name}");
        assert_eq!(e.artifact, Some(0), "{name}");
        assert!(!dest.exists(), "{name}");
    }
    // redirect: refused, and the redirect target is never contacted
    let target = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_bytes(VOL_ENC.to_vec())).expect(0).mount(&target).await;
    let srv = MockServer::start().await;
    Mock::given(method("GET")).and(wpath("/o")).respond_with(ResponseTemplate::new(302).insert_header("Location", format!("{}/x", target.uri()))).expect(1).mount(&srv).await;
    assert_eq!(run(&r, &ops, format!("{}/o", srv.uri())).await.code, Code::ArtifactUnavailable);
    // oversize body is cut at the cap
    let srv = MockServer::start().await;
    serve(&srv, "/o", vec![7u8; 3 * 1024 * 1024], 1).await;
    assert_eq!(run(&r, &ops, format!("{}/o", srv.uri())).await.code, Code::ArtifactUnavailable);
}

#[tokio::test]
async fn http_is_refused_without_the_host_exemption_and_userinfo_is_refused() {
    let r = rig(HostRole::Test, &[]); // FORK_ARTIFACT_HTTP_HOSTS empty
    let srv = MockServer::start().await;
    serve(&srv, "/o", VOL_ENC.to_vec(), 0).await;
    let ops = Fake::new();
    let p = stage_payload(&r, RID, &format!("{}/o", srv.uri()), &format!("{}/o", srv.uri()), None);
    assert_eq!(execute(&r.env, &ops, &r.pins, &task("restore_stage"), &p).await.unwrap_err().code, Code::ArtifactUnavailable);
    assert!(artifact::url_allowed("https://user:pw@h.example/x", &[]).is_err());
    assert!(artifact::url_allowed("https://h.example/x?sig=1", &[]).is_ok());
    assert!(artifact::url_allowed("http://h.example/x", &["other".into()]).is_err());
    assert!(artifact::url_allowed("http://h.example/x", &["h.example".into()]).is_ok());
    assert!(artifact::url_allowed("ftp://h.example/x", &["h.example".into()]).is_err());
}

#[tokio::test]
async fn a_root_that_is_not_shared_with_the_docker_daemon_refuses_stage() {
    let r = rig(HostRole::Test, &["127.0.0.1"]);
    let ops = Fake::new();
    ops.0.lock().unwrap().shared = false;
    let p = stage_payload(&r, RID, "http://127.0.0.1:1/a", "http://127.0.0.1:1/b", None);
    assert_eq!(execute(&r.env, &ops, &r.pins, &task("restore_stage"), &p).await.unwrap_err().code, Code::RootNotShared);
    // probe reports it instead of failing
    let out = execute(&r.env, &ops, &r.pins, &task("restore_probe"), br#"{"v":1}"#).await.unwrap();
    assert_eq!(out["roots"][0]["shared"], false);
    ops.0.lock().unwrap().shared = true;
    let out = execute(&r.env, &ops, &r.pins, &task("restore_probe"), br#"{"v":1}"#).await.unwrap();
    assert_eq!(out["roots"][0]["shared"], true);
    assert!(out["roots"][0]["free_bytes"].as_u64().unwrap() > 0);
    assert!(std::fs::read_dir(&r.root).unwrap().next().is_none(), "probe files are removed");
}

// ---- payload vectors -------------------------------------------------------------------------------------------------------------------
#[tokio::test]
async fn payload_vectors_get_the_expected_agent_decision() {
    let v = rv();
    for c in &v.payload_cases {
        let role = if c.payload["host_role"] == "production" { HostRole::Production } else { HostRole::Test };
        let r = rig(role, &["127.0.0.1"]);
        // the vectors use /srv/restore; the engine runs under a real temp root
        let text = serde_json::to_string(&c.payload).unwrap().replace("/srv/restore", &format!("{}/restore", r.root.display()));
        let ops = Fake::new();
        let ty = c.ty.as_str();
        let mut env = r.env.clone();
        env.compose = Some(crate::fork::compose::tests::compose_env());
        let got = if matches!(ty, "compose_render" | "restore_db" | "compose_up") {
            crate::fork::compose::execute(&env, &ops, &r.pins, &crate::fork::compose::tests::NullSink, &task(ty), text.as_bytes()).await
        } else {
            execute(&r.env, &ops, &r.pins, &task(ty), text.as_bytes()).await
        };
        if c.agent == "ok" {
            if let Err(f) = got {
                assert!(!matches!(f.code, Code::PayloadInvalid | Code::PathNotAllowed | Code::ModeUnsupported | Code::HostRoleMismatch | Code::ApprovalMissing | Code::OverrideInvalid), "{}: {:?}", c.name, f);
            }
        } else {
            assert_eq!(got.unwrap_err().code.as_str(), c.agent, "{}", c.name);
        }
    }
}

#[tokio::test]
async fn host_role_switch_default_test_production_needs_host_optin_and_approval() {
    let r = rig(HostRole::Test, &[]);
    let ops = Fake::new();
    let mut h = header(&r, RID);
    h["host_role"] = json!("production");
    h["approvals"] = json!(["production_target"]);
    let p = merge(h, json!({"workspace_remove": true, "volumes": false, "networks": false, "containers": false}));
    assert_eq!(execute(&r.env, &ops, &r.pins, &task("restore_cleanup"), &p).await.unwrap_err().code, Code::HostRoleMismatch);
    let rp = rig(HostRole::Production, &[]);
    let mut h = header(&rp, RID);
    h["approvals"] = json!([]);
    let p = merge(h, json!({"workspace_remove": true, "volumes": false, "networks": false, "containers": false}));
    assert_eq!(execute(&rp.env, &ops, &rp.pins, &task("restore_cleanup"), &p).await.unwrap_err().code, Code::ApprovalMissing);
    // env parsing: unset ⇒ test; garbage ⇒ error
    let st = std::path::Path::new("/tmp/x/state.json");
    assert_eq!(RestoreEnv::from_env(&|_| None, st, "a").unwrap().host_role, HostRole::Test);
    assert!(RestoreEnv::from_env(&|k| (k == "FORK_HOST_ROLE").then(|| "prod".to_string()), st, "a").is_err());
    assert_eq!(RestoreEnv::from_env(&|k| (k == "FORK_HOST_ROLE").then(|| "production".to_string()), st, "a").unwrap().host_role, HostRole::Production);
    assert!(RestoreEnv::from_env(&|k| (k == "FORK_ALLOWED_PATH_ROOTS").then(|| "/etc".to_string()), st, "a").is_err());
    assert!(RestoreEnv::from_env(&|_| None, st, "a").unwrap().roots.is_empty(), "no roots ⇒ restore.target.v1 not reported");
}

// ---- tar audit (hostile archives) --------------------------------------------------------------------------------------------------------
fn raw_tar(entries: &[(&str, tar::EntryType, u32, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, ty, mode, link, data) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(*ty);
        h.set_mode(*mode);
        h.set_size(data.len() as u64);
        h.set_mtime(0);
        {
            let g = h.as_gnu_mut().unwrap();
            g.name = [0; 100];
            g.name[..name.len()].copy_from_slice(name.as_bytes());
            if let Some(l) = link {
                g.linkname = [0; 100];
                g.linkname[..l.len()].copy_from_slice(l.as_bytes());
            }
        }
        h.set_cksum();
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0u8, (512 - data.len() % 512) % 512));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}
fn gz(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}
fn audit(entries: &[(&str, tar::EntryType, u32, Option<&str>, &[u8])], top: Option<&str>) -> Result<artifact::Audit, Code> {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("a.tar.gz");
    std::fs::write(&f, gz(&raw_tar(entries))).unwrap();
    artifact::audit_tar(&f, top, &Limits::with_inflated(1 << 30))
}
use tar::EntryType as T;

#[test]
fn tar_audit_accepts_a_normal_archive_and_refuses_every_hostile_one() {
    let ok: &[(&str, T, u32, Option<&str>, &[u8])] = &[("vol", T::Directory, 0o755, None, b""), ("vol/a.txt", T::Regular, 0o644, None, b"hi"), ("vol/l", T::Symlink, 0o777, Some("a.txt"), b""), ("vol/h", T::Link, 0o644, Some("vol/a.txt"), b"")];
    assert_eq!(audit(ok, Some("vol")).unwrap().entries, 4);
    let bad: Vec<(&str, Vec<(&str, T, u32, Option<&str>, &[u8])>)> = vec![
        ("absolute", vec![("/etc/passwd", T::Regular, 0o644, None, b"x")]),
        ("dotdot", vec![("a/../../etc/x", T::Regular, 0o644, None, b"x")]),
        ("through_symlink", vec![("l", T::Symlink, 0o777, Some("/etc"), b""), ("l/passwd", T::Regular, 0o644, None, b"x")]),
        ("device", vec![("dev", T::Char, 0o644, None, b"")]),
        ("fifo", vec![("f", T::Fifo, 0o644, None, b"")]),
        ("setuid", vec![("a", T::Regular, 0o4755, None, b"x")]),
        ("setgid", vec![("a", T::Regular, 0o2755, None, b"x")]),
        ("sticky", vec![("a", T::Directory, 0o1777, None, b"")]),
        ("hardlink_to_later", vec![("h", T::Link, 0o644, Some("later"), b""), ("later", T::Regular, 0o644, None, b"x")]),
        ("hardlink_to_symlink", vec![("l", T::Symlink, 0o777, Some("x"), b""), ("h", T::Link, 0o644, Some("l"), b"")]),
        ("type_change", vec![("a", T::Regular, 0o644, None, b"x"), ("a", T::Directory, 0o755, None, b"")]),
        ("control_char", vec![("a\u{7}b", T::Regular, 0o644, None, b"x")]),
        ("outside_top", vec![("other/a", T::Regular, 0o644, None, b"x")]),
    ];
    for (n, e) in &bad {
        assert_eq!(audit(e, Some("vol").filter(|_| *n == "outside_top")), Err(Code::ArchiveInvalid), "{n}");
    }
}

#[test]
fn gzip_must_be_complete_and_nothing_may_follow() {
    let d = tempfile::tempdir().unwrap();
    let good = gz(&raw_tar(&[("a", T::Regular, 0o644, None, b"hi")]));
    let f = d.path().join("g.gz");
    std::fs::write(&f, &good).unwrap();
    assert!(artifact::gzip_complete(&f, 1 << 20).is_ok());
    std::fs::write(&f, &good[..good.len() - 5]).unwrap();
    assert_eq!(artifact::gzip_complete(&f, 1 << 20), Err(Code::ArchiveInvalid), "truncated");
    let mut trailing = good.clone();
    trailing.extend_from_slice(b"junk");
    std::fs::write(&f, &trailing).unwrap();
    assert_eq!(artifact::gzip_complete(&f, 1 << 20), Err(Code::ArchiveInvalid), "trailing data");
    std::fs::write(&f, &good).unwrap();
    assert_eq!(artifact::gzip_complete(&f, 10), Err(Code::ArchiveInvalid), "inflated cap");
}

#[test]
fn pg_dump_check_detects_format_and_rejects_two_files() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("p.tar.gz");
    let lim = Limits::with_inflated(1 << 30);
    std::fs::write(&f, gz(&raw_tar(&[("x.dump", T::Regular, 0o644, None, b"PGDMP\x01\x10")]))).unwrap();
    assert_eq!(artifact::check_pg_dump(&f, Some(manifest::DumpFormat::PgCustom), &lim, d.path()), Ok(artifact::PgDump::Custom));
    assert_eq!(artifact::check_pg_dump(&f, Some(manifest::DumpFormat::PgDirectory), &lim, d.path()), Err(Code::DumpFormatMismatch));
    std::fs::write(&f, gz(&raw_tar(&[("x.sql", T::Regular, 0o644, None, b"-- plain sql")]))).unwrap();
    assert_eq!(artifact::check_pg_dump(&f, None, &lim, d.path()), Err(Code::DumpFormatMismatch));
    std::fs::write(&f, gz(&raw_tar(&[("a", T::Regular, 0o644, None, b"PGDMP"), ("b", T::Regular, 0o644, None, b"PGDMP")]))).unwrap();
    assert_eq!(artifact::check_pg_dump(&f, None, &lim, d.path()), Err(Code::DumpFormatMismatch));
    // -Fd: the single file is a gzip'd tar of the dump directory, audited like any archive
    let inner_ok = gz(&raw_tar(&[("toc.dat", T::Regular, 0o644, None, b"x")]));
    std::fs::write(&f, gz(&raw_tar(&[("d.tar.gz", T::Regular, 0o644, None, &inner_ok)]))).unwrap();
    assert_eq!(artifact::check_pg_dump(&f, Some(manifest::DumpFormat::PgDirectory), &lim, d.path()), Ok(artifact::PgDump::Directory));
    let inner_bad = gz(&raw_tar(&[("../x", T::Regular, 0o644, None, b"x")]));
    std::fs::write(&f, gz(&raw_tar(&[("d.tar.gz", T::Regular, 0o644, None, &inner_bad)]))).unwrap();
    assert_eq!(artifact::check_pg_dump(&f, None, &lim, d.path()), Err(Code::ArchiveInvalid));
}

// ---- sweep ---------------------------------------------------------------------------------------------------------------------------
#[tokio::test]
async fn startup_sweep_removes_secrets_and_tmp_keeps_fresh_stage_expires_old_stage_and_aborts_journals() {
    let r = rig(HostRole::Test, &[]);
    let claim = |rid| workspace::Claim { restore_id: rid, stack_id: "s", rp_id: "r", project: "app", agent_id: &r.v.agent_id };
    let fresh = workspace::Workspace::open_or_create(&r.root.join("a/app"), &claim(RID), NOW - 3600).unwrap();
    let old = workspace::Workspace::open_or_create(&r.root.join("b/app"), &claim(RID2), NOW - 25 * 3600).unwrap();
    for w in [&fresh, &old] {
        std::fs::write(w.secret().join("override.env"), b"SECRET=1").unwrap();
        std::fs::write(w.tmp().join("a0.enc"), b"x").unwrap();
        std::fs::write(w.stage().join("a0.tar.gz"), b"x").unwrap();
    }
    let foreign = r.root.join("c/other");
    std::fs::create_dir_all(foreign.join(".portabase/secret")).unwrap(); // no owner.json: not ours, never touched
    std::fs::write(foreign.join(".portabase/secret/x"), b"keep").unwrap();
    let mut j = journal::Journal::open(&r.env.state_dir, RID).unwrap();
    j.begin("t1", "restore_stage");
    j.step("t1", "restore_stage", "artifact:0", true, Some("abc"));
    let ops = Fake::new();
    let s = sweep::startup_sweep(&r.env, Some(&ops), NOW).await;
    assert_eq!((s.workspaces, s.stage_removed, s.helpers, s.journals_aborted), (2, 1, 3, 1));
    for w in [&fresh, &old] {
        assert!(!w.secret().exists() && !w.tmp().exists());
    }
    assert!(fresh.stage().join("a0.tar.gz").exists(), "fresh stage kept");
    assert!(!old.stage().exists(), "stage idle > 24 h removed");
    assert!(foreign.join(".portabase/secret/x").exists());
    let lines = journal::read_lines(&journal::dir(&r.env.state_dir).join(format!("{RID}.jsonl")));
    assert_eq!(lines.last().unwrap().ev, "abort");
    // idempotent: a second sweep finds nothing left to abort
    assert_eq!(sweep::startup_sweep(&r.env, None, NOW).await.journals_aborted, 0);
}

// ---- through the channel: heartbeats during a long task, deadline, targeting, degrade ---------------------------------------------------
mod channel_level {
    use super::*;
    use crate::fork::capabilities;
    use crate::fork::poll::{Handled, Runtime};
    use crate::fork::state;
    use crate::fork::transport::{Leased, Transport};
    use std::sync::Arc;
    use std::time::Duration;
    use wiremock::matchers::path_regex;

    const CRED: &str = "fork.11111111-1111-4111-8111-111111111111.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn runtime(r: &Rig, server_url: &str, state_path: PathBuf, configured: bool, ops: Option<Arc<dyn DockerOps>>) -> Runtime {
        let v = &r.v;
        let key: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &v.task_key_b64).unwrap().try_into().unwrap();
        Runtime {
            agent_id: v.agent_id.clone(),
            enroll_id: v.enroll_id.clone(),
            pins: pins_of(v),
            bundle_pins: pins_of(v),
            bundle_credential: CRED.to_string(),
            task_key: key,
            capabilities: capabilities::reported(configured, false),
            state: state::load(&state_path, &v.enroll_id).unwrap(),
            state_path,
            transport: Transport::new(server_url, &v.agent_id, CRED, true).unwrap(),
            renv: configured.then(|| r.env.clone()),
            ops,
        }
    }
    fn leased(c: &EnvCase) -> Leased {
        serde_json::from_value(json!({"task_id": "00000000-0000-4000-8000-000000000999", "envelope": c.envelope, "signature": c.signature, "kid": "x", "payload_enc": c.payload_enc,
            "lease_id": "99999999-9999-4999-8999-999999999999", "lease_until": "2099-01-01T00:00:00Z"})).unwrap()
    }
    async fn mount_ok(server: &MockServer) {
        Mock::given(method("POST")).and(path_regex(r"^/api/fork/agent/[^/]+/tasks/[^/]+/(heartbeat|result)$")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true}))).mount(server).await;
    }
    async fn bodies(server: &MockServer, suffix: &str) -> Vec<Value> {
        server.received_requests().await.unwrap().iter().filter(|r| r.url.path().ends_with(suffix)).map(|r| serde_json::from_slice(&r.body).unwrap()).collect()
    }

    #[tokio::test]
    async fn a_targeted_restore_probe_runs_through_the_channel_and_reports_roots() {
        let r = rig(HostRole::Test, &[]);
        let server = MockServer::start().await;
        mount_ok(&server).await;
        let st = tempfile::tempdir().unwrap();
        let mut rt = runtime(&r, &server.uri(), st.path().join("state.json"), true, Some(Arc::new(Fake::new())));
        let c = r.v.cases.iter().find(|c| c.name == "restore_probe_targeted_ok").unwrap();
        assert_eq!(rt.process(&leased(c), r.v.now).await, Handled::Executed("succeeded".into()));
        let res = bodies(&server, "/result").await;
        assert_eq!(res[0]["status"], "succeeded");
        assert_eq!(res[0]["result"]["roots"][0]["shared"], true);
        assert_eq!(res[0]["result"]["workspace_state"], Value::Null);
    }

    #[tokio::test]
    async fn untargeted_foreign_target_and_unconfigured_agent_never_execute() {
        let r = rig(HostRole::Test, &[]);
        for (name, expect, configured) in [("restore_probe_without_target", "target_mismatch", true), ("restore_stage_targeted_at_another_agent", "target_mismatch", true), ("restore_probe_targeted_ok", "capability_missing", false)] {
            let server = MockServer::start().await;
            mount_ok(&server).await;
            let st = tempfile::tempdir().unwrap();
            let mut rt = runtime(&r, &server.uri(), st.path().join("state.json"), configured, None);
            let c = r.v.cases.iter().find(|c| c.name == name).unwrap();
            assert_eq!(rt.process(&leased(c), r.v.now).await, Handled::Rejected(Box::leak(expect.to_string().into_boxed_str())), "{name}");
            assert!(bodies(&server, "/heartbeat").await.is_empty(), "{name}: nothing may start");
            assert_eq!(bodies(&server, "/result").await[0]["status"], "rejected", "{name}");
        }
        // an agent that is not configured for restores does not report the capability at all
        assert!(!capabilities::reported(false, false).iter().any(|c| c == "restore.target.v1") && capabilities::reported(true, false).iter().any(|c| c == "restore.target.v1"));
        // W17-ii: compose.render.v1 only on top of a working restore target and only when compose is ok
        assert!(!capabilities::reported(true, false).iter().any(|c| c == "compose.render.v1"));
        assert!(capabilities::reported(true, true).iter().any(|c| c == "compose.render.v1"));
        assert!(!capabilities::reported(false, true).iter().any(|c| c == "compose.render.v1"));
    }

    #[tokio::test]
    async fn long_tasks_heartbeat_and_the_deadline_cuts_them_off() {
        use crate::fork::exec::{Ended, run_with_heartbeat_every};
        let server = MockServer::start().await;
        mount_ok(&server).await;
        let t = Transport::new(&server.uri(), "11111111-1111-4111-8111-111111111111", CRED, true).unwrap();
        // finishes after ~320 ms with a 50 ms period ⇒ several heartbeats, then the value
        let out = run_with_heartbeat_every(&t, "tid", "lid", Duration::from_secs(5), Duration::from_millis(50), async {
            tokio::time::sleep(Duration::from_millis(320)).await;
            42
        })
        .await;
        assert!(matches!(out, Ended::Done(42)));
        assert!(bodies(&server, "/heartbeat").await.len() >= 3);
        // a task that never ends is dropped at the deadline
        let out: Ended<()> = run_with_heartbeat_every(&t, "tid", "lid", Duration::from_millis(150), Duration::from_millis(50), std::future::pending()).await;
        assert!(matches!(out, Ended::Deadline));
    }
}

// ---- SEC-14 argv audit harness (W17-i part) ---------------------------------------------------------------------------------------------
/// The restore engine starts NO external process: Docker is driven through the API (bollard), data moves through files and streams. So no secret, URL,
/// path from a payload or override value can reach an argv / process list from this module, by construction. This guard fails the day someone adds one;
/// W17-ii (compose CLI) extends it with the fake-binary argv/env capture test.
#[test]
fn the_restore_engine_never_spawns_a_process() {
    // W17-ii: process spawning is confined to ONE file (`compose/run.rs`); the shell literals are the fixed scripts (wipe + the PostgreSQL ones in compose/db.rs)
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fork");
    let mut scanned = 0;
    for sub in ["restore", "compose", "policy"] {
        for e in std::fs::read_dir(base.join(sub)).unwrap().flatten() {
            let p = e.path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if p.extension().and_then(|x| x.to_str()) != Some("rs") || name == "tests.rs" {
                continue;
            }
            scanned += 1;
            let src = std::fs::read_to_string(&p).unwrap();
            let code: String = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
            // the allowed `sh -c` literals: the fixed volume wipe script inside the hardened helper (docker_ops.rs) and the const scripts of db.rs
            let code = code.replace("rm -rf /vol/* /vol/.[!.]* /vol/..?*; true", "");
            let is_run = sub == "compose" && name == "run.rs";
            for banned in ["Command::new", "std::process", "tokio::process", "libc::system", "libc::exec"] {
                assert!(!code.contains(banned) || is_run, "{} contains `{banned}`", p.display());
            }
            if name != "docker_ops.rs" && name != "db.rs" {
                assert!(!code.contains("sh -c"), "{} contains a shell literal", p.display());
            }
            if name == "db.rs" {
                // the only `"sh", "-c"` argument pair of db.rs carries one of the three fixed consts, never a formatted string
                for l in code.lines().filter(|l| l.contains("\"sh\", \"-c\"")) {
                    assert!(l.contains("PG_ISREADY") || l.contains("PG_RESTORE_FD"), "db.rs shell argument is not a fixed const: {l}");
                }
                assert!(!code.contains("format!(\"u=") && !code.contains("PG_RESTORE_FC.replace"));
            }
        }
    }
    assert!(scanned >= 20, "scanned {scanned} files");
}

/// Secrets never show up in Debug output of the environment or failures (Redacted master key, no URLs in Failure).
#[test]
fn debug_output_hides_the_master_key_and_failures_carry_no_urls() {
    let r = rig(HostRole::Test, &[]);
    assert!(!format!("{:?}", r.env).contains(&fixtures_key()));
    let f = Failure::with(Code::ArtifactUnavailable, "https://h/x?X-Amz-Signature=abc");
    assert!(!f.detail.unwrap().contains('/') && !Failure::with(Code::RestoreFailed, "A B").detail.unwrap().contains(' '));
}
