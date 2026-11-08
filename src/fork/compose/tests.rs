//! W17-ii compose tests: render sandbox spec, raw check short-circuit, two-pass owner / remap files, the re-check chain, the D29 guard, the fixed argv / env of
//! `up` / `exec` (SEC-14: a canary override value never reaches argv or the process env), PostgreSQL restore, cleanup of owned containers.
//! No docker, no network, no clock dependence: the Docker daemon is the shared `Fake`, the Compose CLI is a recording shell script.
use super::guard::{check_up, protected_ids};
use super::*;
use crate::fork::restore::docker_ops::{ContainerFacts, LABEL_AGENT, LABEL_RESTORE, RenderError, owner_labels};
use crate::fork::restore::tests::{Fake, NOW, RID, Rig, header, merge, rig, task};
use crate::fork::restore::HostRole;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub(crate) const OWN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CANARY: &str = "CANARY-OVERRIDE-VALUE-7731";

pub(crate) fn compose_env() -> ComposeEnv {
    ComposeEnv { bin: PathBuf::from("/nonexistent/docker-compose"), version: "5.4.0".into(), own_id: OWN.into(), own_image: format!("sha256:{}", "1".repeat(64)), protected_extra: vec![] }
}
pub(crate) struct NullSink;
#[async_trait]
impl RenderSink for NullSink {
    async fn put(&self, _b: Value) -> Result<(), ()> {
        Ok(())
    }
}
#[derive(Default)]
struct Rec(Mutex<Vec<Value>>);
#[async_trait]
impl RenderSink for Rec {
    async fn put(&self, b: Value) -> Result<(), ()> {
        self.0.lock().unwrap().push(b);
        Ok(())
    }
}

/// A recording stand-in for `docker-compose`: appends argv + environment (+ the first bytes of stdin) to `$HOME/log` and keeps a copy of any `rendered.json` it is pointed at.
fn fake_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("w17ii-fakebin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("docker-compose");
        let script = "#!/bin/sh\n{ printf 'ARGS:'; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; printf '\\nENV:\\n'; env | sort; printf 'STDIN:'; head -c 12; echo; echo ---; } >> \"$HOME/log\"\nfor a in \"$@\"; do case \"$a\" in *rendered.json) cp \"$a\" \"$HOME/rendered.copy\";; esac; done\nexit ${FAKE_EXIT:-0}\n";
        std::fs::write(&p, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    })
    .clone()
}

/// a compose binary that outlives any test deadline
fn slow_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("w17ii-slowbin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("docker-compose");
        std::fs::write(&p, "#!/bin/sh\nsleep 30\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    })
    .clone()
}

struct W {
    r: Rig,
    ws: PathBuf,
    ops: Fake,
}
impl W {
    fn dir(&self) -> String {
        format!("{}/compose", self.ws.display())
    }
    fn home(&self) -> PathBuf {
        self.ws.join(".portabase/tmp/home")
    }
    fn log(&self) -> String {
        std::fs::read_to_string(self.home().join("log")).unwrap_or_default()
    }
    fn secret_files(&self) -> usize {
        std::fs::read_dir(self.ws.join(".portabase/secret")).map(|d| d.count()).unwrap_or(0)
    }
    fn doc(&self, extra_service: Option<(&str, Value)>) -> Value {
        let ws = self.ws.display().to_string();
        let mut d = json!({"name": "app", "services": {
            "web": {"image": "nginx:1", "environment": {"OVERRIDE_PROBE": CANARY}, "command": ["sh", "-c", "echo $$HOME"], "networks": {"default": null},
                "volumes": [{"type": "bind", "source": format!("{ws}/compose/www"), "target": "/www", "bind": {}}, {"type": "volume", "source": "appdata", "target": "/appdata", "volume": {}}]},
            "db": {"image": "postgres:17", "networks": {"default": null}, "volumes": [{"type": "volume", "source": "pgdata", "target": "/var/lib/postgresql/data", "volume": {}}]}},
            "networks": {"default": {"name": "app_default"}}, "volumes": {"appdata": {"name": "app_appdata"}, "pgdata": {"name": "app_pgdata"}}});
        if let Some((n, s)) = extra_service {
            d["services"][n] = s;
        }
        d
    }
    fn can_render(&self, doc: &Value, passes: usize) {
        let mut s = self.ops.0.lock().unwrap();
        for _ in 0..passes {
            s.render_out.push_back(Ok(serde_json::to_vec(doc).unwrap()));
        }
    }
    fn body(&self, over: Option<&str>, env: Value, path_map: Value) -> Value {
        json!({"manifest_sha256": self.r.v.stage_world.sha256, "compose": {"dir": self.dir(), "override_yml": over, "env": env, "path_map": path_map}})
    }
    fn payload(&self, extra: Value) -> Vec<u8> {
        merge(header(&self.r, RID), extra)
    }
    fn env(&self) -> RestoreEnv {
        let mut e = self.r.env.clone();
        let mut ce = compose_env();
        ce.bin = fake_bin();
        e.compose = Some(ce);
        e
    }
    async fn render(&self, env: &RestoreEnv, over: Option<&str>, env_pairs: Value, path_map: Value) -> R<Value> {
        let p = self.payload(self.body(over, env_pairs, path_map));
        execute(env, &self.ops, &self.r.pins, &NullSink, &task("compose_render"), &p).await
    }
}

fn world(compose_yml: &str) -> W {
    let r = rig(HostRole::Test, &[]);
    let ws = r.root.join("restore/app");
    let h: Header = serde_json::from_value(header(&r, RID)).unwrap();
    let env = &r.env;
    let w = Workspace::open_or_create(&ws, &claim(env, &h), NOW).unwrap();
    std::fs::create_dir_all(w.stage()).unwrap();
    std::fs::write(w.stage().join("manifest.json"), &r.v.stage_world.json).unwrap();
    std::fs::write(w.stage().join("manifest.sig"), base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &r.v.stage_world.sig_b64).unwrap()).unwrap();
    std::fs::create_dir_all(ws.join("compose/www")).unwrap();
    std::fs::write(ws.join("compose/compose.yml"), compose_yml).unwrap();
    W { r, ws, ops: Fake::new() }
}
const CLEAN_YML: &str = "services:\n  web:\n    image: nginx:1\n  db:\n    image: postgres:17\n";

fn flagged_token(w: &W, sha: &str, rules: Value) -> Value {
    json!({"v": 1, "compose_sha256": sha, "rules_sha256": "e".repeat(64), "roots": [w.ws.display().to_string()], "stack_id": w.r.v.ids["stack_id"], "rp_id": w.r.v.ids["rp_id"],
        "target_agent_id": w.r.env.agent_id, "overrides": rules})
}

// ---- render ---------------------------------------------------------------------------------------------------------------------------
#[tokio::test]
async fn render_sandbox_spec_and_two_passes() {
    let w = world(CLEAN_YML);
    let env = w.env();
    w.can_render(&w.doc(None), 2);
    let sink = Rec::default();
    let p = w.payload(w.body(Some("services: {}\n"), json!({"OVERRIDE_PROBE": CANARY}), json!([])));
    let res = execute(&env, &w.ops, &w.r.pins, &sink, &task("compose_render"), &p).await.unwrap();
    assert_eq!(res["verdict"], "allow");
    let specs = w.ops.0.lock().unwrap().renders.clone();
    assert_eq!(specs.len(), 2);
    let ws = w.ws.display().to_string();
    for s in &specs {
        assert_eq!(s.image, format!("sha256:{}", "1".repeat(64)));
        assert_eq!(s.bin, COMPOSE_BIN);
        assert_eq!(s.workspace, w.ws);
        assert!(s.env.contains(&("OVERRIDE_PROBE".into(), CANARY.into())) && s.env.contains(&("HOME".into(), "/tmp".into())));
        assert!(!s.cmd.iter().any(|a| a.contains(CANARY)), "override value only in env, never in cmd");
        assert_eq!(&s.cmd[..4], ["--project-name", "app", "--project-directory", &format!("{ws}/compose")]);
        assert_eq!(&s.cmd[s.cmd.len() - 3..], ["config", "--format", "json"]);
        assert!(s.cmd.contains(&format!("{ws}/compose/compose.yml")) && s.cmd.contains(&format!("{ws}/.portabase/secret/override.yml")));
    }
    assert!(!specs[0].cmd.iter().any(|a| a.ends_with("owner.yml")) && specs[1].cmd.iter().any(|a| a.ends_with("owner.yml")));
    assert!(!specs[1].cmd.iter().any(|a| a.ends_with("remap.yml")), "no path_map hit ⇒ no remap file");
    // the view uploaded to the dashboard carries no canary and no command text
    let bodies = sink.0.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    let view = String::from_utf8(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bodies[0]["view_b64"].as_str().unwrap()).unwrap()).unwrap();
    assert!(!view.contains(CANARY) && !view.contains("echo $$HOME"));
    assert_eq!(bodies[0]["view_sha256"], res["rendered_sha256"]);
    assert_eq!(bodies[0]["restore_id"], RID);
    assert_eq!(w.secret_files(), 0, "secret/ is empty after a successful render");
}

#[tokio::test]
async fn remap_file_only_when_a_bind_hits_the_path_map_and_owner_file_content() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let mut d = w.doc(None);
    d["services"]["web"]["volumes"][0]["source"] = json!("/opt/stack/www");
    w.can_render(&d, 2);
    w.render(&env, None, json!({}), json!([{"from": "/opt/stack", "to": format!("{}/files/stack", w.ws.display())}])).await.unwrap();
    let specs = w.ops.0.lock().unwrap().renders.clone();
    assert!(specs[1].cmd.iter().any(|a| a.ends_with("remap.yml")) && specs[1].cmd.iter().any(|a| a.ends_with("owner.yml")));
    let remap = super::render::remap_yaml(&d, &w.ws.display().to_string(), &serde_json::from_value::<ComposeRef>(w.body(None, json!({}), json!([{"from": "/opt/stack", "to": "/w/files/stack"}]))["compose"].clone()).unwrap()).unwrap().unwrap();
    assert!(remap.starts_with("services:\n  web:\n    volumes: !override [") && remap.contains("/w/files/stack/www") && !remap.contains("/opt/stack/www"));
    let owner: Value = serde_json::from_str(&super::render::owner_yaml(&w.doc(None), "rid", "aid").unwrap()).unwrap();
    for s in ["web", "db"] {
        assert_eq!(owner["services"][s]["labels"][LABEL_RESTORE], "rid");
        assert_eq!(owner["services"][s]["labels"][LABEL_AGENT], "aid");
    }
    assert!(owner["volumes"]["pgdata"]["labels"].is_object() && owner["networks"]["default"]["labels"].is_object());
    let mut ext = w.doc(None);
    ext["volumes"]["appdata"] = json!({"name": "shared", "external": true});
    let owner: Value = serde_json::from_str(&super::render::owner_yaml(&ext, "rid", "aid").unwrap()).unwrap();
    assert!(owner["volumes"].get("appdata").is_none() && owner["volumes"].get("pgdata").is_some(), "external volumes never get labels");
}

#[tokio::test]
async fn render_failures_are_closed_codes_and_clean_up_secret() {
    let w = world(CLEAN_YML);
    let env = w.env();
    w.ops.0.lock().unwrap().render_out.push_back(Err(RenderError::TooLarge));
    assert_eq!(w.render(&env, Some("services: {}\n"), json!({}), json!([])).await.unwrap_err().code, Code::RenderTooLarge);
    assert_eq!(w.secret_files(), 0);
    w.ops.0.lock().unwrap().render_out.push_back(Err(RenderError::Failed("Error: bad $TOKEN".into())));
    let f = w.render(&env, None, json!({}), json!([])).await.unwrap_err();
    assert_eq!((f.code, f.detail.as_deref()), (Code::RenderFailed, Some("_rror:_bad_______")));
    w.ops.0.lock().unwrap().render_out.push_back(Err(RenderError::Docker));
    assert_eq!(w.render(&env, None, json!({}), json!([])).await.unwrap_err().code, Code::DockerUnavailable);
    // compose not enabled ⇒ closed code, nothing rendered
    assert_eq!(w.render(&w.r.env, None, json!({}), json!([])).await.unwrap_err().code, Code::ComposeUnavailable);
    assert!(w.ops.0.lock().unwrap().renders.len() <= 3);
}

#[tokio::test]
async fn raw_poison_is_refused_before_any_helper_runs() {
    let w = world("services:\n  web:\n    image: x\n    env_file: /etc/hostname\n");
    let env = w.env();
    let sink = Rec::default();
    let p = w.payload(w.body(None, json!({}), json!([])));
    let f = execute(&env, &w.ops, &w.r.pins, &sink, &task("compose_render"), &p).await.unwrap_err();
    assert_eq!((f.code, f.detail.as_deref()), (Code::RawRefused, Some("env_file")));
    assert_eq!(f.result().unwrap()["raw"]["violations"][0]["kind"], "env_file");
    assert!(w.ops.0.lock().unwrap().renders.is_empty() && sink.0.lock().unwrap().is_empty());
    // a poisoned OVERRIDE is judged the same way
    let w = world(CLEAN_YML);
    let f = w.render(&w.env(), Some("services:\n  web:\n    env_file: /etc/passwd\n"), json!({}), json!([])).await.unwrap_err();
    assert_eq!(f.code, Code::RawRefused);
    assert!(w.ops.0.lock().unwrap().renders.is_empty() && w.secret_files() == 0);
}

#[tokio::test]
async fn no_compose_file_and_manifest_hash_mismatch() {
    let w = world(CLEAN_YML);
    std::fs::remove_file(w.ws.join("compose/compose.yml")).unwrap();
    let f = w.render(&w.env(), None, json!({}), json!([])).await.unwrap_err();
    assert_eq!((f.code, f.detail.as_deref()), (Code::RenderFailed, Some("no_compose_file")));
    let w = world(CLEAN_YML);
    let mut b = w.body(None, json!({}), json!([]));
    b["manifest_sha256"] = json!("0".repeat(64));
    let f = execute(&w.env(), &w.ops, &w.r.pins, &NullSink, &task("compose_render"), &w.payload(b)).await.unwrap_err();
    assert_eq!(f.code, Code::ManifestMismatch);
}

#[test]
fn compose_file_discovery_follows_the_signed_hint_then_the_defaults() {
    let d = tempfile::tempdir().unwrap();
    for f in ["compose.yml", "a.yaml", "docker-compose.override.yml", "x.txt"] {
        std::fs::write(d.path().join(f), "x").unwrap();
    }
    std::os::unix::fs::symlink("/etc/passwd", d.path().join("linked.yml")).unwrap();
    let inv = json!({"stack": {"config_files_hint": ["/opt/s/a.yaml", "/opt/s/linked.yml", "/opt/s/x.txt", "/opt/s/missing.yml", "../evil.yml", "/opt/s/a.yaml"]}});
    assert_eq!(discover(d.path(), Some(&inv)), vec!["a.yaml"]);
    assert_eq!(discover(d.path(), None), vec!["compose.yml", "docker-compose.override.yml"]);
}

// ---- guard (pure) ---------------------------------------------------------------------------------------------------------------------
fn cf(id: &str, names: &[&str], image: &str, labels: &[(&str, &str)]) -> ContainerFacts {
    ContainerFacts { id: id.into(), names: names.iter().map(|s| s.to_string()).collect(), image: image.into(), labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), mounts_docker_sock: false, running: true }
}
fn id(c: char) -> String {
    c.to_string().repeat(64)
}
const AG: &str = "33333333-3333-4333-8333-333333333333";

#[test]
fn guard_protects_by_full_id_and_never_touches_foreign_containers() {
    let render = json!({"services": {"web": {"container_name": "uptime-kuma"}}});
    let own = cf(OWN, &["agent"], "portabase-agent-fork:x", &[]);
    let mut sock = cf(&id('b'), &["traefik"], "traefik:3", &[]);
    sock.mounts_docker_sock = true;
    let all = vec![own.clone(), cf(&id('c'), &["portabase"], "ghcr.io/portabase/portabase:1", &[]), cf(&id('d'), &["arc"], "ghcr.io/getarcaneapp/arcane:latest", &[]), sock, cf(&id('e'), &["named"], "busybox", &[]), cf(&id('f'), &["uptime-kuma"], "louislam/uptime-kuma:1", &[])];
    let p = protected_ids(&all, OWN, &["named".to_string()]);
    for c in ['b', 'c', 'd', 'e'] {
        assert!(p.contains(&id(c)), "{c}");
    }
    assert!(p.contains(OWN) && !p.contains(&id('f')));
    // protected container_name ⇒ protected_container; id prefix never matches
    let r = json!({"services": {"web": {"container_name": "traefik"}}});
    assert_eq!(check_up(&r, "app", RID, AG, &all, &p).unwrap_err().code, Code::ProtectedContainer);
    assert!(!protected_ids(&all, OWN, &[id('f')[..12].to_string()]).contains(&id('f')), "a short id prefix protects nothing");
    assert!(protected_ids(&all, OWN, &[id('f')]).contains(&id('f')));
    // foreign container with the same container_name ⇒ conflict, other project or none
    assert_eq!(check_up(&render, "app", RID, AG, &all, &p).unwrap_err().code, Code::ContainerConflict);
    // foreign container in project `app` ⇒ project_in_use
    let all2 = vec![cf(&id('9'), &["x"], "busybox", &[("com.docker.compose.project", "app")])];
    let e = check_up(&json!({"services": {"web": {}}}), "app", RID, AG, &all2, &protected_ids(&all2, OWN, &[])).unwrap_err();
    assert_eq!((e.code, e.detail.as_deref()), (Code::ContainerConflict, Some("project_in_use")));
    // an OWNED container of this restore + project is fine; owned by another restore is not
    let ol = owner_labels(RID, AG);
    let mut labels: Vec<(&str, &str)> = ol.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    labels.push(("com.docker.compose.project", "app"));
    let mine = vec![cf(&id('8'), &["uptime-kuma"], "louislam/uptime-kuma:1", &labels)];
    assert!(check_up(&render, "app", RID, AG, &mine, &protected_ids(&mine, OWN, &[])).is_ok());
    assert!(check_up(&render, "app", "99999999-9999-4999-8999-999999999999", AG, &mine, &protected_ids(&mine, OWN, &[])).is_err());
}

#[tokio::test]
async fn guard_checks_existing_volumes_and_networks_for_ownership() {
    let w = world(CLEAN_YML);
    let d = w.doc(None);
    // nothing exists yet: fine
    super::guard::check_resources(&w.ops, &d, RID, AG).await.unwrap();
    w.ops.0.lock().unwrap().volumes.insert("app_pgdata".into(), HashMap::new());
    assert_eq!(super::guard::check_resources(&w.ops, &d, RID, AG).await.unwrap_err().code, Code::VolumeExists);
    w.ops.0.lock().unwrap().volumes.insert("app_pgdata".into(), owner_labels(RID, AG));
    super::guard::check_resources(&w.ops, &d, RID, AG).await.unwrap();
    w.ops.0.lock().unwrap().networks.insert("app_default".into(), HashMap::new());
    assert_eq!(super::guard::check_resources(&w.ops, &d, RID, AG).await.unwrap_err().code, Code::NetworkExists);
}

// ---- re-check chain + up + db (fake compose CLI) --------------------------------------------------------------------------------------
async fn rendered_sha(w: &W, env: &RestoreEnv, doc: &Value) -> String {
    w.can_render(doc, 2);
    let r = w.render(env, None, json!({}), json!([])).await.unwrap();
    r["rendered_sha256"].as_str().unwrap().to_string()
}
fn up_payload(w: &W, sha: &str, approval: Value, over: Option<&str>, env_pairs: Value, volumes: Value) -> Vec<u8> {
    let mut b = w.body(over, env_pairs, json!([]));
    b["compose_sha256"] = json!(sha);
    b["approval"] = approval;
    b["volumes"] = volumes;
    w.payload(b)
}
async fn up(w: &W, env: &RestoreEnv, p: &[u8]) -> R<Value> {
    execute(env, &w.ops, &w.r.pins, &NullSink, &task("compose_up"), p).await
}

#[tokio::test]
async fn up_runs_the_closed_argument_list_and_never_leaks_the_canary() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let d = w.doc(None);
    let sha = rendered_sha(&w, &env, &d).await; // render once to learn the view hash
    w.can_render(&d, 2);
    let p = up_payload(&w, &sha, Value::Null, Some("services: {}\n"), json!({"OVERRIDE_PROBE": CANARY}), json!(["app_appdata"]));
    // the override changes the render's input but the fake render output is identical ⇒ same hash
    let res = up(&w, &env, &p).await.unwrap();
    assert_eq!(res["project"], "app");
    let log = w.log();
    let ws = w.ws.display().to_string();
    let want = format!("ARGS: [--project-name] [app] [--project-directory] [{ws}/.portabase/empty] [-f] [{ws}/.portabase/secret/rendered.json] [up] [-d] [--no-build] [--pull] [missing]");
    assert!(log.contains(&want), "argv not the closed list:\n{log}");
    assert!(!log.contains(CANARY), "canary in argv / process env / stdin");
    assert!(!log.contains("--remove-orphans") && !log.contains("[down]") && !log.contains("[-v]") && !log.contains("[build]") && !log.contains("[-y]"));
    // env_clear: only the fixed keys
    let env_block = log.split("ENV:\n").nth(1).unwrap().split("STDIN:").next().unwrap();
    for line in env_block.lines().filter(|l| !l.is_empty()) {
        let k = line.split('=').next().unwrap();
        assert!(["HOME", "PATH", "PWD", "SHLVL", "_", "OLDPWD", "DOCKER_HOST"].contains(&k), "unexpected env key {k}");
    }
    // the verified render existed while compose ran, and is gone afterwards
    assert!(w.home().join("rendered.copy").exists());
    assert_eq!(w.secret_files(), 0);
    assert!(std::fs::read_to_string(w.home().join("rendered.copy")).unwrap().contains(CANARY), "compose gets the FULL render");
}

#[tokio::test]
async fn recheck_chain_fails_closed_in_order() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let d = w.doc(None);
    let sha = rendered_sha(&w, &env, &d).await;
    let call = |p: Vec<u8>, doc: Value| {
        let (w, env) = (&w, &env);
        async move {
            w.can_render(&doc, 2);
            up(w, env, &p).await
        }
    };
    // changed hash (one byte off) ⇒ approval_invalid compose_changed
    let e = call(up_payload(&w, &"0".repeat(64), Value::Null, None, json!({}), json!([])), d.clone()).await.unwrap_err();
    assert_eq!((e.code, e.detail.as_deref()), (Code::ApprovalInvalid, Some("compose_changed")));
    // token on an allow verdict ⇒ over_broad
    let tok = flagged_token(&w, &sha, json!([{"service": "web", "rules": ["privileged"]}]));
    let e = call(up_payload(&w, &sha, tok, None, json!({}), json!([])), d.clone()).await.unwrap_err();
    assert_eq!((e.code, e.detail.as_deref()), (Code::ApprovalInvalid, Some("over_broad")));
    // hard refusal (render reads a file outside the root) ⇒ policy_refused before the hash is even compared
    let mut hard = d.clone();
    hard["services"]["web"]["env_file"] = json!([{"path": "/etc/passwd"}]);
    let e = call(up_payload(&w, &sha, Value::Null, None, json!({}), json!([])), hard).await.unwrap_err();
    assert_eq!(e.code, Code::PolicyRefused);
    // flagged verdict: no token ⇒ none; token covering another rule ⇒ not_covered / over_broad; exact token ⇒ passes the chain
    let mut priv_doc = d.clone();
    priv_doc["services"]["web"]["privileged"] = json!(true);
    let psha = rendered_sha(&w, &env, &priv_doc).await;
    let e = call(up_payload(&w, &psha, Value::Null, None, json!({}), json!([])), priv_doc.clone()).await.unwrap_err();
    assert_eq!((e.code, e.detail.as_deref()), (Code::ApprovalInvalid, Some("none")));
    let wrong = flagged_token(&w, &psha, json!([{"service": "web", "rules": ["devices"]}]));
    let e = call(up_payload(&w, &psha, wrong, None, json!({}), json!([])), priv_doc.clone()).await.unwrap_err();
    assert_eq!(e.detail.as_deref(), Some("not_covered"));
    let broad = flagged_token(&w, &psha, json!([{"service": "web", "rules": ["privileged", "devices"]}]));
    let e = call(up_payload(&w, &psha, broad, None, json!({}), json!([])), priv_doc.clone()).await.unwrap_err();
    assert_eq!(e.detail.as_deref(), Some("over_broad"));
    let other = flagged_token(&w, &psha, json!([{"service": "db", "rules": ["privileged"]}]));
    let e = call(up_payload(&w, &psha, other, None, json!({}), json!([])), priv_doc.clone()).await.unwrap_err();
    assert_eq!(e.detail.as_deref(), Some("not_covered"));
    let good = flagged_token(&w, &psha, json!([{"service": "web", "rules": ["privileged"]}]));
    call(up_payload(&w, &psha, good.clone(), None, json!({}), json!([])), priv_doc.clone()).await.unwrap();
    // the same token against a render that changed (override value) ⇒ compose_changed
    let mut changed = priv_doc.clone();
    changed["services"]["web"]["image"] = json!("nginx:2");
    let e = call(up_payload(&w, &psha, good, None, json!({}), json!([])), changed).await.unwrap_err();
    assert_eq!(e.detail.as_deref(), Some("compose_changed"));
    // a restored volume that the render does not declare ⇒ volume_not_in_compose
    let e = call(up_payload(&w, &sha, Value::Null, None, json!({}), json!(["app_ghost"])), d.clone()).await.unwrap_err();
    assert_eq!(e.code, Code::VolumeNotInCompose);
    assert_eq!(w.secret_files(), 0);
}

#[tokio::test]
async fn symlinked_bind_source_under_the_workspace_is_refused() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let d = w.doc(None);
    let sha = rendered_sha(&w, &env, &d).await;
    std::fs::remove_dir(w.ws.join("compose/www")).unwrap();
    std::os::unix::fs::symlink("/etc", w.ws.join("compose/www")).unwrap();
    w.can_render(&d, 2);
    let e = up(&w, &env, &up_payload(&w, &sha, Value::Null, None, json!({}), json!([]))).await.unwrap_err();
    assert_eq!(e.code, Code::SymlinkEscape);
    assert!(!w.log().contains("[up]"), "nothing started");
}

#[tokio::test]
async fn up_refuses_foreign_and_protected_containers_without_touching_them() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let mut d = w.doc(None);
    let sha = rendered_sha(&w, &env, &d).await;
    d["services"]["web"]["container_name"] = json!("w17ii-foreign");
    let sha2 = rendered_sha(&w, &env, &d).await;
    w.ops.0.lock().unwrap().containers = vec![cf(&id('9'), &["w17ii-foreign"], "busybox", &[])];
    w.can_render(&d, 2);
    let e = up(&w, &env, &up_payload(&w, &sha2, Value::Null, None, json!({}), json!([]))).await.unwrap_err();
    assert_eq!(e.code, Code::ContainerConflict);
    // own container name ⇒ protected
    d["services"]["web"]["container_name"] = json!("agent");
    let sha3 = rendered_sha(&w, &env, &d).await;
    w.ops.0.lock().unwrap().containers = vec![cf(OWN, &["agent"], "x", &[])];
    w.can_render(&d, 2);
    let e = up(&w, &env, &up_payload(&w, &sha3, Value::Null, None, json!({}), json!([]))).await.unwrap_err();
    assert_eq!(e.code, Code::ProtectedContainer);
    assert!(w.ops.0.lock().unwrap().removed_containers.is_empty() && !w.log().contains("[up]"));
    let _ = sha;
}

fn pg_tar_gz(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    let f = std::fs::File::create(&p).unwrap();
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(f, flate2::Compression::fast()));
    let data = b"PGDMP-test-dump-bytes";
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o600);
    h.set_cksum();
    b.append_data(&mut h, "dump", &data[..]).unwrap();
    b.into_inner().unwrap().finish().unwrap();
    p
}

#[tokio::test]
async fn restore_db_runs_only_the_fixed_scripts_and_resumes() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let d = w.doc(None);
    let sha = rendered_sha(&w, &env, &d).await;
    let idx = w.r.v.stage_world.db_index;
    std::fs::rename(pg_tar_gz(&w.ws, "tmp-dump.tgz"), w.ws.join(format!(".portabase/stage/a{idx}.tar.gz"))).unwrap();
    let mut b = w.body(Some("services: {}\n"), json!({"OVERRIDE_PROBE": CANARY}), json!([]));
    b["compose_sha256"] = json!(sha);
    b["approval"] = Value::Null;
    b["dbs"] = json!([{"index": idx, "service": "db"}]);
    let p = w.payload(b);
    w.can_render(&d, 2);
    let res = execute(&env, &w.ops, &w.r.pins, &NullSink, &task("restore_db"), &p).await.unwrap();
    assert_eq!(res["dbs"][0], json!({"service": "db", "format": "pg_custom", "status": "restored"}));
    let log = w.log();
    let ws = w.ws.display().to_string();
    let base = format!("[--project-name] [app] [--project-directory] [{ws}/.portabase/empty] [-f] [{ws}/.portabase/secret/rendered.json]");
    assert!(log.contains(&format!("ARGS: {base} [up] [-d] [--no-deps] [--no-build] [--pull] [missing] [db]")));
    assert!(log.contains(&format!("ARGS: {base} [exec] [-T] [db] [sh] [-c] [{}]", db::PG_ISREADY)));
    assert!(log.contains(&format!("ARGS: {base} [exec] [-T] [db] [sh] [-c] [{}]", db::PG_RESTORE_FC)));
    assert!(log.contains("STDIN:PGDMP-test-d"), "the dump reaches pg_restore on stdin, not in argv");
    assert!(!log.contains(CANARY) && !log.contains("PGDMP-test-dump"));
    assert!(!w.ws.join(format!(".portabase/tmp/db{idx}")).exists(), "the extracted dump is deleted");
    // a second run skips the finished database (journal) and needs no compose call for it
    w.can_render(&d, 2);
    let n_before = w.log().matches("---").count();
    let res = execute(&env, &w.ops, &w.r.pins, &NullSink, &task("restore_db"), &p).await.unwrap();
    assert_eq!(res["dbs"][0]["status"], "reused");
    assert_eq!(w.log().matches("---").count(), n_before);
    // a service that is not in the render / a non-PostgreSQL artifact are refused
    let mut bad = serde_json::from_slice::<Value>(&p).unwrap();
    bad["dbs"] = json!([{"index": idx, "service": "ghost"}]);
    w.can_render(&d, 2);
    let e = execute(&env, &w.ops, &w.r.pins, &NullSink, &task("restore_db"), &serde_json::to_vec(&bad).unwrap()).await.unwrap_err();
    assert_eq!(e.code, Code::ManifestMismatch);
    bad["dbs"] = json!([{"index": w.r.v.stage_world.volume_index, "service": "db"}]);
    w.can_render(&d, 2);
    let e = execute(&env, &w.ops, &w.r.pins, &NullSink, &task("restore_db"), &serde_json::to_vec(&bad).unwrap()).await.unwrap_err();
    assert_eq!(e.code, Code::ManifestMismatch);
}

#[tokio::test]
async fn compose_cli_failures_become_closed_codes_without_output() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let d = w.doc(None);
    let sha = rendered_sha(&w, &env, &d).await;
    // `false` as the compose binary: exits 1
    let mut env_fail = env.clone();
    env_fail.compose.as_mut().unwrap().bin = PathBuf::from("/bin/false");
    w.can_render(&d, 2);
    let e = up(&w, &env_fail, &up_payload(&w, &sha, Value::Null, None, json!({}), json!([]))).await.unwrap_err();
    assert_eq!((e.code, e.detail.as_deref()), (Code::ComposeFailed, Some("exit_1")));
    assert_eq!(w.secret_files(), 0, "rendered.json removed after a failure");
    env_fail.compose.as_mut().unwrap().bin = PathBuf::from("/nonexistent/docker-compose");
    w.can_render(&d, 2);
    let e = up(&w, &env_fail, &up_payload(&w, &sha, Value::Null, None, json!({}), json!([]))).await.unwrap_err();
    assert_eq!(e.code, Code::ComposeUnavailable);
}

#[tokio::test]
async fn the_secret_dir_is_emptied_when_a_deadline_drops_the_task() {
    let w = world(CLEAN_YML);
    let env = w.env();
    let d = w.doc(None);
    let sha = rendered_sha(&w, &env, &d).await;
    w.can_render(&d, 2);
    // a compose binary that never returns: `sleep`-like — emulate by a future that is dropped by a timeout after rendered.json was written
    let mut env_slow = env.clone();
    env_slow.compose.as_mut().unwrap().bin = slow_bin();
    let p = up_payload(&w, &sha, Value::Null, None, json!({}), json!([]));
    let fut = up(&w, &env_slow, &p);
    let r = tokio::time::timeout(Duration::from_millis(1500), fut).await;
    assert!(r.is_err(), "the fake compose binary sleeps; the deadline drops the task");
    assert_eq!(w.secret_files(), 0, "SecretGuard cleans on drop");
}

#[tokio::test]
async fn cleanup_containers_removes_only_owned_containers_of_this_project() {
    let w = world(CLEAN_YML);
    let ol = owner_labels(RID, w.r.env.agent_id.as_str());
    let mut owned: Vec<(&str, &str)> = ol.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    owned.push(("com.docker.compose.project", "app"));
    {
        let mut s = w.ops.0.lock().unwrap();
        s.containers = vec![cf(&id('1'), &["app-web-1"], "nginx", &owned), cf(&id('2'), &["foreign"], "nginx", &[("com.docker.compose.project", "app")]), cf(OWN, &["agent"], "x", &owned), cf(&id('3'), &["other-restore"], "nginx", &[(LABEL_RESTORE, "99999999-9999-4999-8999-999999999999"), (LABEL_AGENT, w.r.env.agent_id.as_str()), ("com.docker.compose.project", "app")])];
    }
    let mut env = w.env();
    env.compose.as_mut().unwrap().own_id = OWN.into();
    let p = w.payload(json!({"workspace_remove": false, "volumes": false, "networks": false, "containers": true}));
    let res = crate::fork::restore::execute(&env, &w.ops, &w.r.pins, &task("restore_cleanup"), &p).await.unwrap();
    assert_eq!(res["removed"]["containers"], 1);
    assert_eq!(res["kept_foreign"], 3, "the unowned project-app container, the other restore's one and the (protected) agent are kept, not removed");
    let s = w.ops.0.lock().unwrap();
    assert_eq!(s.removed_containers, vec![id('1')]);
    assert!(s.containers.iter().any(|c| c.id == OWN), "the agent's own container is never removed, even with owner labels");
}

#[tokio::test]
async fn sqlite_placement_removes_stale_siblings_first_and_keeps_owner_and_mode() {
    use crate::fork::restore::apply::place_sqlite;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("kuma.db");
    std::fs::write(&f, b"SQLite format 3").unwrap();
    // the volume artifact restored kuma.db owned by 1000:1000 ⇒ that wins over the archive entry
    let ops = Fake::new();
    ops.0.lock().unwrap().file_metas.insert(("app_kuma".into(), "kuma.db".into()), (1000, 1000, 0o644));
    place_sqlite(&ops, "app_kuma", "kuma.db", &f, Some((0, 0, 0o600))).await.unwrap();
    let s = ops.0.lock().unwrap();
    let rm = s.events.iter().position(|e| e.starts_with("rm:")).expect("helper_rm called");
    let put = s.events.iter().position(|e| e.starts_with("put:")).expect("put called");
    assert!(rm < put, "WAL siblings are removed BEFORE the file is placed: {:?}", s.events);
    for sib in ["/vol/kuma.db-wal", "/vol/kuma.db-shm", "/vol/kuma.db-journal"] {
        assert!(s.events[rm].contains(sib), "{sib}");
    }
    assert_eq!(s.put_metas, vec![(1000, 1000, 0o644)]);
    drop(s);
    // no file at that path yet ⇒ the archive entry's owner / mode; neither ⇒ 0:0 0644
    let ops2 = Fake::new();
    place_sqlite(&ops2, "app_kuma", "kuma.db", &f, Some((1000, 1000, 0o640))).await.unwrap();
    place_sqlite(&ops2, "app_kuma", "other.db", &f, None).await.unwrap();
    assert_eq!(ops2.0.lock().unwrap().put_metas, vec![(1000, 1000, 0o640), (0, 0, 0o644)]);
}
