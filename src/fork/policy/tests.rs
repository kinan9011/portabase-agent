use super::approval::{self, Ctx};
use super::raw::{RawResult, check_raw};
use super::rendered::evaluate;
use super::rules::{HARD_IDS, RULE_IDS, Rules, is_canon_path, rules_sha256_ts};
use super::view::policy_view;
use super::yaml::{Node, RESTORE_YAML_LIMITS, YamlReject, parse_yaml_limited};
use serde_json::{Value, json};
use std::collections::HashMap;

const VECTORS: &[u8] = include_bytes!("corpus/compose-policy-vectors.json");
const APPROVALS: &[u8] = include_bytes!("corpus/compose-policy-approval-vectors.json");
const SOURCE: &[u8] = include_bytes!("corpus/SOURCE.json");

fn rules() -> &'static Rules {
    Rules::embedded().expect("embedded rules")
}
fn vectors() -> Value {
    serde_json::from_slice(VECTORS).unwrap()
}
fn text_of(file: &Value) -> String {
    if let Some(t) = file["text"].as_str() {
        return t.to_string();
    }
    String::new()
}

#[test]
fn corpus_is_the_dashboards_and_the_rule_file_matches_the_rust_consts() {
    use sha2::{Digest, Sha256};
    let src: Value = serde_json::from_slice(SOURCE).unwrap();
    for (name, bytes) in [("compose-deny.json", super::RULES_JSON), ("compose-policy-vectors.json", VECTORS), ("compose-policy-approval-vectors.json", APPROVALS)] {
        assert_eq!(src["files"][name].as_str().unwrap(), hex::encode(Sha256::digest(bytes)), "{name}");
    }
    let r = rules();
    assert_eq!(r.version, 2);
    let ids: Vec<&str> = r.rules.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(ids, RULE_IDS.to_vec());
    let hard: Vec<&str> = r.hard_refusals.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(hard, HARD_IDS.to_vec());
    assert_eq!(rules_sha256_ts().len(), 64);
}

#[test]
fn rendered_vectors_all_64() {
    let v = vectors();
    let cases = v["rendered"].as_array().unwrap();
    assert_eq!(cases.len(), 64);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let roots: Vec<String> = c["roots"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_string()).collect();
        let bytes = match c["compose"].as_str() {
            Some(t) => t.as_bytes().to_vec(), // literal text vectors (not-json, oversized …)
            None => serde_json::to_vec(&c["compose"]).unwrap(),
        };
        let got = evaluate(rules(), &bytes, &roots, &RawResult::clean());
        let exp = &c["expect"];
        assert_eq!(got.verdict, exp["verdict"].as_str().unwrap(), "{name}: verdict {:?} {:?}", got.hard, got.findings);
        let hard: Vec<(Option<&str>, &str)> = exp["hard"].as_array().unwrap().iter().map(|h| (h[0].as_str(), h[1].as_str().unwrap())).collect();
        let mut got_hard: Vec<(Option<&str>, &str)> = got.hard.iter().map(|h| (h.service.as_deref(), h.code)).collect();
        let mut hard = hard;
        hard.sort();
        got_hard.sort();
        hard.dedup();
        got_hard.dedup();
        if exp["verdict"] == "deny" {
            let a: std::collections::BTreeSet<&str> = hard.iter().map(|h| h.1).collect();
            let b: std::collections::BTreeSet<&str> = got_hard.iter().map(|h| h.1).collect();
            assert_eq!(a, b, "{name}: hard ids");
        } else {
            let mut f: Vec<(&str, &str)> = got.findings.iter().map(|f| (f.service.as_str(), f.rule)).collect();
            let mut e: Vec<(&str, &str)> = exp["findings"].as_array().unwrap().iter().map(|p| (p[0].as_str().unwrap(), p[1].as_str().unwrap())).collect();
            f.sort();
            f.dedup();
            e.sort();
            e.dedup();
            assert_eq!(f, e, "{name}: findings");
        }
    }
}

#[test]
fn the_policy_view_changes_no_verdict_for_any_rendered_vector() {
    let v = vectors();
    for c in v["rendered"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let Some(_) = c["compose"].as_object() else { continue };
        let roots: Vec<String> = c["roots"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_string()).collect();
        let full = serde_json::to_vec(&c["compose"]).unwrap();
        let view = policy_view(&full).expect(name);
        let (a, b) = (evaluate(rules(), &full, &roots, &RawResult::clean()), evaluate(rules(), &view, &roots, &RawResult::clean()));
        assert_eq!((a.verdict, &a.hard, &a.findings), (b.verdict, &b.hard, &b.findings), "{name}");
        assert_eq!(b.compose_sha256, crate::fork::crypto::sha256_hex(&view));
        // idempotent: blanking a view changes nothing
        assert_eq!(policy_view(&view).unwrap(), view, "{name}");
    }
}

#[test]
fn the_policy_view_blanks_exactly_the_specified_fields() {
    let full = json!({"name":"p","x-secret":{"t":"abc","n":1},"services":{"web":{"image":"nginx:1","environment":{"A":"s3cret","B":null},"labels":["a=b"],"command":["sh","-c","echo $X"],
        "healthcheck":{"test":["CMD","x"],"interval":"5s"},"ports":[{"target":80,"published":"8080"}],"x-note":"hidden","volumes":[{"type":"bind","source":"/restore/a","target":"/a"}]},
        "db":{"environment":["POSTGRES_PASSWORD=zzz"],"secrets":[{"source":"s","target":"t"}]}},"secrets":{"s":{"content":"c","file":"/etc/x"}},"configs":{"c":{"environment":"VAR"}}});
    let view: Value = serde_json::from_slice(&policy_view(&serde_json::to_vec(&full).unwrap()).unwrap()).unwrap();
    assert_eq!(view["services"]["web"]["environment"], json!({"A":"","B":null}));
    assert_eq!(view["services"]["web"]["command"], json!(["","",""]));
    assert_eq!(view["services"]["web"]["healthcheck"], json!({"test":["",""],"interval":""}));
    assert_eq!(view["services"]["web"]["image"], "nginx:1");
    assert_eq!(view["services"]["web"]["ports"], json!([{"target":80,"published":"8080"}]));
    assert_eq!(view["services"]["web"]["volumes"][0]["source"], "/restore/a");
    assert_eq!(view["services"]["web"]["x-note"], "");
    assert_eq!(view["x-secret"], json!({"t":"","n":""}));
    assert_eq!(view["secrets"]["s"], json!({"content":"","file":"/etc/x"}));
    assert_eq!(view["configs"]["c"], json!({"environment":""}));
    let s = view.to_string();
    for canary in ["s3cret", "zzz", "echo", "abc"] {
        assert!(!s.contains(canary), "{canary}");
    }
    assert!(policy_view(b"not json").is_err() && policy_view(&vec![b' '; 2 * 1024 * 1024 + 1]).is_err());
    assert!(policy_view(format!("{}{}", "[".repeat(40), "]".repeat(40)).as_bytes()).is_err());
}

#[test]
fn raw_vectors_all_27() {
    let v = vectors();
    let cases = v["raw"].as_array().unwrap();
    assert_eq!(cases.len(), 27);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let mut files: HashMap<String, String> = c["files"].as_array().unwrap().iter().map(|f| (f["path"].as_str().unwrap().to_string(), text_of(f))).collect();
        // `text_gen.pad_comment_bytes` (case level): that many bytes of `#` comment are appended to the first file (deviation D-1: the plan said no such vector exists)
        if let Some(pad) = c["text_gen"]["pad_comment_bytes"].as_u64() {
            files.get_mut(c["files"][0]["path"].as_str().unwrap()).unwrap().push_str(&"#".repeat(pad as usize));
        }
        let entry: Vec<String> = c["entry"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect();
        let got = check_raw(rules(), c["root"].as_str().unwrap(), &entry, &|p| files.get(p).cloned()).expect(name);
        let exp = &c["expect"];
        assert_eq!(got.refused, exp["refused"].as_bool().unwrap(), "{name}: {got:?}");
        assert_eq!(got.reason, exp["reason"].as_str(), "{name}: {got:?}");
        let gv: Vec<(String, Option<String>, String)> = got.violations.iter().map(|x| (x.kind.to_string(), x.service.clone(), x.target.clone())).collect();
        let ev: Vec<(String, Option<String>, String)> = exp["violations"].as_array().unwrap().iter().map(|x| (x["kind"].as_str().unwrap().to_string(), x["service"].as_str().map(str::to_string), x["target"].as_str().unwrap().to_string())).collect();
        assert_eq!(gv, ev, "{name}");
    }
}

#[test]
fn approval_vectors_all_12() {
    let a: Value = serde_json::from_slice(APPROVALS).unwrap();
    let cases = a["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let roots: Vec<String> = c["roots"].as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_string()).collect();
        let verdict = evaluate(rules(), c["compose_text"].as_str().unwrap().as_bytes(), &roots, &RawResult::clean());
        let ctx = Ctx { stack_id: c["context"]["stack_id"].as_str().unwrap(), rp_id: c["context"]["rp_id"].as_str().unwrap(), agent_id: c["context"]["target_agent_id"].as_str().unwrap() };
        let got = approval::check(&verdict, Some(&c["token"]), &ctx);
        let exp = c["expect"].as_str().unwrap();
        // D-7: `rules_sha256` is informational on the agent ⇒ the `rules_changed` vector is accepted here
        let exp = if exp == "rules_changed" { "ok" } else { exp };
        match got {
            Ok(()) => assert_eq!(exp, "ok", "{name}"),
            Err(code) => assert_eq!(code, exp, "{name}"),
        }
    }
}

#[test]
fn approval_on_allow_and_without_token() {
    let v = evaluate(rules(), br#"{"name":"r","services":{"a":{"image":"x"}}}"#, &["/w".into()], &RawResult::clean());
    assert_eq!(v.verdict, "allow");
    let ctx = Ctx { stack_id: "11111111-1111-4111-8111-111111111111", rp_id: "22222222-2222-4222-8222-222222222222", agent_id: "33333333-3333-4333-8333-333333333333" };
    assert_eq!(approval::check(&v, None, &ctx), Ok(()));
    assert_eq!(approval::check(&v, Some(&Value::Null), &ctx), Ok(()));
    assert_eq!(approval::check(&v, Some(&json!({"v":1})), &ctx), Err("invalid"));
    let f = evaluate(rules(), br#"{"name":"r","services":{"a":{"image":"x","privileged":true}}}"#, &["/w".into()], &RawResult::clean());
    assert_eq!(f.verdict, "needs-explicit-override");
    assert_eq!(approval::check(&f, None, &ctx), Err("none"));
}

fn yaml(t: &str) -> Result<Node, YamlReject> {
    parse_yaml_limited(t, &RESTORE_YAML_LIMITS)
}

#[test]
fn yaml_locals_not_in_the_corpus() {
    // merge key carrying an outside env_file ⇒ the raw check sees it
    let files: HashMap<String, String> = [("/w/c.yml".to_string(), "x-base: &base\n  env_file: /etc/passwd\nservices:\n  app:\n    <<: *base\n    image: x\n".to_string())].into();
    let r = check_raw(rules(), "/w", &["/w/c.yml".into()], &|p| files.get(p).cloned()).unwrap();
    assert!(r.refused && r.violations.iter().any(|v| v.kind == "env_file" && v.target == "/etc/passwd" && v.service.as_deref() == Some("app")), "{r:?}");
    // compose tags are refused exactly like the dashboard (R-k)
    assert_eq!(yaml("services:\n  a:\n    ports: !override [1]\n").unwrap_err().reason(), "yaml_invalid");
    assert_eq!(yaml("services:\n  a:\n    ports: !reset []\n").unwrap_err().reason(), "yaml_invalid");
    assert_eq!(yaml("a: !!python/object/apply:os.system ['id']\n").unwrap_err().reason(), "yaml_invalid");
    assert!(yaml("a: !!str 5\nb: !!seq [1]\nc: !!map {x: 1}\n").is_ok());
    // alias bomb ⇒ limits
    let bomb = "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n";
    assert_eq!(yaml(bomb).unwrap_err().reason(), "limits");
    assert_eq!(yaml("a: 1\n---\nb: 2\n").unwrap_err().reason(), "yaml_invalid");
    assert_eq!(yaml("a: &x\n  - *x\n").unwrap_err().reason(), "yaml_invalid"); // self reference
    assert_eq!(yaml("a: *nope\n").unwrap_err().reason(), "yaml_invalid");
    // scalars: core schema; quoted stays a string; merge precedence (explicit key wins)
    let n = yaml("n: ~\nb: true\ni: 12\nh: 0x1F\nf: 1.5\ne: \"null\"\ns: 'true'\nm: &m {k: 1, j: 2}\no:\n  <<: *m\n  k: 9\n").unwrap();
    assert_eq!(n.get("n"), Some(&Node::Null));
    assert_eq!(n.get("b"), Some(&Node::Bool(true)));
    assert_eq!(n.get("i"), Some(&Node::Int(12)));
    assert_eq!(n.get("h"), Some(&Node::Int(31)));
    assert_eq!(n.get("f"), Some(&Node::Float(1.5)));
    assert_eq!(n.get("e"), Some(&Node::Str("null".into())));
    assert_eq!(n.get("s"), Some(&Node::Str("true".into())));
    assert_eq!(n.get("o").unwrap().get("k"), Some(&Node::Int(9)));
    assert_eq!(n.get("o").unwrap().get("j"), Some(&Node::Int(2)));
    // limits and robustness: depth, indent, size, empty, garbage never panic
    assert_eq!(yaml(&format!("a: {}{}\n", "[".repeat(30), "]".repeat(30))).unwrap_err().reason(), "limits");
    assert_eq!(yaml(&format!("{}a: 1\n", " ".repeat(300))).unwrap_err().reason(), "limits");
    assert_eq!(yaml(&"#".repeat(300_000)).unwrap_err().reason(), "limits");
    assert_eq!(yaml("").unwrap(), Node::Null);
    for junk in ["{", "a: [", "\t- x\n", ":::", "&a", "- &a\n- *b\n", "? [x\n"] {
        let _ = yaml(junk);
    }
    // dup key in flow style, `<<` twice
    assert_eq!(yaml("{a: 1, a: 2}").unwrap_err().reason(), "yaml_invalid");
    assert!(is_canon_path("/restore/app") && !is_canon_path("/restore/../x") && !is_canon_path("/restore//x") && !is_canon_path("/restore/") && !is_canon_path("rel"));
}
