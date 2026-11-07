use super::*;
use crate::fork::config::{ConfigError, Startup, check_transport, load, parse_bundle};
use base64::Engine as _;
use serde_json::json;
use std::collections::HashMap;

const AGENT: &str = "11111111-1111-4111-8111-111111111111";
fn secret() -> String {
    "A".repeat(43)
}
fn bundle_json(v: &Vectors, url: &str) -> serde_json::Value {
    let p = pins(v);
    json!({"v":1,"enroll_id":v.enroll_id,"server_url":url,"agent_id":AGENT,"credential":format!("fork.{AGENT}.{}", secret()),"task_key_b64":v.task_key_b64,
        "pins":v.pins.iter().map(|p| json!({"kid":p.kid,"pem":p.pem})).collect::<Vec<_>>(),"pin_fingerprint":p[0].fingerprint})
}
fn enc(j: &serde_json::Value) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(j).unwrap())
}

#[test]
fn transport_policy_https_only_with_one_loopback_lab_exemption() {
    assert_eq!(check_transport("https://dash.example.com", false), Ok(false));
    assert_eq!(check_transport("http://dash.example.com", false), Err(ConfigError::InsecureTransport));
    assert_eq!(check_transport("http://localhost:3000", false), Err(ConfigError::InsecureTransport));
    // the pilot: plain-HTTP LAN dashboard — refused, with or without the lab switch
    assert_eq!(check_transport("http://192.168.8.32:8887", false), Err(ConfigError::InsecureTransport));
    assert_eq!(check_transport("http://192.168.8.32:8887", true), Err(ConfigError::InsecureTransport));
    for u in ["http://localhost:3000", "http://forklab-dashboard.localhost:18887", "http://127.0.0.1:3000", "http://[::1]:3000"] {
        assert_eq!(check_transport(u, true), Ok(true), "{u}");
    }
    for u in ["http://localhost.evil.com", "http://127.0.0.1.evil.com", "http://10.0.0.1", "ftp://x", "https://u:p@x.example", "not a url"] {
        assert!(check_transport(u, true).is_err(), "{u}");
    }
}

#[test]
fn bundle_parses_and_pins_are_checked_against_their_kid_and_fingerprint() {
    let v = vectors();
    let (p, insecure) = parse_bundle(&enc(&bundle_json(&v, "https://dash.example")), false).unwrap();
    assert!(!insecure);
    assert_eq!(p.agent_id, AGENT);
    assert_eq!(p.pins.len(), 1);
    // wrong kid for the key
    let mut j = bundle_json(&v, "https://dash.example");
    j["pins"][0]["kid"] = json!("000000000000");
    assert!(parse_bundle(&enc(&j), false).is_err());
    // fingerprint that matches no pin
    let mut j = bundle_json(&v, "https://dash.example");
    j["pin_fingerprint"] = json!("0".repeat(64));
    assert_eq!(parse_bundle(&enc(&j), false).err(), Some(ConfigError::Invalid("pin_fingerprint")));
    // credential for another agent, short key, no pins, garbage
    let mut j = bundle_json(&v, "https://dash.example");
    j["credential"] = json!(format!("fork.22222222-2222-4222-8222-222222222222.{}", secret()));
    assert!(parse_bundle(&enc(&j), false).is_err());
    let mut j = bundle_json(&v, "https://dash.example");
    j["task_key_b64"] = json!("AAAA");
    assert!(parse_bundle(&enc(&j), false).is_err());
    let mut j = bundle_json(&v, "https://dash.example");
    j["pins"] = json!([]);
    assert!(parse_bundle(&enc(&j), false).is_err());
    assert_eq!(parse_bundle("!!!", false).err(), Some(ConfigError::BadBundle));
    // an http bundle is refused unless lab switch + loopback
    assert_eq!(parse_bundle(&enc(&bundle_json(&v, "http://192.168.8.32:8887")), true).err(), Some(ConfigError::InsecureTransport));
    assert_eq!(parse_bundle(&enc(&bundle_json(&v, "http://forklab.localhost:18887")), true).map(|x| x.1), Ok(true));
}

fn env_of(m: HashMap<&'static str, String>) -> impl Fn(&str) -> Option<String> {
    move |k| m.get(k).cloned()
}

#[test]
fn channel_is_off_unless_explicitly_enabled_and_never_without_a_private_bundle_file() {
    let v = vectors();
    assert!(matches!(load(&env_of(HashMap::new())), Ok(Startup::Disabled(_))));
    assert!(matches!(load(&env_of(HashMap::from([("FORK_CHANNEL_ENABLED", "false".to_string())]))), Ok(Startup::Disabled(_))));
    assert!(matches!(load(&env_of(HashMap::from([("FORK_CHANNEL_ENABLED", "1".to_string())]))), Ok(Startup::Disabled(_)))); // strict `true`
    assert_eq!(load(&env_of(HashMap::from([("FORK_CHANNEL_ENABLED", "true".to_string())]))).err(), Some(ConfigError::MissingBundlePath));
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("bundle");
    std::fs::write(&f, enc(&bundle_json(&v, "https://dash.example"))).unwrap();
    let env = |extra: &[(&'static str, String)]| {
        let mut m = HashMap::from([("FORK_CHANNEL_ENABLED", "true".to_string()), ("FORK_CHANNEL_BUNDLE_FILE", f.display().to_string()), ("FORK_CHANNEL_STATE_FILE", dir.path().join("st.json").display().to_string())]);
        m.extend(extra.iter().cloned());
        env_of(m)
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load(&env(&[])).err(), Some(ConfigError::BundlePermissions));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    match load(&env(&[("FORK_CHANNEL_POLL_SECONDS", "9".to_string())])) {
        Ok(Startup::Active(c)) => {
            assert_eq!(c.poll_seconds, 9);
            assert!(!format!("{c:?}").contains(&secret()), "Debug must not print the credential");
        }
        _ => panic!("expected active"),
    }
}
