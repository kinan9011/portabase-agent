//! Rule file v2 (W20a, D27). Parsed once; a rule file that fails its schema makes `Rules::embedded()` fail, so every consumer fails closed
//! (compose capability not reported). Path predicates are the normative D-2 definitions (the corpus is the oracle).
use serde::Deserialize;
use std::sync::OnceLock;

pub const RULE_IDS: [&str; 10] = ["privileged", "network_mode_host", "pid_host", "ipc_host", "devices", "cap_add", "docker_sock", "bind_outside_root", "shared_namespace", "unknown_directive"];
pub const HARD_IDS: [&str; 8] = ["read_outside_root", "path_ambiguous", "yaml_invalid", "limits", "raw_incomplete", "service_name", "top_level_unknown", "shape_invalid"];

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct RuleEntry {
    pub id: String,
    pub directive: String,
    pub plain: String,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct HardEntry {
    pub id: String,
    pub plain: String,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct RawScope {
    pub description: String,
    pub keys: Vec<String>,
    pub max_depth: usize,
    pub max_files: usize,
    pub max_bytes: usize,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct Rules {
    pub version: u32,
    pub description: String,
    pub rules: Vec<RuleEntry>,
    pub hard_refusals: Vec<HardEntry>,
    pub cap_add_allowlist: Vec<String>,
    pub docker_socket_paths: Vec<String>,
    pub docker_socket_basename: String,
    pub top_level_keys: Vec<String>,
    pub service_keys_known: Vec<String>,
    pub namespace_values_ok: Vec<String>,
    pub network_drivers_ok: Vec<String>,
    pub security_opt_ok: Vec<String>,
    pub raw_read_scope: RawScope,
}

#[derive(Deserialize)]
struct Source {
    files: std::collections::BTreeMap<String, String>,
    rules_sha256_ts: String,
}

static EMBEDDED: OnceLock<Result<Rules, &'static str>> = OnceLock::new();

fn same_ids(got: Vec<&str>, want: &[&str]) -> bool {
    got.len() == want.len() && want.iter().all(|w| got.contains(w))
}

impl Rules {
    /// The embedded rule file: version 2, schema-valid, ids equal to the Rust consts, bytes equal to `SOURCE.json`'s recorded sha256.
    pub fn embedded() -> Result<&'static Rules, &'static str> {
        EMBEDDED
            .get_or_init(|| {
                let src: Source = serde_json::from_slice(super::SOURCE_JSON).map_err(|_| "source_invalid")?;
                if src.files.get("compose-deny.json").map(String::as_str) != Some(crate::fork::crypto::sha256_hex(super::RULES_JSON).as_str()) {
                    return Err("corpus_sha_mismatch");
                }
                let r: Rules = serde_json::from_slice(super::RULES_JSON).map_err(|_| "rules_invalid")?;
                if r.version != 2 || r.docker_socket_basename != "docker.sock" || r.docker_socket_paths.is_empty() || !r.docker_socket_paths.iter().all(|p| p.starts_with('/')) {
                    return Err("rules_invalid");
                }
                if !same_ids(r.rules.iter().map(|x| x.id.as_str()).collect(), &RULE_IDS) || !same_ids(r.hard_refusals.iter().map(|x| x.id.as_str()).collect(), &HARD_IDS) {
                    return Err("rule_ids_mismatch");
                }
                if r.raw_read_scope.max_depth == 0 || r.raw_read_scope.max_files == 0 || r.raw_read_scope.max_bytes < 1024 {
                    return Err("rules_invalid");
                }
                Ok(r)
            })
            .as_ref()
            .map_err(|e| *e)
    }
}

/// `rules_sha256` of the TS engine (informational on the agent, D-7): recorded in `SOURCE.json` by the dashboard generator.
pub fn rules_sha256_ts() -> String {
    serde_json::from_slice::<Source>(super::SOURCE_JSON).map(|s| s.rules_sha256_ts).unwrap_or_default()
}

/// canonical absolute path: starts with `/`, ≤ 1024 code points (≤ 2048 UTF-16 units), no control char or `$`, no `//`, no `.`/`..` segment, no trailing `/` (except `/`).
pub fn is_canon_path(p: &str) -> bool {
    if !p.starts_with('/') || p.encode_utf16().count() > 2048 || p.chars().count() > 1024 {
        return false;
    }
    if p.chars().any(|c| (c as u32) <= 0x1f || c as u32 == 0x7f || c == '$') || p.contains("//") {
        return false;
    }
    if p.split('/').any(|s| s == "." || s == "..") {
        return false;
    }
    !(p.len() > 1 && p.ends_with('/'))
}
pub fn is_under_roots(p: &str, roots: &[String]) -> bool {
    roots.iter().any(|r| p == r || (p.starts_with(r.as_str()) && p.as_bytes().get(r.len()) == Some(&b'/')))
}
/// `p` is the docker socket, `/`, or a prefix directory of a socket path, or ends in `/docker.sock`.
pub fn is_socket_path(rules: &Rules, p: &str) -> bool {
    p.ends_with(&format!("/{}", rules.docker_socket_basename)) || p == "/" || rules.docker_socket_paths.iter().any(|s| s == p || s.starts_with(&format!("{p}/")))
}
