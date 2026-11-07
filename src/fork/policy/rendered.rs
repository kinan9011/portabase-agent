//! Rendered-compose policy (ADR-015 D-2, E6): a line-by-line port of the dashboard's `evaluateRenderedCompose` + `evaluateDoc`. Input = the bytes of a
//! `docker compose config --format json` document (on the agent: the POLICY VIEW, whose blanked fields the engine never reads). Verdicts carry rule ids, service
//! names, key names and PATHS only; no value of `environment`, `labels`, `command`, `entrypoint`, `healthcheck`, `x-*`, secrets or configs is ever copied.
use super::raw::RawResult;
use super::rules::{Rules, is_canon_path, is_socket_path, is_under_roots};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

pub const MAX_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DEPTH: usize = 32;
const MAX_SERVICES: usize = 500;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub service: String,
    pub rule: &'static str,
    pub detail: String,
}
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Hard {
    pub code: &'static str,
    pub service: Option<String>,
    pub detail: String,
}
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub verdict: &'static str,
    pub compose_sha256: String,
    pub roots: Vec<String>,
    pub hard: Vec<Hard>,
    pub findings: Vec<Finding>,
}
impl Verdict {
    pub fn services_needing_override(&self) -> Vec<String> {
        let mut s: Vec<String> = self.findings.iter().map(|f| f.service.clone()).collect();
        s.sort();
        s.dedup();
        s
    }
}

fn clean(d: &str) -> String {
    d.chars().map(|c| if c.is_ascii_alphanumeric() || "_./:=-".contains(c) { c } else { '?' }).take(128).collect()
}
fn truthy(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null) | Some(Value::Bool(false)))
}
fn present(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null))
}
fn non_empty(v: Option<&Value>) -> bool {
    present(v) && !matches!(v, Some(Value::Array(a)) if a.is_empty())
}
fn service_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 128 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}
/// string-aware bracket depth of a JSON text, bounded BEFORE parsing
pub fn json_too_deep(text: &[u8], max: usize) -> bool {
    let (mut depth, mut in_str, mut i) = (0usize, false, 0usize);
    while i < text.len() {
        let ch = text[i];
        if in_str {
            if ch == 0x5c {
                i += 1;
            } else if ch == 0x22 {
                in_str = false;
            }
        } else if ch == 0x22 {
            in_str = true;
        } else if ch == b'[' || ch == b'{' {
            depth += 1;
            if depth > max {
                return true;
            }
        } else if ch == b']' || ch == b'}' {
            depth = depth.saturating_sub(1);
        }
        i += 1;
    }
    false
}

#[derive(Default)]
struct Collector {
    findings: HashMap<String, Finding>,
    hard: HashMap<String, Hard>,
}
impl Collector {
    fn flag(&mut self, service: &str, rule: &'static str, detail: &str) {
        let d = clean(detail);
        self.findings.insert(format!("{service}\0{rule}\0{d}"), Finding { service: service.into(), rule, detail: d });
    }
    fn refuse(&mut self, code: &'static str, service: Option<&str>, detail: &str) {
        let d = clean(detail);
        self.hard.insert(format!("{code}\0{}\0{d}", service.unwrap_or("")), Hard { code, service: service.map(str::to_string), detail: d });
    }
}

fn s_of(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}

fn evaluate_doc(rules: &Rules, doc: &Value, roots: &[String], c: &mut Collector) {
    let Some(docm) = doc.as_object() else { return c.refuse("shape_invalid", None, "services") };
    let Some(services) = docm.get("services").and_then(Value::as_object) else { return c.refuse("shape_invalid", None, "services") };
    if services.len() > MAX_SERVICES {
        return c.refuse("limits", None, "services");
    }
    for k in docm.keys() {
        if !k.starts_with("x-") && !rules.top_level_keys.iter().any(|t| t == k) {
            c.refuse("top_level_unknown", None, k);
        }
    }
    // paths: `p` is whatever the document holds (must be a string to be a path at all)
    let read_path = |c: &mut Collector, svc: Option<&str>, p: Option<&Value>, what: &str| match s_of(p) {
        Some(p) if is_canon_path(p) => {
            if !is_under_roots(p, roots) {
                c.refuse("read_outside_root", svc, &format!("{what}: {p}"));
            }
        }
        _ => c.refuse("path_ambiguous", svc, what),
    };
    let host_path = |c: &mut Collector, svc: &str, p: Option<&Value>, what: &str| match s_of(p) {
        Some(p) if is_canon_path(p) => {
            if is_socket_path(rules, p) {
                c.flag(svc, "docker_sock", &format!("{what}: {p}"));
            }
            if !is_under_roots(p, roots) {
                c.flag(svc, "bind_outside_root", &format!("{what}: {p}"));
            }
        }
        _ => c.refuse("path_ambiguous", Some(svc), what),
    };
    for section in ["secrets", "configs"] {
        if let Some(defs) = docm.get(section).and_then(Value::as_object) {
            for def in defs.values() {
                if let Some(d) = def.as_object() {
                    if present(d.get("file")) {
                        read_path(c, None, d.get("file"), "file");
                    }
                }
            }
        }
    }
    let empty = Map::new();
    let networks = docm.get("networks").and_then(Value::as_object).unwrap_or(&empty);
    let volumes = docm.get("volumes").and_then(Value::as_object).unwrap_or(&empty);

    for (svc, sv) in services {
        if !service_name(svc) {
            c.refuse("service_name", None, "service");
            continue;
        }
        let Some(s) = sv.as_object() else {
            c.refuse("shape_invalid", Some(svc), "service");
            continue;
        };
        for k in s.keys() {
            if !k.starts_with("x-") && !rules.service_keys_known.iter().any(|t| t == k) {
                c.flag(svc, "unknown_directive", k);
            }
        }
        if truthy(s.get("privileged")) {
            c.flag(svc, "privileged", "privileged");
        }
        if truthy(s.get("use_api_socket")) {
            c.flag(svc, "docker_sock", "use_api_socket");
        }
        for (key, host_rule) in [("network_mode", "network_mode_host"), ("pid", "pid_host"), ("ipc", "ipc_host")] {
            let v = s.get(key);
            if !present(v) {
                continue;
            }
            match s_of(v) {
                Some("host") => c.flag(svc, host_rule, &format!("{key}: host")),
                Some(x) if x.starts_with("service:") && services.contains_key(&x[8..]) => {}
                Some(x) if rules.namespace_values_ok.iter().any(|o| o == x) => {}
                _ => c.flag(svc, "shared_namespace", key),
            }
        }
        if non_empty(s.get("devices")) {
            c.flag(svc, "devices", "devices");
        }
        let deploy = s.get("deploy");
        if truthy(deploy) {
            let res = deploy.and_then(Value::as_object).and_then(|d| d.get("resources"));
            let rsv = res.and_then(Value::as_object).and_then(|r| r.get("reservations"));
            if deploy.and_then(Value::as_object).is_none() || (truthy(res) && res.and_then(Value::as_object).is_none()) || (truthy(rsv) && rsv.and_then(Value::as_object).is_none()) {
                c.refuse("shape_invalid", Some(svc), "deploy");
            } else if let Some(r) = rsv.and_then(Value::as_object) {
                if non_empty(r.get("devices")) {
                    c.flag(svc, "devices", "deploy devices");
                }
            }
        }
        if present(s.get("cap_add")) {
            match s.get("cap_add").and_then(Value::as_array) {
                None => c.refuse("shape_invalid", Some(svc), "cap_add"),
                Some(caps) => {
                    for cap in caps {
                        let Some(cap) = cap.as_str() else {
                            c.refuse("shape_invalid", Some(svc), "cap_add");
                            continue;
                        };
                        let up = cap.to_ascii_uppercase();
                        let name = up.strip_prefix("CAP_").unwrap_or(&up);
                        if !rules.cap_add_allowlist.iter().any(|a| a == name) {
                            c.flag(svc, "cap_add", &format!("cap_add: {name}"));
                        }
                    }
                }
            }
        }
        if present(s.get("security_opt")) {
            let ok = s.get("security_opt").and_then(Value::as_array).is_some_and(|a| a.iter().all(|o| o.as_str().is_some_and(|o| rules.security_opt_ok.iter().any(|k| k == o))));
            if !ok {
                c.flag(svc, "unknown_directive", "security_opt");
            }
        }
        if present(s.get("env_file")) {
            let ef = s.get("env_file").unwrap();
            let items: Vec<&Value> = match ef {
                Value::Array(a) => a.iter().collect(),
                other => vec![other],
            };
            for it in items {
                let p = if it.is_object() { it.get("path") } else { Some(it) };
                read_path(c, Some(svc), p, "env_file");
            }
        }
        if present(s.get("networks")) {
            let names: Option<Vec<Option<&str>>> = match s.get("networks") {
                Some(Value::Array(a)) => Some(a.iter().map(Value::as_str).collect()),
                Some(Value::Object(o)) => Some(o.keys().map(|k| Some(k.as_str())).collect()),
                _ => None,
            };
            match names {
                None => c.refuse("shape_invalid", Some(svc), "networks"),
                Some(names) => {
                    for n in names {
                        let nd = n.and_then(|n| networks.get(n)).and_then(Value::as_object);
                        match nd {
                            None => c.refuse("shape_invalid", Some(svc), "network"),
                            Some(nd) => {
                                let driver = nd.get("driver");
                                if s_of(nd.get("name")) == Some("host") || s_of(driver) == Some("host") {
                                    c.flag(svc, "network_mode_host", &format!("networks: {}", n.unwrap_or("")));
                                } else {
                                    let ok = !present(driver) || s_of(driver).is_some_and(|d| rules.network_drivers_ok.iter().any(|k| k == d));
                                    if !ok {
                                        c.flag(svc, "unknown_directive", "network driver");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if present(s.get("volumes")) {
            match s.get("volumes").and_then(Value::as_array) {
                None => c.refuse("shape_invalid", Some(svc), "volumes"),
                Some(ms) => {
                    for m in ms {
                        let Some(m) = m.as_object() else {
                            c.refuse("shape_invalid", Some(svc), "volumes");
                            continue;
                        };
                        match s_of(m.get("type")) {
                            Some("bind") => host_path(c, svc, m.get("source"), "volumes"),
                            Some("volume") => {
                                let src = m.get("source");
                                if !present(src) || src == Some(&Value::String(String::new())) {
                                    continue;
                                }
                                let def = s_of(src).and_then(|n| volumes.get(n)).and_then(Value::as_object);
                                let Some(def) = def else {
                                    c.refuse("shape_invalid", Some(svc), "volume");
                                    continue;
                                };
                                if present(def.get("driver")) && s_of(def.get("driver")) != Some("local") {
                                    c.flag(svc, "unknown_directive", "volume driver");
                                } else if !present(def.get("driver_opts")) {
                                    continue;
                                } else if let Some(o) = def.get("driver_opts").and_then(Value::as_object) {
                                    if s_of(o.get("type")) == Some("tmpfs") {
                                        continue;
                                    }
                                    match s_of(o.get("device")) {
                                        Some(d) if d.starts_with('/') => host_path(c, svc, o.get("device"), "volume device"),
                                        _ => c.flag(svc, "unknown_directive", "volume driver_opts"),
                                    }
                                } else {
                                    c.refuse("shape_invalid", Some(svc), "volume");
                                }
                            }
                            t => {
                                if t != Some("tmpfs") {
                                    c.flag(svc, "unknown_directive", "volume type");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// `roots` are the restore roots the document may reference (on the agent: exactly `[workspace]`).
pub fn evaluate(rules: &Rules, bytes: &[u8], roots: &[String], raw: &RawResult) -> Verdict {
    let mut c = Collector::default();
    let mut good_roots: Vec<String> = vec![];
    for r in roots {
        if is_canon_path(r) && r != "/" && !is_socket_path(rules, r) {
            good_roots.push(r.clone());
        } else {
            c.refuse("path_ambiguous", None, "restore root");
        }
    }
    if roots.is_empty() {
        c.refuse("path_ambiguous", None, "restore root");
    }
    if bytes.len() > MAX_BYTES {
        c.refuse("limits", None, "rendered size");
    } else if json_too_deep(bytes, MAX_DEPTH) {
        c.refuse("limits", None, "rendered depth");
    } else {
        match serde_json::from_slice::<Value>(bytes) {
            Err(_) => c.refuse("shape_invalid", None, "not json"),
            Ok(doc) => evaluate_doc(rules, &doc, &good_roots, &mut c),
        }
    }
    if let Some(reason) = raw.reason {
        c.refuse(reason, None, "compose yaml");
    }
    for v in &raw.violations {
        let d = format!("{}: {}", v.kind, v.target);
        if v.kind == "missing" {
            c.refuse("raw_incomplete", v.service.as_deref(), &d);
        } else {
            c.refuse("read_outside_root", v.service.as_deref(), &d);
        }
    }
    if raw.refused && raw.reason.is_none() && raw.violations.is_empty() {
        c.refuse("yaml_invalid", None, "compose yaml");
    }
    let mut hard: Vec<Hard> = c.hard.into_values().collect();
    hard.sort_by(|a, b| (a.code, a.service.as_deref().unwrap_or(""), &a.detail).cmp(&(b.code, b.service.as_deref().unwrap_or(""), &b.detail)));
    let mut findings: Vec<Finding> = c.findings.into_values().collect();
    findings.sort_by(|a, b| (&a.service, a.rule, &a.detail).cmp(&(&b.service, b.rule, &b.detail)));
    let mut sorted_roots = roots.to_vec();
    sorted_roots.sort();
    Verdict {
        verdict: if !hard.is_empty() { "deny" } else if !findings.is_empty() { "needs-explicit-override" } else { "allow" },
        compose_sha256: crate::fork::crypto::sha256_hex(bytes),
        roots: sorted_roots,
        hard,
        findings,
    }
}
