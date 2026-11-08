//! PRE-RENDER check of the RAW compose / override YAML (ADR-015 D-3, E5): a port of `checkRawCompose`. Every file the compose files can pull in (`env_file`,
//! `include`, `extends.file`, `label_file`, `secrets.*.file`, `configs.*.file`) must stay inside the restore root; included / extended files inside the root are
//! scanned recursively. `$` and a leading `~` cannot be proven inside the root ⇒ outside (fail closed). Output carries kinds, service names and target PATHS only.
use super::rules::{Rules, is_canon_path, is_under_roots};
use super::yaml::{Node, RESTORE_YAML_LIMITS, YamlLimits, parse_yaml_limited};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub kind: &'static str,
    pub service: Option<String>,
    pub target: String,
}
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct RawResult {
    pub refused: bool,
    pub violations: Vec<Violation>,
    pub reason: Option<&'static str>,
}
impl RawResult {
    #[allow(dead_code)]
    pub fn clean() -> Self {
        RawResult { refused: false, violations: vec![], reason: None }
    }
}

const TARGET_MAX: usize = 256;
const MAX_VIOLATIONS: usize = 16;

fn show(t: &Node) -> String {
    let s = match t {
        Node::Str(s) => s.clone(),
        other => other.to_json(),
    };
    s.chars().take(TARGET_MAX).collect()
}

/// `path.posix.resolve(base, t)` for an absolute `base`.
fn resolve(base: &str, t: &str) -> String {
    let joined = if t.starts_with('/') { t.to_string() } else { format!("{base}/{t}") };
    let mut parts: Vec<&str> = vec![];
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}
fn dirname(file: &str) -> String {
    match file.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => file[..i].to_string(),
    }
}
/// a target (relative to the declaring file's directory) that does not provably stay inside `root`
fn outside(root: &str, base: &str, t: &Node) -> bool {
    let Node::Str(s) = t else { return true };
    if s.is_empty() || s.contains('\0') || s.contains('$') || s.starts_with('~') {
        return true;
    }
    let full = resolve(base, s);
    !(full == root || (full.starts_with(root) && full.as_bytes().get(root.len()) == Some(&b'/')))
}
fn as_list(v: Option<&Node>) -> Vec<&Node> {
    match v {
        None | Some(Node::Null) => vec![],
        Some(Node::Seq(items)) => items.iter().collect(),
        Some(other) => vec![other],
    }
}
fn file_targets(v: Option<&Node>) -> Vec<&Node> {
    let mut out = vec![];
    for it in as_list(v) {
        if it.is_map() {
            out.extend(as_list(it.get("path")));
        } else {
            out.push(it);
        }
    }
    out
}

/// `read` returns the text of a file inside the workspace (regular file, no symlink, size-bounded) or `None`.
/// `Err` = the caller passed a root / entry that is not canonical (a programming error on the agent side, never produced by a payload that passed `check_task_path`).
pub fn check_raw(rules: &Rules, root: &str, entry: &[String], read: &dyn Fn(&str) -> Option<String>) -> Result<RawResult, &'static str> {
    if !is_canon_path(root) || root == "/" || entry.is_empty() || !entry.iter().all(|e| is_canon_path(e) && is_under_roots(e, &[root.to_string()])) {
        return Err("raw_input_invalid");
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut found: HashMap<String, Violation> = HashMap::new();
    let mut add = |kind: &'static str, service: Option<&str>, target: &Node| {
        let v = Violation { kind, service: service.map(str::to_string), target: show(target) };
        found.insert(format!("{kind}\0{}\0{}", service.unwrap_or(""), v.target), v);
    };
    let limits = YamlLimits { max_bytes: RESTORE_YAML_LIMITS.max_bytes.min(rules.raw_read_scope.max_bytes), ..RESTORE_YAML_LIMITS };
    let mut queue: Vec<(String, usize)> = entry.iter().map(|f| (f.clone(), 0)).collect();
    let mut reason: Option<&'static str> = None;

    let mut q = 0;
    'files: while q < queue.len() {
        let (file, depth) = queue[q].clone();
        q += 1;
        if seen.contains(&file) {
            continue;
        }
        if seen.len() >= rules.raw_read_scope.max_files {
            reason = Some("limits");
            break;
        }
        seen.insert(file.clone());
        let Some(text) = read(&file) else {
            add("missing", None, &Node::Str(file.clone()));
            continue;
        };
        let doc = match parse_yaml_limited(&text, &limits) {
            Ok(d) => d,
            Err(e) => {
                reason = Some(e.reason());
                break;
            }
        };
        if !doc.is_map() {
            reason = Some("yaml_invalid");
            break;
        }
        let base = dirname(&file);
        // include / extends target: refused when outside, queued when inside (depth- and count-bounded). false = a limit was hit.
        let follow = |queue: &mut Vec<(String, usize)>, add: &mut dyn FnMut(&'static str, Option<&str>, &Node), t: &Node, kind: &'static str, service: Option<&str>| -> bool {
            if outside(root, &base, t) {
                add(kind, service, t);
                return true;
            }
            if depth + 1 > rules.raw_read_scope.max_depth {
                return false;
            }
            if let Node::Str(s) = t {
                queue.push((resolve(&base, s), depth + 1));
            }
            true
        };
        for it in as_list(doc.get("include")) {
            if it.is_map() {
                for t in as_list(it.get("path")) {
                    if !follow(&mut queue, &mut add, t, "include", None) {
                        reason = Some("limits");
                        break 'files;
                    }
                }
                for t in as_list(it.get("env_file")) {
                    if outside(root, &base, t) {
                        add("include_env_file", None, t);
                    }
                }
                if let Some(pd) = it.get("project_directory") {
                    if *pd != Node::Null {
                        add("include_project_directory", None, pd);
                    }
                }
            } else if !follow(&mut queue, &mut add, it, "include", None) {
                reason = Some("limits");
                break 'files;
            }
        }
        for (section, kind) in [("secrets", "secret_file"), ("configs", "config_file")] {
            if let Some(Node::Map(defs)) = doc.get(section) {
                for (name, spec) in defs {
                    if let Some(f) = spec.get("file") {
                        if outside(root, &base, f) {
                            add(kind, Some(name), f);
                        }
                    }
                }
            }
        }
        if let Some(Node::Map(services)) = doc.get("services") {
            for (svc, spec) in services {
                if !spec.is_map() {
                    continue;
                }
                for t in file_targets(spec.get("env_file")) {
                    if outside(root, &base, t) {
                        add("env_file", Some(svc), t);
                    }
                }
                for t in as_list(spec.get("label_file")) {
                    if outside(root, &base, t) {
                        add("label_file", Some(svc), t);
                    }
                }
                if let Some(ext) = spec.get("extends") {
                    if let Some(f) = ext.get("file") {
                        if *f != Node::Null && !follow(&mut queue, &mut add, f, "extends", Some(svc)) {
                            reason = Some("limits");
                            break 'files;
                        }
                    }
                }
            }
        }
    }
    let mut violations: Vec<Violation> = found.into_values().collect();
    violations.sort_by(|a, b| (a.kind, a.service.as_deref().unwrap_or(""), &a.target).cmp(&(b.kind, b.service.as_deref().unwrap_or(""), &b.target)));
    violations.truncate(MAX_VIOLATIONS);
    Ok(RawResult { refused: reason.is_some() || !violations.is_empty(), violations, reason })
}
