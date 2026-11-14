//! `applyMirrorSpec` (W20 D-5 / D-6) ported 1:1 from the dashboard's `compose-compiler/env.ts` (the TS file is NORMATIVE; the 72 env + 10 apply vectors of
//! `corpus/compose-mirror-vectors.json` are the oracle and run in `mirror::tests`). Runs ONLY here, where the full secret-bearing render exists: it merges the
//! value-free skeleton `spec.view` with the runner's own pass-2 render, produces the rotated / kept / disabled env values and proves
//! `blank_policy_view(result) == spec.view`. PURE: the seed is injected; no clock, no randomness, no I/O, no process.
use crate::fork::policy::view::blank_policy_view;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"portabase-mirror-env-v1";

/// What to do with the value of one env key (dashboard `EnvAction`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvAction {
    Keep,
    KeepExact,
    Rotate,
    Disable,
    Drop,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub service: String,
    pub target: u32,
    pub host_port: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Postgresql,
    Mysql,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialReset {
    pub service: String,
    pub engine: Engine,
    pub user_key: Option<String>,
    pub password_key: String,
}

/// Dashboard `MirrorSpecV1` (strict). `view` stays a JSON value: it is a policy view, validated by the equality proof, not by a schema.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorSpec {
    pub v: u8,
    pub compiler: u32,
    pub project: String,
    pub workspace: String,
    pub source_view_sha256: String,
    pub rules_sha256: String,
    pub access: Option<Access>,
    pub view: Value,
    pub env: BTreeMap<String, BTreeMap<String, EnvAction>>,
    pub credential_resets: Vec<CredentialReset>,
    pub kept_production_secrets: Vec<String>,
}

/// Dashboard `ApplyError`; the executor maps all but `SeedInvalid` to `apply_failed` (the tag is kept in the sanitized detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    ServiceMissing,
    EnvMissing,
    LabelMissing,
    StructureMismatch,
    SeedInvalid,
}
impl ApplyError {
    pub fn as_str(self) -> &'static str {
        match self {
            ApplyError::ServiceMissing => "service_missing",
            ApplyError::EnvMissing => "env_missing",
            ApplyError::LabelMissing => "label_missing",
            ApplyError::StructureMismatch => "structure_mismatch",
            ApplyError::SeedInvalid => "seed_invalid",
        }
    }
}

/// `H(x)` = first 32 lowercase hex chars of `HMAC-SHA256(seed, "portabase-mirror-env-v1" || 0x00 || UTF-8(x))`.
pub fn mirror_hash(seed: &[u8], x: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(seed).expect("HMAC takes any key length");
    m.update(DOMAIN);
    m.update(&[0]);
    m.update(x.as_bytes());
    hex::encode(m.finalize().into_bytes())[..32].to_string()
}

/// JS `decodeURIComponent` with its failure mode: ANY malformed sequence (bad hex, truncated `%`, bytes that are not UTF-8) returns the raw text.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hx = |c: u8| (c as char).to_digit(16);
            match (b.get(i + 1).copied().and_then(hx), b.get(i + 2).copied().and_then(hx)) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                }
                _ => return s.to_string(),
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

struct Url<'a> {
    scheme: &'a str,
    authority: &'a str,
    rest: &'a str,
}
/// Procedural URL split (for TS parity): `^[A-Za-z][A-Za-z0-9+.-]*://`, authority up to the first `/ ? #`.
fn split_url(v: &str) -> Option<Url<'_>> {
    let b = v.as_bytes();
    if !b.first().is_some_and(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let mut i = 1;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'+' | b'.' | b'-')) {
        i += 1;
    }
    if !v[i..].starts_with("://") {
        return None;
    }
    let scheme_end = i + 3;
    let after = &v[scheme_end..];
    let end = after.find(['/', '?', '#']);
    Some(Url { scheme: &v[..scheme_end], authority: end.map_or(after, |e| &after[..e]), rest: end.map_or("", |e| &after[e..]) })
}

/// The URL with its userinfo password replaced by `H(pctDecode(pass))`; `None` when there is no (non-empty) password.
fn rotate_url_password(v: &str, seed: &[u8]) -> Option<String> {
    let u = split_url(v)?;
    let at = u.authority.rfind('@')?;
    let userinfo = &u.authority[..at];
    let colon = userinfo.find(':')?;
    if colon == userinfo.len() - 1 {
        return None;
    }
    Some(format!("{}{}:{}@{}{}", u.scheme, &userinfo[..colon], mirror_hash(seed, &pct_decode(&userinfo[colon + 1..])), &u.authority[at + 1..], u.rest))
}

/// `None` = drop the key; `Some(None)` = JSON null (pass-through stays null for every action except drop).
pub fn mirror_env_value(action: EnvAction, v: Option<&str>, seed: &[u8]) -> Option<Option<String>> {
    if action == EnvAction::Drop {
        return None;
    }
    let Some(v) = v else { return Some(None) };
    Some(Some(match action {
        EnvAction::KeepExact => v.to_string(),
        EnvAction::Keep => rotate_url_password(v, seed).unwrap_or_else(|| v.to_string()),
        EnvAction::Rotate => {
            if v.is_empty() {
                String::new()
            } else {
                rotate_url_password(v, seed).unwrap_or_else(|| mirror_hash(seed, v))
            }
        }
        EnvAction::Disable => {
            if v.is_empty() {
                String::new()
            } else {
                match split_url(v) {
                    None => "disabled.invalid".to_string(),
                    Some(u) => format!("{}disabled.invalid{}", u.scheme, u.rest),
                }
            }
        }
        EnvAction::Drop => unreachable!(),
    }))
}

const STRUCT_KEYS: [&str; 6] = ["command", "entrypoint", "healthcheck", "secrets", "configs", "annotations"];

fn blank_scalars(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(blank_scalars).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), blank_scalars(x))).collect()),
        Value::Null => Value::Null,
        _ => Value::String(String::new()),
    }
}

/// Order-insensitive deep equality (numbers compare by value like JS `===`).
fn deep_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| deep_equal(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| deep_equal(p, q))),
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

/// JS `String(v)` for the env values compose can emit (strings; numbers / booleans when a project wrote an unquoted scalar).
fn to_env_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() == 0.0 && f.abs() < 1e21 => format!("{}", f as i128),
            _ => n.to_string(),
        }),
        other => Some(other.to_string()),
    }
}

/// D-6. `full` = the runner's own pass-2 render (secret-bearing). Structure (ports, networks, volumes, …) always comes from the spec, never from `full`.
/// The caller must verify `sha256(own view bytes) == spec.source_view_sha256` BEFORE calling this (`source_changed`) and validate the result with
/// `docker compose config` AFTER (this function runs no process).
pub fn apply_mirror_spec(full: &Value, spec: &MirrorSpec, seed: &[u8]) -> Result<Value, ApplyError> {
    if seed.len() != 32 {
        return Err(ApplyError::SeedInvalid);
    }
    let full_services = full.get("services").and_then(Value::as_object).ok_or(ApplyError::StructureMismatch)?;
    let view_services = spec.view.get("services").and_then(Value::as_object).ok_or(ApplyError::StructureMismatch)?;
    let mut out = spec.view.clone();
    for name in view_services.keys() {
        if !full_services.get(name).is_some_and(Value::is_object) {
            return Err(ApplyError::ServiceMissing);
        }
    }
    let out_services = out.get_mut("services").and_then(Value::as_object_mut).ok_or(ApplyError::StructureMismatch)?;
    for (name, o) in out_services.iter_mut() {
        let f = &full_services[name];
        let Some(o) = o.as_object_mut() else { return Err(ApplyError::StructureMismatch) };
        if let Some(Value::Object(labels)) = o.get_mut("labels") {
            let empty = Map::new();
            let fl = f.get("labels").and_then(Value::as_object).unwrap_or(&empty);
            for (k, slot) in labels.iter_mut() {
                *slot = fl.get(k).ok_or(ApplyError::LabelMissing)?.clone();
            }
        }
        if let Some(Value::Object(env)) = o.get_mut("environment") {
            let empty = Map::new();
            let fe = f.get("environment").and_then(Value::as_object).unwrap_or(&empty);
            let acts = spec.env.get(name);
            let keys: Vec<String> = env.keys().cloned().collect();
            for k in keys {
                let fv = fe.get(&k).ok_or(ApplyError::EnvMissing)?;
                let action = *acts.and_then(|a| a.get(&k)).ok_or(ApplyError::StructureMismatch)?;
                match mirror_env_value(action, to_env_string(Some(fv)).as_deref(), seed) {
                    None => {
                        env.remove(&k);
                    }
                    Some(None) => {
                        env.insert(k, Value::Null);
                    }
                    Some(Some(s)) => {
                        env.insert(k, Value::String(s));
                    }
                }
            }
        }
        for k in STRUCT_KEYS {
            let Some(cur) = o.get(k) else { continue };
            let Some(fv) = f.get(k) else { return Err(ApplyError::StructureMismatch) };
            if !deep_equal(&blank_scalars(fv), cur) {
                return Err(ApplyError::StructureMismatch);
            }
            o.insert(k.to_string(), fv.clone());
        }
    }
    for top in ["secrets", "configs"] {
        let Some(Value::Object(defs)) = out.get_mut(top) else { continue };
        let fdefs = full.get(top).and_then(Value::as_object);
        for (k, d) in defs.iter_mut() {
            let (Some(d), Some(fd)) = (d.as_object_mut(), fdefs.and_then(|m| m.get(k)).and_then(Value::as_object)) else { return Err(ApplyError::StructureMismatch) };
            for key in ["content", "environment"] {
                let Some(cur) = d.get(key) else { continue };
                let Some(fv) = fd.get(key) else { return Err(ApplyError::StructureMismatch) };
                if !deep_equal(&blank_scalars(fv), cur) {
                    return Err(ApplyError::StructureMismatch);
                }
                d.insert(key.to_string(), fv.clone());
            }
        }
    }
    if !deep_equal(&blank_policy_view(&out), &spec.view) {
        return Err(ApplyError::StructureMismatch);
    }
    Ok(out)
}
