//! Channel configuration: the enrolment bundle (credential, task key, PINNED public keys) read from a 0600 file, plus the https-only policy.
//! The credential and task key never appear in argv, logs or error text.
use super::crypto::{Pin, parse_pin};
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("FORK_CHANNEL_BUNDLE_FILE is not set")]
    MissingBundlePath,
    #[error("the bundle file cannot be read")]
    Unreadable,
    #[error("the bundle file must not be readable by group/others (chmod 600)")]
    BundlePermissions,
    #[error("the bundle is not valid")]
    BadBundle,
    #[error("the bundle is invalid: {0}")]
    Invalid(&'static str),
    #[error("the dashboard URL must be https:// (http is allowed only for a loopback lab host with FORK_ALLOW_INSECURE_LOOPBACK=true)")]
    InsecureTransport,
}

#[derive(Deserialize)]
struct Bundle {
    v: u8,
    enroll_id: String,
    server_url: String,
    agent_id: String,
    credential: String,
    task_key_b64: String,
    pins: Vec<BundlePin>,
    pin_fingerprint: String,
}
#[derive(Deserialize)]
struct BundlePin {
    kid: String,
    pem: String,
}

pub struct ChannelConfig {
    pub agent_id: String,
    pub enroll_id: String,
    pub server_url: String,
    pub credential: String,
    pub task_key: [u8; 32],
    pub pins: Vec<Pin>,
    pub pin_fingerprint: String,
    pub insecure_lab: bool,
    pub poll_seconds: u64,
    pub state_path: PathBuf,
}

// manual Debug: never print the credential or the task key
impl std::fmt::Debug for ChannelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelConfig").field("agent_id", &self.agent_id).field("server_url", &self.server_url).field("pins", &self.pins.len()).finish_non_exhaustive()
    }
}

pub enum Startup {
    Disabled(&'static str),
    Active(Box<ChannelConfig>),
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() })
}

/// `true` ⇒ the http exemption applies (loopback lab host + explicit switch). Used by BOTH the config and the tests.
pub fn check_transport(server_url: &str, allow_insecure_loopback: bool) -> Result<bool, ConfigError> {
    let u = Url::parse(server_url).map_err(|_| ConfigError::Invalid("server_url"))?;
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return Err(ConfigError::Invalid("server_url"));
    }
    match u.scheme() {
        "https" => Ok(false),
        "http" if allow_insecure_loopback && is_loopback(&u) => Ok(true),
        "http" => Err(ConfigError::InsecureTransport),
        _ => Err(ConfigError::Invalid("server_url")),
    }
}

fn is_loopback(u: &Url) -> bool {
    match u.host() {
        Some(Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

pub fn parse_bundle(text: &str, allow_insecure_loopback: bool) -> Result<(ChannelConfigParts, bool), ConfigError> {
    let raw = general_purpose::URL_SAFE_NO_PAD.decode(text.trim().as_bytes()).map_err(|_| ConfigError::BadBundle)?;
    let b: Bundle = serde_json::from_slice(&raw).map_err(|_| ConfigError::BadBundle)?;
    if b.v != 1 {
        return Err(ConfigError::Invalid("version"));
    }
    if !is_uuid(&b.agent_id) || !is_uuid(&b.enroll_id) {
        return Err(ConfigError::Invalid("ids"));
    }
    let insecure = check_transport(&b.server_url, allow_insecure_loopback)?;
    let prefix = format!("fork.{}.", b.agent_id);
    match b.credential.strip_prefix(&prefix) {
        Some(secret) if secret.len() == 43 && secret.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') => {}
        _ => return Err(ConfigError::Invalid("credential")),
    }
    let key_bytes = general_purpose::STANDARD.decode(b.task_key_b64.as_bytes()).map_err(|_| ConfigError::Invalid("task_key"))?;
    let task_key: [u8; 32] = key_bytes.try_into().map_err(|_| ConfigError::Invalid("task_key"))?;
    if b.pins.is_empty() || b.pins.len() > 8 {
        return Err(ConfigError::Invalid("pins"));
    }
    let mut pins = Vec::new();
    for p in &b.pins {
        pins.push(parse_pin(&p.kid, &p.pem).map_err(ConfigError::Invalid)?);
    }
    if !pins.iter().any(|p| p.fingerprint == b.pin_fingerprint) {
        return Err(ConfigError::Invalid("pin_fingerprint"));
    }
    Ok((
        ChannelConfigParts { agent_id: b.agent_id, enroll_id: b.enroll_id, server_url: b.server_url.trim_end_matches('/').to_string(), credential: b.credential, task_key, pins, pin_fingerprint: b.pin_fingerprint },
        insecure,
    ))
}

pub struct ChannelConfigParts {
    pub agent_id: String,
    pub enroll_id: String,
    pub server_url: String,
    pub credential: String,
    pub task_key: [u8; 32],
    pub pins: Vec<Pin>,
    pub pin_fingerprint: String,
}

fn flag(v: Option<String>) -> bool {
    v.map(|s| s.trim().eq_ignore_ascii_case("true")).unwrap_or(false)
}

/// Strict opt-in: the channel exists only when `FORK_CHANNEL_ENABLED=true` AND a valid bundle file is present. Anything else = disabled / refused.
pub fn load(env: &dyn Fn(&str) -> Option<String>) -> Result<Startup, ConfigError> {
    if !flag(env("FORK_CHANNEL_ENABLED")) {
        return Ok(Startup::Disabled("FORK_CHANNEL_ENABLED is not true"));
    }
    let path = env("FORK_CHANNEL_BUNDLE_FILE").filter(|s| !s.is_empty()).ok_or(ConfigError::MissingBundlePath)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&path).map_err(|_| ConfigError::Unreadable)?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::BundlePermissions);
        }
    }
    let text = std::fs::read_to_string(&path).map_err(|_| ConfigError::Unreadable)?;
    let (p, insecure) = parse_bundle(&text, flag(env("FORK_ALLOW_INSECURE_LOOPBACK")))?;
    let poll_seconds = env("FORK_CHANNEL_POLL_SECONDS").and_then(|s| s.trim().parse::<u64>().ok()).filter(|n| (2..=300).contains(n)).unwrap_or(5);
    let state_path = env("FORK_CHANNEL_STATE_FILE").filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env("DATA_PATH").unwrap_or_else(|| "/config".into())).join("fork-channel-state.json"));
    Ok(Startup::Active(Box::new(ChannelConfig {
        agent_id: p.agent_id,
        enroll_id: p.enroll_id,
        server_url: p.server_url,
        credential: p.credential,
        task_key: p.task_key,
        pins: p.pins,
        pin_fingerprint: p.pin_fingerprint,
        insecure_lab: insecure,
        poll_seconds,
        state_path,
    })))
}
