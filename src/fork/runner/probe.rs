//! `runner_probe` (W21 DD-4): from a hardened helper on a fresh, NON-internal pool network, try every configured production target (TCP, DNS over TCP, DNS name)
//! and report per target `blocked | reachable | error`. The agent only MEASURES; the isolation verdict is the dashboard's (fail closed). Values reach the helper
//! as env lines and quoted positional args only; the script is a constant pinned by a hash test.
use super::Code;
use super::docker::{HelperSpec, LABEL_AGENT, LABEL_PROBE, Labels, RunnerDocker};
use super::wipe::wipe_owned;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

pub const MAX_TARGETS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Tcp,
    DnsTcp,
    DnsName,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub kind: Kind,
    pub host: String,
    #[serde(default)]
    pub port: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbePayload {
    pub v: u8,
    pub probe_id: String,
    pub targets_sha256: String,
    pub timeout_ms: u64,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Blocked,
    Reachable,
    Error,
}
impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Blocked => "blocked",
            Outcome::Reachable => "reachable",
            Outcome::Error => "error",
        }
    }
}

/// The helper script. Pinned by `probe_script_hash_is_pinned`. `S` proves the helper's own name resolves (embedded DNS works), so a `blocked` DNS name is not just a dead resolver.
pub const PROBE_SCRIPT: &str = r#"set -u
echo PBM-PROBE-START
if getent hosts "$PBM_SELF" >/dev/null 2>&1; then echo "S ok"; else echo "S fail"; fi
printf '%s\n' "$PBM_TARGETS" | while read -r id kind host port; do
  [ -z "${id:-}" ] && continue
  if [ "$kind" = dns_name ]; then
    err=$(timeout -k 1 "$PBM_T" getent ahosts "$host" 2>&1 >/dev/null); rc=$?
  else
    err=$(timeout -k 1 "$PBM_T" bash -c 'exec 3<>"/dev/tcp/$1/$2"' pbm "$host" "$port" 2>&1); rc=$?
  fi
  case "$err" in *refused*) c=refused;; *"No route"*) c=noroute;; *nreachable*) c=unreach;; "") c=none;; *) c=other;; esac
  echo "R $id $rc $c"
done
echo PBM-PROBE-END
"#;

fn valid_id(s: &str) -> bool {
    (1..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
fn valid_uuid(s: &str) -> bool {
    s.len() == 36 && s == s.to_ascii_lowercase() && uuid::Uuid::parse_str(s).is_ok()
}
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Loopback, unspecified, link-local, multicast and IPv4-mapped IPv6 are never probe targets (twin of dashboard `isProbeableIp`).
pub fn probeable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !(a.is_loopback() || a.octets()[0] == 0 || a.is_link_local() || a.is_multicast()),
        IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || (a.segments()[0] & 0xffc0) == 0xfe80 || a.to_ipv4_mapped().is_some()),
    }
}
/// Lowercase hostname, ≥ 2 labels, labels `[a-z0-9-]{1,63}` not starting/ending with `-`, total ≤ 253, last label not all digits (twin of `isProbeHostname`).
pub fn valid_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let ok = labels.iter().all(|l| (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
    ok && !labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// Strict validation of a parsed payload (DD-4). Every refusal is `payload_invalid`.
pub fn validate(p: &ProbePayload) -> Result<(), Code> {
    let bad = Err(Code::PayloadInvalid);
    if p.v != 1 || !valid_uuid(&p.probe_id) || !is_hex64(&p.targets_sha256) || !(500..=5000).contains(&p.timeout_ms) || p.targets.is_empty() || p.targets.len() > MAX_TARGETS {
        return bad;
    }
    let mut seen = BTreeSet::new();
    for t in &p.targets {
        if !valid_id(&t.id) || !seen.insert(t.id.as_str()) {
            return bad;
        }
        match t.kind {
            Kind::DnsName => {
                if t.port.is_some() || !valid_hostname(&t.host) {
                    return bad;
                }
            }
            Kind::Tcp | Kind::DnsTcp => {
                let Some(port) = t.port else { return bad };
                if !(1..=65535).contains(&port) {
                    return bad;
                }
                let ok = match (Ipv4Addr::from_str(&t.host), Ipv6Addr::from_str(&t.host)) {
                    (Ok(a), _) => probeable_ip(&IpAddr::V4(a)),
                    (_, Ok(a)) => probeable_ip(&IpAddr::V6(a)),
                    _ => false,
                };
                if !ok {
                    return bad;
                }
            }
        }
    }
    Ok(())
}

pub fn parse(payload: &[u8]) -> Result<ProbePayload, Code> {
    let p: ProbePayload = serde_json::from_slice(payload).map_err(|_| Code::PayloadInvalid)?;
    validate(&p)?;
    Ok(p)
}

/// One line per target for the helper: `id kind host port|-`.
pub fn targets_env(p: &ProbePayload) -> String {
    p.targets
        .iter()
        .map(|t| {
            let k = match t.kind {
                Kind::Tcp => "tcp",
                Kind::DnsTcp => "dns_tcp",
                Kind::DnsName => "dns_name",
            };
            format!("{} {} {} {}", t.id, k, t.host, t.port.map(|x| x.to_string()).unwrap_or_else(|| "-".into()))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Pure outcome of one target. `c` is the helper's stderr class (`refused|noroute|unreach|none|other`). A RST (`refused`) proves a path exists ⇒ `reachable`.
pub fn classify(kind: Kind, rc: i64, c: &str) -> Outcome {
    match kind {
        Kind::Tcp | Kind::DnsTcp => {
            if rc == 0 || c == "refused" {
                Outcome::Reachable
            } else if rc == 124 || rc == 137 || c == "noroute" || c == "unreach" {
                Outcome::Blocked
            } else {
                Outcome::Error
            }
        }
        Kind::DnsName => match rc {
            0 => Outcome::Reachable,
            2 | 124 | 137 => Outcome::Blocked,
            _ => Outcome::Error,
        },
    }
}

/// Executor deadline: `min(300, targets × ceil(timeout_ms/1000 + 1) + 60)` seconds.
pub fn deadline_of(p: &ProbePayload) -> Duration {
    let per = (p.timeout_ms as f64 / 1000.0 + 1.0).ceil() as u64;
    Duration::from_secs((p.targets.len() as u64 * per + 60).min(300))
}

/// Helper stdout → (self DNS ok, outcome per target in payload order). Anything unexpected (missing START/END/S, unknown / duplicate / missing id, bad numbers) is `helper_failed`.
pub fn parse_output(stdout: &str, p: &ProbePayload) -> Result<(bool, Vec<(String, Outcome)>), Code> {
    let bad = Err(Code::HelperFailed);
    let lines: Vec<&str> = stdout.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect();
    if lines.first() != Some(&"PBM-PROBE-START") || lines.last() != Some(&"PBM-PROBE-END") || lines.len() < 3 {
        return bad;
    }
    let mut self_dns = None;
    let mut got: std::collections::BTreeMap<&str, Outcome> = Default::default();
    for l in &lines[1..lines.len() - 1] {
        let parts: Vec<&str> = l.split(' ').collect();
        match parts.as_slice() {
            ["S", v @ ("ok" | "fail")] if self_dns.is_none() => self_dns = Some(*v == "ok"),
            ["R", id, rc, c] => {
                let Some(t) = p.targets.iter().find(|t| t.id == *id) else { return bad };
                let Ok(rc) = rc.parse::<i64>() else { return bad };
                if !["refused", "noroute", "unreach", "none", "other"].contains(c) || got.insert(t.id.as_str(), classify(t.kind, rc, c)).is_some() {
                    return bad;
                }
            }
            _ => return bad,
        }
    }
    let Some(self_dns) = self_dns else { return bad };
    if got.len() != p.targets.len() {
        return bad;
    }
    Ok((self_dns, p.targets.iter().map(|t| (t.id.clone(), got[t.id.as_str()])).collect()))
}

/// Run one probe. The wipe ALWAYS runs (also when the helper or the parse failed) and is verified; a failed wipe wins over every other error.
pub async fn execute(ops: &dyn RunnerDocker, agent_id: &str, payload: &[u8]) -> Result<Value, (Code, Option<Value>)> {
    let p = parse(payload).map_err(|c| (c, None))?;
    let short = &p.probe_id[..8];
    let net = format!("pbr-probe-{short}");
    let labels: Labels = Labels::from([(LABEL_PROBE.to_string(), p.probe_id.clone()), (LABEL_AGENT.to_string(), agent_id.to_string())]);
    let helper = format!("pbr-probe-{short}-h");
    let deadline = deadline_of(&p);
    let ran: Result<(i64, Vec<u8>), Code> = match ops.create_probe_network(&net, &labels).await {
        Err(c) => Err(c),
        Ok(()) => {
            let spec = HelperSpec {
                name: helper.clone(),
                network: net.clone(),
                labels: labels.clone(),
                env: vec![("PBM_TARGETS".into(), targets_env(&p)), ("PBM_T".into(), format!("{:.1}", p.timeout_ms as f64 / 1000.0)), ("PBM_SELF".into(), helper.clone())],
                timeout: deadline.saturating_sub(Duration::from_secs(30)).max(Duration::from_secs(30)),
            };
            ops.run_probe_helper(&spec).await
        }
    };
    let wiped = wipe_owned(ops, LABEL_PROBE, Some(&p.probe_id)).await.map_err(|_| (Code::WipeIncomplete, None))?;
    let (rc, out) = ran.map_err(|c| (c, None))?;
    if rc != 0 {
        return Err((Code::HelperFailed, None));
    }
    let (self_dns, results) = parse_output(&String::from_utf8_lossy(&out), &p).map_err(|c| (c, None))?;
    Ok(json!({
        "v": 1,
        "probe_id": p.probe_id,
        "targets_sha256": p.targets_sha256,
        "self_dns": if self_dns { "ok" } else { "fail" },
        "results": results.iter().map(|(id, o)| json!({"id": id, "outcome": o.as_str()})).collect::<Vec<_>>(),
        "wiped": {"containers": wiped.containers, "networks": wiped.networks},
    }))
}
