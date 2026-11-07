//! Per-service policy approval token re-check on the agent (ADR-015 D-6 / D-7, E6). The token is DATA (no secret, no MAC): its integrity is the D34 task
//! signature that carried it. Fail closed: hard refusals are never overridable and not even representable; one byte off in the render ⇒ `compose_changed`.
//! D-7: `rules_sha256` is informational on the agent (the agent evaluates with ITS embedded rule file; the corpus drift test keeps both equal), so a token
//! built against another rule-set revision is not refused by the hash alone.
use super::rendered::Verdict;
use super::rules::RULE_IDS;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub struct Ctx<'a> {
    pub stack_id: &'a str,
    pub rp_id: &'a str,
    pub agent_id: &'a str,
}

fn hex64(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| crate::fork::restore::is_hex64(s))
}
/// zod `z.uuid()`: 8-4-4-4-12 hex, version 1-8, variant 8-b (case-insensitive), plus the nil / max uuid.
fn is_uuid_any(s: &str) -> bool {
    if s == "00000000-0000-0000-0000-000000000000" || s.eq_ignore_ascii_case("ffffffff-ffff-ffff-ffff-ffffffffffff") {
        return true;
    }
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
        && (b'1'..=b'8').contains(&b[14])
        && matches!(b[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b')
}
fn service_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 128 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

struct Token<'a> {
    compose_sha256: &'a str,
    roots: Vec<&'a str>,
    stack_id: &'a str,
    rp_id: &'a str,
    agent_id: &'a str,
    overrides: Vec<(&'a str, Vec<&'a str>)>,
}

/// strict schema of `PolicyApprovalV1` (unknown key ⇒ invalid)
fn parse(t: &Value) -> Option<Token<'_>> {
    let o = t.as_object()?;
    const KEYS: [&str; 8] = ["v", "compose_sha256", "rules_sha256", "roots", "stack_id", "rp_id", "target_agent_id", "overrides"];
    if o.len() != KEYS.len() || !KEYS.iter().all(|k| o.contains_key(*k)) || o.get("v")?.as_u64() != Some(1) {
        return None;
    }
    hex64(&o["rules_sha256"])?;
    let compose_sha256 = hex64(&o["compose_sha256"])?;
    let roots: Vec<&str> = o["roots"].as_array()?.iter().map(|r| r.as_str().filter(|s| !s.is_empty() && s.chars().count() <= 1024)).collect::<Option<_>>()?;
    if roots.is_empty() || roots.len() > 16 {
        return None;
    }
    let uuid = |k: &str| o[k].as_str().filter(|s| is_uuid_any(s));
    let (stack_id, rp_id, agent_id) = (uuid("stack_id")?, uuid("rp_id")?, uuid("target_agent_id")?);
    let ovs = o["overrides"].as_array()?;
    if ovs.is_empty() || ovs.len() > 500 {
        return None;
    }
    let mut overrides = vec![];
    for ov in ovs {
        let m = ov.as_object()?;
        if m.len() != 2 {
            return None;
        }
        let service = m.get("service")?.as_str().filter(|s| service_ok(s))?;
        let rules: Vec<&str> = m.get("rules")?.as_array()?.iter().map(|r| r.as_str().filter(|r| RULE_IDS.contains(r))).collect::<Option<_>>()?;
        if rules.is_empty() || rules.len() > RULE_IDS.len() {
            return None;
        }
        overrides.push((service, rules));
    }
    Some(Token { compose_sha256, roots, stack_id, rp_id, agent_id, overrides })
}

/// `Ok(())` = the render may run. `Err(code)` = `approval_invalid` detail (the TS `CheckFailure` vocabulary + `none`).
/// `verdict` is the agent's OWN verdict of the freshly rendered policy view; `token` the payload's `approval`.
pub fn check(v: &Verdict, token: Option<&Value>, ctx: &Ctx) -> Result<(), &'static str> {
    let token = token.filter(|t| !t.is_null());
    if !v.hard.is_empty() || v.verdict == "deny" {
        return Err("hard_refusal");
    }
    let want: BTreeMap<String, BTreeSet<&'static str>> = {
        let mut m: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
        for f in &v.findings {
            m.entry(f.service.clone()).or_default().insert(f.rule);
        }
        m
    };
    let Some(token) = token else {
        // an `allow` verdict needs no token; a flagged one needs one
        return if want.is_empty() { Ok(()) } else { Err("none") };
    };
    let t = parse(token).ok_or("invalid")?;
    if want.is_empty() {
        return Err("over_broad"); // a token on an `allow` verdict
    }
    if t.compose_sha256 != v.compose_sha256 {
        return Err("compose_changed");
    }
    let mut troots: Vec<&str> = t.roots.clone();
    troots.sort();
    let vroots: Vec<&str> = v.roots.iter().map(String::as_str).collect();
    if troots != vroots {
        return Err("roots_changed");
    }
    if t.stack_id != ctx.stack_id || t.rp_id != ctx.rp_id || t.agent_id != ctx.agent_id {
        return Err("context_mismatch");
    }
    let mut got: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (service, rules) in &t.overrides {
        let set: BTreeSet<&str> = rules.iter().copied().collect();
        if got.contains_key(service) || set.len() != rules.len() {
            return Err("invalid");
        }
        got.insert(service, set);
    }
    for (service, rules) in &want {
        match got.get(service.as_str()) {
            Some(g) if rules.iter().all(|r| g.contains(r)) => {}
            _ => return Err("not_covered"),
        }
    }
    for (service, rules) in &got {
        match want.get(*service) {
            Some(w) if rules.iter().all(|r| w.contains(r)) => {}
            _ => return Err("over_broad"),
        }
    }
    Ok(())
}
