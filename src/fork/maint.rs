//! Channel maintenance tasks (W15b, ADR-007 A11): signed `pin_add`, `pin_revoke`, `rotate_credential`. Pure: `apply` computes the NEW persisted state
//! and the (non-secret) result from the old state; the caller saves it BEFORE anything is swapped in memory (DD6), so a failed save changes nothing.
//! Rules fail closed: any violation is `payload_invalid` (the dashboard re-checks the same rules before it queues the task).
use super::config::valid_credential;
use super::crypto::{Pin, parse_pin};
use super::state::{State, StoredPin, Redacted};
use serde::Deserialize;
use serde_json::{Value, json};

/// Pins an agent may hold at once (same bound as the bundle parser and the dashboard).
pub const MAX_PINS: usize = 8;

pub fn is_maint(task_type: &str) -> bool {
    matches!(task_type, "pin_add" | "pin_revoke" | "rotate_credential")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinAdd {
    kid: String,
    pem: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRevoke {
    kid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rotate {
    credential: String,
}

/// Bundle pins minus revoked ones plus the runtime-added ones (deduped by kid). 0 or > `MAX_PINS` pins, or an unparsable stored pin ⇒ `Err`
/// (the channel then refuses to start: it never runs with a pin set nobody chose).
pub fn effective_pins(bundle: &[Pin], s: &State) -> Result<Vec<Pin>, &'static str> {
    let mut out: Vec<Pin> = bundle.iter().filter(|p| !s.revoked_kids.contains(&p.kid)).cloned().collect();
    for e in &s.extra_pins {
        let p = parse_pin(&e.kid, &e.pem).map_err(|_| "a stored pin is not valid")?;
        if !out.iter().any(|x| x.kid == p.kid) {
            out.push(p);
        }
    }
    if out.is_empty() || out.len() > MAX_PINS {
        return Err("the pinned key set is empty or too large");
    }
    Ok(out)
}

/// The credential the transport must use: the rotated one if a rotation was applied, else the one from the bundle.
pub fn effective_credential<'a>(bundle: &'a str, s: &'a State) -> &'a str {
    s.credential.as_ref().map(|c| c.0.as_str()).unwrap_or(bundle)
}

fn kids(pins: &[Pin]) -> Vec<String> {
    let mut k: Vec<String> = pins.iter().map(|p| p.kid.clone()).collect();
    k.sort();
    k
}

/// Apply one maintenance task. `signing_kid` = the kid the task envelope was signed with. Returns the new state + the result body
/// (`{"pinned":[kids]}` or `{"rotated":true}` — never a key or a credential).
pub fn apply(s: &State, bundle: &[Pin], bundle_credential: &str, agent_id: &str, signing_kid: &str, task_type: &str, payload: &[u8]) -> Result<(State, Value), &'static str> {
    const BAD: &str = "payload_invalid";
    let current = effective_pins(bundle, s).map_err(|_| BAD)?;
    let mut ns = s.clone();
    match task_type {
        "pin_add" => {
            let p: PinAdd = serde_json::from_slice(payload).map_err(|_| BAD)?;
            let pin = parse_pin(&p.kid, &p.pem).map_err(|_| BAD)?;
            if !current.iter().any(|x| x.kid == pin.kid) {
                if current.len() >= MAX_PINS {
                    return Err(BAD);
                }
                if bundle.iter().any(|b| b.kid == pin.kid) {
                    ns.revoked_kids.retain(|k| *k != pin.kid); // re-adding a revoked bundle pin un-revokes it
                } else {
                    ns.extra_pins.push(StoredPin { kid: pin.kid.clone(), pem: p.pem });
                }
            }
        }
        "pin_revoke" => {
            let p: PinRevoke = serde_json::from_slice(payload).map_err(|_| BAD)?;
            if !current.iter().any(|x| x.kid == p.kid) || p.kid == signing_kid || current.len() < 2 {
                return Err(BAD);
            }
            ns.extra_pins.retain(|e| e.kid != p.kid);
            if bundle.iter().any(|b| b.kid == p.kid) && !ns.revoked_kids.contains(&p.kid) {
                ns.revoked_kids.push(p.kid);
            }
        }
        "rotate_credential" => {
            let p: Rotate = serde_json::from_slice(payload).map_err(|_| BAD)?;
            if !valid_credential(agent_id, &p.credential) || p.credential == effective_credential(bundle_credential, s) {
                return Err(BAD);
            }
            ns.credential = Some(Redacted(p.credential));
            return Ok((ns, json!({"rotated": true})));
        }
        _ => return Err("unsupported_type"),
    }
    let after = effective_pins(bundle, &ns).map_err(|_| BAD)?;
    Ok((ns, json!({"pinned": kids(&after)})))
}
