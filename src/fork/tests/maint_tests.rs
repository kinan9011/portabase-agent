//! Channel maintenance (W15b): the pure rules of `maint::apply` / `effective_pins`, the state-file compatibility and the secret-hygiene canary.
use super::*;
use crate::fork::crypto::Pin;
use crate::fork::maint::{apply, effective_credential, effective_pins, is_maint, MAX_PINS};
use crate::fork::state::{Redacted, State, StoredPin};
use serde_json::{Value, json};

fn kid_of(p: &VPin) -> String {
    p.kid.clone()
}
fn add(v: &Vectors, s: &State, bundle: &[Pin], spare: usize) -> Result<(State, Value), &'static str> {
    let p = &v.spare_pins[spare];
    apply(s, bundle, CRED0, &v.agent_id, &v.pins[0].kid, "pin_add", json!({"kid": p.kid, "pem": p.pem}).to_string().as_bytes())
}
fn revoke(v: &Vectors, s: &State, bundle: &[Pin], kid: &str, signing: &str) -> Result<(State, Value), &'static str> {
    apply(s, bundle, CRED0, &v.agent_id, signing, "pin_revoke", json!({"kid": kid}).to_string().as_bytes())
}
const CRED0: &str = "fork.11111111-1111-4111-8111-111111111111.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CRED1: &str = "fork.11111111-1111-4111-8111-111111111111.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

fn fixture() -> (Vectors, Vec<Pin>, State) {
    let v = vectors();
    let bundle = pins(&v);
    let s = State::fresh(&v.enroll_id);
    (v, bundle, s)
}
fn kids(r: &Value) -> Vec<String> {
    r["pinned"].as_array().unwrap().iter().map(|k| k.as_str().unwrap().to_string()).collect()
}

#[test]
fn the_three_maintenance_types_are_recognised_and_nothing_else() {
    assert!(is_maint("pin_add") && is_maint("pin_revoke") && is_maint("rotate_credential"));
    assert!(!is_maint("noop") && !is_maint("restore") && !is_maint(""));
}

#[test]
fn pin_add_adds_one_key_and_reports_the_sorted_kids() {
    let (v, bundle, s) = fixture();
    let (ns, r) = add(&v, &s, &bundle, 0).unwrap();
    let mut want = vec![kid_of(&v.pins[0]), kid_of(&v.spare_pins[0])];
    want.sort();
    assert_eq!(kids(&r), want);
    assert_eq!(ns.extra_pins.len(), 1);
    assert_eq!(effective_pins(&bundle, &ns).unwrap().len(), 2);
    assert!(!r.to_string().contains("BEGIN"), "a result never carries a key");
}

#[test]
fn pin_add_of_a_pinned_kid_is_an_idempotent_success() {
    let (v, bundle, s) = fixture();
    let (s1, _) = add(&v, &s, &bundle, 0).unwrap();
    let (s2, r) = add(&v, &s1, &bundle, 0).unwrap();
    assert_eq!(s2.extra_pins.len(), 1);
    assert_eq!(kids(&r).len(), 2);
    // the bundle's own pin re-added: also a no-op
    let p = &v.pins[0];
    let (_, r) = apply(&s1, &bundle, CRED0, &v.agent_id, "x", "pin_add", json!({"kid": p.kid, "pem": p.pem}).to_string().as_bytes()).unwrap();
    assert_eq!(kids(&r).len(), 2);
}

#[test]
fn pin_add_stops_at_eight_pins() {
    let (v, bundle, mut s) = fixture();
    for i in 0..(MAX_PINS - 1) {
        s = add(&v, &s, &bundle, i).unwrap().0;
    }
    assert_eq!(effective_pins(&bundle, &s).unwrap().len(), MAX_PINS);
    assert_eq!(add(&v, &s, &bundle, MAX_PINS - 1).unwrap_err(), "payload_invalid");
}

#[test]
fn pin_add_refuses_a_kid_that_is_not_its_key_a_bad_pem_and_extra_fields() {
    let (v, bundle, s) = fixture();
    let p = &v.spare_pins[0];
    let other = &v.spare_pins[1];
    let go = |body: Value| apply(&s, &bundle, CRED0, &v.agent_id, "x", "pin_add", body.to_string().as_bytes()).unwrap_err();
    assert_eq!(go(json!({"kid": other.kid, "pem": p.pem})), "payload_invalid"); // kid of another key
    assert_eq!(go(json!({"kid": p.kid, "pem": "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"})), "payload_invalid");
    assert_eq!(go(json!({"kid": p.kid, "pem": "not a pem"})), "payload_invalid");
    assert_eq!(go(json!({"kid": p.kid, "pem": p.pem, "extra": 1})), "payload_invalid");
    assert_eq!(go(json!({"kid": p.kid})), "payload_invalid");
    // an EC key is not an RSA pin
    let ec = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcMmEAVdL6ZWjHtAd1fE5ii6AFGsZkVGg5pv1Hqg2+LzsJvlSHqSPMtN/tnuOTRoA3xYVwvk8lhgZpc2pcmFx9g==\n-----END PUBLIC KEY-----";
    assert_eq!(go(json!({"kid": "000000000000", "pem": ec})), "payload_invalid");
}

#[test]
fn pin_revoke_removes_an_added_pin_and_a_bundle_pin_goes_to_revoked_kids() {
    let (v, bundle, s) = fixture();
    let (s1, _) = add(&v, &s, &bundle, 0).unwrap();
    // revoke the added one, signed by the bundle key
    let (s2, r) = revoke(&v, &s1, &bundle, &v.spare_pins[0].kid, &v.pins[0].kid).unwrap();
    assert_eq!(kids(&r), vec![v.pins[0].kid.clone()]);
    assert!(s2.extra_pins.is_empty() && s2.revoked_kids.is_empty());
    // revoke the BUNDLE pin, signed by the added key
    let (s3, r) = revoke(&v, &s1, &bundle, &v.pins[0].kid, &v.spare_pins[0].kid).unwrap();
    assert_eq!(kids(&r), vec![v.spare_pins[0].kid.clone()]);
    assert_eq!(s3.revoked_kids, vec![v.pins[0].kid.clone()]);
    assert_eq!(effective_pins(&bundle, &s3).unwrap().len(), 1);
    // un-revoke: pin_add of the revoked bundle key brings it back without duplicating it
    let p = &v.pins[0];
    let (s4, r) = apply(&s3, &bundle, CRED0, &v.agent_id, &v.spare_pins[0].kid, "pin_add", json!({"kid": p.kid, "pem": p.pem}).to_string().as_bytes()).unwrap();
    assert!(s4.revoked_kids.is_empty() && s4.extra_pins.len() == 1);
    assert_eq!(kids(&r).len(), 2);
}

#[test]
fn pin_revoke_refuses_the_signing_kid_the_last_pin_and_an_unknown_kid() {
    let (v, bundle, s) = fixture();
    let (s1, _) = add(&v, &s, &bundle, 0).unwrap();
    assert_eq!(revoke(&v, &s1, &bundle, &v.pins[0].kid, &v.pins[0].kid).unwrap_err(), "payload_invalid", "the key that signed the task");
    assert_eq!(revoke(&v, &s1, &bundle, "ffffffffffff", &v.pins[0].kid).unwrap_err(), "payload_invalid", "unknown kid");
    assert_eq!(revoke(&v, &s, &bundle, &v.pins[0].kid, &v.spare_pins[0].kid).unwrap_err(), "payload_invalid", "the last pin");
    assert_eq!(apply(&s1, &bundle, CRED0, &v.agent_id, "x", "pin_revoke", br#"{"kid":"abc"}"#).unwrap_err(), "payload_invalid");
}

#[test]
fn rotate_stores_the_new_credential_and_refuses_foreign_same_or_malformed_ones() {
    let (v, bundle, s) = fixture();
    let go = |s: &State, c: &str| apply(s, &bundle, CRED0, &v.agent_id, "x", "rotate_credential", json!({"credential": c}).to_string().as_bytes());
    let (ns, r) = go(&s, CRED1).unwrap();
    assert_eq!(r, json!({"rotated": true}));
    assert_eq!(effective_credential(CRED0, &ns), CRED1);
    assert_eq!(effective_credential(CRED0, &s), CRED0);
    assert_eq!(go(&s, CRED0).unwrap_err(), "payload_invalid", "same as the bundle credential");
    assert_eq!(go(&ns, CRED1).unwrap_err(), "payload_invalid", "same as the current rotated credential");
    assert_eq!(go(&s, "fork.99999999-9999-4999-8999-999999999999.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB").unwrap_err(), "payload_invalid", "other agent");
    assert_eq!(go(&s, "fork.11111111-1111-4111-8111-111111111111.short").unwrap_err(), "payload_invalid");
    assert_eq!(go(&s, "garbage").unwrap_err(), "payload_invalid");
    assert_eq!(apply(&s, &bundle, CRED0, &v.agent_id, "x", "rotate_credential", br#"{"credential":"x","y":1}"#).unwrap_err(), "payload_invalid");
}

#[test]
fn an_unknown_type_is_not_a_maintenance_type() {
    let (v, bundle, s) = fixture();
    assert_eq!(apply(&s, &bundle, CRED0, &v.agent_id, "x", "format_disk", b"{}").unwrap_err(), "unsupported_type");
}

#[test]
fn effective_pins_fail_closed() {
    let (v, bundle, s) = fixture();
    // everything revoked
    let mut none = s.clone();
    none.revoked_kids.push(v.pins[0].kid.clone());
    assert!(effective_pins(&bundle, &none).is_err());
    // an unparsable stored pin
    let mut bad = s.clone();
    bad.extra_pins.push(StoredPin { kid: "000000000000".into(), pem: "garbage".into() });
    assert!(effective_pins(&bundle, &bad).is_err());
    // a stored pin whose kid does not match its key
    let mut wrong = s.clone();
    wrong.extra_pins.push(StoredPin { kid: v.spare_pins[1].kid.clone(), pem: v.spare_pins[0].pem.clone() });
    assert!(effective_pins(&bundle, &wrong).is_err());
    // too many
    let mut many = s.clone();
    for p in &v.spare_pins {
        many.extra_pins.push(StoredPin { kid: p.kid.clone(), pem: p.pem.clone() });
    }
    assert!(effective_pins(&bundle, &many).is_err(), "1 bundle + 8 stored = 9");
    // duplicates collapse
    let mut dup = s.clone();
    dup.extra_pins.push(StoredPin { kid: v.pins[0].kid.clone(), pem: v.pins[0].pem.clone() });
    assert_eq!(effective_pins(&bundle, &dup).unwrap().len(), 1);
}

#[test]
fn a_w15_state_file_without_the_new_fields_still_loads_and_the_new_fields_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, r#"{"enroll_id":"e1","last_seq":7,"accepted":[{"task_id":"t","seq":7,"outcome":null}]}"#).unwrap();
    let s = crate::fork::state::load(&path, "e1").unwrap();
    assert_eq!(s.last_seq, 7);
    assert!(s.credential.is_none() && s.extra_pins.is_empty() && s.revoked_kids.is_empty());
    let mut s2 = s.clone();
    s2.credential = Some(Redacted(CRED1.into()));
    s2.revoked_kids.push("aaaaaaaaaaaa".into());
    crate::fork::state::save(&path, &s2).unwrap();
    assert_eq!(crate::fork::state::load(&path, "e1").unwrap(), s2);
    // a new enrolment generation drops all of it (re-enrol is the universal cure)
    let fresh = crate::fork::state::load(&path, "e2").unwrap();
    assert!(fresh.credential.is_none() && fresh.revoked_kids.is_empty());
}

#[test]
fn the_debug_output_of_the_state_never_contains_the_credential() {
    let mut s = State::fresh("e1");
    s.credential = Some(Redacted(CRED1.into()));
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("BBBBBBBB") && dbg.contains("[redacted]"), "{dbg}");
}
