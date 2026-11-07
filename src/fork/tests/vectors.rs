//! Every refusal class + the accept paths, against signatures produced by the dashboard code (cross-language).
use super::*;
use crate::fork::envelope::parse;
use crate::fork::state::{Accepted, Outcome, State};
use crate::fork::verify::{Ctx, Decision, evaluate};

fn run(v: &Vectors, c: &VCase) -> Decision {
    let pins = pins(v);
    let key = task_key(v);
    let mut state = State::fresh(&v.enroll_id);
    state.last_seq = c.last_seq.unwrap_or(0);
    for id in c.known.clone().unwrap_or_default() {
        state.accepted.push(Accepted { task_id: id, seq: state.last_seq, outcome: Some(Outcome { status: "succeeded".into(), reason: None, result: None }) });
    }
    let ctx = Ctx { agent_id: &v.agent_id, enroll_id: &v.enroll_id, pins: &pins, task_key: &key, capabilities: &v.own_capabilities, state: &state, now: v.now };
    evaluate(&ctx, &c.envelope, &c.signature, c.payload_enc.as_deref())
}

#[test]
fn every_vector_gets_exactly_the_expected_decision() {
    let v = vectors();
    assert!(v.cases.len() >= 20);
    for c in &v.cases {
        let got = run(&v, c);
        match (c.expect.as_str(), &got) {
            ("ok", Decision::Accept(a)) => assert_eq!(a.payload, c.payload_plain.as_deref().unwrap_or(r#"{"echo":"hi"}"#).as_bytes(), "{}", c.name),
            ("duplicate", Decision::Duplicate(_)) => {}
            (code, Decision::Reject(r)) => assert_eq!(r.code(), code, "{}", c.name),
            (e, g) => panic!("{}: expected {e}, got {g:?}", c.name),
        }
    }
}

#[test]
fn forged_unsigned_tampered_and_foreign_key_tasks_are_never_accepted() {
    let v = vectors();
    for n in ["forged_signature_other_key", "unsigned", "garbage_signature", "tampered_after_signing", "unknown_kid"] {
        assert!(matches!(run(&v, case(&v, n)), Decision::Reject(_)), "{n}");
    }
}

#[test]
fn expired_future_foreign_and_rolled_back_tasks_are_refused_but_skew_is_tolerated() {
    let v = vectors();
    assert!(matches!(run(&v, case(&v, "valid_within_skew")), Decision::Accept(_)));
    for n in ["expired", "not_yet_valid", "foreign_agent", "other_enrolment", "target_mismatch", "seq_equal_to_last", "seq_below_last"] {
        assert!(matches!(run(&v, case(&v, n)), Decision::Reject(_)), "{n}");
    }
}

#[test]
fn envelope_parser_is_strict() {
    let v = vectors();
    let ok = &case(&v, "valid").envelope;
    assert!(parse(ok).is_some());
    assert!(parse(&ok.replace("\"seq\":1", "\"seq\":1.5")).is_none());
    assert!(parse(&ok.replace("\"v\":1", "\"v\":2")).is_none());
    assert!(parse(&ok.replace('}', ",\"x\":1}")).is_none());
    assert!(parse("").is_none() && parse("[]").is_none() && parse("null").is_none());
}

#[test]
fn replay_state_is_bounded_and_set_once() {
    let mut s = State::fresh("e");
    for i in 0..300u64 {
        s.accept(&format!("t{i}"), i + 1);
    }
    assert_eq!(s.accepted.len(), crate::fork::state::MAX_ACCEPTED);
    assert_eq!(s.last_seq, 300);
    assert!(s.known("t0").is_none() && s.known("t299").is_some());
}
