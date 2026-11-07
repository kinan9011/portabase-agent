//! The decision function of the channel: given what the dashboard sent and what the agent knows, accept or refuse (never partially).
//! Pure (no I/O, injected clock) so every refusal class is a unit-test fixture, including the cross-language vectors signed by the dashboard.
use super::capabilities::task_requires;
use super::crypto::{Pin, decrypt_payload, sha256_hex, verify_signature};
use super::envelope::{Envelope, parse};
use super::state::{Accepted, State};

/// Skew accepted on `not_after` and on a future-dated `issued_at` (ADR-007 D3).
pub const SKEW_AFTER: i64 = 60;
pub const SKEW_BEFORE: i64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    BadSignature,
    UnknownKid,
    BadEnvelope,
    AgentMismatch,
    EnrollMismatch,
    TargetMismatch,
    Expired,
    NotYetValid,
    SeqRollback,
    UnsupportedType,
    CapabilityMissing,
    PayloadHash,
    PayloadInvalid,
    ChannelDisabled,
    StateUnavailable,
}

impl Reject {
    /// The closed reason code the dashboard accepts (`REASONS` in `agent-channel/tasks.ts`).
    pub fn code(self) -> &'static str {
        match self {
            Reject::BadSignature => "bad_signature",
            Reject::UnknownKid => "unknown_kid",
            Reject::BadEnvelope => "bad_envelope",
            Reject::AgentMismatch => "agent_mismatch",
            Reject::EnrollMismatch => "enroll_mismatch",
            Reject::TargetMismatch => "target_mismatch",
            Reject::Expired => "expired",
            Reject::NotYetValid => "not_yet_valid",
            Reject::SeqRollback => "seq_rollback",
            Reject::UnsupportedType => "unsupported_type",
            Reject::CapabilityMissing => "capability_missing",
            Reject::PayloadHash => "payload_hash",
            Reject::PayloadInvalid => "payload_invalid",
            Reject::ChannelDisabled => "channel_disabled",
            Reject::StateUnavailable => "state_unavailable",
        }
    }
}

#[derive(Debug)]
pub struct Verified {
    pub envelope: Envelope,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum Decision {
    Accept(Verified),
    /// Already accepted before (lease expired / result lost): never executed again; the stored outcome is re-reported.
    Duplicate(Box<Accepted>),
    Reject(Reject),
}

pub struct Ctx<'a> {
    pub agent_id: &'a str,
    pub enroll_id: &'a str,
    pub pins: &'a [Pin],
    pub task_key: &'a [u8; 32],
    pub capabilities: &'a [String],
    pub state: &'a State,
    /// Unix seconds.
    pub now: i64,
}

pub fn evaluate(c: &Ctx, envelope_text: &str, signature_b64: &str, payload_enc: Option<&str>) -> Decision {
    use Decision::Reject as R;
    let Some(env) = parse(envelope_text) else { return R(Reject::BadEnvelope) };
    let Some(pin) = c.pins.iter().find(|p| p.kid == env.kid) else { return R(Reject::UnknownKid) };
    if !verify_signature(pin, envelope_text, signature_b64) {
        return R(Reject::BadSignature);
    }
    // ---- from here on the envelope is authentic: it was produced by the dashboard key we pinned ----
    if env.agent_id != c.agent_id {
        return R(Reject::AgentMismatch);
    }
    if env.enroll_id != c.enroll_id {
        return R(Reject::EnrollMismatch);
    }
    if env.target_agent_id.as_deref().is_some_and(|t| t != c.agent_id) {
        return R(Reject::TargetMismatch);
    }
    if let Some(a) = c.state.known(&env.task_id) {
        return Decision::Duplicate(Box::new(a.clone()));
    }
    if c.now > env.not_after + SKEW_AFTER {
        return R(Reject::Expired);
    }
    if env.issued_at > c.now + SKEW_BEFORE {
        return R(Reject::NotYetValid);
    }
    if env.seq <= c.state.last_seq {
        return R(Reject::SeqRollback);
    }
    let Some(needs) = task_requires(&env.task_type) else { return R(Reject::UnsupportedType) };
    // both what the type needs and what the dashboard says it needs must be covered by what THIS agent reports
    if !needs.iter().all(|n| c.capabilities.iter().any(|x| x == n)) || !env.requires.iter().all(|n| c.capabilities.iter().any(|x| x == n)) {
        return R(Reject::CapabilityMissing);
    }
    let Some(enc) = payload_enc else { return R(Reject::PayloadInvalid) };
    let Some(payload) = decrypt_payload(c.task_key, &env.task_id, c.agent_id, &env.task_type, enc) else { return R(Reject::PayloadInvalid) };
    if sha256_hex(&payload) != env.payload_sha256 {
        return R(Reject::PayloadHash);
    }
    Decision::Accept(Verified { envelope: env, payload })
}
