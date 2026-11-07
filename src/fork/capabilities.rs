//! Capabilities, not versions (ADR-007 D6). Reported in every lease; the dashboard never gates fork features on the agent version.
pub const CHANNEL: &str = "channel.v1";
pub const NOOP: &str = "noop.v1";
pub const PLAINTEXT_HASH: &str = "plaintext-hash.v1";
/// W15b: signed `pin_add` / `pin_revoke` / `rotate_credential` (ADR-007 A11).
pub const MAINT: &str = "channel-maint.v1";

pub fn reported() -> Vec<String> {
    vec![CHANNEL.to_string(), NOOP.to_string(), PLAINTEXT_HASH.to_string(), MAINT.to_string()]
}

/// Task types this build can execute, with the capabilities each needs. Closed list: anything else is refused (`unsupported_type`).
pub fn task_requires(task_type: &str) -> Option<&'static [&'static str]> {
    match task_type {
        "noop" => Some(&[NOOP]),
        "pin_add" | "pin_revoke" | "rotate_credential" => Some(&[MAINT]),
        _ => None,
    }
}
