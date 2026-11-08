//! Capabilities, not versions (ADR-007 D6). Reported in every lease; the dashboard never gates fork features on the agent version.
pub const CHANNEL: &str = "channel.v1";
pub const NOOP: &str = "noop.v1";
pub const PLAINTEXT_HASH: &str = "plaintext-hash.v1";
/// W15b: signed `pin_add` / `pin_revoke` / `rotate_credential` (ADR-007 A11).
pub const MAINT: &str = "channel-maint.v1";

/// W17-i: signed, target-addressed restore tasks (`restore_probe|stage|apply|cleanup`). Reported ONLY when the host is configured for it (valid
/// `FORK_ALLOWED_PATH_ROOTS` AND the Docker daemon answers): an agent without that stays a plain backup agent and the W16 planner blocks with `target_capability_missing`.
pub const RESTORE_TARGET: &str = "restore.target.v1";
/// W17-ii: `compose_render` / `restore_db` / `compose_up` (sandboxed render, agent-side policy re-check, D29 guard). Reported only when restore is enabled AND the
/// agent knows its own container + image, runs the pinned Compose CLI and loaded its embedded rule file (E17); never without them.
pub const COMPOSE_RENDER: &str = "compose.render.v1";

/// Task types whose envelope MUST name this agent in `target_agent_id` (ADR-007 D8b). Mirrors the dashboard's `TARGETED_TASK_TYPES`.
pub const TARGETED: &[&str] = &["restore_probe", "restore_stage", "restore_apply", "restore_cleanup", "compose_render", "restore_db", "compose_up"];
pub fn is_targeted(task_type: &str) -> bool {
    TARGETED.contains(&task_type)
}

pub fn reported(restore_ok: bool, compose_ok: bool) -> Vec<String> {
    let mut v = vec![CHANNEL.to_string(), NOOP.to_string(), PLAINTEXT_HASH.to_string(), MAINT.to_string()];
    if restore_ok {
        v.push(RESTORE_TARGET.to_string());
        if compose_ok {
            v.push(COMPOSE_RENDER.to_string());
        }
    }
    v
}

/// Task types this build can execute, with the capabilities each needs. Closed list: anything else is refused (`unsupported_type`).
pub fn task_requires(task_type: &str) -> Option<&'static [&'static str]> {
    match task_type {
        "noop" => Some(&[NOOP]),
        "pin_add" | "pin_revoke" | "rotate_credential" => Some(&[MAINT]),
        "restore_probe" | "restore_stage" | "restore_apply" | "restore_cleanup" => Some(&[RESTORE_TARGET]),
        "compose_render" | "restore_db" | "compose_up" => Some(&[RESTORE_TARGET, COMPOSE_RENDER]),
        _ => None,
    }
}
