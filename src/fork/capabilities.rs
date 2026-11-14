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

/// W17b: composite `quiesce` (stop → capture window → start, journaled, agent-local deadline) and the journal-bound `quiesce_start`. Reported ONLY when the host
/// owner opted in (`FORK_QUIESCE_ENABLED=true` on the agent), Docker answers, the agent knows its own container id and `FORK_PROTECTED_CONTAINERS` is valid.
pub const QUIESCE: &str = "quiesce.v1";

/// W-TR: `restore_verify` (engine integrity check of staged data in a no-network helper, ADR-007 A16). Reported only when restore is enabled AND this image
/// has the checkers (`sqlite3`, `pg_restore`): otherwise the dashboard refuses to schedule test restores for this agent.
pub const TEST_RESTORE: &str = "test-restore.v1";

/// W21 (ADR-008): the mirror RUNNER role. Reported ONLY when `FORK_HOST_ROLE=runner`, Docker answers and the helper image resolves. A runner reports
/// no restore / compose / quiesce / test-restore / plaintext-hash capability (it takes no backups and restores no production data).
pub const RUNNER: &str = "runner.v1";

/// W22a-f1: signed, target-addressed mirror tasks (`mirror_*`). Reported ONLY by a runner whose `FORK_MIRROR_ROOT` is valid, Docker answers, the Compose CLI is the pinned
/// one and the instance master key decodes (realised residual R-W21-1, ADR-008 §12). A runner without it stays a probe-only runner.
pub const MIRROR: &str = "mirror.v1";

/// Task types only a runner executes. A runner refuses everything that is neither runner-only nor common, and every non-runner refuses these.
pub const RUNNER_ONLY: &[&str] = &["runner_probe", "mirror_probe", "mirror_stage", "mirror_apply", "mirror_render", "mirror_finalize", "mirror_db", "mirror_up", "mirror_check", "mirror_wipe", "mirror_stop"];
/// Task types both roles accept (channel hygiene: no data, no Docker).
pub const COMMON: &[&str] = &["noop", "pin_add", "pin_revoke", "rotate_credential"];
pub fn is_runner_only(task_type: &str) -> bool {
    RUNNER_ONLY.contains(&task_type)
}
/// The nine `mirror_*` task types (W22a-f1).
pub fn is_mirror(task_type: &str) -> bool {
    task_type.starts_with("mirror_") && is_runner_only(task_type)
}
pub fn is_common(task_type: &str) -> bool {
    COMMON.contains(&task_type)
}
/// The exact capability set of a runner agent (DD-2; ADR-008 §12 adds `mirror.v1` for a mirror-enabled runner).
pub fn runner_reported(mirror_ok: bool) -> Vec<String> {
    let mut v = vec![CHANNEL.to_string(), NOOP.to_string(), MAINT.to_string(), RUNNER.to_string()];
    if mirror_ok {
        v.push(MIRROR.to_string());
    }
    v
}

/// Task types whose envelope MUST name this agent in `target_agent_id` (ADR-007 D8b). Mirrors the dashboard's `TARGETED_TASK_TYPES`.
pub const TARGETED: &[&str] = &["restore_probe", "restore_stage", "restore_apply", "restore_cleanup", "compose_render", "restore_db", "compose_up", "quiesce", "quiesce_start", "restore_verify", "runner_probe", "mirror_probe", "mirror_stage", "mirror_apply", "mirror_render", "mirror_finalize", "mirror_db", "mirror_up", "mirror_check", "mirror_wipe", "mirror_stop"];
pub fn is_targeted(task_type: &str) -> bool {
    TARGETED.contains(&task_type)
}

pub fn reported(restore_ok: bool, compose_ok: bool, quiesce_ok: bool, test_restore_ok: bool) -> Vec<String> {
    let mut v = vec![CHANNEL.to_string(), NOOP.to_string(), PLAINTEXT_HASH.to_string(), MAINT.to_string()];
    if restore_ok {
        v.push(RESTORE_TARGET.to_string());
        if compose_ok {
            v.push(COMPOSE_RENDER.to_string());
        }
        if test_restore_ok {
            v.push(TEST_RESTORE.to_string());
        }
    }
    if quiesce_ok {
        v.push(QUIESCE.to_string());
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
        "restore_verify" => Some(&[RESTORE_TARGET, TEST_RESTORE]),
        "quiesce" | "quiesce_start" => Some(&[QUIESCE]),
        "runner_probe" => Some(&[RUNNER]),
        "mirror_probe" | "mirror_stage" | "mirror_apply" | "mirror_render" | "mirror_finalize" | "mirror_db" | "mirror_up" | "mirror_check" | "mirror_wipe" | "mirror_stop" => Some(&[RUNNER, MIRROR]),
        _ => None,
    }
}
