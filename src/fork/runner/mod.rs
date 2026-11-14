//! W21 (ADR-008): the mirror RUNNER role. A host started with `FORK_HOST_ROLE=runner` reports exactly `channel.v1, noop.v1, channel-maint.v1, runner.v1`
//! (never a restore / compose / quiesce / test-restore capability), accepts only runner + common task types (`verify.rs` `role_forbidden`) and never loads the
//! instance master key into fork state. Everything here is fork-only; no upstream file is touched.
pub mod docker;
pub mod mirror;
pub mod probe;
pub mod wipe;

#[cfg(test)]
mod tests;

/// Closed failure codes of the runner executors. The dashboard accepts exactly these as `failed` reasons (`REASONS` in `agent-channel/tasks.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    PayloadInvalid,
    DockerUnavailable,
    HelperFailed,
    WipeIncomplete,
    DeadlineExceeded,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::PayloadInvalid => "payload_invalid",
            Code::DockerUnavailable => "docker_unavailable",
            Code::HelperFailed => "helper_failed",
            Code::WipeIncomplete => "wipe_incomplete",
            Code::DeadlineExceeded => "deadline_exceeded",
        }
    }
}

/// `true` only for `FORK_HOST_ROLE=runner` (trimmed, exact). Any other value keeps the restore path (and its own validation of the variable).
pub fn role_is_runner(env: &dyn Fn(&str) -> Option<String>) -> bool {
    env("FORK_HOST_ROLE").is_some_and(|v| v.trim() == "runner")
}
