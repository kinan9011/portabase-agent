//! Fork agent task channel (W15, ADR-007 D34). Compiled only with the cargo feature `fork-stacks`; the stock build contains none of this.
//!
//! The dashboard → agent direction is **signed**: the agent verifies every task against a public key it pinned from the enrolment bundle
//! (never learned over the channel), refuses unsigned / forged / expired / replayed / rolled-back / mis-addressed tasks, and only ever
//! executes a closed list of task types. The agent → dashboard direction is authenticated with a per-agent random credential. https only
//! (one explicit loopback exemption for the fork lab). See the vault ADR-007 for the full design and risk list.
pub mod capabilities;
pub mod config;
pub mod crypto;
pub mod envelope;
pub mod hash;
pub mod maint;
pub mod poll;
pub mod state;
pub mod tasks;
pub mod transport;
pub mod verify;

#[cfg(test)]
mod tests;

use std::sync::{Arc, OnceLock};

/// What the plaintext-hash hook (A03) needs once the channel is running. Set exactly once by `start()`.
pub(crate) struct Active {
    pub client: transport::Transport,
    pub capabilities: Vec<String>,
}
static ACTIVE: OnceLock<Arc<Active>> = OnceLock::new();
pub(crate) fn active() -> Option<Arc<Active>> {
    ACTIVE.get().cloned()
}

/// Entry point (hook A01). Never panics and never blocks the stock poll loop: a disabled or misconfigured channel logs once and returns,
/// and in that case NO request is ever made to the dashboard (the agent has nothing to lease, so nothing can be delivered).
pub async fn start() {
    let env = |k: &str| std::env::var(k).ok();
    match config::load(&env) {
        Ok(config::Startup::Disabled(why)) => tracing::info!("Fork task channel disabled ({why})"),
        Ok(config::Startup::Active(cfg)) => {
            tracing::info!("Fork task channel enabled for agent {} (bundle pin fingerprint {})", cfg.agent_id, cfg.pin_fingerprint);
            if cfg.insecure_lab {
                tracing::warn!("Fork task channel: INSECURE http transport allowed for a loopback lab host (FORK_ALLOW_INSECURE_LOOPBACK). Never use this outside the fork lab.");
            }
            poll::run(*cfg).await;
        }
        Err(e) => tracing::error!("Fork task channel NOT started: {e}"),
    }
}

pub(crate) fn set_active(a: Arc<Active>) {
    let _ = ACTIVE.set(a);
}
