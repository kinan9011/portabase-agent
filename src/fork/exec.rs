//! Long-task executor (G1, DD6): the channel's lease is 60 s, a restore takes minutes. The task future runs under a heartbeat loop (every 20 s, so a lost
//! heartbeat or two does not lose the lease) and a hard deadline; the deadline drops the future (child processes are `kill_on_drop`, helper containers are removed
//! by their own `finally`, the startup sweep catches the rest) and reports `deadline_exceeded`.
use super::transport::Transport;
use std::future::Future;
use std::time::Duration;

pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(20);

pub enum Ended<T> {
    Done(T),
    Deadline,
}

pub async fn run_with_heartbeat<T>(transport: &Transport, task_id: &str, lease_id: &str, deadline: Duration, fut: impl Future<Output = T>) -> Ended<T> {
    run_with_heartbeat_every(transport, task_id, lease_id, deadline, HEARTBEAT_EVERY, fut).await
}

/// Same with an explicit period (tests use milliseconds instead of waiting 20 s).
pub async fn run_with_heartbeat_every<T>(transport: &Transport, task_id: &str, lease_id: &str, deadline: Duration, every: Duration, fut: impl Future<Output = T>) -> Ended<T> {
    tokio::pin!(fut);
    let sleep = tokio::time::sleep(deadline);
    tokio::pin!(sleep);
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // the first tick fires immediately; the caller already sent the first heartbeat
    loop {
        tokio::select! {
            out = &mut fut => return Ended::Done(out),
            _ = &mut sleep => return Ended::Deadline,
            _ = tick.tick() => {
                // a 409 lease_mismatch / network error is logged by the transport caller, never fatal: the result path re-delivers via Duplicate (A2)
                if let Err(e) = transport.heartbeat(task_id, lease_id).await {
                    tracing::warn!("Fork channel: heartbeat for task {task_id} failed ({e:?})");
                }
            }
        }
    }
}
