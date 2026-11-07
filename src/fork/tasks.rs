//! Task executors. W15 ships exactly one: `noop` (an echo that proves the signed round trip end to end). Restore / compose / quiesce types
//! are W17 / W17b; every one of them must be idempotent under its `task_id` and bounded by its own deadline.
use serde_json::{Value, json};

pub fn execute(task_type: &str, payload: &[u8]) -> Result<Value, &'static str> {
    match task_type {
        "noop" => {
            let v: Value = serde_json::from_slice(payload).map_err(|_| "payload_invalid")?;
            let echo = v.get("echo").and_then(Value::as_str).ok_or("payload_invalid")?;
            if echo.is_empty() || echo.len() > 64 || !echo.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err("payload_invalid");
            }
            Ok(json!({"echo": echo, "agent": "fork-stacks"}))
        }
        _ => Err("unsupported_type"),
    }
}
