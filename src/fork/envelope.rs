use serde::Deserialize;

/// The signed task envelope. Parsed AFTER nothing is trusted yet, strictly (`deny_unknown_fields`), from the exact bytes the dashboard signed.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u8,
    pub task_id: String,
    pub agent_id: String,
    pub enroll_id: String,
    #[serde(rename = "type")]
    pub task_type: String,
    pub seq: u64,
    pub issued_at: i64,
    pub not_after: i64,
    pub nonce: String,
    pub payload_sha256: String,
    pub requires: Vec<String>,
    pub kid: String,
    #[serde(default)]
    pub target_agent_id: Option<String>,
}

pub fn parse(text: &str) -> Option<Envelope> {
    let e: Envelope = serde_json::from_str(text).ok()?;
    (e.v == 1).then_some(e)
}
