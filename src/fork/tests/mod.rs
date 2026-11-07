//! Unit + integration tests of the fork task channel. The integration tests run the REAL poll/verify/state/transport code against an in-process
//! mock dashboard (wiremock). `vectors.json` is generated and signed by the dashboard's own code (TS) — the agent verifies those exact bytes.
mod channel;
mod config_tests;
mod maint_tests;
mod vectors;

use super::crypto::Pin;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct VPin {
    pub kid: String,
    pub pem: String,
}
#[derive(Deserialize, Clone)]
pub struct VCase {
    pub name: String,
    pub envelope: String,
    pub signature: String,
    pub payload_enc: Option<String>,
    pub expect: String,
    pub last_seq: Option<u64>,
    pub known: Option<Vec<String>>,
    pub payload_plain: Option<String>,
}
#[derive(Deserialize, Clone)]
pub struct Vectors {
    pub now: i64,
    pub agent_id: String,
    pub enroll_id: String,
    pub own_capabilities: Vec<String>,
    pub pins: Vec<VPin>,
    pub spare_pins: Vec<VPin>,
    pub task_key_b64: String,
    pub cases: Vec<VCase>,
}

pub fn vectors() -> Vectors {
    serde_json::from_str(include_str!("vectors.json")).expect("vectors.json")
}
pub fn pins(v: &Vectors) -> Vec<Pin> {
    v.pins.iter().map(|p| super::crypto::parse_pin(&p.kid, &p.pem).expect("pin")).collect()
}
pub fn task_key(v: &Vectors) -> [u8; 32] {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(&v.task_key_b64).unwrap().try_into().unwrap()
}
pub fn case<'a>(v: &'a Vectors, name: &str) -> &'a VCase {
    v.cases.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("vector {name}"))
}
