//! Compose policy engine of the fork agent (W17-ii, ADR-015 D-2 / D-3 / D-6 / D-7): a Rust port of the dashboard's `src/fork/policy/*.ts`.
//! The rule file and the three corpus files in `corpus/` are BYTE-IDENTICAL copies written by the dashboard test `w17-agent-corpus.test.ts`
//! (D27: one rule file, no drift); `tests.rs` evaluates every vector of the shared corpus. Pure: no I/O, no clock, no process, no logging.
pub mod approval;
pub mod raw;
pub mod rendered;
pub mod rules;
pub mod view;
pub mod yaml;

#[cfg(test)]
mod tests;

pub(crate) const RULES_JSON: &[u8] = include_bytes!("corpus/compose-deny.json");
pub(crate) const SOURCE_JSON: &[u8] = include_bytes!("corpus/SOURCE.json");
