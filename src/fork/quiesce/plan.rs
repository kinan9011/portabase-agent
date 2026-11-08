//! Pure agent-side resolution of a quiesce payload against what Docker says (D8 rules 2–5). The dashboard planner is UX only; THIS is the security check.
//! Everything works on FULL container ids; the payload's 12+ hex prefix is only a pointer that must resolve to exactly one container of the project.
use super::{QuiesceBody, is_hex_id, is_service, is_project};
use crate::fork::restore::docker_ops::{CState, ContainerFacts, LABEL_HELPER, LABEL_RESTORE};
use crate::fork::restore::{Code, is_uuid};
use std::collections::{HashMap, HashSet};

pub const PROJECT_LABEL: &str = "com.docker.compose.project";
pub const SERVICE_LABEL: &str = "com.docker.compose.service";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: String,
    pub service: String,
    pub name: String,
    pub was_running: bool,
    pub stop_timeout: u32,
}

/// D8 rule 1: strict grammar and bounds. Nothing here is free-form.
pub fn validate(b: &QuiesceBody) -> Result<(), Code> {
    let bad = Code::PayloadInvalid;
    if b.v != 1 || !is_uuid(&b.run_id) || !is_uuid(&b.stack_id) || !is_project(&b.project) {
        return Err(bad);
    }
    if b.targets.is_empty() || b.targets.len() > 32 {
        return Err(bad);
    }
    if !(60..=3600).contains(&b.max_stop_seconds) || !(10..=300).contains(&b.stop_timeout_cap_seconds) || !(30..=600).contains(&b.start_timeout_seconds) {
        return Err(bad);
    }
    let mut services = HashSet::new();
    let mut ids = HashSet::new();
    for t in &b.targets {
        if !is_service(&t.service) || !is_hex_id(&t.container_id) || !services.insert(t.service.as_str()) || !ids.insert(t.container_id.as_str()) {
            return Err(bad);
        }
    }
    Ok(())
}

/// D8 rules 2–5. `states` holds `inspect_state` of every container of the project (by full id); `protected` = `guard::protected_ids`.
pub fn resolve(body: &QuiesceBody, all: &[ContainerFacts], states: &HashMap<String, CState>, protected: &HashSet<String>, cap: u32) -> Result<Vec<Target>, Code> {
    let in_project = |c: &ContainerFacts| c.labels.get(PROJECT_LABEL).map(String::as_str) == Some(body.project.as_str());
    // 2. a protected container anywhere in the project refuses the whole task (OD-W17b-7)
    if all.iter().any(|c| in_project(c) && protected.contains(&c.id)) {
        return Err(Code::ProtectedInProject);
    }
    let mut out: Vec<Target> = Vec::new();
    for t in &body.targets {
        let matches: Vec<&ContainerFacts> = all.iter().filter(|c| c.id.starts_with(&t.container_id)).collect();
        // 3a. protected first (so an attacker cannot hide it behind another refusal)
        if matches.iter().any(|c| protected.contains(&c.id)) {
            return Err(Code::ProtectedContainer);
        }
        // 3b. outside the stack's project
        if matches.iter().any(|c| !in_project(c)) {
            return Err(Code::NotInProject);
        }
        // 3c. exactly one project container behind the prefix
        let [c] = matches.as_slice() else { return Err(Code::ContainerChanged) };
        if c.labels.get(SERVICE_LABEL).map(String::as_str) != Some(t.service.as_str()) {
            return Err(Code::ContainerChanged);
        }
        // 3d. never a container a restore owns / a helper
        if c.labels.contains_key(LABEL_RESTORE) || c.labels.contains_key(LABEL_HELPER) {
            return Err(Code::RestoreOwned);
        }
        let st = states.get(&c.id).ok_or(Code::ContainerChanged)?;
        // 5. state
        let was_running = match st.status.as_str() {
            "running" => true,
            "exited" | "created" => false,
            _ => return Err(Code::ContainerUnstable),
        };
        let own_timeout = st.stop_timeout.filter(|t| *t > 0).map(|t| t as u32).unwrap_or(10);
        out.push(Target { id: c.id.clone(), service: t.service.clone(), name: c.names.first().cloned().unwrap_or_default(), was_running, stop_timeout: own_timeout.min(cap) });
    }
    // 4. a running replica of a selected service that is not listed
    let selected: HashSet<&str> = body.targets.iter().map(|t| t.service.as_str()).collect();
    let listed: HashSet<&str> = out.iter().map(|t| t.id.as_str()).collect();
    for c in all.iter().filter(|c| in_project(c) && c.running) {
        if c.labels.get(SERVICE_LABEL).is_some_and(|s| selected.contains(s.as_str())) && !listed.contains(c.id.as_str()) {
            return Err(Code::ReplicaNotListed);
        }
    }
    Ok(out)
}
