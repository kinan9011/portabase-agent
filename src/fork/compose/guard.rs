//! D29 container guard (W17-ii E8, plan-W17 DD13). `docker compose up` silently takes over existing containers of the same project and recreates them when
//! the configuration differs, so the guard looks at EVERY existing container of project P, not only `container_name` collisions. Refusal is the only action:
//! W17-ii never stops, kills, renames or recreates a container it does not own. Protection works on FULL container ids only (never a prefix, never a name).
use crate::fork::restore::docker_ops::{ContainerFacts, DockerOps, LABEL_AGENT, LABEL_RESTORE, owned_by};
use crate::fork::restore::{Code, Failure, R};
use serde_json::Value;
use std::collections::HashSet;

const PROJECT_LABEL: &str = "com.docker.compose.project";
const SERVICE_LABEL: &str = "com.docker.compose.service";

/// image reference without registry noise, tag and digest
fn repo_of(image: &str) -> String {
    let no_digest = image.split('@').next().unwrap_or("");
    let tail_start = no_digest.rfind('/').map(|i| i + 1).unwrap_or(0);
    let repo = match no_digest[tail_start..].find(':') {
        Some(i) => &no_digest[..tail_start + i],
        None => no_digest,
    };
    repo.trim_start_matches("docker.io/").trim_start_matches("library/").to_ascii_lowercase()
}
fn is_manager_image(image: &str) -> bool {
    let r = repo_of(image);
    let last = r.rsplit('/').next().unwrap_or("");
    r == "portabase/portabase" || r == "portabase/agent" || r.starts_with("ghcr.io/portabase/") || r.ends_with("/portabase/portabase") || r.ends_with("/portabase/agent")
        || r.contains("portabase-agent-fork") || r.contains("getarcaneapp/arcane") || last == "arcane"
}
fn is_hex64(s: &str) -> bool {
    crate::fork::restore::is_hex64(s)
}

/// own id ∪ Portabase / agent / Arcane images ∪ containers that mount the docker socket ∪ `FORK_PROTECTED_CONTAINERS` (names or 64-hex ids).
pub fn protected_ids(all: &[ContainerFacts], own_id: &str, extra: &[String]) -> HashSet<String> {
    let mut p: HashSet<String> = HashSet::new();
    p.insert(own_id.to_string());
    for c in all {
        if is_manager_image(&c.image) || c.mounts_docker_sock {
            p.insert(c.id.clone());
        }
        if extra.iter().any(|e| (is_hex64(e) && *e == c.id) || c.names.iter().any(|n| n == e)) {
            p.insert(c.id.clone());
        }
    }
    p
}

fn conflict(detail: &str) -> Failure {
    Failure::with(Code::ContainerConflict, detail)
}

/// Pure container checks. `render` = the full rendered compose document (JSON).
pub fn check_up(render: &Value, project: &str, restore_id: &str, agent_id: &str, all: &[ContainerFacts], protected: &HashSet<String>) -> R<()> {
    let mine = |c: &ContainerFacts| owned_by(&c.labels, restore_id, agent_id) && c.labels.get(PROJECT_LABEL).map(String::as_str) == Some(project);
    if let Some(services) = render.get("services").and_then(Value::as_object) {
        for s in services.values() {
            let Some(name) = s.get("container_name").and_then(Value::as_str) else { continue };
            for c in all.iter().filter(|c| c.names.iter().any(|n| n == name)) {
                if protected.contains(&c.id) {
                    return Err(Code::ProtectedContainer.into());
                }
                if !mine(c) {
                    return Err(conflict("container_name"));
                }
            }
        }
    }
    for c in all {
        if c.labels.get(PROJECT_LABEL).map(String::as_str) == Some(project) {
            if protected.contains(&c.id) {
                return Err(Code::ProtectedContainer.into());
            }
            if !owned_by(&c.labels, restore_id, agent_id) {
                return Err(conflict("project_in_use"));
            }
        }
    }
    Ok(())
}

/// Non-external volumes / networks of the render that already exist must carry this restore's owner labels (a fresh `pgdata` does not exist yet: fine).
pub async fn check_resources(ops: &dyn DockerOps, render: &Value, restore_id: &str, agent_id: &str) -> R<()> {
    for (section, code) in [("volumes", Code::VolumeExists), ("networks", Code::NetworkExists)] {
        let Some(defs) = render.get(section).and_then(Value::as_object) else { continue };
        for (key, def) in defs {
            let external = matches!(def.get("external"), Some(Value::Bool(true))) || def.get("external").is_some_and(Value::is_object);
            if external {
                continue;
            }
            let Some(name) = def.get("name").and_then(Value::as_str).or(Some(key.as_str())) else { continue };
            let labels = if section == "volumes" { ops.volume_labels(name).await? } else { ops.network_labels(name).await? };
            if let Some(l) = labels {
                if !owned_by(&l, restore_id, agent_id) {
                    return Err(Failure::from(code));
                }
            }
        }
    }
    Ok(())
}

/// The container of project `project` whose service label or name is `name_or_service` — never a protected one. Exported for W17b (quiesce); W17-ii itself
/// never stops anything.
#[allow(dead_code)]
pub async fn resolve_stack_container(ops: &dyn DockerOps, project: &str, name_or_service: &str, protected: &HashSet<String>) -> Result<String, Code> {
    let all = ops.containers().await?;
    let hit = all.iter().find(|c| c.labels.get(PROJECT_LABEL).map(String::as_str) == Some(project) && (c.labels.get(SERVICE_LABEL).map(String::as_str) == Some(name_or_service) || c.names.iter().any(|n| n == name_or_service)));
    match hit {
        None => Err(Code::ContainerConflict),
        Some(c) if protected.contains(&c.id) => Err(Code::ProtectedContainer),
        Some(c) => Ok(c.id.clone()),
    }
}
#[allow(dead_code)]
pub const OWNER_LABELS: [&str; 2] = [LABEL_RESTORE, LABEL_AGENT];
