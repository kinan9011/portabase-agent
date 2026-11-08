//! The re-check chain run before anything starts (E9, plan-W17 DD11). Every step fails closed and in this order: render → hard refusals of the agent's OWN verdict
//! → hash binding to the payload (D-5: "the bytes the agent returned") → hash-bound per-service approval token → realpath gate on host paths under the
//! workspace (#142) → restored volumes present in the render → D29 container guard.
use super::guard::{check_resources, check_up, protected_ids};
use super::render::{Rendered, lexically_under, render_full};
use super::Job;
use crate::fork::policy::approval::{self, Ctx};
use crate::fork::restore::{Code, Failure, R, paths};
use serde_json::Value;
use std::path::Path;

fn approval_failure(detail: &str) -> Failure {
    Failure::with(Code::ApprovalInvalid, detail)
}

/// host paths of the FULL render that are lexically under the workspace must not traverse a symlink (the part outside the workspace is covered by the approval)
fn realpath_gate(doc: &Value, ws: &str) -> R<()> {
    let check = |p: &str| -> R<()> {
        if lexically_under(ws, p) && !paths::no_symlink_on_existing_prefix(Path::new(p)) {
            return Err(Code::SymlinkEscape.into());
        }
        Ok(())
    };
    if let Some(services) = doc.get("services").and_then(Value::as_object) {
        for s in services.values() {
            for v in s.get("volumes").and_then(Value::as_array).into_iter().flatten() {
                if v.get("type").and_then(Value::as_str) == Some("bind") {
                    if let Some(src) = v.get("source").and_then(Value::as_str) {
                        check(src)?;
                    }
                }
            }
        }
    }
    if let Some(vols) = doc.get("volumes").and_then(Value::as_object) {
        for v in vols.values() {
            if let Some(d) = v.get("driver_opts").and_then(|o| o.get("device")).and_then(Value::as_str) {
                check(d)?;
            }
        }
    }
    Ok(())
}

/// `volumes`: docker volume names W17-i restored for this restore; each must appear as some `volumes.*.name` of the render (else `compose up` would silently create an empty one).
pub async fn recheck(job: &Job<'_>, compose_sha256: &str, approval_token: &Value, volumes: Option<&[String]>) -> R<Rendered> {
    let r = render_full(job).await?;
    if let Some(h) = r.verdict.hard.first() {
        return Err(Failure::with(Code::PolicyRefused, h.code));
    }
    if r.sha != compose_sha256 {
        return Err(approval_failure("compose_changed"));
    }
    let ctx = Ctx { stack_id: &job.h.stack_id, rp_id: &job.h.rp_id, agent_id: &job.env.agent_id };
    approval::check(&r.verdict, Some(approval_token), &ctx).map_err(approval_failure)?;
    let ws = job.ws_str();
    realpath_gate(&r.doc, &ws)?;
    if let Some(vols) = volumes {
        let names: Vec<&str> = r.doc.get("volumes").and_then(Value::as_object).map(|o| o.values().filter_map(|v| v.get("name").and_then(Value::as_str)).collect()).unwrap_or_default();
        if vols.iter().any(|v| !names.contains(&v.as_str())) {
            return Err(Code::VolumeNotInCompose.into());
        }
    }
    let all = job.ops.containers().await?;
    let protected = protected_ids(&all, &job.ce.own_id, &job.ce.protected_extra);
    check_up(&r.doc, &job.h.project, &job.h.restore_id, &job.env.agent_id, &all, &protected)?;
    check_resources(job.ops, &r.doc, &job.h.restore_id, &job.env.agent_id).await?;
    Ok(r)
}
