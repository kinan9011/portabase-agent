//! `restore_apply` and `restore_cleanup` (i-9, W17-i parts). Apply creates labelled Docker volumes / networks and fills them from the audited staged archives,
//! puts sqlite files, unpacks non-PostgreSQL dumps; PostgreSQL dumps stay staged (W17-ii restores them). Every resource carries `restore_id` + `agent_id`
//! labels; cleanup removes ONLY what carries both. Idempotent: a journaled-done volume is skipped, an owned unfinished one is wiped and redone, a foreign one
//! with the same name is never touched (`volume_exists` / `volume_not_owned`).
use super::artifact;
use super::docker_ops::{DockerOps, LABEL_RESTORE, owned_by, owner_labels};
use super::journal::Journal;
use super::manifest::{self, Expect, Role};
use super::stage::{role_name, staged_file, write_0600};
use super::workspace::{Claim, Workspace};
use super::{ApplyBody, CleanupBody, Code, Failure, Header, Purpose, R, RestoreEnv, Task, paths, split};
use crate::fork::crypto::Pin;
use serde_json::{Value, json};
use std::path::PathBuf;

fn claim<'a>(env: &'a RestoreEnv, h: &'a Header) -> Claim<'a> {
    Claim { restore_id: &h.restore_id, stack_id: &h.stack_id, rp_id: &h.rp_id, project: &h.project, agent_id: &env.agent_id }
}

pub async fn run_apply(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, ApplyBody) = split(payload)?;
    h.check(env)?;
    if !super::is_hex64(&b.manifest_sha256) || b.volumes.len() > 100 || b.sqlite.len() > 100 || b.networks.len() > 50 || b.unpack.len() > 100 {
        return Err(Code::PayloadInvalid.into());
    }
    if b.volumes.iter().any(|v| !paths::is_name(&v.name, 255) || !paths::is_name(&v.compose_volume, 255))
        || b.networks.iter().any(|n| !paths::is_name(&n.name, 128))
        || b.sqlite.iter().any(|s| !paths::is_name(&s.volume, 255) || !paths::rel_ok(&s.relative_path))
        || b.unpack.iter().any(|u| !paths::is_name(&u.service, 128))
    {
        return Err(Code::PayloadInvalid.into());
    }
    if h.purpose == Purpose::TestRestore && (!b.volumes.is_empty() || !b.networks.is_empty()) {
        return Err(Code::ModeUnsupported.into()); // a test restore creates no volumes / networks (ADR-014 D-W16-10)
    }
    let ws_path = paths::check_task_path(&env.roots, &env.state_dir, &h.workspace)?;
    let mut j = Journal::open(&env.state_dir, &h.restore_id)?;
    j.begin(t.id, t.ty);
    let r = apply_inner(env, ops, pins, t, &h, &b, &ws_path, &mut j).await;
    j.end(t.id, t.ty, r.is_ok());
    r
}

#[allow(clippy::too_many_arguments)]
async fn apply_inner(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, h: &Header, b: &ApplyBody, ws_path: &std::path::Path, j: &mut Journal) -> R<Value> {
    let ws = Workspace::open_owned(ws_path, &claim(env, h), t.now)?;
    let json = std::fs::read(ws.stage().join("manifest.json")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    let sig = std::fs::read(ws.stage().join("manifest.sig")).map_err(|_| Failure::with(Code::RestoreFailed, "not_staged"))?;
    let m = manifest::verify(&json, &sig, pins, &Expect { rp_id: &h.rp_id, stack_id: &h.stack_id, sequence: None, sha256: &b.manifest_sha256, min_sequence: None })?;
    let role_of = |index: usize, want: Role| -> R<()> {
        let a = m.artifacts.get(index).ok_or_else(|| Failure::from(Code::ManifestMismatch).at(index))?;
        if manifest::role(a) != want {
            return Err(Failure::with(Code::ManifestMismatch, role_name(manifest::role(a))).at(index));
        }
        Ok(())
    };
    let labels_of = owner_labels(&h.restore_id, &env.agent_id);
    let mut consumed: Vec<usize> = Vec::new();
    let mut vols = Vec::new();
    for v in &b.volumes {
        role_of(v.index, Role::Volume)?;
        let step = format!("volume:{}", v.name);
        if j.done(&step).is_some() {
            vols.push(json!({"name": v.name, "status": "reused"}));
            continue;
        }
        let file = staged_file(&ws, v.index);
        if !file.exists() {
            return Err(Failure::with(Code::RestoreFailed, "not_staged").at(v.index));
        }
        let mut status = "created";
        match ops.volume_labels(&v.name).await? {
            None => {
                let mut l = labels_of.clone();
                l.insert("com.docker.compose.project".into(), h.project.clone());
                l.insert("com.docker.compose.volume".into(), v.compose_volume.clone());
                ops.create_volume(&v.name, &l).await?;
            }
            Some(l) if owned_by(&l, &h.restore_id, &env.agent_id) => {
                ops.helper_wipe(&v.name).await?; // owned but unfinished: redo from scratch
                status = "redone";
            }
            Some(l) => return Err(Failure::from(if l.contains_key(LABEL_RESTORE) { Code::VolumeNotOwned } else { Code::VolumeExists }).at(v.index)),
        }
        ops.helper_extract(&v.name, &file).await.map_err(|c| Failure::from(c).at(v.index))?;
        j.step(t.id, t.ty, &step, true, None);
        consumed.push(v.index);
        vols.push(json!({"name": v.name, "status": status}));
    }
    let mut sqlite = 0usize;
    for s in &b.sqlite {
        role_of(s.index, Role::Sqlite)?;
        if !b.volumes.iter().any(|v| v.name == s.volume) {
            return Err(Failure::from(Code::VolumeNotOwned).at(s.index));
        }
        let step = format!("sqlite:{}", s.index);
        if j.done(&step).is_some() {
            sqlite += 1;
            continue;
        }
        match ops.volume_labels(&s.volume).await? {
            Some(l) if owned_by(&l, &h.restore_id, &env.agent_id) => {}
            _ => return Err(Failure::from(Code::VolumeNotOwned).at(s.index)),
        }
        let file = staged_file(&ws, s.index);
        let single = ws.tmp().join(format!("sq{}.db", s.index));
        single_file(&file, &single).map_err(|c| Failure::from(c).at(s.index))?;
        ops.helper_put_file(&s.volume, &s.relative_path, &single).await.map_err(|c| Failure::from(c).at(s.index))?;
        let _ = std::fs::remove_file(&single);
        j.step(t.id, t.ty, &step, true, None);
        consumed.push(s.index);
        sqlite += 1;
    }
    let mut nets = 0usize;
    for n in &b.networks {
        let step = format!("network:{}", n.name);
        if j.done(&step).is_some() {
            nets += 1;
            continue;
        }
        match ops.network_labels(&n.name).await? {
            None => ops.create_network(&n.name, &labels_of).await?,
            Some(l) if owned_by(&l, &h.restore_id, &env.agent_id) => {}
            Some(_) => return Err(Failure::with(Code::RestoreFailed, "network_exists")),
        }
        j.step(t.id, t.ty, &step, true, None);
        nets += 1;
    }
    let mut unpacked = Vec::new();
    for u in &b.unpack {
        role_of(u.index, Role::DbOther)?;
        let step = format!("unpack:{}", u.service);
        let dest = paths::check_task_path(&env.roots, &env.state_dir, &format!("{}/databases/{}", h.workspace, u.service))?;
        if j.done(&step).is_none() {
            let file = staged_file(&ws, u.index);
            if !file.exists() {
                return Err(Failure::with(Code::RestoreFailed, "not_staged").at(u.index));
            }
            if dest.exists() {
                std::fs::remove_dir_all(&dest).map_err(|_| Failure::from(Code::RestoreFailed).at(u.index))?;
            }
            artifact::extract(&file, &dest).map_err(|c| Failure::from(c).at(u.index))?;
            j.step(t.id, t.ty, &step, true, None);
            consumed.push(u.index);
        }
        unpacked.push(json!({"service": u.service, "engine": m.artifacts[u.index].engine}));
    }
    // consumed archives are not needed any more; PostgreSQL dumps stay staged for W17-ii
    for i in consumed {
        let _ = std::fs::remove_file(staged_file(&ws, i));
    }
    ws.clear_tmp();
    Ok(json!({"volumes": vols, "sqlite": sqlite, "networks": nets, "unpacked": unpacked}))
}

/// The staged archive of an agent sqlite backup holds exactly one regular file: write its content to `out` (0600).
fn single_file(tar_gz: &std::path::Path, out: &std::path::Path) -> Result<(), Code> {
    use flate2::read::GzDecoder;
    let f = std::fs::File::open(tar_gz).map_err(|_| Code::RestoreFailed)?;
    let mut ar = tar::Archive::new(GzDecoder::new(std::io::BufReader::new(f)));
    let mut found = false;
    for e in ar.entries().map_err(|_| Code::ArchiveInvalid)? {
        let mut e = e.map_err(|_| Code::ArchiveInvalid)?;
        if e.header().entry_type().is_dir() {
            continue;
        }
        if !e.header().entry_type().is_file() || found {
            return Err(Code::ArchiveInvalid);
        }
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut e, &mut data).map_err(|_| Code::ArchiveInvalid)?;
        write_0600(out, &data).map_err(|f| f.code)?;
        found = true;
    }
    found.then_some(()).ok_or(Code::ArchiveInvalid)
}

pub async fn run_cleanup(env: &RestoreEnv, ops: &dyn DockerOps, t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, CleanupBody) = split(payload)?;
    h.check(env)?;
    if b.containers {
        return Err(Code::ModeUnsupported.into()); // W17-ii owns container cleanup
    }
    let ws_path = paths::check_task_path(&env.roots, &env.state_dir, &h.workspace)?;
    let mut j = Journal::open(&env.state_dir, &h.restore_id)?;
    j.begin(t.id, t.ty);
    let prefix = format!("{}_", h.project);
    let (mut vols, mut nets, mut kept) = (0usize, 0usize, 0usize);
    let r: R<bool> = async {
        if b.volumes {
            for (name, l) in ops.list_volumes().await? {
                if owned_by(&l, &h.restore_id, &env.agent_id) {
                    ops.remove_volume(&name).await?;
                    vols += 1;
                } else if name.starts_with(&prefix) {
                    kept += 1;
                }
            }
        }
        if b.networks {
            for (name, l) in ops.list_networks().await? {
                if owned_by(&l, &h.restore_id, &env.agent_id) {
                    ops.remove_network(&name).await?;
                    nets += 1;
                } else if name.starts_with(&prefix) {
                    kept += 1;
                }
            }
        }
        let mut removed_ws = false;
        if b.workspace_remove && ws_path.exists() {
            match Workspace::read_owner(&ws_path) {
                Some(o) if o.restore_id == h.restore_id && o.agent_id == env.agent_id => {
                    // the path was re-checked above (no symlink on the existing part); a symlinked leaf was refused there
                    std::fs::remove_dir_all(&ws_path).map_err(|_| Failure::from(Code::RestoreFailed))?;
                    removed_ws = true;
                }
                _ => kept += 1,
            }
        }
        Ok(removed_ws)
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    let removed_ws = r?;
    let _: Option<PathBuf> = None;
    Ok(json!({"removed": {"volumes": vols, "networks": nets, "containers": 0, "workspace": removed_ws}, "kept_foreign": kept}))
}
