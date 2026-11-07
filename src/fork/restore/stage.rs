//! `restore_stage` (i-8): verify the signed manifest, then for each artifact download → decrypt → checksum → gzip → tar audit (→ PostgreSQL dump check), keep
//! the verified plaintext archive in `stage/`, and extract file / bind artifacts into their destinations under the workspace. Nothing is extracted before the
//! manifest and the artifact's checksum verified. Idempotent per `restore_id`: journaled-done artifacts are reused when their staged file still hashes right.
use super::artifact::{self, Limits};
use super::docker_ops::DockerOps;
use super::journal::Journal;
use super::manifest::{self, Expect, Role};
use super::workspace::{Claim, Workspace};
use super::{Code, Failure, Purpose, R, RestoreEnv, StageBody, Task, paths, probe, split};
use crate::fork::crypto::Pin;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub fn role_name(r: Role) -> &'static str {
    match r {
        Role::Files => "files",
        Role::Volume => "volume",
        Role::PgDump => "pg_dump",
        Role::Sqlite => "sqlite",
        Role::DbOther => "db_other",
    }
}
pub fn staged_file(ws: &Workspace, index: usize) -> PathBuf {
    ws.stage().join(format!("a{index}.tar.gz"))
}

/// Ciphertext overhead bound: 28 bytes per 16 MiB chunk + header; `size/64` is generous, +1 MiB for the header line.
fn cap_of(plain: u64) -> u64 {
    plain + plain / 64 + 1024 * 1024
}

pub async fn run(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (_, StageBody) = split(payload)?;
    h.check(env)?;
    // ---- shape of the body ----
    if !super::is_hex64(&b.manifest.sha256) || b.artifacts.len() > 200 || b.paths.len() > 200 {
        return Err(Code::PayloadInvalid.into());
    }
    let mut seen = std::collections::HashSet::new();
    for a in &b.artifacts {
        if a.source != "archive" || a.url.len() > 4096 || !seen.insert(a.index) {
            return Err(Code::PayloadInvalid.into()); // restic artifacts are not part of the W17-i payload (follow-up W17-i-f1)
        }
    }
    // ---- paths ----
    let ws_path = paths::check_task_path(&env.roots, &env.state_dir, &h.workspace)?;
    let mut dests = Vec::new();
    for p in &b.paths {
        if !paths::canon(&p.dest) {
            return Err(Code::PayloadInvalid.into()); // grammar violations are payload errors, root violations are `path_not_allowed`
        }
        let d = paths::check_task_path(&env.roots, &env.state_dir, &p.dest)?;
        if !paths::within(&ws_path, &d) {
            return Err(Code::PathNotAllowed.into());
        }
        if h.purpose == Purpose::TestRestore && !p.dest.starts_with(&format!("{}/scratch/", h.workspace)) {
            return Err(Code::ModeUnsupported.into()); // test restores only ever write to scratch (ADR-014 D-W16-10)
        }
        if !seen.contains(&p.index) {
            return Err(Code::PayloadInvalid.into());
        }
        dests.push((p.index, d));
    }
    let root = env.roots.iter().find(|r| ws_path.starts_with(r)).ok_or(Code::PathNotAllowed)?;
    if !probe::root_shared(ops, root).await? {
        return Err(Code::RootNotShared.into());
    }
    let master = env.master_b64.as_ref().ok_or_else(|| Failure::with(Code::RestoreFailed, "no_master_key"))?;

    let mut journal = Journal::open(&env.state_dir, &h.restore_id)?;
    journal.begin(t.id, t.ty);
    let r = inner(env, pins, t, &h, b, &ws_path, dests, &master.0, &mut journal).await;
    match &r {
        Ok(_) => journal.end(t.id, t.ty, true),
        Err(_) => journal.end(t.id, t.ty, false),
    }
    r
}

#[allow(clippy::too_many_arguments)]
async fn inner(env: &RestoreEnv, pins: &[Pin], t: &Task<'_>, h: &super::Header, b: StageBody, ws_path: &Path, dests: Vec<(usize, PathBuf)>, master: &str, j: &mut Journal) -> R<Value> {
    let claim = Claim { restore_id: &h.restore_id, stack_id: &h.stack_id, rp_id: &h.rp_id, project: &h.project, agent_id: &env.agent_id };
    let ws = Workspace::open_or_create(ws_path, &claim, t.now)?;
    // ---- manifest (before anything is downloaded) ----
    let json = STANDARD.decode(b.manifest.json_b64.as_bytes()).map_err(|_| Failure::from(Code::ManifestInvalid))?;
    let sig = STANDARD.decode(b.manifest.sig_b64.as_bytes()).map_err(|_| Failure::from(Code::ManifestInvalid))?;
    let m = manifest::verify(&json, &sig, pins, &Expect { rp_id: &h.rp_id, stack_id: &h.stack_id, sequence: None, sha256: &b.manifest.sha256, min_sequence: b.manifest.min_sequence })?;
    // keep the verified bytes for `restore_apply` (it re-verifies them against its own bound hash)
    write_0600(&ws.stage().join("manifest.json"), &json)?;
    write_0600(&ws.stage().join("manifest.sig"), &sig)?;
    // ---- disk ----
    let mut need = 0u64;
    for a in &b.artifacts {
        let ma = m.artifacts.get(a.index).ok_or_else(|| Failure::from(Code::ManifestMismatch).at(a.index))?;
        let plain = ma.plaintext_size.ok_or_else(|| Failure::with(Code::ChecksumMismatch, "no_expected_size").at(a.index))?;
        need = need.saturating_add(cap_of(plain)).saturating_add(plain);
    }
    if probe::free_bytes(&ws.root).is_some_and(|free| free < need.saturating_add(need / 10)) {
        return Err(Code::DiskFull.into());
    }
    // ---- artifacts ----
    let mut staged = Vec::new();
    for a in &b.artifacts {
        let ma = &m.artifacts[a.index];
        let (Some(sha), Some(size)) = (ma.plaintext_sha256.clone(), ma.plaintext_size) else { return Err(Failure::with(Code::ChecksumMismatch, "no_expected_hash").at(a.index)) };
        let role = manifest::role(ma);
        let out = staged_file(&ws, a.index);
        let step = format!("artifact:{}", a.index);
        let reuse = j.done(&step).is_some_and(|s| s == sha) && crate::fork::hash::plaintext_hash(&out).await.map(|(s, n)| s == sha && n == size).unwrap_or(false);
        if !reuse {
            let enc = ws.tmp().join(format!("a{}.enc", a.index));
            let part = ws.tmp().join(format!("a{}.plain", a.index));
            artifact::download(&a.url, cap_of(size), &env.http_hosts, &enc).await.map_err(|c| Failure::from(c).at(a.index))?;
            artifact::decrypt_verify(&enc, if ma.encrypted { &part } else { &enc }, master, ma.encrypted, &sha, size).await.map_err(|c| Failure::from(c).at(a.index))?;
            let plain = if ma.encrypted { &part } else { &enc };
            let lim = Limits::with_inflated(size.saturating_mul(1024).max(1 << 30));
            artifact::gzip_complete(plain, lim.max_inflated).map_err(|c| Failure::from(c).at(a.index))?;
            artifact::audit_tar(plain, (role == Role::Volume).then_some("vol"), &lim).map_err(|c| Failure::from(c).at(a.index))?;
            if role == Role::PgDump {
                artifact::check_pg_dump(plain, ma.dump_format, &lim, &ws.tmp()).map_err(|c| Failure::from(c).at(a.index))?;
            }
            std::fs::rename(plain, &out).map_err(|_| Failure::from(Code::RestoreFailed).at(a.index))?;
            let _ = std::fs::remove_file(&enc);
            j.step(t.id, t.ty, &step, true, Some(&sha));
        }
        staged.push(json!({"index": a.index, "role": role_name(role), "plaintext_sha256": sha, "size": size}));
    }
    // ---- extraction into the planned destinations ----
    let mut extracted = 0usize;
    for (index, dest) in dests {
        let ma = &m.artifacts[index];
        let role = manifest::role(ma);
        let step = format!("extract:{index}");
        if j.done(&step).is_some() && dest.exists() {
            extracted += 1;
            continue;
        }
        // re-check right before writing (#142): nothing on the existing part may have become a symlink since the payload check
        let dest = paths::check_task_path(&env.roots, &env.state_dir, &dest.to_string_lossy())?;
        if dest.exists() {
            std::fs::remove_dir_all(&dest).map_err(|_| Failure::from(Code::RestoreFailed).at(index))?; // inside our own workspace, extraction not journaled done
        }
        let file = staged_file(&ws, index);
        if role == Role::Volume {
            let tmpdir = ws.tmp().join(format!("x{index}"));
            let _ = std::fs::remove_dir_all(&tmpdir);
            artifact::extract(&file, &tmpdir).map_err(|c| Failure::from(c).at(index))?;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|_| Failure::from(Code::RestoreFailed).at(index))?;
            }
            std::fs::rename(tmpdir.join("vol"), &dest).map_err(|_| Failure::from(Code::RestoreFailed).at(index))?;
            let _ = std::fs::remove_dir_all(&tmpdir);
        } else {
            artifact::extract(&file, &dest).map_err(|c| Failure::from(c).at(index))?;
        }
        j.step(t.id, t.ty, &step, true, None);
        extracted += 1;
    }
    ws.clear_tmp();
    Ok(json!({"staged": staged, "extracted": extracted, "manifest_sequence": m.rp.sequence, "kid": m.kid}))
}

pub fn write_0600(path: &Path, data: &[u8]) -> R<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(path).map_err(|_| Failure::from(Code::RestoreFailed))?;
    f.write_all(data).and_then(|_| f.sync_all()).map_err(|_| Failure::from(Code::DiskFull))
}
