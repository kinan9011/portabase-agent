//! `restore_db` (E11, CLI parity with `portabase-recover restore_databases`): PostgreSQL dumps staged by `restore_stage` are restored INSIDE the stack's own database
//! service container (its matching major version, its local socket, no credentials on the agent). The three scripts are fixed literals copied from the CLI:
//! no payload data is ever interpolated into a shell string. Other engines stay "unpacked for manual import" (W17-i).
use super::check::recheck;
use super::run;
use super::up::{base_args, exit_failure};
use super::{DbBody, SecretGuard, open_job};
use crate::fork::crypto::Pin;
use crate::fork::restore::apply::single_file;
use crate::fork::restore::docker_ops::DockerOps;
use crate::fork::restore::manifest::{DumpFormat, Role, role};
use crate::fork::restore::stage::{role_name, staged_file, write_0600};
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, paths, split};
use serde_json::{Value, json};
use std::time::Duration;

pub const PG_ISREADY: &str = r#"pg_isready -q -U "${POSTGRES_USER:-postgres}""#;
pub const PG_RESTORE_FC: &str = r#"u="${POSTGRES_USER:?POSTGRES_USER is not set in the container}"; db="${POSTGRES_DB:-$u}"; pg_restore -U "$u" -d "$db" --no-owner --clean --if-exists"#;
pub const PG_RESTORE_FD: &str = r#"u="${POSTGRES_USER:?POSTGRES_USER is not set in the container}"; db="${POSTGRES_DB:-$u}"; t=$(mktemp -d) && tar -xzf - -C "$t" && pg_restore -U "$u" -d "$db" --no-owner --clean --if-exists "$t"; rc=$?; rm -rf "$t"; exit $rc"#;
pub const READY_TRIES: u32 = 60;
pub const READY_EVERY: Duration = Duration::from_secs(2);

pub async fn run_db(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, DbBody) = split(payload)?;
    if !crate::fork::restore::is_hex64(&b.compose_sha256) || b.dbs.is_empty() || b.dbs.len() > 20 || b.dbs.iter().any(|d| !paths::is_name(&d.service, 128)) {
        return Err(Code::PayloadInvalid.into());
    }
    let job = open_job(env, ops, pins, t, h, &b.manifest_sha256, b.compose).await?;
    let mut j = job.journal()?;
    j.begin(t.id, t.ty);
    let _guard = SecretGuard::new(&job.ws);
    let r = async {
        let r = recheck(&job, &b.compose_sha256, &b.approval, None).await?;
        write_0600(&job.ws.secret().join("rendered.json"), &r.full)?;
        let base = base_args(&job.h.project, &job.ws.root);
        let home = job.ws.tmp().join("home");
        let long = super::DEADLINE_DB - Duration::from_secs(60);
        let mut dbs = vec![];
        for d in &b.dbs {
            let a = job.manifest.artifacts.get(d.index).ok_or_else(|| Failure::from(Code::ManifestMismatch).at(d.index))?;
            if role(a) != Role::PgDump {
                return Err(Failure::with(Code::ManifestMismatch, role_name(role(a))).at(d.index));
            }
            if r.doc.get("services").and_then(|s| s.get(&d.service)).is_none() {
                return Err(Failure::with(Code::ManifestMismatch, "service_not_in_compose").at(d.index));
            }
            let format = if a.dump_format == Some(DumpFormat::PgDirectory) { "pg_directory" } else { "pg_custom" };
            let step = format!("db:{}", d.service);
            if j.done(&step).is_some() {
                dbs.push(json!({"service": d.service, "format": format, "status": "reused"}));
                continue;
            }
            let file = staged_file(&job.ws, d.index);
            if !file.exists() {
                return Err(Failure::with(Code::RestoreFailed, "not_staged").at(d.index));
            }
            let mut up = base.clone();
            up.extend(["up", "-d", "--no-deps", "--no-build", "--pull", "missing"].map(String::from));
            up.push(d.service.clone());
            let o = run::compose(&job.ce.bin, &up, &home, None, long).await?;
            if o.code != 0 {
                return Err(exit_failure(Code::DbRestoreFailed, &o).at(d.index));
            }
            let mut ready = false;
            for _ in 0..READY_TRIES {
                let mut a = base.clone();
                a.extend(["exec", "-T", d.service.as_str(), "sh", "-c", PG_ISREADY].map(String::from));
                if run::compose(&job.ce.bin, &a, &home, None, Duration::from_secs(30)).await.is_ok_and(|o| o.code == 0) {
                    ready = true;
                    break;
                }
                tokio::time::sleep(READY_EVERY).await;
            }
            if !ready {
                return Err(Failure::with(Code::DbRestoreFailed, "not_ready").at(d.index));
            }
            let single = job.ws.tmp().join(format!("db{}", d.index));
            single_file(&file, &single).map_err(|c| Failure::from(c).at(d.index))?;
            let stdin = std::fs::File::open(&single).map_err(|_| Failure::from(Code::RestoreFailed).at(d.index))?;
            let mut a = base.clone();
            a.extend(["exec", "-T", d.service.as_str(), "sh", "-c", if format == "pg_directory" { PG_RESTORE_FD } else { PG_RESTORE_FC }].map(String::from));
            let o = run::compose(&job.ce.bin, &a, &home, Some(stdin), long).await;
            let _ = std::fs::remove_file(&single);
            let o = o?;
            if o.code != 0 {
                return Err(exit_failure(Code::DbRestoreFailed, &o).at(d.index));
            }
            j.step(t.id, t.ty, &step, true, None);
            dbs.push(json!({"service": d.service, "format": format, "status": "restored"}));
        }
        Ok(json!({"dbs": dbs}))
    }
    .await;
    j.end(t.id, t.ty, r.is_ok());
    r
}
