//! `mirror_db`: start ONLY the database services of the final project, wait healthy, apply the credential resets (the DB role gets the rotated password the app was
//! given; a database restored from a VOLUME would otherwise keep the production password, W20 D-5), then restore the staged PostgreSQL dumps with the same fixed
//! scripts as W17-ii `restore_db`. The reset SQL travels on stdin only (a 0600 file under `secret/`, emptied by the guard): never in argv, a log or a result.
use super::apply_spec::Engine;
use super::payload::DbBody;
use super::{Ctx, base_args, final_check, load_manifest, open_light};
use crate::fork::compose::db::{PG_ISREADY, PG_RESTORE_FC, PG_RESTORE_FD, READY_EVERY, READY_TRIES};
use crate::fork::compose::guard::{check_resources, check_up, protected_ids};
use crate::fork::compose::run;
use crate::fork::compose::up::exit_failure;
use crate::fork::compose::SecretGuard;
use crate::fork::crypto::Pin;
use crate::fork::restore::apply::single_file;
use crate::fork::restore::docker_ops::DockerOps;
use crate::fork::restore::manifest::{DumpFormat, Role, role};
use crate::fork::restore::stage::{role_name, staged_file, write_0600};
use crate::fork::restore::{Code, Failure, Header, R, RestoreEnv, Task, split};
use serde_json::{Value, json};
use std::time::Duration;

/// `ALTER ROLE "<user>" WITH PASSWORD '<password>'` with the identifier and the literal quoted (doubling). Pure; the only place the statement is built.
pub fn reset_sql(user: &str, password: &str) -> String {
    format!("ALTER ROLE \"{}\" WITH PASSWORD '{}';\n", user.replace('"', "\"\""), password.replace('\'', "''"))
}
fn user_ok(u: &str) -> bool {
    !u.is_empty() && u.len() <= 63 && u.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}
/// compose escapes a literal `$` as `$$` in its config output; the container sees the literal one
fn unescape_dollars(s: &str) -> String {
    s.replace("$$", "$")
}

pub async fn run(env: &RestoreEnv, ops: &dyn DockerOps, pins: &[Pin], t: &Task<'_>, payload: &[u8]) -> R<Value> {
    let (h, b): (Header, DbBody) = split(payload)?;
    b.check()?;
    let c = open_light(env, ops, t, h)?;
    if b.resets.iter().any(|r| r.engine != Engine::Postgresql) {
        return Err(Code::CredentialResetUnsupported.into()); // MySQL / MariaDB: an honest FAILED, never a silent skip (OD-W22a-10)
    }
    let manifest = load_manifest(&c, pins, &b.manifest_sha256)?;
    let mut j = Journal::open(&c.env.state_dir, &c.h.restore_id)?;
    j.begin(t.id, t.ty);
    let _guard = SecretGuard::new(&c.ws);
    let r = inner(&c, &b, &manifest, &mut j, t).await;
    j.end(t.id, t.ty, r.is_ok());
    r
}
use crate::fork::restore::journal::Journal;

async fn inner(c: &Ctx<'_>, b: &DbBody, manifest: &crate::fork::restore::manifest::ManifestV1, j: &mut Journal, t: &Task<'_>) -> R<Value> {
    let doc = final_check(c, &b.final_sha256).await?;
    let all = c.ops.containers().await?;
    let protected = protected_ids(&all, &c.ce.own_id, &c.ce.protected_extra);
    check_up(&doc, &c.h.project, &c.h.restore_id, &c.env.agent_id, &all, &protected)?;
    check_resources(c.ops, &doc, &c.h.restore_id, &c.env.agent_id).await?;
    let services = doc.get("services").and_then(Value::as_object).ok_or(Failure::from(Code::ManifestMismatch))?;
    let mut wanted: Vec<&str> = Vec::new();
    for s in b.dbs.iter().map(|d| d.service.as_str()).chain(b.resets.iter().map(|r| r.service.as_str())) {
        if !services.contains_key(s) {
            return Err(Failure::with(Code::ManifestMismatch, "service_not_in_compose"));
        }
        if !wanted.contains(&s) {
            wanted.push(s);
        }
    }
    let base = base_args(&c.h.project, &c.ws.root);
    let home = c.ws.tmp().join("home");
    let long = super::DEADLINE_STEP - Duration::from_secs(60);
    for svc in &wanted {
        let mut up = base.clone();
        up.extend(["up", "-d", "--no-deps", "--no-build", "--pull", "missing"].map(String::from));
        up.push(svc.to_string());
        let o = run::compose(&c.ce.bin, &up, &home, None, long).await?;
        if o.code != 0 {
            return Err(exit_failure(Code::DbRestoreFailed, &o));
        }
        let mut ready = false;
        for _ in 0..READY_TRIES {
            let mut a = base.clone();
            a.extend(["exec", "-T", svc, "sh", "-c", PG_ISREADY].map(String::from));
            if run::compose(&c.ce.bin, &a, &home, None, Duration::from_secs(30)).await.is_ok_and(|o| o.code == 0) {
                ready = true;
                break;
            }
            tokio::time::sleep(READY_EVERY).await;
        }
        if !ready {
            return Err(Failure::with(Code::DbRestoreFailed, "not_ready"));
        }
    }
    // ---- credential resets (postgresql only; the password is the value the container was configured with) ----
    let mut resets = vec![];
    for r in &b.resets {
        let step = format!("reset:{}:{}", r.service, r.password_key);
        if j.done(&step).is_some() {
            resets.push(json!({"service": r.service, "status": "done"}));
            continue;
        }
        let envm = services[&r.service].get("environment").and_then(Value::as_object);
        let pw = envm.and_then(|e| e.get(&r.password_key)).and_then(Value::as_str).map(unescape_dollars).ok_or_else(|| Failure::with(Code::CredentialResetFailed, "no_password"))?;
        let user = match &r.user_key {
            Some(k) => envm.and_then(|e| e.get(k)).and_then(Value::as_str).map(unescape_dollars).ok_or_else(|| Failure::with(Code::CredentialResetFailed, "no_user"))?,
            None => "postgres".to_string(),
        };
        if pw.is_empty() || !user_ok(&user) {
            return Err(Failure::with(Code::CredentialResetFailed, if pw.is_empty() { "empty_password" } else { "bad_user" }));
        }
        let sql = c.ws.secret().join("reset.sql");
        write_0600(&sql, reset_sql(&user, &pw).as_bytes())?;
        let stdin = std::fs::File::open(&sql).map_err(|_| Failure::from(Code::CredentialResetFailed))?;
        let mut a = base.clone();
        a.extend(["exec", "-T", r.service.as_str(), "psql", "-v", "ON_ERROR_STOP=1", "-U", user.as_str(), "-d", "postgres"].map(String::from));
        let o = run::compose(&c.ce.bin, &a, &home, Some(stdin), Duration::from_secs(60)).await;
        let _ = std::fs::remove_file(&sql);
        let o = o?;
        if o.code != 0 {
            return Err(exit_failure(Code::CredentialResetFailed, &o));
        }
        j.step(t.id, t.ty, &step, true, None);
        resets.push(json!({"service": r.service, "status": "done"}));
    }
    // ---- dumps ----
    let mut dbs = vec![];
    for d in &b.dbs {
        let a = manifest.artifacts.get(d.index).ok_or_else(|| Failure::from(Code::ManifestMismatch).at(d.index))?;
        if role(a) != Role::PgDump {
            return Err(Failure::with(Code::ManifestMismatch, role_name(role(a))).at(d.index));
        }
        let format = if a.dump_format == Some(DumpFormat::PgDirectory) { "pg_directory" } else { "pg_custom" };
        let step = format!("db:{}", d.service);
        if j.done(&step).is_none() {
            let file = staged_file(&c.ws, d.index);
            if !file.exists() {
                return Err(Failure::with(Code::RestoreFailed, "not_staged").at(d.index));
            }
            let single = c.ws.tmp().join(format!("db{}", d.index));
            single_file(&file, &single).map_err(|code| Failure::from(code).at(d.index))?;
            let stdin = std::fs::File::open(&single).map_err(|_| Failure::from(Code::RestoreFailed).at(d.index))?;
            let mut a = base.clone();
            a.extend(["exec", "-T", d.service.as_str(), "sh", "-c", if format == "pg_directory" { PG_RESTORE_FD } else { PG_RESTORE_FC }].map(String::from));
            let o = run::compose(&c.ce.bin, &a, &home, Some(stdin), long).await;
            let _ = std::fs::remove_file(&single);
            let o = o?;
            if o.code != 0 {
                return Err(exit_failure(Code::DbRestoreFailed, &o).at(d.index));
            }
            j.step(t.id, t.ty, &step, true, None);
        }
        dbs.push(json!({"index": d.index, "service": d.service, "status": "restored"}));
    }
    Ok(json!({"v": 1, "dbs": dbs, "resets": resets}))
}
