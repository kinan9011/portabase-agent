//! The ONLY process spawner of the fork agent (W17-ii, E10). Runs the pinned Compose CLI with a closed argument list: `env_clear()` + a fixed environment (never a
//! payload value), `kill_on_drop`, bounded output (4 KiB heads, local log only), a hard timeout. A static test (`restore::tests`) forbids process spawning anywhere else.
use crate::fork::restore::Code;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

pub const PATH_ENV: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const HEAD: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub code: i32,
    pub stdout_head: String,
    pub stderr_head: String,
}

async fn head<R: AsyncRead + Unpin>(mut r: R) -> String {
    let mut buf = Vec::with_capacity(HEAD);
    let _ = (&mut r).take(HEAD as u64).read_to_end(&mut buf).await;
    let _ = tokio::io::copy(&mut r, &mut tokio::io::sink()).await; // drain: the child must never block on a full pipe
    String::from_utf8_lossy(&buf).into_owned()
}

/// Run `bin args…`; `stdin` (a file the agent wrote, 0600) is connected when given. `DOCKER_HOST` is passed through only when the agent itself has it.
pub async fn compose(bin: &Path, args: &[String], home: &Path, stdin: Option<std::fs::File>, timeout: Duration) -> Result<Out, Code> {
    let _ = std::fs::create_dir_all(home);
    let mut cmd = Command::new(bin);
    cmd.args(args).env_clear().env("PATH", PATH_ENV).env("HOME", home).kill_on_drop(true).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Ok(h) = std::env::var("DOCKER_HOST") {
        cmd.env("DOCKER_HOST", h);
    }
    cmd.stdin(match stdin {
        Some(f) => Stdio::from(f),
        None => Stdio::null(),
    });
    let mut child = cmd.spawn().map_err(|_| Code::ComposeUnavailable)?;
    let (so, se) = (child.stdout.take().ok_or(Code::ComposeFailed)?, child.stderr.take().ok_or(Code::ComposeFailed)?);
    let work = async {
        let (o, e, st) = tokio::join!(head(so), head(se), child.wait());
        Ok::<_, Code>(Out { code: st.map_err(|_| Code::ComposeFailed)?.code().unwrap_or(-1), stdout_head: o, stderr_head: e })
    };
    match tokio::time::timeout(timeout, work).await {
        Ok(r) => r,
        Err(_) => Err(Code::DeadlineExceeded), // the dropped child is killed (kill_on_drop)
    }
}

/// `docker-compose version --short` (10 s); `None` when the binary is missing or fails.
pub async fn version(bin: &Path) -> Option<String> {
    let home = std::env::temp_dir().join("portabase-compose-home");
    let out = compose(bin, &["version".to_string(), "--short".to_string()], &home, None, Duration::from_secs(10)).await.ok()?;
    (out.code == 0).then(|| out.stdout_head.trim().to_string())
}
