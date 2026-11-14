//! W24 route forwarder (DD-3): the agent binary itself, started as `app pbm-route <upstream-file>` inside the hardened per-mirror route container (A05 hook in `main.rs`).
//! It listens on `0.0.0.0:8080` INSIDE its own network namespace (the container publishes only `127.0.0.1:<route_port>` on the runner host) and, per accepted connection,
//! re-reads the upstream file (`<container-name>:<port>`, written by `mirror_route` via an atomic `rename(2)`), connects with a 5 s timeout and pipes bytes. A garbage /
//! missing file drops the connection. No address, byte or error text is ever logged. Limits: 256 concurrent connections, no idle timeout (OD-W24-11; ponytail: add keepalive /
//! idle timeout if a stale connection after a switch ever matters).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

pub const LISTEN: &str = "0.0.0.0:8080";
pub const MAX_CONNS: usize = 256;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const FILE_CAP: u64 = 256;

/// `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}:[0-9]{1,5}\n?$` with port 1..=65535. Anything else (space, NUL, second line, empty) is `None`.
pub fn parse_upstream(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    let s = s.strip_suffix('\n').unwrap_or(s);
    let (host, port) = s.rsplit_once(':')?;
    let host_ok = !host.is_empty() && host.len() <= 128 && host.as_bytes()[0].is_ascii_alphanumeric() && host.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'));
    let port_ok = (1..=5).contains(&port.len()) && port.bytes().all(|c| c.is_ascii_digit()) && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p));
    (host_ok && port_ok).then(|| s.to_string())
}

async fn read_upstream(file: &Path) -> Option<String> {
    let f = tokio::fs::File::open(file).await.ok()?;
    let mut buf = Vec::new();
    f.take(FILE_CAP + 1).read_to_end(&mut buf).await.ok()?;
    (buf.len() as u64 <= FILE_CAP).then(|| parse_upstream(&buf)).flatten()
}

async fn handle(mut client: TcpStream, upstream_file: PathBuf) {
    let Some(up) = read_upstream(&upstream_file).await else { return };
    let Ok(Ok(mut server)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(up)).await else { return };
    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
}

/// Accept loop (the listener is injected so tests use `127.0.0.1:0`). Never returns.
pub async fn serve(listener: TcpListener, upstream_file: PathBuf, sem: Arc<Semaphore>) {
    loop {
        let Ok((client, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = sem.clone().try_acquire_owned() else { continue }; // over the cap: the connection is dropped
        let f = upstream_file.clone();
        tokio::spawn(async move {
            handle(client, f).await;
            drop(permit);
        });
    }
}

/// `Some(exit code)` only when the process was started as `app pbm-route <file>`; `None` ⇒ the normal agent continues. Called FIRST in `main()` (hook A05).
pub async fn main_from_args() -> Option<i32> {
    let mut a = std::env::args();
    a.next();
    if a.next().as_deref() != Some("pbm-route") {
        return None;
    }
    let Some(file) = a.next() else { return Some(2) };
    let Ok(listener) = TcpListener::bind(LISTEN).await else { return Some(1) };
    serve(listener, PathBuf::from(file), Arc::new(Semaphore::new(MAX_CONNS))).await;
    Some(0)
}
