//! W24 route tests: the forwarder (`proxy.rs`) on real loopback sockets, the upstream grammar, and the `FakeRoute` the executor tests in `mirror/tests.rs` drive
//! (call log + the upstream file content AT the moment of every network change, so "swap before detach" is asserted on order, not on the end state).
use super::proxy::{parse_upstream, serve};
use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

#[derive(Default)]
pub(crate) struct RouteState {
    pub(crate) containers: BTreeMap<String, RouteFacts>,
    /// `create <net> upstream=<content at that moment>` / `remove`
    pub(crate) log: Vec<String>,
    /// the upstream file the swap is observed through
    pub(crate) upstream_file: Option<PathBuf>,
    /// `remove` answers Ok but the container stays (a route_incomplete leftover)
    pub(crate) keep: bool,
}
#[derive(Default)]
pub(crate) struct FakeRoute(pub(crate) Mutex<RouteState>);

#[async_trait]
impl RouteOps for FakeRoute {
    async fn inspect(&self, name: &str) -> Result<Option<RouteFacts>, Code> {
        Ok(self.0.lock().unwrap().containers.get(name).cloned())
    }
    async fn create_start(&self, spec: &RouteSpec) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.upstream_file = Some(spec.dir.join(UPSTREAM));
        let up = std::fs::read_to_string(spec.dir.join(UPSTREAM)).unwrap_or_default();
        s.log.push(format!("create {} upstream={}", spec.network, up.trim()));
        s.containers.insert(spec.name.clone(), RouteFacts { running: true, image: spec.image.clone(), labels: spec.labels.clone(), networks: vec![spec.network.clone()], ports: vec![("127.0.0.1".into(), spec.route_port, FORWARDER_PORT)] });
        Ok(())
    }
    async fn remove(&self, name: &str) -> Result<(), Code> {
        let mut s = self.0.lock().unwrap();
        s.log.push("remove".into());
        if !s.keep {
            s.containers.remove(name);
        }
        Ok(())
    }
}

// ---- upstream grammar -----------------------------------------------------------------------------------------------------------------
#[test]
fn upstream_grammar_accepts_name_port_and_nothing_else() {
    for ok in ["pbm-demo-r2-web-1:80\n", "pbm-demo-r2-web-1:80", "a:1", "A_b.c-d:65535", "127.0.0.1:8080\n"] {
        assert!(parse_upstream(ok.as_bytes()).is_some(), "{ok:?}");
    }
    let long = format!("{}:80", "a".repeat(129));
    for bad in ["", "\n", ":80", "host", "host:", "host:0", "host:65536", "host:123456", "host:8o", "a b:80", "host:80 ", "-x:80", "x\ny:80", "x:80\ny:80", "x:80\n\n", "h\0:80", "h/x:80", "h@x:80", "[::1]:80", &long, "ünï:80"] {
        assert!(parse_upstream(bad.as_bytes()).is_none(), "{bad:?}");
    }
    assert!(parse_upstream(&[0xff, 0xfe, b':', b'8']).is_none());
}

// ---- the forwarder on real sockets --------------------------------------------------------------------------------------------------
/// a one-shot upstream: writes `tag`, then closes
async fn tagged_upstream(tag: &'static [u8]) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else { return };
            let _ = c.write_all(tag).await;
        }
    });
    port
}
async fn start_proxy(file: &Path, cap: usize) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(serve(l, file.to_path_buf(), Arc::new(Semaphore::new(cap))));
    port
}
async fn hit(port: u16) -> Vec<u8> {
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut b = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut b)).await;
    b
}
fn swap(file: &Path, content: &str) {
    let tmp = file.with_extension("tmp");
    std::fs::write(&tmp, content).unwrap();
    std::fs::rename(&tmp, file).unwrap();
}

#[tokio::test]
async fn the_forwarder_follows_the_upstream_file_per_new_connection() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("upstream");
    let (a, b) = (tagged_upstream(b"A").await, tagged_upstream(b"B").await);
    swap(&f, &format!("127.0.0.1:{a}\n"));
    let p = start_proxy(&f, 8).await;
    assert_eq!(hit(p).await, b"A");
    swap(&f, &format!("127.0.0.1:{b}\n"));
    assert_eq!(hit(p).await, b"B", "the next connection after the rename goes to the new upstream");
    assert_eq!(hit(p).await, b"B");
}

#[tokio::test]
async fn a_garbage_missing_or_oversized_upstream_file_closes_the_connection_without_bytes() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("upstream");
    let a = tagged_upstream(b"A").await;
    let p = start_proxy(&f, 8).await;
    assert!(hit(p).await.is_empty(), "no upstream file yet");
    for garbage in ["not an upstream".to_string(), format!("127.0.0.1:{a} extra"), format!("127.0.0.1:{a}\nsecond:80"), "x".repeat(4000), format!("127.0.0.1:{}", 0)] {
        swap(&f, &garbage);
        assert!(hit(p).await.is_empty(), "{:?}", &garbage[..garbage.len().min(30)]);
    }
    swap(&f, &format!("127.0.0.1:{a}\n"));
    assert_eq!(hit(p).await, b"A", "a valid file works again immediately");
}

#[tokio::test]
async fn over_the_connection_cap_the_connection_is_dropped() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("upstream");
    let hold = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hp = hold.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut keep = vec![];
        while let Ok((c, _)) = hold.accept().await {
            keep.push(c); // never answers, never closes
        }
    });
    swap(&f, &format!("127.0.0.1:{hp}\n"));
    let p = start_proxy(&f, 1).await;
    let _first = TcpStream::connect(("127.0.0.1", p)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(hit(p).await.is_empty(), "the second connection exceeds the cap of 1 and is dropped");
}

#[tokio::test]
async fn the_forwarder_never_runs_as_a_normal_agent_start() {
    // the test binary was not started as `app pbm-route …`: the hook must be a no-op for every other start
    assert_eq!(super::proxy::main_from_args().await, None);
}

#[test]
fn the_forwarder_source_never_logs() {
    let src = include_str!("proxy.rs");
    for banned in ["println!", "eprintln!", "tracing::", "log::", "info!(", "warn!(", "error!(", "debug!(", "dbg!"] {
        assert!(!src.contains(banned), "{banned}");
    }
}
