//! The only Docker (bollard) user of the restore engine (i-9). A trait with the real implementation and one test fake (two implementations, on purpose:
//! ownership / idempotency / cleanup rules are unit-tested without a daemon). Every resource the engine creates carries the ownership labels; helper
//! containers are hardened (no network, caps dropped, no-new-privileges) and labelled `com.portabase.fork.helper=true` so the startup sweep finds them.
use super::Code;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;

pub const LABEL_RESTORE: &str = "com.portabase.fork.restore_id";
pub const LABEL_AGENT: &str = "com.portabase.fork.agent_id";
pub const LABEL_HELPER: &str = "com.portabase.fork.helper";

pub type Labels = HashMap<String, String>;

/// One container as the D29 guard sees it (W17-ii E8): full 64-hex id, names without the leading `/`, image reference, labels, docker-socket mount.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerFacts {
    pub id: String,
    pub names: Vec<String>,
    pub image: String,
    pub labels: Labels,
    pub mounts_docker_sock: bool,
    pub running: bool,
}

/// W17b: what quiesce needs to know about one container (inspect, by FULL id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CState {
    /// running|exited|paused|restarting|created|dead|removing
    pub status: String,
    pub running: bool,
    /// `None` = the image/service defines no healthcheck; else healthy|unhealthy|starting
    pub health: Option<String>,
    pub restart_count: i64,
    pub stop_timeout: Option<i64>,
}

/// The sandboxed `docker-compose config` helper (W17-ii E3). `image` = the agent's OWN image id; `cmd` is the closed argument list; `env` = payload pairs only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderSpec {
    pub image: String,
    pub bin: String,
    pub workspace: std::path::PathBuf,
    pub cmd: Vec<String>,
    pub env: Vec<(String, String)>,
}
/// (uid, gid, mode) of a file inside a volume.
pub type FileMeta = (u64, u64, u32);
pub const RENDER_STDOUT_CAP: usize = 2 * 1024 * 1024;
pub const RENDER_STDERR_CAP: usize = 4096;

/// W-TR (ADR-007 A16): exit code + stdout (≤ `CHECK_STDOUT_CAP`) of one integrity-check helper. stderr is discarded (it may name paths or contain data fragments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOut {
    pub code: i64,
    pub stdout: Vec<u8>,
}
pub const CHECK_STDOUT_CAP: usize = 4096;

pub fn owner_labels(restore_id: &str, agent_id: &str) -> Labels {
    HashMap::from([(LABEL_RESTORE.to_string(), restore_id.to_string()), (LABEL_AGENT.to_string(), agent_id.to_string())])
}
pub fn owned_by(labels: &Labels, restore_id: &str, agent_id: &str) -> bool {
    labels.get(LABEL_RESTORE).map(String::as_str) == Some(restore_id) && labels.get(LABEL_AGENT).map(String::as_str) == Some(agent_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    TooLarge,
    Failed(String),
    Docker,
}

#[async_trait]
pub trait DockerOps: Send + Sync {
    async fn ping(&self) -> bool;
    /// Root identity probe: a helper binds `dir:/probe:ro` and returns `file`'s content (`None` when it is not visible there).
    async fn read_from_bind(&self, dir: &Path, file: &str) -> Result<Option<Vec<u8>>, Code>;
    async fn volume_labels(&self, name: &str) -> Result<Option<Labels>, Code>;
    async fn create_volume(&self, name: &str, labels: &Labels) -> Result<(), Code>;
    async fn remove_volume(&self, name: &str) -> Result<(), Code>;
    async fn list_volumes(&self) -> Result<Vec<(String, Labels)>, Code>;
    async fn network_labels(&self, name: &str) -> Result<Option<Labels>, Code>;
    async fn create_network(&self, name: &str, labels: &Labels) -> Result<(), Code>;
    async fn remove_network(&self, name: &str) -> Result<(), Code>;
    async fn list_networks(&self) -> Result<Vec<(String, Labels)>, Code>;
    /// `rm -rf` the volume's content (an owned, unfinished volume is redone from scratch).
    async fn helper_wipe(&self, volume: &str) -> Result<(), Code>;
    /// Upload an AUDITED `tar.gz` whose members live under `vol/` into the volume (decompressed on the fly).
    async fn helper_extract(&self, volume: &str, tar_gz: &Path) -> Result<(), Code>;
    /// Put one file at `relative_path` inside the volume with the given owner / mode.
    async fn helper_put_file(&self, volume: &str, relative_path: &str, file: &Path, meta: FileMeta) -> Result<(), Code>;
    /// Owner / mode of `relative_path` inside the volume (`None` when it does not exist).
    async fn file_meta(&self, volume: &str, relative_path: &str) -> Result<Option<FileMeta>, Code>;
    /// `rm -f -- <paths>` inside the volume (argument list, no shell). Paths are absolute inside the helper (`/vol/...`).
    async fn helper_rm(&self, volume: &str, paths: &[String]) -> Result<(), Code>;
    /// Sandboxed compose render (E3): returns stdout (≤ 2 MiB) or `RenderTooLarge` / `RenderFailed(first stderr line)`.
    async fn render(&self, spec: &RenderSpec) -> Result<Vec<u8>, RenderError>;
    /// W-TR: run `argv` in a hardened helper (network none + disabled, cap_drop ALL, no-new-privileges, read-only rootfs, helper label, runs as the agent's own uid:gid)
    /// with `dir` bound at `/v` read-write. Returns exit code + stdout (≤ 4 KiB, stderr discarded). The container is removed in every outcome. Timeout ⇒ `Err(DeadlineExceeded)`.
    async fn helper_check(&self, dir: &Path, argv: Vec<String>, timeout: std::time::Duration) -> Result<CheckOut, Code>;
    /// Every container incl. stopped ones, with the facts the D29 guard needs.
    async fn containers(&self) -> Result<Vec<ContainerFacts>, Code>;
    /// Stop (10 s) then remove (with anonymous volumes) one container by FULL id.
    async fn stop_remove(&self, id: &str) -> Result<(), Code>;
    /// Image id (`sha256:…`) the container `own_id` runs (self-inspect).
    async fn image_of_container(&self, own_id: &str) -> Result<String, Code>;
    /// Remove every helper container (startup sweep). Returns how many.
    async fn remove_helpers(&self) -> usize;
    /// W17b: inspect one container by FULL id. `None` = no such container.
    async fn inspect_state(&self, id: &str) -> Result<Option<CState>, Code>;
    /// W17b: graceful stop by FULL id with an explicit timeout (seconds); 304 (already stopped) = Ok.
    async fn stop_container(&self, id: &str, timeout_s: u32) -> Result<(), Code>;
    /// W17b: start by FULL id; 304 (already running) = Ok; 404 = `Err(Code::ContainerChanged)`.
    async fn start_container(&self, id: &str) -> Result<(), Code>;
}

pub struct RealDocker {
    docker: bollard::Docker,
}

impl RealDocker {
    pub fn connect() -> Result<Self, Code> {
        Ok(Self { docker: crate::domain::docker_volume::docker::client().map_err(|_| Code::DockerUnavailable)? })
    }
    async fn image(&self) -> Result<String, Code> {
        crate::domain::docker_volume::docker::resolve_helper_image(&self.docker).await.map_err(|_| Code::DockerUnavailable)
    }
}

mod real {
    use super::*;
    use bollard::models::{ContainerCreateBody, HostConfig, NetworkCreateRequest, VolumeCreateRequest};
    use bollard::query_parameters::{CreateContainerOptions, ListContainersOptions, ListNetworksOptions, ListVolumesOptions, RemoveContainerOptions, StartContainerOptions, UploadToContainerOptions, DownloadFromContainerOptions};
    use futures_util::StreamExt;
    use std::io::Read;

    fn dk<E>(_: E) -> Code {
        Code::DockerUnavailable
    }

    impl RealDocker {
        /// Hardened helper: created (and started only when `start`); removed by the caller in a `finally`.
        async fn make_helper(&self, binds: Vec<String>, caps: &[&str], readonly: bool, cmd: Option<Vec<String>>) -> Result<String, Code> {
            self.make_helper_as("0:0", binds, caps, readonly, cmd, false).await
        }
        /// `attach`: the caller attaches stdout/stderr before start (log driver `none`: the output never reaches the daemon's log).
        async fn make_helper_as(&self, user: &str, binds: Vec<String>, caps: &[&str], readonly: bool, cmd: Option<Vec<String>>, attach: bool) -> Result<String, Code> {
            use bollard::models::HostConfigLogConfig;
            let body = ContainerCreateBody {
                image: Some(self.image().await?),
                cmd,
                user: Some(user.into()),
                attach_stdout: attach.then_some(true),
                attach_stderr: attach.then_some(true),
                network_disabled: Some(true),
                labels: Some(HashMap::from([(LABEL_HELPER.to_string(), "true".to_string()), ("com.docker.compose.project".to_string(), String::new())])),
                host_config: Some(HostConfig {
                    binds: Some(binds),
                    network_mode: Some("none".into()),
                    cap_drop: Some(vec!["ALL".into()]),
                    cap_add: Some(caps.iter().map(|c| c.to_string()).collect()),
                    security_opt: Some(vec!["no-new-privileges".into()]),
                    readonly_rootfs: Some(readonly),
                    log_config: attach.then(|| HostConfigLogConfig { typ: Some("none".into()), config: None }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let name = format!("portabase-fork-helper-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            Ok(self.docker.create_container(Some(CreateContainerOptions { name: Some(name), ..Default::default() }), body).await.map_err(dk)?.id)
        }
        async fn drop_helper(&self, id: &str) {
            let _ = self.docker.remove_container(id, Some(RemoveContainerOptions { force: true, v: true, ..Default::default() })).await;
        }
        async fn upload_tar(&self, helper: &str, stream: impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static) -> Result<(), Code> {
            self.docker.upload_to_container(helper, Some(UploadToContainerOptions { path: "/".to_string(), ..Default::default() }), bollard::body_try_stream(stream)).await.map_err(dk)
        }
    }

    #[async_trait]
    impl DockerOps for RealDocker {
        async fn ping(&self) -> bool {
            self.docker.ping().await.is_ok()
        }
        async fn read_from_bind(&self, dir: &Path, file: &str) -> Result<Option<Vec<u8>>, Code> {
            let id = self.make_helper(vec![format!("{}:/probe:ro", dir.display())], &[], true, None).await?;
            let r = async {
                let mut s = self.docker.download_from_container(&id, Some(DownloadFromContainerOptions { path: format!("/probe/{file}") }));
                let mut tar_bytes = Vec::new();
                while let Some(c) = s.next().await {
                    match c {
                        Ok(b) => tar_bytes.extend_from_slice(&b),
                        Err(_) => return Ok(None), // not found in the daemon's view of the directory
                    }
                    if tar_bytes.len() > 1024 * 1024 {
                        return Ok(None);
                    }
                }
                let mut ar = tar::Archive::new(std::io::Cursor::new(tar_bytes));
                let mut out = Vec::new();
                for e in ar.entries().map_err(|_| Code::RestoreFailed)? {
                    let mut e = e.map_err(|_| Code::RestoreFailed)?;
                    if e.header().entry_type().is_file() {
                        e.by_ref().take(4096).read_to_end(&mut out).map_err(|_| Code::RestoreFailed)?;
                        return Ok(Some(out));
                    }
                }
                Ok(None)
            }
            .await;
            self.drop_helper(&id).await;
            r
        }
        async fn volume_labels(&self, name: &str) -> Result<Option<Labels>, Code> {
            match self.docker.inspect_volume(name).await {
                Ok(v) => Ok(Some(v.labels)),
                Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(None),
                Err(_) => Err(Code::DockerUnavailable),
            }
        }
        async fn create_volume(&self, name: &str, labels: &Labels) -> Result<(), Code> {
            self.docker.create_volume(VolumeCreateRequest { name: Some(name.to_string()), labels: Some(labels.clone()), ..Default::default() }).await.map(|_| ()).map_err(dk)
        }
        async fn remove_volume(&self, name: &str) -> Result<(), Code> {
            self.docker.remove_volume(name, None::<bollard::query_parameters::RemoveVolumeOptions>).await.map_err(dk)
        }
        async fn list_volumes(&self) -> Result<Vec<(String, Labels)>, Code> {
            let r = self.docker.list_volumes(None::<ListVolumesOptions>).await.map_err(dk)?;
            Ok(r.volumes.unwrap_or_default().into_iter().map(|v| (v.name, v.labels)).collect())
        }
        async fn network_labels(&self, name: &str) -> Result<Option<Labels>, Code> {
            match self.docker.inspect_network(name, None).await {
                Ok(n) => Ok(Some(n.labels.unwrap_or_default())),
                Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(None),
                Err(_) => Err(Code::DockerUnavailable),
            }
        }
        async fn create_network(&self, name: &str, labels: &Labels) -> Result<(), Code> {
            self.docker.create_network(NetworkCreateRequest { name: name.to_string(), driver: Some("bridge".into()), labels: Some(labels.clone()), ..Default::default() }).await.map(|_| ()).map_err(dk)
        }
        async fn remove_network(&self, name: &str) -> Result<(), Code> {
            self.docker.remove_network(name).await.map_err(dk)
        }
        async fn list_networks(&self) -> Result<Vec<(String, Labels)>, Code> {
            let r = self.docker.list_networks(None::<ListNetworksOptions>).await.map_err(dk)?;
            Ok(r.into_iter().filter_map(|n| Some((n.name?, n.labels.unwrap_or_default()))).collect())
        }
        async fn helper_wipe(&self, volume: &str) -> Result<(), Code> {
            let id = self.make_helper(vec![format!("{volume}:/vol")], &["DAC_OVERRIDE", "FOWNER"], true, Some(vec!["sh".into(), "-c".into(), "rm -rf /vol/* /vol/.[!.]* /vol/..?*; true".into()])).await?;
            let r = async {
                self.docker.start_container(&id, None::<StartContainerOptions>).await.map_err(dk)?;
                let mut w = self.docker.wait_container(&id, None::<bollard::query_parameters::WaitContainerOptions>);
                match w.next().await {
                    Some(Ok(res)) if res.status_code == 0 => Ok(()),
                    _ => Err(Code::RestoreFailed),
                }
            }
            .await;
            self.drop_helper(&id).await;
            r
        }
        async fn helper_extract(&self, volume: &str, tar_gz: &Path) -> Result<(), Code> {
            // no read-only rootfs here: the Docker archive-upload API refuses uploads into a read-only rootfs container
            let id = self.make_helper(vec![format!("{volume}:/vol")], &["CHOWN", "DAC_OVERRIDE", "FOWNER"], false, None).await?;
            let r = async {
                let f = tokio::fs::File::open(tar_gz).await.map_err(|_| Code::RestoreFailed)?;
                let dec = async_compression::tokio::bufread::GzipDecoder::new(tokio::io::BufReader::new(f));
                self.upload_tar(&id, tokio_util::io::ReaderStream::new(dec)).await
            }
            .await;
            self.drop_helper(&id).await;
            r
        }
        async fn helper_put_file(&self, volume: &str, relative_path: &str, file: &Path, meta: FileMeta) -> Result<(), Code> {
            let id = self.make_helper(vec![format!("{volume}:/vol")], &["CHOWN", "DAC_OVERRIDE", "FOWNER"], false, None).await?;
            let r = async {
                let mut b = tar::Builder::new(Vec::new());
                let mut f = std::fs::File::open(file).map_err(|_| Code::RestoreFailed)?;
                let mut hdr = tar::Header::new_gnu();
                hdr.set_size(f.metadata().map_err(|_| Code::RestoreFailed)?.len());
                hdr.set_uid(meta.0);
                hdr.set_gid(meta.1);
                hdr.set_mode(meta.2);
                hdr.set_mtime(0);
                hdr.set_entry_type(tar::EntryType::Regular);
                b.append_data(&mut hdr, format!("vol/{relative_path}"), &mut f).map_err(|_| Code::RestoreFailed)?;
                let bytes = b.into_inner().map_err(|_| Code::RestoreFailed)?;
                self.upload_tar(&id, futures_util::stream::once(async move { Ok(bytes::Bytes::from(bytes)) })).await
            }
            .await;
            self.drop_helper(&id).await;
            r
        }
        async fn file_meta(&self, volume: &str, relative_path: &str) -> Result<Option<FileMeta>, Code> {
            let id = self.make_helper(vec![format!("{volume}:/vol:ro")], &[], true, None).await?;
            let r = async {
                let mut s = self.docker.download_from_container(&id, Some(DownloadFromContainerOptions { path: format!("/vol/{relative_path}") }));
                let mut tar_bytes = Vec::new();
                while let Some(c) = s.next().await {
                    match c {
                        Ok(b) => tar_bytes.extend_from_slice(&b),
                        Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => return Ok(None),
                        Err(_) => return Err(Code::DockerUnavailable),
                    }
                    if tar_bytes.len() > 1024 * 1024 * 1024 {
                        return Ok(None); // only the first header matters; a huge database is not buffered further
                    }
                }
                let mut ar = tar::Archive::new(std::io::Cursor::new(tar_bytes));
                for e in ar.entries().map_err(|_| Code::RestoreFailed)? {
                    let e = e.map_err(|_| Code::RestoreFailed)?;
                    if e.header().entry_type().is_file() {
                        return Ok(Some((e.header().uid().unwrap_or(0), e.header().gid().unwrap_or(0), e.header().mode().unwrap_or(0o644))));
                    }
                }
                Ok(None)
            }
            .await;
            self.drop_helper(&id).await;
            r
        }
        async fn helper_rm(&self, volume: &str, paths: &[String]) -> Result<(), Code> {
            let mut cmd = vec!["rm".to_string(), "-f".to_string(), "--".to_string()];
            cmd.extend(paths.iter().cloned());
            let id = self.make_helper(vec![format!("{volume}:/vol")], &["DAC_OVERRIDE", "FOWNER"], true, Some(cmd)).await?;
            let r = async {
                self.docker.start_container(&id, None::<StartContainerOptions>).await.map_err(dk)?;
                let mut w = self.docker.wait_container(&id, None::<bollard::query_parameters::WaitContainerOptions>);
                match w.next().await {
                    Some(Ok(res)) if res.status_code == 0 => Ok(()),
                    _ => Err(Code::RestoreFailed),
                }
            }
            .await;
            self.drop_helper(&id).await;
            r
        }
        async fn render(&self, spec: &RenderSpec) -> Result<Vec<u8>, RenderError> {
            use bollard::models::{HostConfigLogConfig};
            use bollard::container::LogOutput;
            let ws = spec.workspace.display().to_string();
            let body = ContainerCreateBody {
                image: Some(spec.image.clone()),
                entrypoint: Some(vec![spec.bin.clone()]),
                cmd: Some(spec.cmd.clone()),
                env: Some(spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect()),
                hostname: Some("portabase-render".into()),
                user: Some("0:0".into()),
                network_disabled: Some(true),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                labels: Some(HashMap::from([(LABEL_HELPER.to_string(), "true".to_string()), ("com.docker.compose.project".to_string(), String::new())])),
                host_config: Some(HostConfig {
                    binds: Some(vec![format!("{ws}:{ws}:ro")]),
                    network_mode: Some("none".into()),
                    cap_drop: Some(vec!["ALL".into()]),
                    cap_add: Some(vec!["DAC_READ_SEARCH".into()]),
                    security_opt: Some(vec!["no-new-privileges".into()]),
                    readonly_rootfs: Some(true),
                    tmpfs: Some(HashMap::from([("/tmp".to_string(), "rw,nosuid,nodev,noexec,size=16m".to_string())])),
                    log_config: Some(HostConfigLogConfig { typ: Some("none".into()), config: None }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let name = format!("portabase-fork-render-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            let id = self.docker.create_container(Some(CreateContainerOptions { name: Some(name), ..Default::default() }), body).await.map_err(|_| RenderError::Docker)?.id;
            let r = async {
                // attach BEFORE start: the output is never written to the daemon's log driver (log type none)
                let mut att = self.docker.attach_container(&id, Some(bollard::query_parameters::AttachContainerOptions { stream: true, stdout: true, stderr: true, ..Default::default() })).await.map_err(|_| RenderError::Docker)?;
                self.docker.start_container(&id, None::<StartContainerOptions>).await.map_err(|_| RenderError::Docker)?;
                let (mut out, mut err) = (Vec::new(), Vec::new());
                while let Some(c) = att.output.next().await {
                    match c.map_err(|_| RenderError::Docker)? {
                        LogOutput::StdOut { message } => {
                            if out.len() + message.len() > RENDER_STDOUT_CAP {
                                return Err(RenderError::TooLarge);
                            }
                            out.extend_from_slice(&message);
                        }
                        LogOutput::StdErr { message } => {
                            if err.len() < RENDER_STDERR_CAP {
                                err.extend_from_slice(&message[..message.len().min(RENDER_STDERR_CAP - err.len())]);
                            }
                        }
                        _ => {}
                    }
                }
                let mut w = self.docker.wait_container(&id, None::<bollard::query_parameters::WaitContainerOptions>);
                let code = match w.next().await {
                    Some(Ok(res)) => res.status_code,
                    Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. })) => code,
                    _ => return Err(RenderError::Docker),
                };
                if code != 0 {
                    let first = String::from_utf8_lossy(&err).lines().next().unwrap_or("").to_string();
                    return Err(RenderError::Failed(first));
                }
                Ok(out)
            }
            .await;
            self.drop_helper(&id).await;
            r
        }
        async fn helper_check(&self, dir: &Path, argv: Vec<String>, timeout: std::time::Duration) -> Result<CheckOut, Code> {
            use bollard::container::LogOutput;
            // the helper owns the files it reads (agent uid:gid) so no capability is needed; the bind is the ONLY mount, the rootfs is read-only
            let user = format!("{}:{}", unsafe { libc::geteuid() }, unsafe { libc::getegid() });
            let id = self.make_helper_as(&user, vec![format!("{}:/v:rw", dir.display())], &[], true, Some(argv), true).await?;
            let r = tokio::time::timeout(timeout, async {
                let mut att = self.docker.attach_container(&id, Some(bollard::query_parameters::AttachContainerOptions { stream: true, stdout: true, stderr: true, ..Default::default() })).await.map_err(dk)?;
                self.docker.start_container(&id, None::<StartContainerOptions>).await.map_err(dk)?;
                let mut out = Vec::new();
                while let Some(c) = att.output.next().await {
                    if let LogOutput::StdOut { message } = c.map_err(dk)? {
                        let room = CHECK_STDOUT_CAP.saturating_sub(out.len());
                        out.extend_from_slice(&message[..message.len().min(room)]);
                    }
                }
                let mut w = self.docker.wait_container(&id, None::<bollard::query_parameters::WaitContainerOptions>);
                let code = match w.next().await {
                    Some(Ok(res)) => res.status_code,
                    Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. })) => code,
                    _ => return Err(Code::DockerUnavailable),
                };
                Ok(CheckOut { code, stdout: out })
            })
            .await;
            self.drop_helper(&id).await;
            r.unwrap_or(Err(Code::DeadlineExceeded))
        }
        async fn containers(&self) -> Result<Vec<ContainerFacts>, Code> {
            let list = self.docker.list_containers(Some(ListContainersOptions { all: true, ..Default::default() })).await.map_err(dk)?;
            Ok(list
                .into_iter()
                .filter_map(|c| {
                    let sock = c.mounts.unwrap_or_default().iter().any(|m| matches!(m.source.as_deref(), Some("/var/run/docker.sock") | Some("/run/docker.sock")));
                    Some(ContainerFacts {
                        id: c.id?,
                        names: c.names.unwrap_or_default().into_iter().map(|n| n.trim_start_matches('/').to_string()).collect(),
                        image: c.image.unwrap_or_default(),
                        labels: c.labels.unwrap_or_default(),
                        mounts_docker_sock: sock,
                        running: c.state.map(|s| s.to_string() == "running").unwrap_or(false),
                    })
                })
                .collect())
        }
        async fn stop_remove(&self, id: &str) -> Result<(), Code> {
            let _ = self.docker.stop_container(id, Some(bollard::query_parameters::StopContainerOptions { t: Some(10), ..Default::default() })).await;
            self.docker.remove_container(id, Some(RemoveContainerOptions { force: false, v: true, ..Default::default() })).await.map_err(dk)
        }
        async fn image_of_container(&self, own_id: &str) -> Result<String, Code> {
            self.docker.inspect_container(own_id, None::<bollard::query_parameters::InspectContainerOptions>).await.map_err(dk)?.image.ok_or(Code::DockerUnavailable)
        }
        async fn inspect_state(&self, id: &str) -> Result<Option<CState>, Code> {
            match self.docker.inspect_container(id, None::<bollard::query_parameters::InspectContainerOptions>).await {
                Ok(c) => {
                    let st = c.state.unwrap_or_default();
                    Ok(Some(CState {
                        status: st.status.map(|s| s.to_string()).unwrap_or_default(),
                        running: st.running.unwrap_or(false),
                        health: st.health.and_then(|h| h.status).map(|s| s.to_string()).filter(|s| !s.is_empty() && s != "none"),
                        restart_count: c.restart_count.unwrap_or(0),
                        stop_timeout: c.config.and_then(|c| c.stop_timeout),
                    }))
                }
                Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(None),
                Err(_) => Err(Code::DockerUnavailable),
            }
        }
        async fn stop_container(&self, id: &str, timeout_s: u32) -> Result<(), Code> {
            match self.docker.stop_container(id, Some(bollard::query_parameters::StopContainerOptions { t: Some(timeout_s as i32), ..Default::default() })).await {
                Ok(_) | Err(bollard::errors::Error::DockerResponseServerError { status_code: 304, .. }) => Ok(()),
                Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Err(Code::ContainerChanged),
                Err(_) => Err(Code::DockerUnavailable),
            }
        }
        async fn start_container(&self, id: &str) -> Result<(), Code> {
            match self.docker.start_container(id, None::<StartContainerOptions>).await {
                Ok(_) | Err(bollard::errors::Error::DockerResponseServerError { status_code: 304, .. }) => Ok(()),
                Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Err(Code::ContainerChanged),
                Err(_) => Err(Code::DockerUnavailable),
            }
        }
        async fn remove_helpers(&self) -> usize {
            let filters = HashMap::from([("label".to_string(), vec![format!("{LABEL_HELPER}=true")])]);
            let Ok(list) = self.docker.list_containers(Some(ListContainersOptions { all: true, filters: Some(filters), ..Default::default() })).await else { return 0 };
            let mut n = 0;
            for c in list {
                if let Some(id) = c.id {
                    self.drop_helper(&id).await;
                    n += 1;
                }
            }
            n
        }
    }
}
