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

pub fn owner_labels(restore_id: &str, agent_id: &str) -> Labels {
    HashMap::from([(LABEL_RESTORE.to_string(), restore_id.to_string()), (LABEL_AGENT.to_string(), agent_id.to_string())])
}
pub fn owned_by(labels: &Labels, restore_id: &str, agent_id: &str) -> bool {
    labels.get(LABEL_RESTORE).map(String::as_str) == Some(restore_id) && labels.get(LABEL_AGENT).map(String::as_str) == Some(agent_id)
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
    /// Put one file at `relative_path` inside the volume.
    async fn helper_put_file(&self, volume: &str, relative_path: &str, file: &Path) -> Result<(), Code>;
    /// Remove every helper container (startup sweep). Returns how many.
    async fn remove_helpers(&self) -> usize;
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
            let body = ContainerCreateBody {
                image: Some(self.image().await?),
                cmd,
                user: Some("0:0".into()),
                network_disabled: Some(true),
                labels: Some(HashMap::from([(LABEL_HELPER.to_string(), "true".to_string()), ("com.docker.compose.project".to_string(), String::new())])),
                host_config: Some(HostConfig {
                    binds: Some(binds),
                    network_mode: Some("none".into()),
                    cap_drop: Some(vec!["ALL".into()]),
                    cap_add: Some(caps.iter().map(|c| c.to_string()).collect()),
                    security_opt: Some(vec!["no-new-privileges".into()]),
                    readonly_rootfs: Some(readonly),
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
        async fn helper_put_file(&self, volume: &str, relative_path: &str, file: &Path) -> Result<(), Code> {
            let id = self.make_helper(vec![format!("{volume}:/vol")], &["CHOWN", "DAC_OVERRIDE", "FOWNER"], false, None).await?;
            let r = async {
                let mut b = tar::Builder::new(Vec::new());
                let mut f = std::fs::File::open(file).map_err(|_| Code::RestoreFailed)?;
                b.append_file(format!("vol/{relative_path}"), &mut f).map_err(|_| Code::RestoreFailed)?;
                let bytes = b.into_inner().map_err(|_| Code::RestoreFailed)?;
                self.upload_tar(&id, futures_util::stream::once(async move { Ok(bytes::Bytes::from(bytes)) })).await
            }
            .await;
            self.drop_helper(&id).await;
            r
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
