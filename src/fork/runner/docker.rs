//! The only Docker (bollard) user of the runner role. A trait with the real implementation and one test fake, so ownership / wipe / hardening rules are unit-tested without a daemon.
use super::Code;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;

/// Every object a probe creates carries this label (value = probe id) so the wipe and the startup sweep find it.
pub const LABEL_PROBE: &str = "com.portabase.fork.runner_probe";
pub const LABEL_AGENT: &str = "com.portabase.fork.agent_id";
pub const HELPER_STDOUT_CAP: usize = 64 * 1024;
pub type Labels = HashMap<String, String>;

/// What the probe helper is run with (everything else is fixed by `helper_body`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperSpec {
    pub name: String,
    pub network: String,
    pub labels: Labels,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
}

/// Objects carrying an ownership label: container ids, network names, volume names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owned {
    pub containers: Vec<String>,
    pub networks: Vec<String>,
    pub volumes: Vec<String>,
}
impl Owned {
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty() && self.networks.is_empty() && self.volumes.is_empty()
    }
}

pub fn has_label(labels: &Labels, key: &str, value: Option<&str>) -> bool {
    match labels.get(key) {
        Some(v) => value.is_none_or(|want| v == want),
        None => false,
    }
}

#[async_trait]
pub trait RunnerDocker: Send + Sync {
    async fn ping(&self) -> bool;
    /// The image the helper runs (the agent's own image: `resolve_helper_image`, never edited here).
    async fn helper_image(&self) -> Result<String, Code>;
    /// Create the probe network exactly like a mirror network is created by the daemon: bridge, NOT internal, no IPAM, no options (subnet from the daemon's pool).
    async fn create_probe_network(&self, name: &str, labels: &Labels) -> Result<(), Code>;
    /// Run the hardened helper to completion: exit code + stdout (≤ 64 KiB). stderr is discarded. The caller wipes afterwards.
    async fn run_probe_helper(&self, spec: &HelperSpec) -> Result<(i64, Vec<u8>), Code>;
    async fn list_owned(&self, key: &str, value: Option<&str>) -> Result<Owned, Code>;
    async fn remove_container(&self, id: &str) -> Result<(), Code>;
    async fn remove_network(&self, name: &str) -> Result<(), Code>;
    async fn remove_volume(&self, name: &str) -> Result<(), Code>;
}

pub mod real {
    use super::*;
    use bollard::models::{ContainerCreateBody, HostConfig, HostConfigLogConfig, NetworkCreateRequest};
    use bollard::query_parameters::{CreateContainerOptions, ListContainersOptions, ListNetworksOptions, ListVolumesOptions, RemoveContainerOptions, StartContainerOptions};
    use futures::StreamExt;

    fn dk<E>(_: E) -> Code {
        Code::DockerUnavailable
    }

    /// The probe network request. `internal: false` is the point of the whole probe (ADR-008 §Probe): `internal: true` would hide exactly the leak we look for.
    pub fn network_request(name: &str, labels: &Labels) -> NetworkCreateRequest {
        NetworkCreateRequest { name: name.to_string(), driver: Some("bridge".into()), internal: Some(false), ipam: None, options: None, labels: Some(labels.clone()), ..Default::default() }
    }

    /// The hardened helper: non-root, no caps, no-new-privileges, read-only rootfs, no binds, 64 MiB / 64 pids, log driver none, on the probe network, daemon DNS (no `dns` override).
    pub fn helper_body(image: &str, spec: &HelperSpec) -> ContainerCreateBody {
        ContainerCreateBody {
            image: Some(image.to_string()),
            entrypoint: Some(vec!["bash".into()]),
            cmd: Some(vec!["-c".into(), super::super::probe::PROBE_SCRIPT.into(), "pbm-probe".into()]),
            user: Some("65534:65534".into()),
            env: Some(spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            labels: Some(spec.labels.clone()),
            host_config: Some(HostConfig {
                network_mode: Some(spec.network.clone()),
                binds: None,
                cap_drop: Some(vec!["ALL".into()]),
                security_opt: Some(vec!["no-new-privileges".into()]),
                readonly_rootfs: Some(true),
                memory: Some(64 << 20),
                pids_limit: Some(64),
                log_config: Some(HostConfigLogConfig { typ: Some("none".into()), config: None }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub struct RealRunnerDocker {
        docker: bollard::Docker,
    }
    impl RealRunnerDocker {
        pub fn connect() -> Result<Self, Code> {
            Ok(Self { docker: crate::domain::docker_volume::docker::client().map_err(|_| Code::DockerUnavailable)? })
        }
    }

    #[async_trait]
    impl RunnerDocker for RealRunnerDocker {
        async fn ping(&self) -> bool {
            self.docker.ping().await.is_ok()
        }
        async fn helper_image(&self) -> Result<String, Code> {
            crate::domain::docker_volume::docker::resolve_helper_image(&self.docker).await.map_err(|_| Code::DockerUnavailable)
        }
        async fn create_probe_network(&self, name: &str, labels: &Labels) -> Result<(), Code> {
            self.docker.create_network(network_request(name, labels)).await.map(|_| ()).map_err(dk)
        }
        async fn run_probe_helper(&self, spec: &HelperSpec) -> Result<(i64, Vec<u8>), Code> {
            use bollard::container::LogOutput;
            let image = self.helper_image().await?;
            let id = self.docker.create_container(Some(CreateContainerOptions { name: Some(spec.name.clone()), ..Default::default() }), helper_body(&image, spec)).await.map_err(dk)?.id;
            let r = tokio::time::timeout(spec.timeout, async {
                let mut att = self.docker.attach_container(&id, Some(bollard::query_parameters::AttachContainerOptions { stream: true, stdout: true, stderr: true, ..Default::default() })).await.map_err(dk)?;
                self.docker.start_container(&id, None::<StartContainerOptions>).await.map_err(dk)?;
                let mut out = Vec::new();
                while let Some(c) = att.output.next().await {
                    if let LogOutput::StdOut { message } = c.map_err(dk)? {
                        let room = HELPER_STDOUT_CAP.saturating_sub(out.len());
                        out.extend_from_slice(&message[..message.len().min(room)]);
                    }
                }
                let mut w = self.docker.wait_container(&id, None::<bollard::query_parameters::WaitContainerOptions>);
                let code = match w.next().await {
                    Some(Ok(res)) => res.status_code,
                    Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. })) => code,
                    _ => return Err(Code::DockerUnavailable),
                };
                Ok((code, out))
            })
            .await;
            // the helper is NOT removed here: the caller's verified wipe removes it (and proves it is gone) on every path
            r.unwrap_or(Err(Code::DeadlineExceeded))
        }
        async fn list_owned(&self, key: &str, value: Option<&str>) -> Result<Owned, Code> {
            let cs = self.docker.list_containers(Some(ListContainersOptions { all: true, ..Default::default() })).await.map_err(dk)?;
            let ns = self.docker.list_networks(None::<ListNetworksOptions>).await.map_err(dk)?;
            let vs = self.docker.list_volumes(None::<ListVolumesOptions>).await.map_err(dk)?;
            Ok(Owned {
                containers: cs.into_iter().filter(|c| has_label(&c.labels.clone().unwrap_or_default(), key, value)).filter_map(|c| c.id).collect(),
                networks: ns.into_iter().filter(|n| has_label(&n.labels.clone().unwrap_or_default(), key, value)).filter_map(|n| n.name).collect(),
                volumes: vs.volumes.unwrap_or_default().into_iter().filter(|v| has_label(&v.labels, key, value)).map(|v| v.name).collect(),
            })
        }
        async fn remove_container(&self, id: &str) -> Result<(), Code> {
            self.docker.remove_container(id, Some(RemoveContainerOptions { force: true, v: true, ..Default::default() })).await.map_err(dk)
        }
        async fn remove_network(&self, name: &str) -> Result<(), Code> {
            self.docker.remove_network(name).await.map_err(dk)
        }
        async fn remove_volume(&self, name: &str) -> Result<(), Code> {
            self.docker.remove_volume(name, None::<bollard::query_parameters::RemoveVolumeOptions>).await.map_err(dk)
        }
    }
}
