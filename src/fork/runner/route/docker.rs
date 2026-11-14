//! Real `RouteOps` (bollard) for the per-mirror forwarder. The container is as hardened as the smoke / probe helpers: user 65534, `cap_drop ALL`, `no-new-privileges`,
//! read-only rootfs, 64 MiB / 64 pids, log driver `none`, restart `unless-stopped`, ONE published port `127.0.0.1:<route_port> → 8080/tcp`, attached to ONE network, the route
//! directory bound read-only at `/route`. (No `connect` / `disconnect`: see the module doc of `route/mod.rs`.) It carries `route=<mirror_id>` + the agent id but NOT `helper=true` and NOT a restore id (the startup sweep and `mirror_wipe` must not touch it).
use super::{RouteFacts, RouteOps, RouteSpec};
use crate::fork::restore::Code;
use async_trait::async_trait;
use bollard::models::{ContainerCreateBody, HostConfig, HostConfigLogConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};
use bollard::query_parameters::{CreateContainerOptions, InspectContainerOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions};
use std::collections::HashMap;

fn dk<E>(_: E) -> Code {
    Code::DockerUnavailable
}

pub fn create_body(spec: &RouteSpec) -> ContainerCreateBody {
    let published = HashMap::from([("8080/tcp".to_string(), Some(vec![PortBinding { host_ip: Some("127.0.0.1".into()), host_port: Some(spec.route_port.to_string()) }]))]);
    ContainerCreateBody {
        image: Some(spec.image.clone()),
        entrypoint: Some(vec!["/usr/local/bin/app".into()]),
        cmd: Some(vec!["pbm-route".into(), "/route/upstream".into()]),
        user: Some("65534:65534".into()),
        labels: Some(spec.labels.clone()),
        exposed_ports: Some(vec!["8080/tcp".to_string()]),
        host_config: Some(HostConfig {
            network_mode: Some(spec.network.clone()),
            binds: Some(vec![format!("{}:/route:ro", spec.dir.display())]),
            port_bindings: Some(published),
            cap_drop: Some(vec!["ALL".into()]),
            security_opt: Some(vec!["no-new-privileges".into()]),
            readonly_rootfs: Some(true),
            memory: Some(64 << 20),
            pids_limit: Some(64),
            log_config: Some(HostConfigLogConfig { typ: Some("none".into()), config: None }),
            restart_policy: Some(RestartPolicy { name: Some(RestartPolicyNameEnum::UNLESS_STOPPED), maximum_retry_count: None }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub struct RealRoute {
    docker: bollard::Docker,
}
impl RealRoute {
    pub fn connect() -> Result<Self, Code> {
        Ok(Self { docker: crate::domain::docker_volume::docker::client().map_err(|_| Code::DockerUnavailable)? })
    }
}

#[async_trait]
impl RouteOps for RealRoute {
    async fn inspect(&self, name: &str) -> Result<Option<RouteFacts>, Code> {
        match self.docker.inspect_container(name, None::<InspectContainerOptions>).await {
            Ok(c) => {
                let mut ports = vec![];
                for (k, v) in c.host_config.and_then(|h| h.port_bindings).unwrap_or_default() {
                    let cport: u16 = k.split('/').next().and_then(|p| p.parse().ok()).unwrap_or(0);
                    for b in v.unwrap_or_default() {
                        ports.push((b.host_ip.unwrap_or_default(), b.host_port.and_then(|p| p.parse().ok()).unwrap_or(0), cport));
                    }
                }
                ports.sort();
                let mut networks: Vec<String> = c.network_settings.and_then(|n| n.networks).map(|m| m.into_keys().collect()).unwrap_or_default();
                networks.sort();
                let cfg = c.config.unwrap_or_default();
                Ok(Some(RouteFacts { running: c.state.and_then(|s| s.running).unwrap_or(false), image: cfg.image.unwrap_or_default(), labels: cfg.labels.unwrap_or_default(), networks, ports }))
            }
            Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(None),
            Err(_) => Err(Code::DockerUnavailable),
        }
    }
    async fn create_start(&self, spec: &RouteSpec) -> Result<(), Code> {
        let id = self.docker.create_container(Some(CreateContainerOptions { name: Some(spec.name.clone()), ..Default::default() }), create_body(spec)).await.map_err(dk)?.id;
        if self.docker.start_container(&id, None::<StartContainerOptions>).await.is_err() {
            let _ = self.docker.remove_container(&id, Some(RemoveContainerOptions { force: true, v: true, ..Default::default() })).await;
            return Err(Code::DockerUnavailable);
        }
        Ok(())
    }
    async fn remove(&self, name: &str) -> Result<(), Code> {
        let _ = self.docker.stop_container(name, Some(StopContainerOptions { t: Some(5), ..Default::default() })).await;
        match self.docker.remove_container(name, Some(RemoveContainerOptions { force: true, v: true, ..Default::default() })).await {
            Ok(_) | Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => Ok(()),
            Err(_) => Err(Code::DockerUnavailable),
        }
    }
}
