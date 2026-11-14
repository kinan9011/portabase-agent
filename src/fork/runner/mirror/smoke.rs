//! App smoke helper of `mirror_check` (OD-W22a-3): a hardened helper attached to the mirror's own `<project>_pbm_access` network opens a TCP connection to
//! `access.service:target` (and, with `http_path`, reads the HTTP status line). Same hardening as the runner probe helper: non-root, no caps, no-new-privileges,
//! read-only rootfs, no binds, 64 MiB / 64 pids, log driver `none`. The script is a pinned constant (SHA-256 asserted by a unit test); values reach it ONLY as
//! positional arguments, never through string interpolation. The helper carries the revision's owner labels, so `mirror_wipe` also finds a leaked one.
use crate::fork::restore::Code;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;

pub type Labels = HashMap<String, String>;
pub const STDOUT_CAP: usize = 4096;

/// stdout contract: `HTTP <nnn>` (only with a path) then `OK`; every failure is a distinct non-zero exit code (3 connect, 4 write, 5 no status line, 6 not a status line).
pub const SMOKE_SCRIPT: &str = r#"set -u
host="$1"; port="$2"; path="${3:-}"
exec 3<>"/dev/tcp/$host/$port" || exit 3
if [ -n "$path" ]; then
  printf 'GET %s HTTP/1.0\r\nHost: mirror\r\nConnection: close\r\n\r\n' "$path" >&3 || exit 4
  IFS= read -r -t 10 line <&3 || exit 5
  code="${line#* }"; code="${code%% *}"
  case "$code" in [0-9][0-9][0-9]) echo "HTTP $code";; *) exit 6;; esac
fi
echo OK
"#;

pub fn smoke_cmd(host: &str, port: u32, path: Option<&str>) -> Vec<String> {
    let mut c: Vec<String> = ["-k", "1", "20", "bash", "-c", SMOKE_SCRIPT, "pbm-smoke", host].map(String::from).to_vec();
    c.push(port.to_string());
    c.push(path.unwrap_or("").to_string());
    c
}

#[async_trait]
pub trait Smoke: Send + Sync {
    /// Run `timeout <args>` in the hardened helper on `network`; exit code + stdout (≤ 4 KiB, stderr discarded). The helper is removed in EVERY outcome and its
    /// absence verified (`smoke_failed_internal` otherwise).
    async fn run(&self, name: &str, network: &str, labels: &Labels, args: &[String], timeout: Duration) -> Result<(i64, Vec<u8>), Code>;
}

pub mod real {
    use super::*;
    use bollard::models::{ContainerCreateBody, HostConfig, HostConfigLogConfig};
    use bollard::query_parameters::{CreateContainerOptions, RemoveContainerOptions, StartContainerOptions};
    use futures::StreamExt;

    fn dk<E>(_: E) -> Code {
        Code::DockerUnavailable
    }

    pub fn helper_body(image: &str, network: &str, labels: &Labels, args: &[String]) -> ContainerCreateBody {
        ContainerCreateBody {
            image: Some(image.to_string()),
            entrypoint: Some(vec!["timeout".into()]),
            cmd: Some(args.to_vec()),
            user: Some("65534:65534".into()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            labels: Some(labels.clone()),
            host_config: Some(HostConfig {
                network_mode: Some(network.to_string()),
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

    pub struct RealSmoke {
        docker: bollard::Docker,
    }
    impl RealSmoke {
        pub fn connect() -> Result<Self, Code> {
            Ok(Self { docker: crate::domain::docker_volume::docker::client().map_err(|_| Code::DockerUnavailable)? })
        }
    }

    #[async_trait]
    impl Smoke for RealSmoke {
        async fn run(&self, name: &str, network: &str, labels: &Labels, args: &[String], timeout: Duration) -> Result<(i64, Vec<u8>), Code> {
            use bollard::container::LogOutput;
            let image = crate::domain::docker_volume::docker::resolve_helper_image(&self.docker).await.map_err(|_| Code::DockerUnavailable)?;
            let id = self.docker.create_container(Some(CreateContainerOptions { name: Some(name.to_string()), ..Default::default() }), helper_body(&image, network, labels, args)).await.map_err(dk)?.id;
            let r = tokio::time::timeout(timeout, async {
                let mut att = self.docker.attach_container(&id, Some(bollard::query_parameters::AttachContainerOptions { stream: true, stdout: true, stderr: true, ..Default::default() })).await.map_err(dk)?;
                self.docker.start_container(&id, None::<StartContainerOptions>).await.map_err(dk)?;
                let mut out = Vec::new();
                while let Some(c) = att.output.next().await {
                    if let LogOutput::StdOut { message } = c.map_err(dk)? {
                        let room = STDOUT_CAP.saturating_sub(out.len());
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
            .await
            .unwrap_or(Err(Code::DeadlineExceeded));
            // removal is part of the contract: force-remove, then prove it is gone
            let _ = self.docker.remove_container(&id, Some(RemoveContainerOptions { force: true, v: true, ..Default::default() })).await;
            match self.docker.inspect_container(&id, None::<bollard::query_parameters::InspectContainerOptions>).await {
                Err(bollard::errors::Error::DockerResponseServerError { status_code: 404, .. }) => r,
                _ => Err(Code::SmokeFailedInternal),
            }
        }
    }
}
