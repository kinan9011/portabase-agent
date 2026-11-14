//! Verified wipe (W21 DD-10): remove every container → network → volume carrying an ownership label, then RE-LIST. Anything left is `wipe_incomplete`, never a silent success.
use super::Code;
use super::docker::RunnerDocker;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WipeReport {
    pub containers: usize,
    pub networks: usize,
    pub volumes: usize,
}

/// `value = None` removes every object that carries `key` (startup sweep); `Some(v)` only the ones labelled `key=v` (one probe).
pub async fn wipe_owned(ops: &dyn RunnerDocker, key: &str, value: Option<&str>) -> Result<WipeReport, Code> {
    let first = ops.list_owned(key, value).await?;
    // individual removal errors are not fatal on their own: the re-list below is the judge
    for c in &first.containers {
        let _ = ops.remove_container(c).await;
    }
    for n in &first.networks {
        let _ = ops.remove_network(n).await;
    }
    for v in &first.volumes {
        let _ = ops.remove_volume(v).await;
    }
    let left = ops.list_owned(key, value).await.map_err(|_| Code::WipeIncomplete)?;
    if !left.is_empty() {
        return Err(Code::WipeIncomplete);
    }
    Ok(WipeReport { containers: first.containers.len(), networks: first.networks.len(), volumes: first.volumes.len() })
}
