//! D45: plaintext SHA-256 + size of an archive artifact, computed BEFORE encryption and reported through the channel (capability `plaintext-hash.v1`).
//! The dashboard's verify job cross-checks it against its own server-side hash; a mismatch makes the RecoveryPoint `failed`. Failures here never fail a backup.
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

pub async fn plaintext_hash(path: &Path) -> std::io::Result<(String, u64)> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hex::encode(h.finalize()), size))
}

/// Hook A03 target. Only when the channel runs AND the artifact will be encrypted (an unencrypted upload is its own plaintext). The hash is computed
/// BEFORE the uploads start (the file may be removed after them); the report itself is sent in the background with a few retries.
pub async fn report_plaintext(file: Option<&Path>, backup_id: &str, encrypt: bool) {
    let Some(active) = super::active() else { return };
    if !encrypt || !active.capabilities.iter().any(|c| c == super::capabilities::PLAINTEXT_HASH) {
        return;
    }
    let Some(file) = file else { return };
    let (sha, size) = match plaintext_hash(file).await {
        Ok(v) => v,
        Err(e) => {
            warn!("Fork channel: cannot hash the archive for backup {backup_id} ({e})");
            return;
        }
    };
    let backup_id = backup_id.to_string();
    tokio::spawn(async move {
        for (i, delay) in [0u64, 5, 20].into_iter().enumerate() {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            match active.client.hash_report(&backup_id, &sha, size).await {
                Ok(()) => {
                    debug!("Fork channel: plaintext hash reported for backup {backup_id}");
                    return;
                }
                Err(e) => warn!("Fork channel: hash report for backup {backup_id} failed (attempt {}, {e:?})", i + 1),
            }
        }
    });
}
