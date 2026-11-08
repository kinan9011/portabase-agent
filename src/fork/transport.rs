//! HTTP client of the channel. https-only (unless the explicit lab exemption), NO redirects (a redirect could downgrade to http or leak the bearer),
//! bounded bodies, the credential is a sensitive header and never logged. Paths are the dashboard's fork-only `/api/fork/agent/**` routes.
use super::state::Outcome;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, RwLock};
use std::time::Duration;

const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct Leased {
    pub task_id: String,
    pub envelope: String,
    pub signature: String,
    #[allow(dead_code)]
    pub kid: String,
    pub payload_enc: Option<String>,
    pub lease_id: String,
    #[allow(dead_code)]
    pub lease_until: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CallError {
    /// 401 — the credential is wrong, revoked or the agent id is unknown (the dashboard never says which).
    Unauthorized,
    /// 403 — the operator switched the channel off for this agent.
    Disabled,
    RateLimited(u64),
    Conflict,
    NotFound,
    Http(u16),
    Network,
    BadBody,
}

#[derive(Clone)]
pub struct Transport {
    http: reqwest::Client,
    base: String,
    agent_id: String,
    /// Shared by every clone: a rotated credential (signed `rotate_credential`) must reach the clone the D45 hook uses too.
    auth: Arc<RwLock<HeaderValue>>,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport").field("base", &self.base).field("agent_id", &self.agent_id).finish_non_exhaustive()
    }
}

impl Transport {
    pub fn new(server_url: &str, agent_id: &str, credential: &str, insecure_lab: bool) -> Result<Self, CallError> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .https_only(!insecure_lab)
            .build()
            .map_err(|_| CallError::Network)?;
        let auth = Self::header(credential)?;
        Ok(Self { http, base: server_url.trim_end_matches('/').to_string(), agent_id: agent_id.to_string(), auth: Arc::new(RwLock::new(auth)) })
    }

    fn header(credential: &str) -> Result<HeaderValue, CallError> {
        let mut auth = HeaderValue::from_str(&format!("Bearer {credential}")).map_err(|_| CallError::BadBody)?;
        auth.set_sensitive(true);
        Ok(auth)
    }

    /// Swap the bearer for ALL clones (after a rotation was persisted).
    pub fn set_credential(&self, credential: &str) -> Result<(), CallError> {
        let h = Self::header(credential)?;
        *self.auth.write().map_err(|_| CallError::BadBody)? = h;
        Ok(())
    }

    fn url(&self, tail: &str) -> String {
        format!("{}/api/fork/agent/{}/{}", self.base, self.agent_id, tail)
    }

    async fn post(&self, tail: &str, body: serde_json::Value) -> Result<(u16, Vec<u8>), CallError> {
        // clone under the read lock, never hold it across an await
        let auth = self.auth.read().map_err(|_| CallError::BadBody)?.clone();
        let res = self.http.post(self.url(tail)).header(AUTHORIZATION, auth).json(&body).send().await.map_err(|_| CallError::Network)?;
        let status = res.status().as_u16();
        let retry = res.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(30);
        if res.content_length().is_some_and(|l| l as usize > MAX_BODY) {
            return Err(CallError::BadBody);
        }
        let bytes = res.bytes().await.map_err(|_| CallError::Network)?;
        if bytes.len() > MAX_BODY {
            return Err(CallError::BadBody);
        }
        match status {
            200 | 204 => Ok((status, bytes.to_vec())),
            401 => Err(CallError::Unauthorized),
            403 => Err(CallError::Disabled),
            404 => Err(CallError::NotFound),
            409 => Err(CallError::Conflict),
            429 => Err(CallError::RateLimited(retry)),
            s => Err(CallError::Http(s)),
        }
    }

    pub async fn lease(&self, capabilities: &[String]) -> Result<Option<Leased>, CallError> {
        let (status, body) = self.post("lease", json!({"capabilities": capabilities, "channel_version": 1})).await?;
        if status == 204 {
            return Ok(None);
        }
        serde_json::from_slice::<Leased>(&body).map(Some).map_err(|_| CallError::BadBody)
    }

    pub async fn heartbeat(&self, task_id: &str, lease_id: &str) -> Result<(), CallError> {
        self.post(&format!("tasks/{task_id}/heartbeat"), json!({"lease_id": lease_id})).await.map(|_| ())
    }

    pub async fn result(&self, task_id: &str, lease_id: &str, o: &Outcome) -> Result<(), CallError> {
        let mut body = json!({"lease_id": lease_id, "status": o.status});
        if let Some(r) = &o.reason {
            body["reason"] = json!(r);
        }
        if let Some(r) = &o.result {
            body["result"] = r.clone();
        }
        self.post(&format!("tasks/{task_id}/result"), body).await.map(|_| ())
    }

    /// D45: plaintext SHA-256 + size of an archive, before encryption.
    /// W17-ii E13: upload the policy view of a `compose_render` task. 3 tries (1 s, 4 s) on network errors / 5xx; a 4xx answer is final.
    pub async fn render(&self, task_id: &str, lease_id: &str, mut body: serde_json::Value) -> Result<(), CallError> {
        body["lease_id"] = json!(lease_id);
        let mut last = CallError::Network;
        for wait in [0u64, 1, 4] {
            if wait > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            }
            match self.post(&format!("tasks/{task_id}/render"), body.clone()).await {
                Ok(_) => return Ok(()),
                Err(e @ (CallError::Network | CallError::Http(500..=599))) => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }

    /// W17b: quiesce window progress. `phase` = `stopped` (once, with the containers) | `waiting`. Returns the dashboard's `release` answer.
    /// 404 / 409 (`NotFound` / `Conflict`) are final: the dashboard no longer knows the task; the caller treats them as "release" (fail safe).
    pub async fn quiesce(&self, task_id: &str, lease_id: &str, phase: &str, containers: Option<serde_json::Value>) -> Result<bool, CallError> {
        let mut body = json!({"lease_id": lease_id, "phase": phase});
        if let Some(c) = containers {
            body["containers"] = c;
        }
        let (_, bytes) = self.post(&format!("tasks/{task_id}/quiesce"), body).await?;
        serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|v| v["release"].as_bool()).ok_or(CallError::BadBody)
    }

    pub async fn hash_report(&self, backup_id: &str, sha256: &str, size_bytes: u64) -> Result<(), CallError> {
        self.post("hash-report", json!({"backup_id": backup_id, "sha256": sha256, "size_bytes": size_bytes})).await.map(|_| ())
    }
}
