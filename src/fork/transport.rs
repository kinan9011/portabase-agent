//! HTTP client of the channel. https-only (unless the explicit lab exemption), NO redirects (a redirect could downgrade to http or leak the bearer),
//! bounded bodies, the credential is a sensitive header and never logged. Paths are the dashboard's fork-only `/api/fork/agent/**` routes.
use super::state::Outcome;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::json;
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
    auth: HeaderValue,
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
        let mut auth = HeaderValue::from_str(&format!("Bearer {credential}")).map_err(|_| CallError::BadBody)?;
        auth.set_sensitive(true);
        Ok(Self { http, base: server_url.trim_end_matches('/').to_string(), agent_id: agent_id.to_string(), auth })
    }

    fn url(&self, tail: &str) -> String {
        format!("{}/api/fork/agent/{}/{}", self.base, self.agent_id, tail)
    }

    async fn post(&self, tail: &str, body: serde_json::Value) -> Result<(u16, Vec<u8>), CallError> {
        let res = self.http.post(self.url(tail)).header(AUTHORIZATION, self.auth.clone()).json(&body).send().await.map_err(|_| CallError::Network)?;
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
    pub async fn hash_report(&self, backup_id: &str, sha256: &str, size_bytes: u64) -> Result<(), CallError> {
        self.post("hash-report", json!({"backup_id": backup_id, "sha256": sha256, "size_bytes": size_bytes})).await.map(|_| ())
    }
}
