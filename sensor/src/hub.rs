//! The two calls a node makes to the hub (docs/PROTOCOL.md).

use crate::{config::Config, status::NodeState};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};

pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
    domains: Vec<String>,
}

#[derive(Serialize)]
struct Heartbeat<'a> {
    ts: String,
    version: &'static str,
    domains: &'a [String],
    cursor_file: &'a str,
    cursor_offset: u64,
    uptime_s: u64,
    state: &'a str,
    detail: &'a serde_json::Value,
}

#[derive(Deserialize, Debug, Default)]
pub struct HeartbeatReply {
    #[serde(default)]
    pub your_ip: Option<IpAddr>,
}

impl Client {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("thf-pot-sensor/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(30))
                .build()?,
            base: cfg.hub_url.clone(),
            token: cfg.sensor_token.clone(),
            domains: cfg.domains.clone(),
        })
    }

    /// Tell the hub how we are; it tells us the address it saw us from.
    pub async fn heartbeat(&self, st: &NodeState, cursor: (&str, u64), uptime_s: u64) -> anyhow::Result<HeartbeatReply> {
        let hb = Heartbeat {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            version: env!("CARGO_PKG_VERSION"),
            domains: &self.domains,
            cursor_file: cursor.0,
            cursor_offset: cursor.1,
            uptime_s,
            state: &st.state,
            detail: &st.detail,
        };
        let resp = self
            .http
            .post(format!("{}/api/v1/heartbeat", self.base))
            .bearer_auth(&self.token)
            .json(&hb)
            .send()
            .await
            .context("hub unreachable")?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("heartbeat answered {status}");
        }
        Ok(resp.json().await.unwrap_or_default())
    }

    /// One gzip-compressed NDJSON batch. Any 2xx acknowledges the whole batch.
    pub async fn ingest(&self, gz: Vec<u8>) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/api/v1/ingest", self.base))
            .bearer_auth(&self.token)
            .header("Content-Type", "application/x-ndjson")
            .header("Content-Encoding", "gzip")
            .body(gz)
            .send()
            .await
            .context("hub unreachable")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("hub answered {status}: {}", text.chars().take(200).collect::<String>());
        }
        Ok(())
    }
}
