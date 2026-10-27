//! Configuration. Three variables are required; everything else defaults to something sensible.

use ipnet::IpNet;
use std::{net::IpAddr, path::PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the hub, e.g. https://pot.thfops.net (no trailing slash).
    pub hub_url: String,
    /// Bearer token identifying this node to the hub. The hub maps token -> sensor.
    pub sensor_token: String,
    /// Hostnames this node answers for over TLS. Certificates are obtained automatically.
    pub domains: Vec<String>,
    pub acme_email: Option<String>,
    pub acme_staging: bool,
    /// Serve plain HTTP only (development, or behind a TLS-terminating proxy).
    pub http_only: bool,
    pub http_port: u16,
    pub https_port: u16,
    pub log_dir: PathBuf,
    pub bundles_dir: PathBuf,
    pub profiles_file: PathBuf,
    /// Body bytes read from the client at most (the rest is drained and counted, not stored).
    pub max_read: usize,
    /// Body bytes kept verbatim in the record (base64).
    pub max_store: usize,
    /// Addresses and networks whose requests are our own probes; marked `self: true`, still logged.
    pub self_ips: Vec<IpAddr>,
    pub self_nets: Vec<IpNet>,
    /// Honour X-Forwarded-For / X-Real-IP. Off by default: this node terminates TLS itself.
    pub trust_proxy: bool,
    pub ship_interval_secs: u64,
    pub heartbeat_secs: u64,
    /// Day files older than this are deleted once fully shipped. 0 keeps everything.
    pub retain_days: u32,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_bool(k: &str, default: bool) -> bool {
    env(k)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn env_num<T: std::str::FromStr>(k: &str, default: T) -> T {
    env(k).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_list(k: &str) -> Vec<String> {
    env(k)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let hub_url = env("HUB_URL")
            .ok_or_else(|| anyhow::anyhow!("HUB_URL is required (e.g. https://pot.thfops.net)"))?
            .trim_end_matches('/')
            .to_string();
        // NODE_TOKEN is the name (node = this server); SENSOR_TOKEN is accepted for deployments made before the rename.
        let sensor_token = env("NODE_TOKEN")
            .or_else(|| env("SENSOR_TOKEN"))
            .ok_or_else(|| anyhow::anyhow!("NODE_TOKEN is required"))?;
        let http_only = env_bool("HTTP_ONLY", false);
        let domains: Vec<String> = env_list("DOMAINS")
            .into_iter()
            .map(|d| d.to_ascii_lowercase())
            .collect();
        if domains.is_empty() && !http_only {
            anyhow::bail!("DOMAINS is required unless HTTP_ONLY=1 (comma-separated hostnames this node serves)");
        }

        let self_ips: Vec<IpAddr> = env_list("SELF_IPS")
            .into_iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let self_nets: Vec<IpNet> = match env("SELF_NETS") {
            Some(v) => v.split(',').filter_map(|s| s.trim().parse().ok()).collect(),
            None => [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "127.0.0.0/8",
                "::1/128",
            ]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        };

        Ok(Self {
            hub_url,
            sensor_token,
            domains,
            acme_email: env("ACME_EMAIL"),
            acme_staging: env_bool("ACME_STAGING", false),
            http_only,
            http_port: env_num("HTTP_PORT", 8080),
            https_port: env_num("HTTPS_PORT", 8443),
            log_dir: PathBuf::from(env("LOG_DIR").unwrap_or_else(|| "/data".into())),
            bundles_dir: PathBuf::from(env("BUNDLES_DIR").unwrap_or_else(|| "/bundles".into())),
            profiles_file: PathBuf::from(
                env("PROFILES_FILE").unwrap_or_else(|| "/profiles.toml".into()),
            ),
            max_read: env_num("MAX_READ_BYTES", 64 * 1024 * 1024),
            // Default: keep everything that was read. A honeypot that truncates the payload keeps the
            // wrapping and throws away the gift; memory is bounded by MAX_READ_BYTES per request.
            max_store: env_num("MAX_STORE_BYTES", 64 * 1024 * 1024),
            self_ips,
            self_nets,
            trust_proxy: env_bool("TRUST_PROXY", false),
            ship_interval_secs: env_num("SHIP_INTERVAL_SECS", 2),
            heartbeat_secs: env_num("HEARTBEAT_SECS", 60),
            retain_days: env_num("RETAIN_DAYS", 30),
        })
    }

    pub fn is_self(&self, ip: IpAddr) -> bool {
        self.self_ips.contains(&ip) || self.self_nets.iter().any(|n| n.contains(&ip))
    }
}
