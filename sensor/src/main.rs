//! thf-pot sensor: a low-interaction web honeypot node.
//!
//! It answers HTTP(S) like a small PHP site, records every request as one JSON line on local disk,
//! and ships those lines to the hub. It holds no detection logic: a captured node reveals nothing
//! about what the hub looks for. Three environment variables deploy it: HUB_URL, SENSOR_TOKEN, DOMAINS.

mod bundle;
mod capture;
mod config;
mod multipart;
mod profiles;
mod server;
mod shipper;
mod store;

use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // One crypto provider for everything (rustls-acme, axum-server, reqwest).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = Arc::new(config::Config::from_env()?);
    std::fs::create_dir_all(&cfg.log_dir)?;
    let profiles = Arc::new(profiles::Profiles::load(&cfg)?);
    let store = Arc::new(store::Store::new(cfg.log_dir.clone()));

    info!(
        version = env!("CARGO_PKG_VERSION"),
        hub = %cfg.hub_url,
        domains = ?cfg.domains,
        profiles = profiles.len(),
        log_dir = %cfg.log_dir.display(),
        "thf-pot sensor starting"
    );

    tokio::spawn(shipper::run(cfg.clone(), store.clone()));
    server::serve(cfg, profiles, store).await
}
