//! thf-pot sensor: a low-interaction web honeypot node.
//!
//! It answers HTTP(S) like a small PHP site, records every request as one JSON line on local disk,
//! and ships those lines to the hub. It holds no detection logic: a captured node reveals nothing
//! about what the hub looks for. Three environment variables deploy it: HUB_URL, SENSOR_TOKEN, DOMAINS.
//!
//! Start-up order: config → preflight (hub reachable, every domain resolves to this node) →
//! listeners + certificates → shipping. The hub sees each phase as it happens.

mod bundle;
mod capture;
mod config;
mod hub;
mod multipart;
mod preflight;
mod profiles;
mod server;
mod shipper;
mod status;
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
    let hub = Arc::new(hub::Client::new(&cfg)?);
    let status = status::new();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        hub = %cfg.hub_url,
        domains = ?cfg.domains,
        profiles = profiles.len(),
        log_dir = %cfg.log_dir.display(),
        "thf-pot sensor starting"
    );

    if cfg.domains.is_empty() {
        status.set("ready", serde_json::json!({ "tls": "disabled", "dns": "skipped" }));
    } else {
        // Blocks until every domain resolves to this node; nothing listens before that. Behind a
        // TLS-terminating proxy (HTTP_ONLY) the check is just as valid; only the certificate phase is
        // somebody else's.
        preflight::run(&cfg, &hub, &status).await;
        let mut d = status.get().detail;
        if cfg.http_only {
            d["tls"] = serde_json::json!("disabled");
            status.set("ready", d);
        } else {
            status.set("cert_pending", d);
        }
    }

    tokio::spawn(shipper::run(cfg.clone(), store.clone(), hub.clone(), status.clone()));
    server::serve(cfg, profiles, store, status).await
}
