//! Before a node opens a port or asks a CA for anything, every domain it was given must resolve
//! to the address the hub sees it from. Otherwise it reports `dns_failed` with what each name
//! actually resolved to, and waits: the check repeats every minute, so fixing the records is all
//! an operator has to do.

use crate::{config::Config, hub, status::Shared};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
use tokio::net::lookup_host;
use tracing::{info, warn};

const RETRY: Duration = Duration::from_secs(60);

async fn resolve(domain: &str) -> Vec<IpAddr> {
    match lookup_host((domain, 443)).await {
        Ok(addrs) => {
            let mut v: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            v.sort();
            v.dedup();
            v
        }
        Err(_) => Vec::new(),
    }
}

pub async fn run(cfg: &Config, hub: &hub::Client, status: &Shared) {
    let started = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        // 1. Learn our public address from the hub. Nothing proceeds without it.
        let me = match hub
            .heartbeat(&status.get(), ("", 0), started.elapsed().as_secs())
            .await
        {
            Ok(reply) => reply.your_ip,
            Err(e) => {
                warn!(error = %e, retry_in_s = 10, "preflight: hub unreachable");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let Some(me) = me else {
            warn!("preflight: hub did not report our address; retrying");
            tokio::time::sleep(RETRY).await;
            continue;
        };

        // 2. Every domain must resolve to it. A wildcard is checked through a label nobody would
        //    have created explicitly, so only the wildcard record can answer it.
        let mut domains = BTreeMap::new();
        let mut all_ok = true;
        for d in &cfg.domains {
            let probe = d
                .strip_prefix("*.")
                .map(|rest| format!("thf-pot-preflight.{rest}"))
                .unwrap_or_else(|| d.clone());
            let ips = resolve(&probe).await;
            let ok = ips.contains(&me);
            all_ok &= ok;
            domains.insert(d.clone(), serde_json::json!({ "ok": ok, "resolved": ips }));
        }
        let detail = serde_json::json!({ "public_ip": me, "domains": domains, "attempt": attempt });
        if all_ok {
            info!(public_ip = %me, "preflight: all domains resolve to this node");
            status.set("dns_ok", detail);
            // Report the good news before the TLS listener starts.
            let _ = hub
                .heartbeat(&status.get(), ("", 0), started.elapsed().as_secs())
                .await;
            return;
        }
        warn!(public_ip = %me, "preflight: DNS mismatch; not starting until it is fixed (re-check in {}s)", RETRY.as_secs());
        status.set("dns_failed", detail);
        let _ = hub
            .heartbeat(&status.get(), ("", 0), started.elapsed().as_secs())
            .await;
        tokio::time::sleep(RETRY).await;
    }
}
