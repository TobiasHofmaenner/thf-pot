//! The listener. Every request, whatever the method or path, is captured, answered from the
//! selected persona, and written to the store before the response goes out.

use crate::{
    bundle::{Scope, Tier},
    capture::{self, BodyInfo, HttpInfo, Record, RespInfo},
    config::Config,
    mint, multipart,
    profiles::Profiles,
    status::Shared,
    store::Store,
};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    response::Response,
    Router,
};
use base64::Engine;
use futures_util::StreamExt;
use rustls_acme::{caches::DirCache, AcmeConfig, EventOk};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    profiles: Arc<Profiles>,
    store: Arc<Store>,
    /// "http" or "https": one router per listener, so the record knows which socket it came in on.
    scheme: &'static str,
}

pub async fn serve(
    cfg: Arc<Config>,
    profiles: Arc<Profiles>,
    store: Arc<Store>,
    status: Shared,
) -> anyhow::Result<()> {
    let make = |scheme: &'static str| {
        Router::new()
            .fallback(handle)
            .with_state(AppState {
                cfg: cfg.clone(),
                profiles: profiles.clone(),
                store: store.clone(),
                scheme,
            })
            .into_make_service_with_connect_info::<SocketAddr>()
    };

    let http_addr: SocketAddr = ([0, 0, 0, 0], cfg.http_port).into();
    if cfg.http_only {
        info!(%http_addr, "listening (HTTP only)");
        axum_server::bind(http_addr).serve(make("http")).await?;
        return Ok(());
    }

    let https_addr: SocketAddr = ([0, 0, 0, 0], cfg.https_port).into();
    let mut acme = AcmeConfig::new(cfg.domains.clone())
        .cache(DirCache::new(cfg.log_dir.join("acme")))
        .directory_lets_encrypt(!cfg.acme_staging);
    if let Some(email) = &cfg.acme_email {
        acme = acme.contact_push(format!("mailto:{email}"));
    }
    let mut acme_state = acme.state();
    let acceptor = acme_state.axum_acceptor(acme_state.default_rustls_config());
    let domains = cfg.domains.clone();
    tokio::spawn(async move {
        // Certificate phase, reported to the hub: a deployed certificate (fresh or from the
        // cache) means `ready`; any ACME failure, including a renewal later on, is `cert_error`.
        loop {
            match acme_state.next().await {
                Some(Ok(ev @ (EventOk::DeployedCachedCert | EventOk::DeployedNewCert))) => {
                    info!(event = ?ev, "acme: certificate deployed");
                    let mut d = status.get().detail;
                    d["certs"] = serde_json::json!(domains);
                    if let Some(o) = d.as_object_mut() {
                        o.remove("error");
                    }
                    status.set("ready", d);
                }
                Some(Ok(ev)) => info!(event = ?ev, "acme"),
                Some(Err(e)) => {
                    warn!(error = %e, "acme");
                    let mut d = status.get().detail;
                    d["error"] =
                        serde_json::json!(e.to_string().chars().take(300).collect::<String>());
                    status.set("cert_error", d);
                }
                None => break,
            }
        }
    });

    info!(%http_addr, %https_addr, staging = cfg.acme_staging, "listening");
    let https = axum_server::bind(https_addr)
        .acceptor(acceptor)
        .serve(make("https"));
    let http = axum_server::bind(http_addr).serve(make("http"));
    tokio::try_join!(https, http)?;
    Ok(())
}

/// Read the body: count up to `max_read`, keep the first `max_store` bytes verbatim.
async fn read_body(body: Body, max_read: usize, max_store: usize) -> (Vec<u8>, u64, bool) {
    let mut stream = body.into_data_stream();
    let mut sample = Vec::with_capacity(max_store.min(64 * 1024));
    let mut read: usize = 0;
    let mut truncated = false;
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { break };
        if read >= max_read {
            truncated = true;
            break;
        }
        let take = chunk.len().min(max_read - read);
        read += take;
        if sample.len() < max_store {
            let room = max_store - sample.len();
            sample.extend_from_slice(&chunk[..take.min(room)]);
        }
        if take < chunk.len() {
            truncated = true;
            break;
        }
    }
    (sample, read as u64, truncated)
}

fn truncate(s: std::borrow::Cow<'_, str>, n: usize) -> String {
    if s.len() <= n {
        s.into_owned()
    } else {
        let mut end = n;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

async fn handle(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let t0 = Instant::now();
    let mut scheme = st.scheme;
    let (parts, body) = req.into_parts();

    // Source address. Only trust proxy headers when told to; this node normally terminates TLS itself.
    let mut src = peer.ip();
    if st.cfg.trust_proxy {
        if let Some(p) = parts
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
        {
            scheme = if p.eq_ignore_ascii_case("https") {
                "https"
            } else {
                "http"
            };
        }
        let fwd = parts
            .headers
            .get("x-real-ip")
            .or_else(|| parts.headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok());
        if let Some(ip) = fwd {
            src = ip;
        }
    }

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                truncate(String::from_utf8_lossy(v.as_bytes()), 2000),
            )
        })
        .collect();
    let hdr_fp = capture::header_fingerprint(&headers);

    let ctype = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or("").to_ascii_lowercase())
        .or_else(|| parts.uri.host().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default();

    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or(&path)
        .to_string();

    let (sample, read_len, truncated) = read_body(body, st.cfg.max_read, st.cfg.max_store).await;

    let mp = if ctype.to_ascii_lowercase().starts_with("multipart/") {
        multipart::boundary_of(&ctype).map(|b| multipart::stats(&sample, &b))
    } else {
        None
    };
    let flags = capture::flags(&headers, &ctype, declared, read_len, mp.as_ref());

    // Choose the persona and the answer.
    let profile = st.profiles.select(src, &host, &path);
    let (status, kind, page) = profile.bundle.route(profile.tier, &path, &query);

    // Fill in whatever this answer hands out, and remember the keys. Nothing here looks at the
    // request: the node mints and records, the hub does the thinking.
    let mut minted: Vec<(String, String)> = Vec::new();
    let payload = page.render(|slot| match slot.scope {
        Scope::Node => match profile.bundle.node_value(&slot.name) {
            Some((key, value)) => {
                minted.push((slot.label(), key.clone()));
                value.clone()
            }
            None => String::new(),
        },
        Scope::Request => {
            let key = mint::key();
            let value = mint::value(&slot.name, &key);
            minted.push((slot.label(), key));
            value
        }
    });
    let cookie = profile.bundle.cookie.as_ref().map(|name| {
        let key = mint::key();
        let value = mint::value("cookie", &key);
        minted.push(("cookie".to_string(), key));
        format!("{name}={value}; path=/")
    });

    let rec = Record {
        v: 1,
        id: ulid::Ulid::new().to_string(),
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        src: src.to_string(),
        src_port: peer.port(),
        is_self: st.cfg.is_self(src),
        http: HttpInfo {
            scheme,
            version: format!("{:?}", parts.version),
            method: parts.method.to_string(),
            target: truncate(target.into(), 4000),
            path: truncate(path.clone().into(), 2000),
            query: truncate(query.into(), 2000),
            headers,
            hdr_fp,
        },
        host: truncate(host.into(), 253),
        body: BodyInfo {
            declared_len: declared,
            read_len,
            truncated,
            sha256: (!sample.is_empty()).then(|| format!("{:x}", Sha256::digest(&sample))),
            sample_b64: (!sample.is_empty())
                .then(|| base64::engine::general_purpose::STANDARD.encode(&sample)),
        },
        multipart: mp,
        flags,
        resp: RespInfo {
            status,
            profile: profile.name.clone(),
            bundle: profile.bundle.name.clone(),
            tier: profile.tier.as_str().into(),
            kind: kind.as_str().into(),
            minted,
        },
        dur_ms: t0.elapsed().as_millis() as u64,
    };
    if let Err(e) = st.store.append(&rec).await {
        // Never let logging break the honeypot; say so loudly and keep answering.
        warn!(error = %e, "event write failed");
    }

    let mut resp = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
        .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .header(header::SERVER, profile.bundle.server.as_str());
    if profile.tier != Tier::Bare {
        if let Some(pb) = &profile.bundle.powered_by {
            resp = resp.header("X-Powered-By", pb.as_str());
        }
    }
    if let Some(cookie) = &cookie {
        resp = resp.header(header::SET_COOKIE, cookie.as_str());
    }
    resp.body(Body::from(payload)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap()
    })
}
