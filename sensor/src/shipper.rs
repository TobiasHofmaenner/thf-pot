//! Ships event lines to the hub: tail the day files, keep a byte cursor, batch, gzip, POST.
//!
//! At-least-once: a batch is only acknowledged once the hub answered 2xx, and the hub dedupes on
//! the ULID in each record. If the hub is unreachable the cursor simply stops advancing and the
//! local files keep growing. A day file is deleted only when it is older than RETAIN_DAYS *and*
//! the cursor has moved past it, so an outage never costs evidence.

use crate::{config::Config, store::Store};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{info, warn};

const MAX_BATCH_LINES: usize = 500;
const MAX_BATCH_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
struct Cursor {
    file: String,
    offset: u64,
}

impl Cursor {
    fn load(p: &Path) -> Self {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    fn save(&self, p: &Path) -> anyhow::Result<()> {
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(&tmp, p)?;
        Ok(())
    }
}

fn day_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.starts_with("events-") && n.ends_with(".jsonl"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Delete day files that are both older than `retain_days` and entirely behind the cursor.
fn prune(dir: &Path, cur: &Cursor, retain_days: u32) {
    if retain_days == 0 {
        return;
    }
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(i64::from(retain_days)))
        .format("events-%Y-%m-%d.jsonl")
        .to_string();
    for f in day_files(dir) {
        if f.as_str() < cutoff.as_str() && f.as_str() < cur.file.as_str() {
            match std::fs::remove_file(dir.join(&f)) {
                Ok(()) => info!(file = %f, "pruned shipped day file"),
                Err(e) => warn!(file = %f, error = %e, "prune failed"),
            }
        }
    }
}

/// Take one batch of complete lines from the cursor position. Returns (bytes, line_count).
fn next_batch(dir: &Path, cur: &mut Cursor) -> anyhow::Result<Option<(Vec<u8>, usize)>> {
    let files = day_files(dir);
    if files.is_empty() {
        return Ok(None);
    }
    if cur.file.is_empty() || !files.contains(&cur.file) {
        // Start at the earliest file we have not seen, or the first file at all.
        cur.file = files
            .iter()
            .find(|f| f.as_str() > cur.file.as_str())
            .cloned()
            .unwrap_or_else(|| files[0].clone());
        cur.offset = 0;
    }
    let path = dir.join(&cur.file);
    let mut f = std::fs::File::open(&path).with_context(|| path.display().to_string())?;
    let len = f.metadata()?.len();
    if cur.offset > len {
        // File was truncated or replaced; start it over rather than skip data.
        cur.offset = 0;
    }
    f.seek(SeekFrom::Start(cur.offset))?;
    let mut buf = Vec::with_capacity(MAX_BATCH_BYTES.min((len - cur.offset) as usize + 1));
    f.take(MAX_BATCH_BYTES as u64).read_to_end(&mut buf)?;

    // Only complete lines.
    let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') else {
        // Nothing complete here. If a later day file exists, move on to it.
        if let Some(next) = files.iter().find(|n| n.as_str() > cur.file.as_str()) {
            cur.file = next.clone();
            cur.offset = 0;
            return next_batch(dir, cur);
        }
        return Ok(None);
    };
    let mut cut = last_nl + 1;
    let mut lines = buf[..cut].iter().filter(|&&b| b == b'\n').count();
    if lines > MAX_BATCH_LINES {
        // Trim to the first MAX_BATCH_LINES lines.
        let mut seen = 0;
        for (i, &b) in buf.iter().enumerate() {
            if b == b'\n' {
                seen += 1;
                if seen == MAX_BATCH_LINES {
                    cut = i + 1;
                    break;
                }
            }
        }
        lines = MAX_BATCH_LINES;
    }
    buf.truncate(cut);
    Ok(Some((buf, lines)))
}

fn gzip(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

async fn post_batch(cfg: &Config, client: &reqwest::Client, body: Vec<u8>) -> anyhow::Result<()> {
    let gz = gzip(&body)?;
    let resp = client
        .post(format!("{}/api/v1/ingest", cfg.hub_url))
        .bearer_auth(&cfg.sensor_token)
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

#[derive(Serialize)]
struct Heartbeat<'a> {
    ts: String,
    version: &'static str,
    domains: &'a [String],
    cursor_file: &'a str,
    cursor_offset: u64,
    uptime_s: u64,
}

async fn heartbeat(cfg: &Config, client: &reqwest::Client, cur: &Cursor, started: Instant) -> anyhow::Result<()> {
    let hb = Heartbeat {
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        version: env!("CARGO_PKG_VERSION"),
        domains: &cfg.domains,
        cursor_file: &cur.file,
        cursor_offset: cur.offset,
        uptime_s: started.elapsed().as_secs(),
    };
    let resp = client
        .post(format!("{}/api/v1/heartbeat", cfg.hub_url))
        .bearer_auth(&cfg.sensor_token)
        .json(&hb)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("heartbeat answered {}", resp.status());
    }
    Ok(())
}

pub async fn run(cfg: Arc<Config>, store: Arc<Store>) {
    let client = match reqwest::Client::builder()
        .user_agent(concat!("thf-pot-sensor/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "shipper disabled: cannot build http client");
            return;
        }
    };
    let cursor_path = store.dir.join(".shipper-cursor.json");
    let mut cur = Cursor::load(&cursor_path);
    let started = Instant::now();
    let mut last_hb: Option<Instant> = None;
    let mut last_prune: Option<Instant> = None;
    let mut backoff = 1u64;
    info!(file = %cur.file, offset = cur.offset, retain_days = cfg.retain_days, "shipper starting");

    loop {
        let dir = store.dir.clone();
        let mut c = cur.clone();
        let batch = tokio::task::spawn_blocking(move || next_batch(&dir, &mut c).map(|b| (b, c))).await;
        // Housekeeping below must run on every pass, including during a hub outage, so failures
        // adjust the pause instead of short-circuiting the loop.
        let mut pause = Duration::from_secs(cfg.ship_interval_secs);
        match batch {
            Ok(Ok((Some((bytes, lines)), advanced))) => {
                let new_offset = advanced.offset + bytes.len() as u64;
                match post_batch(&cfg, &client, bytes).await {
                    Ok(()) => {
                        cur = Cursor { file: advanced.file, offset: new_offset };
                        if let Err(e) = cur.save(&cursor_path) {
                            warn!(error = %e, "cursor save failed");
                        }
                        backoff = 1;
                        info!(lines, file = %cur.file, offset = cur.offset, "shipped");
                        pause = Duration::ZERO; // more may be waiting
                    }
                    Err(e) => {
                        warn!(error = %e, retry_in_s = backoff, "ship failed");
                        pause = Duration::from_secs(backoff);
                        backoff = (backoff * 2).min(60);
                    }
                }
            }
            Ok(Ok((None, advanced))) => {
                cur = advanced;
                backoff = 1;
            }
            Ok(Err(e)) => warn!(error = %e, "reading events"),
            Err(e) => warn!(error = %e, "shipper task"),
        }

        // One attempt per interval whether or not it succeeds; an unreachable hub is already
        // visible in the ship failures above and must not double the log noise.
        if last_hb.is_none_or(|t| t.elapsed() >= Duration::from_secs(cfg.heartbeat_secs)) {
            last_hb = Some(Instant::now());
            if let Err(e) = heartbeat(&cfg, &client, &cur, started).await {
                warn!(error = %e, "heartbeat failed");
            }
        }
        if last_prune.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
            last_prune = Some(Instant::now());
            let (dir, c, days) = (store.dir.clone(), cur.clone(), cfg.retain_days);
            let _ = tokio::task::spawn_blocking(move || prune(&dir, &c, days)).await;
        }
        tokio::time::sleep(pause).await;
    }
}
