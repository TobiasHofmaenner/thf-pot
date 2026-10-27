//! Ships event lines to the hub: tail the day files, keep a byte cursor, batch, gzip, POST.
//!
//! At-least-once: a batch is only acknowledged once the hub answered 2xx, and the hub dedupes on
//! the ULID in each record. If the hub is unreachable the cursor simply stops advancing and the
//! local files keep growing. A day file is deleted only when it is older than RETAIN_DAYS *and*
//! the cursor has moved past it, so an outage never costs evidence.

use crate::{config::Config, hub, status::Shared, store::Store};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{info, warn};

const MAX_BATCH_LINES: usize = 500;
const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// A single record (one request with its full body, base64) may exceed a batch; it then ships alone.
/// Beyond this it is skipped with a warning rather than stalling the cursor forever.
const MAX_LINE_BYTES: usize = 128 * 1024 * 1024;

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
    (&mut f)
        .take(MAX_BATCH_BYTES as u64)
        .read_to_end(&mut buf)?;

    // A record longer than a whole batch (a request with a full-size body): read to its newline
    // and ship it on its own.
    if buf.len() >= MAX_BATCH_BYTES && !buf.contains(&b'\n') {
        let mut rest = Vec::new();
        std::io::BufReader::new(&mut f).read_until(b'\n', &mut rest)?;
        if rest.last() != Some(&b'\n') {
            return Ok(None); // still being written
        }
        if buf.len() + rest.len() > MAX_LINE_BYTES {
            warn!(bytes = buf.len() + rest.len(), file = %cur.file, "record larger than MAX_LINE_BYTES skipped");
            cur.offset += (buf.len() + rest.len()) as u64;
            return next_batch(dir, cur);
        }
        buf.extend_from_slice(&rest);
        return Ok(Some((buf, 1)));
    }

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

pub async fn run(cfg: Arc<Config>, store: Arc<Store>, hub: Arc<hub::Client>, status: Shared) {
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
        let batch =
            tokio::task::spawn_blocking(move || next_batch(&dir, &mut c).map(|b| (b, c))).await;
        // Housekeeping below must run on every pass, including during a hub outage, so failures
        // adjust the pause instead of short-circuiting the loop.
        let mut pause = Duration::from_secs(cfg.ship_interval_secs);
        match batch {
            Ok(Ok((Some((bytes, lines)), advanced))) => {
                let new_offset = advanced.offset + bytes.len() as u64;
                match gzip(&bytes) {
                    Ok(gz) => match hub.ingest(gz).await {
                        Ok(()) => {
                            cur = Cursor {
                                file: advanced.file,
                                offset: new_offset,
                            };
                            if let Err(e) = cur.save(&cursor_path) {
                                warn!(error = %e, "cursor save failed");
                            }
                            backoff = 1;
                            info!(lines, file = %cur.file, offset = cur.offset, "shipped");
                            pause = Duration::ZERO; // more may be waiting
                        }
                        // A single record the hub calls too large would be retried forever and block
                        // everything behind it. Leave it in the day file (RETAIN_DAYS still applies)
                        // and move on; a whole batch refused that way is a configuration mismatch
                        // and keeps being retried, loudly.
                        Err(e)
                            if lines == 1
                                && e.downcast_ref::<hub::Rejected>()
                                    .is_some_and(|r| r.status == 413) =>
                        {
                            warn!(error = %e, bytes = bytes.len(), file = %advanced.file, "hub refused the record as too large; skipped, kept on disk");
                            cur = Cursor {
                                file: advanced.file,
                                offset: new_offset,
                            };
                            if let Err(e) = cur.save(&cursor_path) {
                                warn!(error = %e, "cursor save failed");
                            }
                            pause = Duration::ZERO;
                        }
                        Err(e) => {
                            warn!(error = %e, retry_in_s = backoff, "ship failed");
                            pause = Duration::from_secs(backoff);
                            backoff = (backoff * 2).min(60);
                        }
                    },
                    Err(e) => warn!(error = %e, "gzip failed"),
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
            if let Err(e) = hub
                .heartbeat(
                    &status.get(),
                    (&cur.file, cur.offset),
                    started.elapsed().as_secs(),
                )
                .await
            {
                warn!(error = %e, "heartbeat failed");
            }
        }
        if last_prune.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
            last_prune = Some(Instant::now());
            let (dir, c, days) = (store.dir.clone(), cur.clone(), cfg.retain_days);
            let _ = tokio::task::spawn_blocking(move || prune(&dir, &c, days)).await;
        }
        // A state change (certificate obtained, renewal failed, …) is reported at once.
        if tokio::time::timeout(pause, status.changed.notified())
            .await
            .is_ok()
        {
            last_hb = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("thf-pot-shipper-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn take(d: &Path, cur: &mut Cursor) -> Option<(Vec<u8>, usize)> {
        let got = next_batch(d, cur).unwrap();
        if let Some((b, _)) = &got {
            cur.offset += b.len() as u64; // what run() does after a 2xx
        }
        got
    }

    #[test]
    fn a_record_larger_than_a_batch_ships_alone_and_nothing_is_skipped() {
        let d = scratch("big");
        let small = "{\"v\":1}\n";
        let big = format!(
            "{{\"v\":1,\"b\":\"{}\"}}\n",
            "A".repeat(MAX_BATCH_BYTES + 4096)
        );
        std::fs::write(
            d.join("events-2026-10-26.jsonl"),
            format!("{small}{big}{small}"),
        )
        .unwrap();
        let mut cur = Cursor::default();

        let (b, n) = take(&d, &mut cur).unwrap();
        assert_eq!((b.as_slice(), n), (small.as_bytes(), 1));
        let (b, n) = take(&d, &mut cur).unwrap();
        assert_eq!(n, 1);
        assert_eq!(b, big.as_bytes());
        let (b, n) = take(&d, &mut cur).unwrap();
        assert_eq!((b.as_slice(), n), (small.as_bytes(), 1));
        assert!(take(&d, &mut cur).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_big_record_still_being_written_waits() {
        let d = scratch("partial");
        std::fs::write(
            d.join("events-2026-10-26.jsonl"),
            "A".repeat(MAX_BATCH_BYTES + 10),
        )
        .unwrap();
        let mut cur = Cursor::default();
        assert!(take(&d, &mut cur).is_none());
        assert_eq!(cur.offset, 0);
        let _ = std::fs::remove_dir_all(&d);
    }
}
