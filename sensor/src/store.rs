//! Local event store: one JSON line per request, one file per UTC day.
//!
//! This is both the durable buffer for the shipper and the second copy of the evidence. Lines are
//! appended whole; a torn final line (power loss mid-write) simply fails to parse and the shipper
//! waits for the newline that never comes until the next event pushes past it.

use crate::capture::Record;
use std::{io::Write, path::PathBuf};
use tokio::sync::Mutex;

pub struct Store {
    pub dir: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, lock: Mutex::new(()) }
    }

    pub fn file_for_day(&self, day: &str) -> PathBuf {
        self.dir.join(format!("events-{day}.jsonl"))
    }

    pub async fn append(&self, rec: &Record) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(rec)?;
        line.push('\n');
        let path = self.file_for_day(&rec.ts[..10]);
        let _guard = self.lock.lock().await;
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            f.write_all(line.as_bytes())
        })
        .await??;
        Ok(())
    }
}
