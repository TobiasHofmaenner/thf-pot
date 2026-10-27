//! The node's lifecycle state, reported to the hub on every change and with every heartbeat:
//! starting → dns_failed* → dns_ok → cert_pending → cert_error* / ready.

use serde::Serialize;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Serialize, Clone, Debug)]
pub struct NodeState {
    pub state: String,
    pub detail: serde_json::Value,
    pub since: String,
}

pub struct Status {
    inner: Mutex<NodeState>,
    /// Woken on every change so the shipper sends a heartbeat at once instead of in up to 60 s.
    pub changed: Notify,
}

pub type Shared = Arc<Status>;

pub fn new() -> Shared {
    Arc::new(Status {
        inner: Mutex::new(NodeState {
            state: "starting".into(),
            detail: serde_json::json!({}),
            since: now(),
        }),
        changed: Notify::new(),
    })
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl Status {
    pub fn set(&self, state: &str, detail: serde_json::Value) {
        let mut s = self.inner.lock().unwrap();
        if s.state != state || s.detail != detail {
            tracing::info!(state, detail = %detail, "node state");
            *s = NodeState {
                state: state.into(),
                detail,
                since: now(),
            };
            self.changed.notify_one();
        }
    }

    pub fn get(&self) -> NodeState {
        self.inner.lock().unwrap().clone()
    }
}
