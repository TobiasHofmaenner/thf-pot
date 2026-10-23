//! The event record. One JSON line per request; schema version 1.
//!
//! Identity: `id` is a ULID minted here, so the hub can deduplicate retried batches. The node's own
//! identity is NOT in the record; the hub assigns it from the bearer token so a node cannot claim
//! to be another.

use crate::multipart::MultipartStats;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct Record {
    pub v: u8,
    pub id: String,
    pub ts: String,
    pub src: String,
    pub src_port: u16,
    #[serde(rename = "self")]
    pub is_self: bool,
    pub http: HttpInfo,
    pub host: String,
    pub body: BodyInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multipart: Option<MultipartStats>,
    pub flags: Vec<String>,
    pub resp: RespInfo,
    pub dur_ms: u64,
}

#[derive(Serialize, Debug)]
pub struct HttpInfo {
    pub scheme: &'static str,
    pub version: String,
    pub method: String,
    /// Raw request target as received (path + query), truncated.
    pub target: String,
    pub path: String,
    pub query: String,
    /// Header name/value pairs in wire order. Names lowercased.
    pub headers: Vec<(String, String)>,
    /// First 16 hex chars of sha256 over the ordered, comma-joined header names.
    /// Identifies the client software far better than the user-agent it claims.
    pub hdr_fp: String,
}

#[derive(Serialize, Debug)]
pub struct BodyInfo {
    pub declared_len: Option<u64>,
    pub read_len: u64,
    /// True if the client offered more than MAX_READ_BYTES; the remainder was not read.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// First MAX_STORE_BYTES of the body, base64. The sha256 above is over this sample.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_b64: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct RespInfo {
    pub status: u16,
    pub profile: String,
    pub bundle: String,
    pub tier: String,
    pub kind: String,
}

/// Structural flags. Deliberately named for what was observed, not for any campaign.
pub fn flags(
    headers: &[(String, String)],
    ctype: &str,
    declared: Option<u64>,
    read_len: u64,
    mp: Option<&MultipartStats>,
) -> Vec<String> {
    let mut f = Vec::new();
    if ctype
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
    {
        f.push("multipart".into());
        if let Some(m) = mp {
            if m.session_upload_progress {
                f.push("mp:upload_progress_field".into());
            }
            if m.max_headers_in_part > 30 {
                f.push("mp:excessive_part_headers".into());
            }
            if m.empty_file_parts > 20 {
                f.push("mp:many_empty_file_parts".into());
            }
            if m.max_name_depth > 10 {
                f.push("mp:deep_nesting".into());
            }
            if m.parts > 1000 {
                f.push("mp:huge_part_count".into());
            }
            if m.preamble_len.unwrap_or(0) > 64 {
                f.push("mp:preamble".into());
            }
        }
        if declared.is_none() {
            f.push("no_content_length".into());
        }
        if read_len > 8 * 1024 * 1024 {
            f.push("large_body".into());
        }
    }
    if headers
        .iter()
        .any(|(k, v)| k == "cookie" && v.contains("PHPSESSID"))
    {
        f.push("cookie:phpsessid".into());
    }
    f
}

pub fn header_fingerprint(headers: &[(String, String)]) -> String {
    use sha2::{Digest, Sha256};
    let joined = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let h = Sha256::digest(joined.as_bytes());
    h.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
