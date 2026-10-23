//! A persona bundle: static files plus a small routing table. Bundles are data, never code.
//! Today they are baked into the image; later the hub ships them.

use anyhow::Context;
use bytes::Bytes;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize, Debug)]
struct BundleToml {
    server: String,
    powered_by: Option<String>,
    cookie: Option<String>,
    #[serde(default)]
    info_names: Vec<String>,
    #[serde(default)]
    info_dirs: Vec<String>,
    routes: Routes,
}

#[derive(Deserialize, Debug)]
struct Routes {
    index: String,
    plain: String,
    notfound: String,
    upload: Option<String>,
    info: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Bare placeholder, no version header, no info page.
    Bare,
    /// The site plus a version header, but no info page and no upload form.
    Header,
    /// Everything.
    Full,
}

impl Tier {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "bare" | "silent" | "0" => Tier::Bare,
            "header" | "1" => Tier::Header,
            "full" | "2" => Tier::Full,
            other => anyhow::bail!("unknown tier {other:?} (bare|header|full)"),
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Bare => "bare",
            Tier::Header => "header",
            Tier::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Index,
    Upload,
    Info,
    Plain,
    NotFound,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Index => "index",
            Kind::Upload => "upload",
            Kind::Info => "info",
            Kind::Plain => "plain",
            Kind::NotFound => "notfound",
        }
    }
}

#[derive(Debug)]
pub struct Bundle {
    pub name: String,
    pub server: String,
    pub powered_by: Option<String>,
    pub cookie: Option<String>,
    info_names: Vec<String>,
    info_dirs: Vec<String>,
    index: Bytes,
    plain: Bytes,
    notfound: Bytes,
    upload: Option<Bytes>,
    info: Option<Bytes>,
}

fn read(dir: &Path, f: &str) -> anyhow::Result<Bytes> {
    Ok(Bytes::from(
        std::fs::read(dir.join(f)).with_context(|| format!("reading {}", dir.join(f).display()))?,
    ))
}

impl Bundle {
    pub fn load(bundles_dir: &Path, name: &str) -> anyhow::Result<Self> {
        let dir = bundles_dir.join(name);
        let t: BundleToml = toml::from_str(
            &std::fs::read_to_string(dir.join("bundle.toml"))
                .with_context(|| format!("bundle {name}: bundle.toml"))?,
        )?;
        Ok(Self {
            name: name.to_string(),
            server: t.server,
            powered_by: t.powered_by,
            cookie: t.cookie,
            info_names: t.info_names.into_iter().map(|s| s.to_ascii_lowercase()).collect(),
            info_dirs: t.info_dirs.into_iter().map(|s| s.to_ascii_lowercase()).collect(),
            index: read(&dir, &t.routes.index)?,
            plain: read(&dir, &t.routes.plain)?,
            notfound: read(&dir, &t.routes.notfound)?,
            upload: t.routes.upload.as_deref().map(|f| read(&dir, f)).transpose()?,
            info: t.routes.info.as_deref().map(|f| read(&dir, f)).transpose()?,
        })
    }

    fn is_info_path(&self, path: &str) -> bool {
        let p = path.to_ascii_lowercase();
        if self.info_dirs.iter().any(|d| p.contains(d.as_str())) {
            return true;
        }
        let last = p.trim_end_matches('/').rsplit('/').next().unwrap_or("");
        let stem = last.strip_suffix(".php").unwrap_or(last);
        !stem.is_empty() && self.info_names.iter().any(|n| n == stem)
    }

    /// Decide what to answer. Mirrors the three exposure tiers the fleet has been measuring.
    pub fn route(&self, tier: Tier, path: &str, query: &str) -> (u16, Kind, Bytes) {
        let is_index = path == "/" || path == "/index.php";
        let q = query.to_ascii_lowercase();
        if tier == Tier::Full {
            if let Some(info) = &self.info {
                if self.is_info_path(path) {
                    return (200, Kind::Info, info.clone());
                }
            }
            if let Some(up) = &self.upload {
                if is_index && q.contains("page=upload") {
                    return (200, Kind::Upload, up.clone());
                }
            }
        }
        if tier == Tier::Bare {
            return if is_index {
                (200, Kind::Plain, self.plain.clone())
            } else {
                (404, Kind::NotFound, self.notfound.clone())
            };
        }
        let php_page = path.ends_with(".php") && !path.contains("wp-");
        if is_index || php_page {
            (200, Kind::Index, self.index.clone())
        } else {
            (404, Kind::NotFound, self.notfound.clone())
        }
    }
}
