//! A persona bundle: static files plus a small routing table. Bundles are data, never code.
//! Today they are baked into the image; later the hub ships them.
//!
//! A page may carry slots written `@@scope:name@@`, filled in when the page is served: `req:` once
//! per answer, `node:` once per node at start-up. Filling a slot is a concatenation and nothing
//! else; nothing in a bundle is ever executed, and no slot ever receives anything from the request.

use crate::mint;
use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use serde::Deserialize;
use std::{collections::HashMap, path::Path};
use tracing::warn;

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

/// How often a slot's value changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A fresh value in every answer: a return proves the sender read that one answer.
    Request,
    /// One value for this node's lifetime: a return proves the sender read this node at some point.
    Node,
}

#[derive(Debug, Clone)]
pub struct Slot {
    pub scope: Scope,
    pub name: String,
}

impl Slot {
    fn parse(s: &str) -> Option<Self> {
        let (scope, name) = s.split_once(':')?;
        let scope = match scope {
            "req" => Scope::Request,
            "node" => Scope::Node,
            _ => return None,
        };
        let ok = !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        ok.then(|| Self {
            scope,
            name: name.to_string(),
        })
    }

    /// How this slot is named in the record.
    pub fn label(&self) -> String {
        let scope = match self.scope {
            Scope::Request => "req",
            Scope::Node => "node",
        };
        format!("{scope}:{}", self.name)
    }
}

/// A served page, split on its slots once at load, so filling them is a concatenation.
#[derive(Debug)]
pub struct Page {
    /// Literal pieces; one more than there are slots.
    lit: Vec<Bytes>,
    slots: Vec<Slot>,
    len_hint: usize,
}

impl Page {
    fn parse(raw: Bytes) -> Self {
        let Ok(text) = std::str::from_utf8(&raw) else {
            return Self::literal(raw);
        };
        let parts: Vec<&str> = text.split("@@").collect();
        // literal @@ slot @@ literal …: fewer than three pieces means no slot at all, and an even
        // number means a marker was left open. Either way the page is served exactly as it is.
        if parts.len() < 3 || parts.len().is_multiple_of(2) {
            if parts.len() > 1 {
                warn!("a page has an unclosed @@ slot marker and is served as it is");
            }
            return Self::literal(raw);
        }
        let mut lit = Vec::with_capacity(parts.len() / 2 + 1);
        let mut slots = Vec::with_capacity(parts.len() / 2);
        for (i, p) in parts.iter().enumerate() {
            if i % 2 == 0 {
                lit.push(Bytes::from(p.to_string()));
            } else if let Some(s) = Slot::parse(p) {
                slots.push(s);
            } else {
                warn!(slot = %p, "a page has an unreadable slot marker and is served as it is");
                return Self::literal(raw);
            }
        }
        let len_hint = raw.len();
        Self {
            lit,
            slots,
            len_hint,
        }
    }

    fn literal(raw: Bytes) -> Self {
        let len_hint = raw.len();
        Self {
            lit: vec![raw],
            slots: Vec::new(),
            len_hint,
        }
    }

    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Fill the slots. `f` is called once per slot, in the order they appear in the page.
    pub fn render(&self, mut f: impl FnMut(&Slot) -> String) -> Bytes {
        if self.slots.is_empty() {
            return self.lit[0].clone();
        }
        let mut out = BytesMut::with_capacity(self.len_hint + 64 * self.slots.len());
        for (i, l) in self.lit.iter().enumerate() {
            out.put_slice(l);
            if let Some(s) = self.slots.get(i) {
                out.put_slice(f(s).as_bytes());
            }
        }
        out.freeze()
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
    index: Page,
    plain: Page,
    notfound: Page,
    upload: Option<Page>,
    info: Option<Page>,
    /// Node-scoped slot values, minted once at start-up: name -> (key, value).
    node_values: HashMap<String, (String, String)>,
}

fn read(dir: &Path, f: &str) -> anyhow::Result<Page> {
    let raw =
        std::fs::read(dir.join(f)).with_context(|| format!("reading {}", dir.join(f).display()))?;
    Ok(Page::parse(Bytes::from(raw)))
}

impl Bundle {
    pub fn load(bundles_dir: &Path, name: &str) -> anyhow::Result<Self> {
        let dir = bundles_dir.join(name);
        let t: BundleToml = toml::from_str(
            &std::fs::read_to_string(dir.join("bundle.toml"))
                .with_context(|| format!("bundle {name}: bundle.toml"))?,
        )?;
        let mut b = Self {
            name: name.to_string(),
            server: t.server,
            powered_by: t.powered_by,
            cookie: t.cookie,
            info_names: t
                .info_names
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            info_dirs: t
                .info_dirs
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            index: read(&dir, &t.routes.index)?,
            plain: read(&dir, &t.routes.plain)?,
            notfound: read(&dir, &t.routes.notfound)?,
            upload: t
                .routes
                .upload
                .as_deref()
                .map(|f| read(&dir, f))
                .transpose()?,
            info: t
                .routes
                .info
                .as_deref()
                .map(|f| read(&dir, f))
                .transpose()?,
            node_values: HashMap::new(),
        };
        let mut node_slots: Vec<String> = Vec::new();
        for p in [
            Some(&b.index),
            Some(&b.plain),
            Some(&b.notfound),
            b.upload.as_ref(),
            b.info.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            for s in p.slots() {
                if s.scope == Scope::Node && !node_slots.contains(&s.name) {
                    node_slots.push(s.name.clone());
                }
            }
        }
        for n in node_slots {
            let k = mint::key();
            let v = mint::value(&n, &k);
            b.node_values.insert(n, (k, v));
        }
        Ok(b)
    }

    /// The stable value for a node-scoped slot, as (key, value).
    pub fn node_value(&self, name: &str) -> Option<&(String, String)> {
        self.node_values.get(name)
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
    pub fn route(&self, tier: Tier, path: &str, query: &str) -> (u16, Kind, &Page) {
        let is_index = path == "/" || path == "/index.php";
        let q = query.to_ascii_lowercase();
        if tier == Tier::Full {
            if let Some(info) = &self.info {
                if self.is_info_path(path) {
                    return (200, Kind::Info, info);
                }
            }
            if let Some(up) = &self.upload {
                if is_index && q.contains("page=upload") {
                    return (200, Kind::Upload, up);
                }
            }
        }
        if tier == Tier::Bare {
            return if is_index {
                (200, Kind::Plain, &self.plain)
            } else {
                (404, Kind::NotFound, &self.notfound)
            };
        }
        let php_page = path.ends_with(".php") && !path.contains("wp-");
        if is_index || php_page {
            (200, Kind::Index, &self.index)
        } else {
            (404, Kind::NotFound, &self.notfound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(s: &str) -> Page {
        Page::parse(Bytes::from(s.to_string()))
    }

    fn filled(p: &Page) -> String {
        String::from_utf8(p.render(|s| format!("<{}>", s.label())).to_vec()).unwrap()
    }

    #[test]
    fn a_page_without_slots_is_served_unchanged() {
        let p = page("<html>plain</html>");
        assert!(p.slots().is_empty());
        assert_eq!(filled(&p), "<html>plain</html>");
    }

    #[test]
    fn slots_are_filled_in_page_order() {
        let p = page("a@@req:form_token@@b@@node:upload_tmp_dir@@c");
        assert_eq!(
            p.slots().iter().map(|s| s.label()).collect::<Vec<_>>(),
            ["req:form_token", "node:upload_tmp_dir"]
        );
        assert_eq!(filled(&p), "a<req:form_token>b<node:upload_tmp_dir>c");
    }

    #[test]
    fn a_malformed_or_unknown_marker_leaves_the_page_alone() {
        for s in [
            "a@@req:form_token",
            "a@@nope:x@@b",
            "a@@@@b",
            "a@@req:bad name@@b",
        ] {
            let p = page(s);
            assert!(p.slots().is_empty(), "{s}");
            assert_eq!(filled(&p), s);
        }
    }

    #[test]
    fn a_node_slot_keeps_one_value_and_a_request_slot_does_not() {
        let dir = Path::new("bundles");
        let b = Bundle::load(dir, "php").expect("the php bundle loads");
        let (_, _, upload) = b.route(Tier::Full, "/index.php", "page=upload");
        let once = |p: &Page| {
            String::from_utf8(
                p.render(|s| match s.scope {
                    Scope::Node => b.node_value(&s.name).unwrap().1.clone(),
                    Scope::Request => mint::value(&s.name, &mint::key()),
                })
                .to_vec(),
            )
            .unwrap()
        };
        assert_ne!(
            once(upload),
            once(upload),
            "a request slot changes every time"
        );
        let (_, _, info) = b.route(Tier::Full, "/phpinfo.php", "");
        assert_eq!(once(info), once(info), "a node slot does not");
        // Every node-scoped slot the bundle uses got a value at load.
        for p in [upload, info] {
            for s in p.slots().iter().filter(|s| s.scope == Scope::Node) {
                assert!(b.node_value(&s.name).is_some(), "{}", s.name);
            }
        }
    }
}
