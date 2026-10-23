//! Profile selection: which persona answers a given request.
//!
//! A profile is a bundle, a tier, and a match condition. Conditions are things a node can decide
//! instantly and cannot get wrong: source network, hostname, path prefix. All keys inside one
//! match block are ANDed; a missing key matches anything. First match wins; the last profile in
//! the file should therefore be a catch-all.

use crate::bundle::{Bundle, Tier};
use crate::config::Config;
use anyhow::Context;
use ipnet::IpNet;
use serde::Deserialize;
use std::{collections::HashMap, net::IpAddr, sync::Arc};

#[derive(Deserialize, Debug)]
struct ProfilesFile {
    #[serde(default)]
    profile: Vec<ProfileDef>,
}

#[derive(Deserialize, Debug, Clone)]
struct ProfileDef {
    name: String,
    bundle: String,
    #[serde(default = "default_tier")]
    tier: String,
    #[serde(default, rename = "match")]
    m: MatchDef,
}

fn default_tier() -> String {
    "full".into()
}

#[derive(Deserialize, Debug, Clone, Default)]
struct MatchDef {
    #[serde(default)]
    cidr: Vec<String>,
    #[serde(default)]
    host: Vec<String>,
    #[serde(default)]
    path_prefix: Vec<String>,
}

pub struct Profile {
    pub name: String,
    pub bundle: Arc<Bundle>,
    pub tier: Tier,
    nets: Vec<IpNet>,
    hosts: Vec<String>,
    prefixes: Vec<String>,
}

impl Profile {
    fn matches(&self, ip: IpAddr, host: &str, path: &str) -> bool {
        if !self.nets.is_empty() && !self.nets.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        if !self.hosts.is_empty()
            && !self.hosts.iter().any(|h| {
                if let Some(suffix) = h.strip_prefix("*.") {
                    host == suffix || host.ends_with(&format!(".{suffix}"))
                } else {
                    host == h
                }
            })
        {
            return false;
        }
        if !self.prefixes.is_empty() && !self.prefixes.iter().any(|p| path.starts_with(p.as_str())) {
            return false;
        }
        true
    }
}

pub struct Profiles {
    list: Vec<Profile>,
}

impl Profiles {
    pub fn load(cfg: &Config) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(&cfg.profiles_file)
            .with_context(|| format!("reading {}", cfg.profiles_file.display()))?;
        let file: ProfilesFile = toml::from_str(&text).context("parsing profiles.toml")?;
        if file.profile.is_empty() {
            anyhow::bail!("profiles.toml defines no [[profile]]");
        }
        let mut bundles: HashMap<String, Arc<Bundle>> = HashMap::new();
        let mut list = Vec::with_capacity(file.profile.len());
        for d in file.profile {
            let bundle = match bundles.get(&d.bundle) {
                Some(b) => b.clone(),
                None => {
                    let b = Arc::new(Bundle::load(&cfg.bundles_dir, &d.bundle)?);
                    bundles.insert(d.bundle.clone(), b.clone());
                    b
                }
            };
            let nets = d
                .m
                .cidr
                .iter()
                .map(|c| {
                    // Accept a bare address as a /32 or /128.
                    c.parse::<IpNet>().or_else(|_| {
                        c.parse::<IpAddr>().map(IpNet::from).map_err(|e| anyhow::anyhow!("{c}: {e}"))
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
                .with_context(|| format!("profile {}: cidr", d.name))?;
            list.push(Profile {
                name: d.name,
                bundle,
                tier: Tier::parse(&d.tier)?,
                nets,
                hosts: d.m.host.iter().map(|h| h.to_ascii_lowercase()).collect(),
                prefixes: d.m.path_prefix,
            });
        }
        Ok(Self { list })
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn select(&self, ip: IpAddr, host: &str, path: &str) -> &Profile {
        self.list
            .iter()
            .find(|p| p.matches(ip, host, path))
            .unwrap_or_else(|| self.list.last().expect("non-empty"))
    }
}
