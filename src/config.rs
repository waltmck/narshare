//! Single-TOML-file configuration (wgautomesh-style: flat knobs + [[peers]]), passed with
//! -c/--config. Everything except listen addresses and peers has a default; ceilings and policies
//! only — operating points (chunk size, stream counts, zstd level) are found at runtime.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Byte size, deserializable from a bare integer or a "16MiB"-style string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl fmt::Debug for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}B", self.0)
    }
}

fn parse_bytes(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let alpha = s.find(|c: char| c.is_ascii_alphabetic())?;
    let (num, suffix) = s.split_at(alpha);
    let mult: u64 = match suffix.trim() {
        "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        _ => return None,
    };
    let v: f64 = num.trim().parse().ok()?;
    if v < 0.0 {
        return None;
    }
    Some((v * mult as f64) as u64)
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Int(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Int(n) => Ok(ByteSize(n)),
            Raw::Str(s) => parse_bytes(&s)
                .map(ByteSize)
                .ok_or_else(|| serde::de::Error::custom(format!("invalid byte size {s:?}"))),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// This node's mesh-wide name — the identifier every peer's [[peers]] entry for this node
    /// must use. Origin identity for the sync protocol: watermark vectors are keyed by it, so
    /// all nodes must agree on it (validated at runtime against sync responses).
    pub name: String,
    pub serve: Option<ServeCfg>,
    pub proxy: Option<ProxyCfg>,
    #[serde(default)]
    pub io: IoCfg,
    #[serde(default)]
    pub cache: CacheCfg,
    /// The mesh's shared relay-gate trust anchor, as "name:base64" entries. Feasible narinfos
    /// are CA, or signed under one of these keys — verified when exporting, when applying sync
    /// data, and again at use. Unset: parsed from /etc/nix/nix.conf (trusted-public-keys /
    /// extra-trusted-public-keys, with nix's built-in default when absent) — exactly what the
    /// consuming nix will accept at ingestion. Set to `[]` to relay content-addressed paths only.
    pub trusted_public_keys: Option<Vec<String>>,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheCfg {
    /// The mesh index database lives at <dir>/index.db — the daemon's only on-disk state, and
    /// state it can always afford to lose (self-verifying, re-learnable from the mesh; loss
    /// bumps this node's generation so peers resync it from a snapshot).
    #[serde(default = "d_cache_dir")]
    pub dir: PathBuf,
}

impl Default for CacheCfg {
    fn default() -> Self {
        Self { dir: d_cache_dir() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeCfg {
    /// Mesh address to serve on; reachability policy is the mesh firewall's job.
    pub listen: SocketAddr,
    #[serde(default = "d_serve_priority")]
    pub priority: u32,
    /// CPU cap on the per-chunk zstd level requesters may ask for.
    #[serde(default = "d_max_zstd_level")]
    pub max_zstd_level: i32,
    /// Manifest granularity within large files.
    #[serde(default = "d_segment_bytes")]
    pub segment_bytes: ByteSize,
    /// Overridable for tests only.
    #[serde(default = "d_store_dir")]
    pub store_dir: PathBuf,
    /// Overridable for tests only.
    #[serde(default = "d_db_path")]
    pub db_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IoCfg {
    /// Bounded in-flight reads: keeps NVMe queue depth full.
    #[serde(default = "d_io_concurrency")]
    pub concurrency: usize,
    /// auto (uring if available) | uring | blocking.
    #[serde(default)]
    pub backend: IoBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IoBackend {
    #[default]
    Auto,
    Uring,
    Blocking,
}

impl Default for IoCfg {
    fn default() -> Self {
        Self { concurrency: d_io_concurrency(), backend: IoBackend::Auto }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyCfg {
    /// Loopback address nix talks to.
    pub listen: SocketAddr,
    #[serde(default = "d_proxy_priority")]
    pub priority: u32,

    /// Ceiling; actual chunk size adapts toward ~2s per chunk.
    #[serde(default = "d_chunk_max")]
    pub chunk_max: ByteSize,
    /// Ordered read-ahead bound.
    #[serde(default = "d_window_bytes")]
    pub window_bytes: ByteSize,
    /// Retention budget for replayed duplicate segments.
    #[serde(default = "d_dedup_budget")]
    pub dedup_budget_bytes: ByteSize,
    /// Ceiling; the governor finds the operating point.
    #[serde(default = "d_per_peer_connections")]
    pub per_peer_connections: usize,

    /// Cap on small mesh requests (manifest fetches; sync pulls get a generous multiple).
    #[serde(with = "humantime_serde", default = "d_narinfo_timeout")]
    pub narinfo_timeout: Duration,
    /// Give up when NO bytes arrive for this long (byte-progress liveness).
    #[serde(with = "humantime_serde", default = "d_stall_timeout")]
    pub stall_timeout: Duration,

    /// Give-up floor, off when 0. Also sets the small-transfer exemption together with the grace.
    #[serde(default = "d_zero_bytes")]
    pub min_bandwidth: ByteSize,
    #[serde(with = "humantime_serde", default = "d_min_bandwidth_grace")]
    pub min_bandwidth_grace: Duration,

    #[serde(default = "d_breaker_failures")]
    pub breaker_failures: u32,
    #[serde(with = "humantime_serde", default = "d_breaker_cooldown")]
    pub breaker_cooldown: Duration,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    pub url: String,
    /// Lower tiers are preferred; higher tiers are only consulted when no lower-tier peer holds
    /// the path.
    #[serde(default = "d_tier")]
    pub tier: u32,
    /// "auto" (goodput-tiered zstd level), "none", or "zstd:<level>".
    #[serde(default = "d_encoding")]
    pub encoding: String,
}

fn d_serve_priority() -> u32 { 30 }
fn d_proxy_priority() -> u32 { 30 }
fn d_max_zstd_level() -> i32 { 19 }
fn d_segment_bytes() -> ByteSize { ByteSize(4 << 20) }
fn d_store_dir() -> PathBuf { "/nix/store".into() }
fn d_db_path() -> PathBuf { "/nix/var/nix/db/db.sqlite".into() }
fn d_io_concurrency() -> usize { 64 }
fn d_chunk_max() -> ByteSize { ByteSize(16 << 20) }
fn d_window_bytes() -> ByteSize { ByteSize(256 << 20) }
fn d_dedup_budget() -> ByteSize { ByteSize(512 << 20) }
fn d_per_peer_connections() -> usize { 8 }
fn d_narinfo_timeout() -> Duration { Duration::from_secs(5) }
fn d_stall_timeout() -> Duration { Duration::from_secs(60) }
fn d_cache_dir() -> PathBuf { "/var/cache/narshare".into() }
fn d_zero_bytes() -> ByteSize { ByteSize(0) }
fn d_min_bandwidth_grace() -> Duration { Duration::from_secs(60) }
fn d_breaker_failures() -> u32 { 3 }
fn d_breaker_cooldown() -> Duration { Duration::from_secs(15) }
fn d_tier() -> u32 { 1 }
fn d_encoding() -> String { "auto".into() }

pub fn load(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> Result<()> {
    if cfg.name.is_empty() {
        bail!("`name` must be this node's mesh-wide name (peers reference it in [[peers]])");
    }
    if cfg.serve.is_none() && cfg.proxy.is_none() {
        bail!("config must define at least one of [serve] or [proxy]");
    }
    if cfg.proxy.is_some() && cfg.peers.is_empty() {
        bail!("[proxy] is configured but no [[peers]] are defined");
    }
    let mut names: Vec<&str> = cfg.peers.iter().map(|p| p.name.as_str()).collect();
    names.push(&cfg.name);
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        bail!("node and peer names must all be distinct (they are mesh-wide origin identifiers)");
    }
    if let Some(s) = &cfg.serve {
        // 0 would make the manifest builder loop forever (min(0) never advances).
        if s.segment_bytes.0 < 4096 {
            bail!("serve.segment_bytes must be at least 4096 (got {})", s.segment_bytes.0);
        }
    }
    if let Some(p) = &cfg.proxy {
        if p.breaker_failures == 0 {
            bail!("proxy.breaker_failures must be at least 1");
        }
    }
    for p in &cfg.peers {
        if !(p.encoding == "auto"
            || p.encoding == "none"
            || p.encoding
                .strip_prefix("zstd:")
                .is_some_and(|l| l.parse::<i32>().is_ok_and(|l| (1..=22).contains(&l))))
        {
            bail!("peer {:?}: invalid encoding {:?} (auto | none | zstd:<1..=22>)", p.name, p.encoding);
        }
        if !p.url.starts_with("http://") {
            if p.url.starts_with("https://") {
                bail!(
                    "peer {:?}: https urls are unsupported (narshare is built without TLS; \
                     peers are reached over the mesh, which owns transport privacy, and \
                     integrity comes from content addressing)",
                    p.name
                );
            }
            bail!("peer {:?}: url must be http://", p.name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example() {
        let cfg: Config = toml::from_str(
            r#"
            name = "me"
            [serve]
            listen = "127.0.0.1:15050"
            [proxy]
            listen = "127.0.0.1:15051"
            chunk_max = "16MiB"
            stall_timeout = "60s"
            min_bandwidth = "0"
            [cache]
            dir = "/tmp/narshare-cache"
            [[peers]]
            name = "a"
            url = "http://10.0.0.1:5050"
            encoding = "zstd:9"
            "#,
        )
        .unwrap();
        validate(&cfg).unwrap();
        let p = cfg.proxy.unwrap();
        assert_eq!(p.chunk_max.0, 16 << 20);
        assert_eq!(p.stall_timeout, Duration::from_secs(60));
        assert_eq!(p.min_bandwidth.0, 0);
        assert_eq!(cfg.serve.unwrap().priority, 30);
        assert_eq!(cfg.name, "me");
        assert_eq!(cfg.cache.dir, PathBuf::from("/tmp/narshare-cache"));
    }

    #[test]
    fn byte_sizes() {
        assert_eq!(parse_bytes("0"), Some(0));
        assert_eq!(parse_bytes("512"), Some(512));
        assert_eq!(parse_bytes("16MiB"), Some(16 << 20));
        assert_eq!(parse_bytes("1.5KiB"), Some(1536));
        assert_eq!(parse_bytes("2GiB"), Some(2 << 30));
        assert_eq!(parse_bytes("5MB"), None);
    }

    fn mk(pre: &str, proxy_extra: &str, peer: &str) -> String {
        format!(
            "name = \"me\"\n{pre}\n[proxy]\nlisten = \"127.0.0.1:1\"\n{proxy_extra}\n\
             [[peers]]\nname = \"a\"\nurl = \"http://x:1\"\n{peer}"
        )
    }

    #[test]
    fn trusted_public_keys_parse() {
        // Unset: defer to /etc/nix/nix.conf at startup.
        let cfg: Config = toml::from_str(&mk("", "", "")).unwrap();
        assert_eq!(cfg.trusted_public_keys, None);
        // Explicit list, and the explicit-empty "CA paths only" form.
        let cfg: Config =
            toml::from_str(&mk("trusted_public_keys = [\"k-1:AAAA\"]", "", "")).unwrap();
        assert_eq!(cfg.trusted_public_keys.as_deref(), Some(&["k-1:AAAA".to_owned()][..]));
        let cfg: Config = toml::from_str(&mk("trusted_public_keys = []", "", "")).unwrap();
        assert_eq!(cfg.trusted_public_keys.as_deref(), Some(&[][..]));
    }

    #[test]
    fn rejects_degenerate_proxy_knobs() {
        let cfg: Config = toml::from_str(&mk("", "", "")).unwrap();
        validate(&cfg).unwrap();
        let cfg: Config = toml::from_str(&mk("", "breaker_failures = 0", "")).unwrap();
        assert!(validate(&cfg).is_err());
        // https accepted at parse time would only fail at request time: no TLS is built in.
        let cfg: Config = toml::from_str(&mk("", "", "").replace("http://x:1", "https://x:1"))
            .unwrap();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn rejects_bad() {
        // missing node name
        assert!(toml::from_str::<Config>("[serve]\nlisten = \"127.0.0.1:1\"").is_err());
        // neither section
        let cfg: Config = toml::from_str("name = \"me\"").unwrap();
        assert!(validate(&cfg).is_err());
        // proxy without peers
        let cfg: Config =
            toml::from_str("name = \"me\"\n[proxy]\nlisten = \"127.0.0.1:1\"").unwrap();
        assert!(validate(&cfg).is_err());
        // name collision with a peer: origin identifiers must be distinct mesh-wide
        let cfg: Config = toml::from_str(&mk("", "", "").replace("\"a\"", "\"me\"")).unwrap();
        assert!(validate(&cfg).is_err());
        // unknown key
        assert!(toml::from_str::<Config>(
            "name = \"me\"\n[serve]\nlisten = \"127.0.0.1:1\"\nbogus = 1"
        )
        .is_err());
    }
}
