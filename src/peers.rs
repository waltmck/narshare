//! Peer client: NAR/manifest fetches and index-sync calls against other narshare nodes.
//!
//! Only hard errors trip the circuit breaker (connect refused/reset, 5xx, dead bodies). After
//! `breaker_failures` consecutive strikes a peer is skipped for `breaker_cooldown`, then probed
//! again. Breakers handle *dead*; MW weights (pool.rs) handle *slow*; the two are deliberately
//! separate. Lookup latency machinery is gone: narinfo answers come from the local mesh index
//! (index.rs), not from per-request fan-outs.

use crate::config;
use crate::index::proto;
use crate::manifest::Manifest;
use crate::nixbase32;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use prost::Message as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio_stream::StreamExt;
use tracing::{debug, warn};

/// Response-body ceilings: a peer's response must never make us allocate without bound.
/// Manifests are ~1.3 MB per 100 GB of content; sync responses are suffix-capped per origin.
const MANIFEST_CAP: usize = 256 << 20;
/// Compressed sync-response cap, and the bound on its decompressed form.
const SYNC_CAP: usize = 64 << 20;
const SYNC_RAW_CAP: usize = 256 << 20;
/// Sync round-trips move megabytes over possibly-thin links: a generous fixed budget.
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);
/// Slack over the requested length allowed for a compressed chunk body (zstd's worst-case
/// expansion plus framing is tiny; this is deliberately loose).
const WIRE_SLACK: usize = 64 << 10;

/// Read a response body with a hard cap, checking Content-Length first and bounding the stream.
/// Neither reqwest nor HTTP bounds this by default, so without a cap a response of any size would
/// be buffered in full.
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<Bytes> {
    if let Some(len) = resp.content_length() {
        if len > cap as u64 {
            bail!("response Content-Length {len} exceeds cap {cap}");
        }
    }
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading response body")?;
        if buf.len() + chunk.len() > cap {
            bail!("response body exceeds cap {cap}");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}

pub struct Peers {
    pub list: Vec<Peer>,
    client: reqwest::Client,
    /// Cap on small mesh requests (manifests); sync gets SYNC_TIMEOUT.
    pub cap: Duration,
    breaker_failures: u32,
    breaker_cooldown: Duration,
}

pub struct Peer {
    pub name: String,
    pub base: reqwest::Url,
    pub tier: u32,
    health: Mutex<Health>,
}

#[derive(Default)]
struct Health {
    strikes: u32,
    open_until: Option<Instant>,
}

impl Peer {
    /// Breaker gate. An elapsed cooldown lets requests through again (probing); a failed probe
    /// re-opens, a success resets.
    pub fn available(&self) -> bool {
        let h = self.health.lock().unwrap();
        h.open_until.is_none_or(|until| Instant::now() >= until)
    }

    fn open_until(&self) -> Option<Instant> {
        self.health.lock().unwrap().open_until
    }

    fn record_ok(&self) {
        let mut h = self.health.lock().unwrap();
        h.strikes = 0;
        h.open_until = None;
    }

    fn record_strike(&self, threshold: u32, cooldown: Duration, name: &str) {
        let mut h = self.health.lock().unwrap();
        h.strikes = h.strikes.saturating_add(1);
        if h.strikes >= threshold {
            h.open_until = Some(Instant::now() + cooldown);
            warn!(
                "peer {name}: breaker open for {cooldown:?} ({} strikes)",
                h.strikes
            );
        }
    }
}

/// One fetched chunk, with the timing breakdown that lets the requester classify the chunk's
/// bottleneck (fetch.rs observe_encoding): where did the service time go — the peer's disk, the
/// peer's CPU (queue + encode), the wire, or our own decode?
pub struct Chunk {
    /// Uncompressed NAR bytes.
    pub bytes: Bytes,
    /// Bytes as they traveled on the wire.
    pub wire: u64,
    /// Peer-reported disk-read time (zero when the peer predates the header).
    pub srv_read: Duration,
    /// Peer-reported encode-pool wait + encode time (zero when absent).
    pub srv_encode: Duration,
    /// Local decompression time (zero for raw bodies).
    pub decode: Duration,
}

fn micros_header(resp: &reqwest::Response, name: &str) -> Duration {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_micros)
        .unwrap_or_default()
}

impl Peers {
    pub fn new(
        peers: &[config::Peer],
        cap: Duration,
        breaker_failures: u32,
        breaker_cooldown: Duration,
        pool_idle: usize,
    ) -> Result<Self> {
        let list = peers
            .iter()
            .map(|p| {
                // A trailing slash makes Url::join treat the base as a directory.
                let base = reqwest::Url::parse(&format!("{}/", p.url.trim_end_matches('/')))
                    .with_context(|| format!("peer {:?}: bad url {:?}", p.name, p.url))?;
                Ok(Peer {
                    name: p.name.clone(),
                    base,
                    tier: p.tier,
                    health: Mutex::default(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(pool_idle)
            .connect_timeout(Duration::from_secs(3))
            .build()
            .context("building http client")?;
        Ok(Self { list, client, cap, breaker_failures, breaker_cooldown })
    }

    pub fn idx_of(&self, name: &str) -> Option<usize> {
        self.list.iter().position(|p| p.name == name)
    }

    /// One sync round-trip: POST our clock vector, get per-origin suffixes/snapshots back
    /// (zstd-compressed protobuf). Hard failures strike the breaker; success resets it.
    pub async fn sync_pull(
        &self,
        idx: usize,
        req: &proto::SyncRequest,
    ) -> Result<proto::SyncResponse> {
        let peer = &self.list[idx];
        let url = peer.base.join("narshare/v1/sync").context("bad sync url")?;
        let exchange = async {
            let resp = self
                .client
                .post(url)
                .body(req.encode_to_vec())
                .send()
                .await
                .with_context(|| format!("peer {}", peer.name))?;
            if !resp.status().is_success() {
                bail!("peer {}: sync HTTP {}", peer.name, resp.status());
            }
            let body = read_capped(resp, SYNC_CAP).await?;
            let raw = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                use std::io::Read;
                let mut dec = zstd::stream::read::Decoder::new(&body[..])?;
                let mut out = Vec::new();
                dec.by_ref().take(SYNC_RAW_CAP as u64 + 1).read_to_end(&mut out)?;
                if out.len() > SYNC_RAW_CAP {
                    bail!("sync response exceeds decompressed cap");
                }
                Ok(out)
            })
            .await
            .expect("decode task panicked")?;
            proto::SyncResponse::decode(&raw[..]).context("bad sync response proto")
        };
        match tokio::time::timeout(SYNC_TIMEOUT, exchange).await {
            Ok(Ok(resp)) => {
                peer.record_ok();
                Ok(resp)
            }
            Ok(Err(e)) => {
                self.strike(idx);
                Err(e)
            }
            Err(_) => {
                self.strike(idx);
                bail!("peer {}: sync exceeded {SYNC_TIMEOUT:?}", peer.name)
            }
        }
    }

    /// Fire-and-forget "I have news — pull from me."
    pub async fn hint(&self, idx: usize, from: &str) {
        let peer = &self.list[idx];
        let Ok(url) = peer.base.join("narshare/v1/sync-hint") else { return };
        let body = proto::SyncHint { from: from.to_owned() }.encode_to_vec();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            self.client.post(url).body(body).send(),
        )
        .await;
    }

    pub fn strike(&self, idx: usize) {
        let peer = &self.list[idx];
        peer.record_strike(self.breaker_failures, self.breaker_cooldown, &peer.name);
    }

    /// When the soonest currently-open breaker among `ids` will recover, or None if any of them is
    /// already available. Lets a stalled transfer re-poll exactly when a peer comes back rather
    /// than coasting to the full stall_timeout.
    pub fn soonest_recovery(&self, ids: &[usize]) -> Option<Instant> {
        let now = Instant::now();
        let mut soonest: Option<Instant> = None;
        for &i in ids {
            match self.list[i].open_until() {
                None => return None,
                Some(t) if t <= now => return None,
                Some(t) => soonest = Some(soonest.map_or(t, |s| s.min(t))),
            }
        }
        soonest
    }

    /// Fetch a peer's segment manifest for a narhash. Absence — 404, an old peer, a build error,
    /// even a 5xx — is NOT a transfer failure: the caller degrades to plain striping, so the
    /// manifest endpoint must never strike the breaker (a single unmanifestable path, e.g. one
    /// with a non-UTF-8 filename, would otherwise cool a healthy peer down for every path). Only
    /// a genuine transport failure (connect refused) strikes, and that via the shared client.
    pub async fn fetch_manifest(&self, peer_idx: usize, nar_hash: &[u8; 32]) -> Option<Manifest> {
        let peer = &self.list[peer_idx];
        let url = peer
            .base
            .join(&format!(
                "narshare/v1/manifest/{}",
                nixbase32::encode(nar_hash)
            ))
            .ok()?;
        // The cap bounds the WHOLE exchange, body included: this runs BEFORE a transfer's stall
        // watchdog exists, so a peer dribbling a manifest body forever must cost at most the cap
        // — plain striping is always available as the degradation.
        let exchange = async {
            match self.client.get(url).send().await {
                Ok(r) if r.status().is_success() => {
                    let body = read_capped(r, MANIFEST_CAP).await.ok()?;
                    match serde_json::from_slice::<Manifest>(&body) {
                        Ok(m) if m.version == crate::manifest::VERSION => Some(m),
                        Ok(m) => {
                            debug!(
                                "peer {}: manifest version {} unsupported",
                                peer.name, m.version
                            );
                            None
                        }
                        Err(e) => {
                            debug!("peer {}: bad manifest: {e}", peer.name);
                            None
                        }
                    }
                }
                Ok(_) => None, // 404/5xx: absence, not a strike.
                Err(e) => {
                    if e.is_connect() {
                        self.strike(peer_idx);
                    }
                    None
                }
            }
        };
        tokio::time::timeout(self.cap, exchange).await.ok().flatten()
    }

    /// Fetch one chunk [start, end) of a NAR from a specific peer, optionally zstd-framed on the
    /// wire (the narshare chunk-encoding extension: request `x-narshare-accept: zstd:<level>`,
    /// response `x-narshare-encoding: zstd`). Returns the UNCOMPRESSED bytes plus the timing
    /// breakdown the adaptive-encoding controller consumes. Hard failures strike the breaker;
    /// the caller records pool/rate outcomes.
    pub async fn fetch_range(
        &self,
        peer_idx: usize,
        nar_url: &str,
        start: u64,
        end: u64,
        zstd_level: Option<i32>,
    ) -> Result<Chunk> {
        let peer = &self.list[peer_idx];
        let url = peer.base.join(nar_url).context("bad NAR url from peer")?;
        let mut req = self.client.get(url).header(
            reqwest::header::RANGE,
            format!("bytes={}-{}", start, end - 1),
        );
        if let Some(level) = zstd_level {
            req = req.header("x-narshare-accept", format!("zstd:{level}"));
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                if e.is_connect() {
                    self.strike(peer_idx);
                }
                return Err(e).with_context(|| format!("peer {}", peer.name));
            }
        };
        if resp.status().is_server_error() {
            self.strike(peer_idx);
            bail!("peer {}: HTTP {}", peer.name, resp.status());
        }
        if resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            bail!("peer {}: expected 206, got {}", peer.name, resp.status());
        }
        let encoded = resp
            .headers()
            .get("x-narshare-encoding")
            .is_some_and(|v| v.as_bytes() == b"zstd");
        let srv_read = micros_header(&resp, "x-narshare-read-us");
        let srv_encode = micros_header(&resp, "x-narshare-encode-us");
        let want = (end - start) as usize;
        // Cap the WIRE body: raw must be exactly `want`; a compressed frame must be no larger than
        // `want + slack` (it should be smaller). This bounds the read before decompression.
        let wire_cap = if encoded { want + WIRE_SLACK } else { want };
        let body = match read_capped(resp, wire_cap).await {
            Ok(b) => b,
            Err(e) => {
                // A body that dies mid-read (reset) or overruns its cap is a hard failure,
                // the same class as a refused connect.
                self.strike(peer_idx);
                return Err(e).with_context(|| format!("peer {}", peer.name));
            }
        };
        let wire = body.len() as u64;
        let (bytes, decode) = if encoded {
            // Bound the DECOMPRESSED output to `want`: the decoder must stop before a small frame
            // can expand into an unbounded allocation. Read at most want+1 bytes; a frame that
            // produces more is rejected below by the exact-length check.
            let name = peer.name.clone();
            let (raw, decode) = tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Duration)> {
                use std::io::Read;
                let t0 = Instant::now();
                let mut dec = zstd::stream::read::Decoder::new(&body[..])
                    .with_context(|| format!("peer {name}: bad zstd frame"))?;
                let mut out = Vec::with_capacity(want);
                dec.by_ref()
                    .take(want as u64 + 1)
                    .read_to_end(&mut out)
                    .with_context(|| format!("peer {name}: bad zstd frame"))?;
                Ok((out, t0.elapsed()))
            })
            .await
            .expect("decode task panicked")?;
            (Bytes::from(raw), decode)
        } else {
            (body, Duration::ZERO)
        };
        if bytes.len() != want {
            bail!(
                "peer {}: chunk length {} != requested {}",
                peer.name,
                bytes.len(),
                want
            );
        }
        peer.record_ok(); // a delivered chunk closes any half-open breaker
        Ok(Chunk { bytes, wire, srv_read, srv_encode, decode })
    }
}
