//! Peer client: narinfo lookups and NAR fetches against other narshare serve listeners, with the
//! M3 resilience semantics:
//!
//!   * **Hedge deadlines adapt to observed latency** (TCP-RTO-style: srtt + 4·rttvar, clamped to
//!     [100ms, narinfo_timeout]). A peer with no samples yet gets the full cap — generous first
//!     contact, tightening as evidence arrives.
//!   * **Missing the hedge deadline is "late", never "failed"**: the responder stops waiting, but
//!     the lookup runs on to the cap and a late positive still lands (holder map, negative-cache
//!     clearing) via the drainer.
//!   * **Only hard errors trip the circuit breaker** (connect refused/reset, 5xx, malformed
//!     narinfo). After `breaker_failures` consecutive strikes a peer is skipped for
//!     `breaker_cooldown`, then probed again. Breakers handle *dead*; adaptive deadlines handle
//!     *slow*; the two are deliberately separate.

use crate::config::{self, ProxyCfg};
use crate::manifest::Manifest;
use crate::narinfo::{parse_narinfo, RemoteNarinfo};
use crate::nixbase32;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio_stream::StreamExt;
use tracing::{debug, warn};

pub(crate) const DEADLINE_FLOOR: Duration = Duration::from_millis(100);
/// Response-body ceilings: a peer's response must never make the proxy allocate without bound.
/// narinfos are ~1 KB; manifests are ~1.3 MB per 100 GB of content — both capped generously.
const NARINFO_CAP: usize = 1 << 20;
const MANIFEST_CAP: usize = 256 << 20;
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
    /// narinfo_timeout: the hard cap on any lookup, and the deadline before latency is learned.
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
    /// Smoothed narinfo round-trip stats, milliseconds (RFC 6298 shape).
    srtt: f64,
    rttvar: f64,
    samples: u32,
    strikes: u32,
    open_until: Option<Instant>,
}

impl Peer {
    /// Hedge deadline for this peer: how long the responder should wait for it.
    pub fn deadline(&self, cap: Duration) -> Duration {
        let h = self.health.lock().unwrap();
        if h.samples == 0 {
            return cap;
        }
        // cap ≥ floor is enforced by config validation; max() keeps a hand-built cap from
        // panicking the clamp.
        Duration::from_millis((h.srtt + 4.0 * h.rttvar) as u64)
            .clamp(DEADLINE_FLOOR, cap.max(DEADLINE_FLOOR))
    }

    /// Breaker gate. An elapsed cooldown lets requests through again (probing); a failed probe
    /// re-opens, a success resets.
    pub fn available(&self) -> bool {
        let h = self.health.lock().unwrap();
        h.open_until.is_none_or(|until| Instant::now() >= until)
    }

    fn open_until(&self) -> Option<Instant> {
        self.health.lock().unwrap().open_until
    }

    fn record_ok(&self, rtt: Duration) {
        let mut h = self.health.lock().unwrap();
        h.strikes = 0;
        h.open_until = None;
        let ms = rtt.as_secs_f64() * 1000.0;
        if h.samples == 0 {
            h.srtt = ms;
            h.rttvar = ms / 2.0;
        } else {
            let err = (ms - h.srtt).abs();
            h.rttvar = 0.75 * h.rttvar + 0.25 * err;
            h.srtt = 0.875 * h.srtt + 0.125 * ms;
        }
        h.samples = h.samples.saturating_add(1);
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

/// One peer's answer to a narinfo lookup.
pub enum Answer {
    Found(RemoteNarinfo),
    /// Definitive 404 — the peer does not have the path.
    NotFound,
    /// Hard error (struck) or cap timeout (not struck): no information.
    Unknown,
}

impl Peers {
    pub fn new(peers: &[config::Peer], proxy: &ProxyCfg) -> Result<Self> {
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
            .pool_max_idle_per_host(proxy.per_peer_connections)
            .connect_timeout(Duration::from_secs(3))
            .build()
            .context("building http client")?;
        Ok(Self {
            list,
            client,
            cap: proxy.narinfo_timeout,
            breaker_failures: proxy.breaker_failures,
            breaker_cooldown: proxy.breaker_cooldown,
        })
    }

    /// Look up one narinfo on one peer, recording health. Runs to the cap regardless of hedge
    /// deadlines — the caller decides how long to *wait*, not how long we *try*. The cap bounds
    /// the WHOLE exchange, body included: a peer that returns headers and then dribbles the body
    /// forever must not pin the lookup task (and its drainer) past the cap.
    pub async fn lookup(&self, idx: usize, hash_part: &str) -> Answer {
        let peer = &self.list[idx];
        let Ok(url) = peer.base.join(&format!("{hash_part}.narinfo")) else {
            return Answer::Unknown;
        };
        let started = Instant::now();
        let exchange = async {
            match self.client.get(url).send().await {
                Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                    peer.record_ok(started.elapsed());
                    Answer::NotFound
                }
                Ok(r) if r.status().is_success() => match read_capped(r, NARINFO_CAP).await {
                    Ok(body) => match parse_narinfo(&String::from_utf8_lossy(&body)) {
                        Ok(info) => {
                            peer.record_ok(started.elapsed());
                            Answer::Found(info)
                        }
                        Err(e) => {
                            warn!("peer {}: unparseable narinfo: {e:#}", peer.name);
                            self.strike(idx);
                            Answer::Unknown
                        }
                    },
                    Err(e) => {
                        debug!("peer {}: narinfo body error: {e:#}", peer.name);
                        self.strike(idx);
                        Answer::Unknown
                    }
                },
                Ok(r) => {
                    debug!("peer {}: narinfo HTTP {}", peer.name, r.status());
                    self.strike(idx);
                    Answer::Unknown
                }
                Err(e) => {
                    debug!("peer {}: narinfo error: {e}", peer.name);
                    self.strike(idx);
                    Answer::Unknown
                }
            }
        };
        match tokio::time::timeout(self.cap, exchange).await {
            Ok(answer) => answer,
            Err(_) => {
                // Cap timeout: "late", not "failed" — no strike, no sample.
                debug!("peer {}: narinfo exceeded cap", peer.name);
                Answer::Unknown
            }
        }
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

    /// HEAD-probe a peer for a NAR by hash (proxy-restart recovery: nix caches narinfos
    /// client-side and may request a NAR we never resolved). Returns its size when present.
    pub async fn head_nar(&self, peer_idx: usize, nar_url: &str) -> Option<u64> {
        let peer = &self.list[peer_idx];
        let url = peer.base.join(nar_url).ok()?;
        let resp = tokio::time::timeout(self.cap, self.client.head(url).send()).await;
        match resp {
            Ok(Ok(r)) if r.status().is_success() => r
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            Ok(Ok(r)) => {
                if r.status().is_server_error() {
                    self.strike(peer_idx);
                }
                None
            }
            Ok(Err(e)) => {
                if e.is_connect() {
                    self.strike(peer_idx);
                }
                None
            }
            Err(_) => None,
        }
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
    /// response `x-narshare-encoding: zstd`). Returns the UNCOMPRESSED bytes plus the wire size.
    /// Hard failures strike the breaker; the caller records pool/rate outcomes.
    pub async fn fetch_range(
        &self,
        peer_idx: usize,
        nar_url: &str,
        start: u64,
        end: u64,
        zstd_level: Option<i32>,
    ) -> Result<(Bytes, u64)> {
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
        let bytes = if encoded {
            // Bound the DECOMPRESSED output to `want`: the decoder must stop before a small frame
            // can expand into an unbounded allocation. Read at most want+1 bytes; a frame that
            // produces more is rejected below by the exact-length check.
            let name = peer.name.clone();
            let raw = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                use std::io::Read;
                let mut dec = zstd::stream::read::Decoder::new(&body[..])
                    .with_context(|| format!("peer {name}: bad zstd frame"))?;
                let mut out = Vec::with_capacity(want);
                dec.by_ref()
                    .take(want as u64 + 1)
                    .read_to_end(&mut out)
                    .with_context(|| format!("peer {name}: bad zstd frame"))?;
                Ok(out)
            })
            .await
            .expect("decode task panicked")?;
            Bytes::from(raw)
        } else {
            body
        };
        if bytes.len() != want {
            bail!(
                "peer {}: chunk length {} != requested {}",
                peer.name,
                bytes.len(),
                want
            );
        }
        Ok((bytes, wire))
    }
}
