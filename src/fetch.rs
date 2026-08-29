//! The striped NAR fetch engine: one transfer = one ordered byte stream to the local nix,
//! reconstructed from an execution *plan* over the NAR's byte layout.
//!
//! With a manifest (M5), the plan knows the tree: framing literals are synthesized locally and
//! never fetched; file segments are fetched once per distinct blake3 across all holding peers and
//! *replayed* at later occurrences under a bounded retention budget (dedup.rs); every fetched
//! segment is blake3-verified before emission, giving per-peer corruption attribution. Without a
//! manifest the plan degrades to one unverified span — exactly the M4 behavior.
//!
//! Engine shape adapted from propnix pin/engine.rs (same author): a queue, not a retry ladder
//! (failures requeue at the lowest offset and re-consult the MW pool); liveness by byte progress,
//! not attempt counts; the window IS the queue. Chunk sizes target ~2s from per-peer goodput
//! EWMAs; per-peer stream counts come from the hill-climbing governor; the wire zstd level is
//! goodput-tiered when `encoding = "auto"`.

use crate::config::{Peer as PeerCfg, ProxyCfg};
use crate::dedup;
use crate::governor::{Governor, Pressure};
use crate::manifest::{self, Manifest, SpanKind};
use crate::narinfo::RemoteNarinfo;
use crate::nixbase32;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Smallest chunk worth a request; also the floor of the adaptive size.
const CHUNK_MIN: u64 = 256 * 1024;
/// Chunk size before a peer has any goodput samples.
const CHUNK_SEED: u64 = 4 << 20;
/// Target duration of one chunk — the constant that makes MW feedback arrive at a fixed *rate*
/// regardless of link speed.
const CHUNK_TARGET_SECS: f64 = 2.0;
/// Governor epoch length.
const EPOCH: Duration = Duration::from_secs(1);
/// How long a min_bandwidth abort keeps refusing oversized paths.
const ROAMING_EPOCH: Duration = Duration::from_secs(600);
/// Transfers below this skip the manifest roundtrip — not worth it.
const MANIFEST_MIN: u64 = 4 << 20;
/// A segment failing verification is refetched at most this many times before the transfer
/// aborts (an incorrect manifest, or peers that persistently return the wrong bytes).
const SEG_RETRIES: u32 = 3;

#[derive(Default)]
pub struct Stats {
    /// Uncompressed NAR bytes fetched from peers.
    pub remote_bytes: AtomicU64,
    /// Bytes as they traveled on the wire (compressed).
    pub wire_bytes: AtomicU64,
    /// Bytes emitted by replaying an already-fetched duplicate segment.
    pub replayed_bytes: AtomicU64,
    /// Framing bytes synthesized locally from manifests (never fetched).
    pub lit_bytes: AtomicU64,
    /// Chunk-level failures that were requeued.
    pub requeues: AtomicU64,
}

/// Per-peer dynamic stream budget, sized by the governor.
pub struct PeerLimit {
    state: Mutex<LimState>,
    governor: Mutex<Governor>,
    epoch: Mutex<Epoch>,
}

struct LimState {
    inflight: usize,
    limit: usize,
}

struct Epoch {
    started: Instant,
    bytes: u64,
    ok: u64,
    err: u64,
    blocked: bool,
}

impl PeerLimit {
    fn new(max: usize) -> Self {
        let start = 2.min(max);
        Self {
            state: Mutex::new(LimState { inflight: 0, limit: start }),
            governor: Mutex::new(Governor::new(start, 1, max)),
            epoch: Mutex::new(Epoch {
                started: Instant::now(),
                bytes: 0,
                ok: 0,
                err: 0,
                blocked: false,
            }),
        }
    }

    fn try_acquire(&self) -> bool {
        let mut s = self.state.lock().unwrap();
        if s.inflight < s.limit {
            s.inflight += 1;
            true
        } else {
            false
        }
    }

    fn release(&self) {
        self.state.lock().unwrap().inflight -= 1;
    }

    fn has_idle_capacity(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.inflight < s.limit
    }

    /// Fold a completion into the current epoch; close the epoch when it has run long enough.
    fn observe(&self, ok: bool, bytes: u64) {
        let mut e = self.epoch.lock().unwrap();
        if ok {
            e.ok += 1;
            e.bytes += bytes;
        } else {
            e.err += 1;
        }
        if e.started.elapsed() >= EPOCH {
            let secs = e.started.elapsed().as_secs_f64();
            let throughput = e.bytes as f64 / secs;
            let pressure =
                if e.blocked && e.bytes == 0 { Pressure::ConsumerBound } else { Pressure::Network };
            let (ok_n, err_n) = (e.ok, e.err);
            *e = Epoch { started: Instant::now(), bytes: 0, ok: 0, err: 0, blocked: false };
            drop(e);
            let new_limit =
                self.governor.lock().unwrap().observe(throughput, pressure, ok_n, err_n);
            self.state.lock().unwrap().limit = new_limit;
        }
    }

    fn note_blocked(&self) {
        self.epoch.lock().unwrap().blocked = true;
    }
}

/// The `encoding = "auto"` level controller: CLOSED-LOOP, per completed chunk. The chunk's
/// service time decomposes into enc (the peer's encode-pool wait + encode, reported in a
/// response header), read (the peer's disk time, likewise reported), our own decode, and
/// transfer (the remainder: wire + RTT). The controller compares stages and steps the level:
/// encode-dominated → shed CPU fast; peer-disk-dominated → hold (the level can neither help nor
/// hurt); wire-dominated with encode slack → buy ratio with the idle CPU. Chunk frames are
/// independent and self-describing, so a level switch between chunks is FREE — there is
/// deliberately no hysteresis, and flapping near equilibrium is harmless. No zstd-internal
/// machinery (--adapt, multithreading) is involved anywhere.
const ENC_SEED: i32 = 3;
const ENC_MAX: i32 = 19;
/// Shedding CPU is urgent (an encode-bound chunk delays real bytes): step down faster…
const ENC_STEP_DOWN: i32 = 2;
/// …climb by 1 near the knee, and faster while compression has lots of slack.
const ENC_STEP_UP: i32 = 1;
const ENC_STEP_UP_FAST: i32 = 3;
/// Climb while enc/transfer is below this; the knee sits where they are comparable.
const ENC_CLIMB_BELOW: f64 = 0.5;
/// "Lots of slack": enc/transfer below this takes the fast step.
const ENC_SLACK: f64 = 0.1;
/// Open-loop fallback for peers that predate the timing headers: goodput-tiered
/// (tier's upper rate bound in B/s, zstd level) — spend CPU where the link is thin.
const ENC_TIERS: &[(f64, i32)] = &[(4e6, 19), (4e7, 9), (4e8, 3), (f64::INFINITY, 1)];

/// Per-peer network-adaptation state.
struct PeerNet {
    /// Per-stream goodput EWMA, bytes/sec (0 = no sample yet).
    rate: f64,
    /// Current auto-encoding level (the closed-loop controller's state).
    level: i32,
}

/// Everything the striped fetches share across transfers.
pub struct FetchCtx {
    pub pool: crate::pool::HostPool,
    limits: Vec<PeerLimit>,
    net: Vec<Mutex<PeerNet>>,
    encodings: Vec<String>,
    pub stats: Stats,
    roaming_until: Mutex<Option<Instant>>,
    cfg_chunk_max: u64,
    cfg_window: u64,
    cfg_stall: Duration,
    cfg_min_bw: u64,
    cfg_grace: Duration,
    cfg_dedup_budget: u64,
}

impl FetchCtx {
    pub fn new(peer_cfgs: &[PeerCfg], cfg: &ProxyCfg) -> Self {
        let n = peer_cfgs.len().max(1);
        Self {
            pool: crate::pool::HostPool::new(n),
            limits: (0..n).map(|_| PeerLimit::new(cfg.per_peer_connections.max(1))).collect(),
            net: (0..n)
                .map(|_| Mutex::new(PeerNet { rate: 0.0, level: ENC_SEED }))
                .collect(),
            encodings: peer_cfgs.iter().map(|p| p.encoding.clone()).collect(),
            stats: Stats::default(),
            roaming_until: Mutex::new(None),
            cfg_chunk_max: cfg.chunk_max.0.max(CHUNK_MIN),
            cfg_window: cfg.window_bytes.0.max(CHUNK_MIN * 4),
            cfg_stall: cfg.stall_timeout,
            cfg_min_bw: cfg.min_bandwidth.0,
            cfg_grace: cfg.min_bandwidth_grace,
            cfg_dedup_budget: cfg.dedup_budget_bytes.0,
        }
    }

    fn rate_of(&self, peer: usize) -> f64 {
        self.net[peer].lock().unwrap().rate
    }

    #[cfg(test)]
    fn set_rate(&self, peer: usize, r: f64) {
        self.net[peer].lock().unwrap().rate = r;
    }

    fn record_rate(&self, peer: usize, bytes: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0005 {
            return;
        }
        let r = bytes as f64 / secs;
        let mut net = self.net[peer].lock().unwrap();
        net.rate = if net.rate == 0.0 { r } else { 0.7 * net.rate + 0.3 * r };
    }

    fn chunk_size(&self, peer: usize) -> u64 {
        let r = self.rate_of(peer);
        if r <= 0.0 {
            return CHUNK_SEED.min(self.cfg_chunk_max);
        }
        ((r * CHUNK_TARGET_SECS) as u64).clamp(CHUNK_MIN, self.cfg_chunk_max)
    }

    /// Wire encoding for a chunk from this peer: config override, or the closed-loop
    /// controller's current level when "auto". A manual override pins what is REQUESTED; the
    /// serving peer still caps it (max_zstd_level).
    fn zstd_level(&self, peer: usize) -> Option<i32> {
        match self.encodings.get(peer).map(String::as_str) {
            Some("none") => None,
            Some(enc) if enc.starts_with("zstd:") => enc[5..].parse().ok(),
            _ => Some(self.net[peer].lock().unwrap().level),
        }
    }

    /// Fold one completed chunk into the auto-encoding controller (no-op for pinned encodings).
    fn observe_encoding(&self, peer: usize, elapsed: Duration, c: &crate::peers::Chunk) {
        match self.encodings.get(peer).map(String::as_str) {
            Some("none") => return,
            Some(enc) if enc.starts_with("zstd:") => return,
            _ => {}
        }
        let mut net = self.net[peer].lock().unwrap();
        if c.srv_read.is_zero() && c.srv_encode.is_zero() {
            // Peer predates the timing headers: open-loop goodput ladder.
            if net.rate > 0.0 {
                net.level = ENC_TIERS.iter().find(|&&(t, _)| net.rate < t).unwrap().1;
            }
            return;
        }
        let enc = c.srv_encode.as_secs_f64();
        let read = c.srv_read.as_secs_f64();
        let decode = c.decode.as_secs_f64();
        // Wire + RTT: whatever the peer's disk/CPU and our decode don't account for.
        let transfer = (elapsed.as_secs_f64() - enc - read - decode).max(1e-4);
        if enc > transfer {
            // The peer's CPU (or its encode queue) is the bottleneck: shed load fast.
            net.level = (net.level - ENC_STEP_DOWN).max(1);
        } else if read > transfer {
            // The peer's disk is the bottleneck: the level can neither help nor hurt. Hold.
        } else if enc < transfer * ENC_CLIMB_BELOW && decode < transfer {
            // The wire is the bottleneck and compression has slack: buy ratio with idle CPU.
            let step = if enc < transfer * ENC_SLACK { ENC_STEP_UP_FAST } else { ENC_STEP_UP };
            net.level = (net.level + step).min(ENC_MAX);
        }
        // Otherwise: near the knee — hold.
    }

    /// Per-chunk soft deadline: generous multiple of the expected duration, so one hung stream
    /// requeues without killing the transfer (the global stall watchdog remains authoritative).
    fn chunk_deadline(&self, peer: usize, len: u64) -> Duration {
        let r = self.rate_of(peer).max(64.0 * 1024.0);
        Duration::from_secs_f64((8.0 * len as f64 / r).clamp(10.0, 300.0))
    }

    pub fn set_roaming(&self) {
        *self.roaming_until.lock().unwrap() = Some(Instant::now() + ROAMING_EPOCH);
    }

    /// While a roaming epoch is active, paths bigger than the floor×grace bound are refused at
    /// lookup time — exactly the ones a `min_bandwidth` abort would forfeit anyway.
    pub fn refuses_while_roaming(&self, nar_size: u64) -> bool {
        if self.cfg_min_bw == 0 {
            return false;
        }
        let active =
            self.roaming_until.lock().unwrap().is_some_and(|until| Instant::now() < until);
        active && nar_size > self.threshold_bytes()
    }

    fn threshold_bytes(&self) -> u64 {
        (self.cfg_min_bw as f64 * self.cfg_grace.as_secs_f64()) as u64
    }
}

// ------------------------------------------------------------------------------------------
// The execution plan
// ------------------------------------------------------------------------------------------

enum SpanExec {
    /// Framing bytes synthesized locally.
    Lit { lit_off: usize, len: u64 },
    /// Bytes fetched from peers; verified per-segment when a manifest hash is known.
    Fetch { len: u64, verify: Option<[u8; 32]>, retain: Option<(usize, usize)> },
    /// A later occurrence of a retained segment.
    Replay { unique: usize, len: u64 },
}

struct Plan {
    /// (nar_off, span), contiguous and in order over [start, end).
    spans: Vec<(u64, SpanExec)>,
    lits: Bytes,
    /// Fetchable NAR ranges (sorted, disjoint) — the chunker's carving ground.
    ranges: Vec<(u64, u64)>,
}

fn fallback_plan(start: u64, end: u64) -> Plan {
    Plan {
        spans: vec![(start, SpanExec::Fetch { len: end - start, verify: None, retain: None })],
        lits: Bytes::new(),
        ranges: vec![(start, end - start)],
    }
}

/// Turn a manifest into an execution plan: literals local, distinct segments fetched once,
/// duplicates replayed under the retention budget. `window` bounds the largest verifiable span.
fn manifest_plan(m: &Manifest, info: &RemoteNarinfo, budget: u64, window: u64) -> anyhow::Result<Plan> {
    if m.nar_hash != format!("sha256:{}", nixbase32::encode(&info.nar_hash)) {
        anyhow::bail!("manifest narhash disagrees with narinfo");
    }
    let layout = manifest::synth_layout(m)?;
    if layout.nar_size != info.nar_size {
        anyhow::bail!("manifest NarSize {} != narinfo {}", layout.nar_size, info.nar_size);
    }

    // Dedup plan over the segment occurrences, in NAR order. Two guards on the peer-supplied manifest:
    //   * No span may exceed the fetch window, or it could never be fully buffered for
    //     verification and every transfer would stall out (data-path #2).
    //   * A given segment hash must have ONE length across all its occurrences, or replay would
    //     emit the wrong number of bytes and desync the stream past the NarHash gate (data-path
    //     #1). Reject rather than fall back — a manifest this inconsistent cannot be relied on.
    let mut keys = Vec::new();
    let mut sizes = Vec::new();
    let mut len_of: HashMap<[u8; 32], u64> = HashMap::new();
    for span in &layout.spans {
        if let SpanKind::Segment { hash } = &span.kind {
            if span.len > window {
                anyhow::bail!("manifest segment ({} B) exceeds window ({} B)", span.len, window);
            }
            if let Some(&prev) = len_of.get(hash) {
                if prev != span.len {
                    anyhow::bail!("manifest reuses a segment hash with two different lengths");
                }
            } else {
                len_of.insert(*hash, span.len);
            }
            keys.push(*hash);
            sizes.push(span.len);
        }
    }
    let steps = dedup::plan(&keys, &sizes, budget);

    let mut spans = Vec::with_capacity(layout.spans.len());
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut seg_i = 0;
    for span in &layout.spans {
        match &span.kind {
            SpanKind::Lit { lit_off } => {
                spans.push((span.nar_off, SpanExec::Lit { lit_off: *lit_off, len: span.len }))
            }
            SpanKind::Segment { hash } => {
                let step = steps[seg_i];
                seg_i += 1;
                match step {
                    dedup::Step::Fetch { unique, retain_for } => {
                        spans.push((
                            span.nar_off,
                            SpanExec::Fetch {
                                len: span.len,
                                verify: Some(*hash),
                                retain: (retain_for > 0).then_some((unique, retain_for)),
                            },
                        ));
                        // Coalesce adjacent fetch ranges.
                        match ranges.last_mut() {
                            Some((o, l)) if *o + *l == span.nar_off => *l += span.len,
                            _ => ranges.push((span.nar_off, span.len)),
                        }
                    }
                    dedup::Step::Cached { unique } => {
                        spans.push((span.nar_off, SpanExec::Replay { unique, len: span.len }))
                    }
                }
            }
        }
    }
    Ok(Plan { spans, lits: layout.lits, ranges })
}

// ------------------------------------------------------------------------------------------
// The engine
// ------------------------------------------------------------------------------------------

struct Done {
    off: u64,
    len: u64,
    peer: usize,
    elapsed: Duration,
    result: anyhow::Result<crate::peers::Chunk>,
}

/// RAII stream slot: released on drop, so a worker aborted mid-fetch (transfer abort, client
/// disconnect) cannot leak budget from the GLOBAL per-peer limit.
struct Slot {
    st: Arc<crate::proxy::ProxyState>,
    peer: usize,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.st.fetch.limits[self.peer].release();
    }
}

enum Pump {
    NeedData,
    Finished,
    Refetch(u64, u64),
    Abort(String),
}

/// Emission state: walks the plan in order, consuming buffered fetched bytes, synthesizing
/// literals, verifying + retaining segments, replaying duplicates, hashing the whole stream.
struct Emitter {
    spans: Vec<(u64, SpanExec)>,
    lits: Bytes,
    span_i: usize,
    /// Bytes of the CURRENT streaming (unverified Fetch) span already emitted.
    span_emitted: u64,
    emit_pos: u64,
    end: u64,
    full: bool,
    nar_hash: [u8; 32],
    hasher: Sha256,
    buffered: BTreeMap<u64, Bytes>,
    held: HashMap<usize, (Bytes, usize)>,
    retries: HashMap<u64, u32>,
}

impl Emitter {
    /// Push plan progress as far as the buffered data allows, sending to `out`.
    /// Ok(Pump::NeedData) means "no more progress until more chunks land".
    async fn pump(
        &mut self,
        out: &mpsc::Sender<std::io::Result<Bytes>>,
        stats: &Stats,
    ) -> Result<Pump, ()> {
        loop {
            if self.span_i >= self.spans.len() {
                return Ok(Pump::Finished);
            }
            let (off, span) = &self.spans[self.span_i];
            let off = *off;
            match span {
                SpanExec::Lit { lit_off, len } => {
                    let b = self.lits.slice(*lit_off..*lit_off + *len as usize);
                    stats.lit_bytes.fetch_add(*len, Ordering::Relaxed);
                    self.emit(out, b).await?;
                    self.span_i += 1;
                }
                SpanExec::Replay { unique, len } => {
                    let unique = *unique;
                    let len = *len;
                    let (bytes, remaining) = {
                        let Some(entry) = self.held.get_mut(&unique) else {
                            return Ok(Pump::Abort("replay before retention (plan bug)".into()));
                        };
                        entry.1 -= 1;
                        (entry.0.clone(), entry.1)
                    };
                    // Defence in depth: the retained bytes must be exactly this span's length, or
                    // emitting them would desync emit_pos from the layout and slip past the final
                    // NarHash gate. manifest_plan already rejects same-hash/different-length
                    // manifests, so this can only fire on an internal bug.
                    if bytes.len() as u64 != len {
                        return Ok(Pump::Abort(format!(
                            "replay length {} != span length {len}",
                            bytes.len()
                        )));
                    }
                    if remaining == 0 {
                        self.held.remove(&unique);
                    }
                    stats.replayed_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    self.emit(out, bytes).await?;
                    self.span_i += 1;
                }
                SpanExec::Fetch { len, verify: None, .. } => {
                    // Streaming span (no per-segment hash): emit any contiguous prefix.
                    let len = *len;
                    while self.span_emitted < len {
                        let want = len - self.span_emitted;
                        match take_prefix(&mut self.buffered, self.emit_pos, want) {
                            Some(b) => {
                                self.span_emitted += b.len() as u64;
                                self.emit(out, b).await?;
                            }
                            None => return Ok(Pump::NeedData),
                        }
                    }
                    self.span_emitted = 0;
                    self.span_i += 1;
                }
                SpanExec::Fetch { len, verify: Some(hash), retain } => {
                    let (len, hash, retain) = (*len, *hash, *retain);
                    let Some(slices) = take_span(&mut self.buffered, off, off + len) else {
                        return Ok(Pump::NeedData);
                    };
                    let mut h = blake3::Hasher::new();
                    for b in &slices {
                        h.update(b);
                    }
                    if h.finalize().as_bytes() != &hash {
                        let n = self.retries.entry(off).or_insert(0);
                        *n += 1;
                        if *n > SEG_RETRIES {
                            return Ok(Pump::Abort(format!(
                                "segment @{off} failed verification {SEG_RETRIES} times"
                            )));
                        }
                        return Ok(Pump::Refetch(off, len));
                    }
                    if let Some((unique, retain_for)) = retain {
                        // Copy retained bytes OUT of the wire chunks: a Bytes slice would pin its
                        // whole source chunk's allocation for the retention lifetime, letting real
                        // memory exceed dedup_budget_bytes by up to chunk_size/segment_size. One
                        // memcpy per RETAINED segment only.
                        let mut owned = Vec::with_capacity(len as usize);
                        for b in &slices {
                            owned.extend_from_slice(b);
                        }
                        self.held.insert(unique, (Bytes::from(owned), retain_for));
                    }
                    for b in slices {
                        self.emit(out, b).await?;
                    }
                    self.span_i += 1;
                }
            }
        }
    }

    /// Send one piece downstream, hashing, with the final bytes of a full transfer withheld
    /// until the NarHash verifies. Err(()) = client went away or hash mismatch (already reported).
    async fn emit(
        &mut self,
        out: &mpsc::Sender<std::io::Result<Bytes>>,
        b: Bytes,
    ) -> Result<(), ()> {
        if self.full {
            self.hasher.update(&b);
            if self.emit_pos + b.len() as u64 == self.end {
                let got = self.hasher.clone().finalize();
                if got[..] != self.nar_hash {
                    warn!("NarHash mismatch on reconstruction — aborting stream");
                    let _ = out.send(Err(std::io::Error::other("NarHash mismatch"))).await;
                    return Err(());
                }
            }
        }
        self.emit_pos += b.len() as u64;
        out.send(Ok(b)).await.map_err(|_| ())
    }
}

/// Extract exactly [off, end) from the buffered chunks iff fully covered, splitting boundary
/// chunks zero-copy. Buffered entries are disjoint.
fn take_span(buf: &mut BTreeMap<u64, Bytes>, off: u64, end: u64) -> Option<Vec<Bytes>> {
    // Coverage check first (no mutation on failure).
    let mut cur = off;
    let mut keys = Vec::new();
    while cur < end {
        let (&k, b) = buf.range(..=cur).next_back()?;
        if k + b.len() as u64 <= cur {
            return None;
        }
        keys.push(k);
        cur = k + b.len() as u64;
    }
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        let b = buf.remove(&k).unwrap();
        let blen = b.len() as u64;
        let s = off.max(k);
        let e = end.min(k + blen);
        if k < s {
            buf.insert(k, b.slice(0..(s - k) as usize));
        }
        if k + blen > e {
            buf.insert(e, b.slice((e - k) as usize..));
        }
        out.push(b.slice((s - k) as usize..(e - k) as usize));
    }
    Some(out)
}

/// Take a contiguous piece starting exactly at `pos` (up to `max` bytes), if buffered.
fn take_prefix(buf: &mut BTreeMap<u64, Bytes>, pos: u64, max: u64) -> Option<Bytes> {
    let (&k, b) = buf.range(..=pos).next_back()?;
    let end = k + b.len() as u64;
    if end <= pos {
        return None;
    }
    let b = buf.remove(&k).unwrap();
    if k < pos {
        buf.insert(k, b.slice(0..(pos - k) as usize));
    }
    let avail = end - pos;
    let take = avail.min(max);
    let piece = b.slice((pos - k) as usize..(pos - k + take) as usize);
    if take < avail {
        buf.insert(pos + take, b.slice((pos - k + take) as usize..));
    }
    Some(piece)
}

/// Try to fetch a manifest from up to two distinct holders, MW-sampled.
async fn acquire_manifest(
    st: &Arc<crate::proxy::ProxyState>,
    info: &RemoteNarinfo,
    peer_ids: &[usize],
) -> Option<Manifest> {
    let avail: Vec<usize> =
        peer_ids.iter().copied().filter(|&p| st.peers.list[p].available()).collect();
    let mut tried = Vec::new();
    for _ in 0..2 {
        let candidates: Vec<usize> =
            avail.iter().copied().filter(|p| !tried.contains(p)).collect();
        let p = st.fetch.pool.pick_among(&candidates)?;
        tried.push(p);
        if let Some(m) = st.peers.fetch_manifest(p, &info.nar_hash).await {
            return Some(m);
        }
    }
    None
}

/// Drive one transfer of [start, end) of `info`'s NAR into `out`, striped across `sources`.
/// Failures are reported through `out` as an Err mid-stream (a clean transfer error for nix).
pub async fn run_transfer(
    st: Arc<crate::proxy::ProxyState>,
    info: RemoteNarinfo,
    sources: Vec<(usize, String)>,
    start: u64,
    end: u64,
    out: mpsc::Sender<std::io::Result<Bytes>>,
) {
    let ctx = &st.fetch;
    let t0 = Instant::now();
    let peer_ids: Vec<usize> = sources.iter().map(|(p, _)| *p).collect();
    let url_of: HashMap<usize, String> = sources.into_iter().collect();
    let full = start == 0 && end == info.nar_size;

    // Plan: manifest-driven when it pays and a holder can supply one; plain striping otherwise.
    let plan = if full && info.nar_size >= MANIFEST_MIN {
        match acquire_manifest(&st, &info, &peer_ids).await {
            Some(m) => match manifest_plan(&m, &info, ctx.cfg_dedup_budget, ctx.cfg_window) {
                Ok(p) => {
                    debug!(
                        "manifest plan for {}: {} spans, {} fetch ranges",
                        info.store_path,
                        p.spans.len(),
                        p.ranges.len()
                    );
                    p
                }
                Err(e) => {
                    warn!("unusable manifest for {}: {e:#}", info.store_path);
                    fallback_plan(start, end)
                }
            },
            None => fallback_plan(start, end),
        }
    } else {
        fallback_plan(start, end)
    };

    let ranges = plan.ranges.clone();
    let mut em = Emitter {
        spans: plan.spans,
        lits: plan.lits,
        span_i: 0,
        span_emitted: 0,
        emit_pos: start,
        end,
        full,
        nar_hash: info.nar_hash,
        hasher: Sha256::new(),
        buffered: BTreeMap::new(),
        held: HashMap::new(),
        retries: HashMap::new(),
    };

    let (done_tx, mut done_rx) = mpsc::channel::<Done>(256);
    let mut workers = tokio::task::JoinSet::new();
    let mut requeue: BinaryHeap<Reverse<(u64, u64)>> = BinaryHeap::new();
    // Carving cursor over the fetch ranges.
    let mut range_i = 0usize;
    let mut range_pos = 0u64;
    // Which peer supplied which bytes, for verification blame. Pruned as emission advances.
    let mut origin: Vec<(u64, u64, usize)> = Vec::new();
    let mut last_progress = Instant::now();
    let mut retry_gate: Option<Instant> = None;
    // Bytes actually pulled from the network for THIS transfer (excludes local lits and replays),
    // so the min_bandwidth floor measures real link goodput, not synthesized/replayed bytes.
    let mut remote_fetched: u64 = 0;

    // Emit whatever needs no data at all (lits-first layouts, pure-replay tails).
    match em.pump(&out, &ctx.stats).await {
        Err(()) => return,
        Ok(Pump::Finished) => return,
        Ok(Pump::NeedData) => {}
        Ok(Pump::Refetch(off, len)) => {
            ctx.stats.requeues.fetch_add(1, Ordering::Relaxed);
            requeue.push(Reverse((off, len)));
            retry_gate = Some(Instant::now() + Duration::from_millis(100));
        }
        Ok(Pump::Abort(msg)) => {
            let _ = out.send(Err(std::io::Error::other(msg))).await;
            return;
        }
    }

    loop {
        // Reap finished workers. tokio's JoinSet retains every completed task's handle until it is
        // joined; without this a long transfer accumulates one dead entry per chunk (hundreds of
        // thousands for a large game), freed only when run_transfer returns. try_join_next removes
        // only already-finished tasks — the results are `()` sent via the channel, so dropping
        // them here is a no-op.
        while workers.try_join_next().is_some() {}

        // Launch whatever the window and the per-peer budgets allow right now.
        loop {
            let gated = retry_gate.is_some_and(|g| Instant::now() < g);
            // Candidate: requeued work first (lowest offset), else carve fresh.
            let (off, queued_len) = match requeue.peek() {
                Some(&Reverse((o, l))) if !gated => (o, Some(l)),
                _ => {
                    // Advance the carve cursor past exhausted ranges.
                    while range_i < ranges.len() && range_pos >= ranges[range_i].1 {
                        range_i += 1;
                        range_pos = 0;
                    }
                    if range_i >= ranges.len() {
                        break;
                    }
                    (ranges[range_i].0 + range_pos, None)
                }
            };
            if off >= em.emit_pos + ctx.cfg_window {
                // Window-bound, not network-bound: tell idle peers' governors.
                for &p in &peer_ids {
                    if ctx.limits[p].has_idle_capacity() {
                        ctx.limits[p].note_blocked();
                    }
                }
                break;
            }
            let avail: Vec<usize> =
                peer_ids.iter().copied().filter(|&p| st.peers.list[p].available()).collect();
            let Some((peer, slot)) = try_pick(&st, &avail) else { break };
            let len = match queued_len {
                Some(l) => {
                    requeue.pop();
                    l
                }
                None => {
                    let room = ranges[range_i].1 - range_pos;
                    let l = ctx.chunk_size(peer).min(room);
                    range_pos += l;
                    l
                }
            };
            let url = url_of[&peer].clone();
            let dtx = done_tx.clone();
            let stc = st.clone();
            let level = ctx.zstd_level(peer);
            let deadline = ctx.chunk_deadline(peer, len);
            workers.spawn(async move {
                let started = Instant::now();
                let result = match tokio::time::timeout(
                    deadline,
                    stc.peers.fetch_range(peer, &url, off, off + len, level),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err(anyhow::anyhow!("chunk deadline ({deadline:?}) exceeded")),
                };
                drop(slot); // free the stream slot before reporting, so relaunch sees capacity
                let _ = dtx.send(Done { off, len, peer, elapsed: started.elapsed(), result }).await;
            });
        }

        let mut wake = last_progress + ctx.cfg_stall;
        if let Some(g) = retry_gate {
            if !requeue.is_empty() {
                wake = wake.min(g);
            }
        }
        // Nothing in flight but bytes still owed ⟹ every holder's breaker is open (a peer with
        // free capacity would have been launched). Re-poll when the soonest one recovers, rather
        // than coasting to stall_timeout and aborting a transfer that could still complete.
        if workers.is_empty() && em.emit_pos < end {
            let repoll = st
                .peers
                .soonest_recovery(&peer_ids)
                .map(|t| t + Duration::from_millis(10))
                .unwrap_or_else(|| Instant::now() + Duration::from_millis(200));
            wake = wake.min(repoll);
        }
        let stall_at = tokio::time::Instant::from_std(wake);
        tokio::select! {
            done = done_rx.recv() => {
                let Some(done) = done else { return };
                match done.result {
                    Ok(chunk) => {
                        ctx.pool.record_success(done.peer, done.len, done.elapsed);
                        ctx.record_rate(done.peer, done.len, done.elapsed);
                        ctx.observe_encoding(done.peer, done.elapsed, &chunk);
                        ctx.limits[done.peer].observe(true, done.len);
                        remote_fetched += done.len;
                        ctx.stats.remote_bytes.fetch_add(done.len, Ordering::Relaxed);
                        ctx.stats.wire_bytes.fetch_add(chunk.wire, Ordering::Relaxed);
                        em.buffered.insert(done.off, chunk.bytes);
                        origin.push((done.off, done.len, done.peer));
                        last_progress = Instant::now();

                        match em.pump(&out, &ctx.stats).await {
                            Err(()) => { workers.abort_all(); return; }
                            Ok(Pump::Finished) => return,
                            Ok(Pump::NeedData) => {}
                            Ok(Pump::Refetch(off, len)) => {
                                // Blame every peer whose bytes overlapped the bad segment, then
                                // drop those attributions: the refetch gets fresh origin entries,
                                // so a second failure blames only the replacement's supplier.
                                for &(o, l, p) in &origin {
                                    if o < off + len && o + l > off {
                                        warn!(
                                            "segment @{off} of {} failed blake3; blaming peer {}",
                                            info.store_path, st.peers.list[p].name
                                        );
                                        ctx.pool.record_failure(p);
                                    }
                                }
                                origin.retain(|&(o, l, _)| !(o < off + len && o + l > off));
                                ctx.stats.requeues.fetch_add(1, Ordering::Relaxed);
                                requeue.push(Reverse((off, len)));
                                retry_gate = Some(Instant::now() + Duration::from_millis(100));
                            }
                            Ok(Pump::Abort(msg)) => {
                                warn!("aborting transfer of {}: {msg}", info.store_path);
                                let _ = out.send(Err(std::io::Error::other(msg))).await;
                                workers.abort_all();
                                return;
                            }
                        }
                        origin.retain(|&(o, l, _)| o + l > em.emit_pos);

                        // The give-up floor: alive but hopeless forfeits to the builder. Measured
                        // on bytes actually pulled from the NETWORK (not local lits/replays), so a
                        // dedup-heavy transfer over a dead link is correctly judged hopeless.
                        if ctx.cfg_min_bw > 0 && t0.elapsed() > ctx.cfg_grace {
                            let rate = remote_fetched as f64 / t0.elapsed().as_secs_f64();
                            if rate < ctx.cfg_min_bw as f64 {
                                warn!(
                                    "transfer of {} below min_bandwidth ({rate:.0} B/s); entering \
                                     roaming epoch and forfeiting to origin",
                                    info.store_path
                                );
                                ctx.set_roaming();
                                let _ = out
                                    .send(Err(std::io::Error::other("below min_bandwidth")))
                                    .await;
                                workers.abort_all();
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("chunk @{} from peer {} failed: {e:#}", done.off, done.peer);
                        ctx.pool.record_failure(done.peer);
                        ctx.limits[done.peer].observe(false, 0);
                        ctx.stats.requeues.fetch_add(1, Ordering::Relaxed);
                        requeue.push(Reverse((done.off, done.len)));
                        retry_gate = Some(Instant::now() + Duration::from_millis(100));
                    }
                }
            }
            _ = tokio::time::sleep_until(stall_at) => {
                if last_progress.elapsed() >= ctx.cfg_stall {
                    warn!(
                        "transfer of {} stalled ({:?} without progress)",
                        info.store_path, ctx.cfg_stall
                    );
                    let _ = out.send(Err(std::io::Error::other("transfer stalled"))).await;
                    workers.abort_all();
                    return;
                }
                retry_gate = None; // the gate expired: relaunch requeued work
            }
        }
    }
}

/// Weighted sample among peers with spare stream budget: a few MW draws with rejection, then a
/// linear fallback so capacity is never left idle by unlucky sampling. The returned Slot releases
/// the stream budget on drop, however the worker ends.
fn try_pick(st: &Arc<crate::proxy::ProxyState>, avail: &[usize]) -> Option<(usize, Slot)> {
    let ctx = &st.fetch;
    for _ in 0..4 {
        let p = ctx.pool.pick_among(avail)?;
        if ctx.limits[p].try_acquire() {
            return Some((p, Slot { st: st.clone(), peer: p }));
        }
    }
    avail
        .iter()
        .copied()
        .find(|&p| ctx.limits[p].try_acquire())
        .map(|p| (p, Slot { st: st.clone(), peer: p }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_span_and_prefix_split_correctly() {
        let mut buf = BTreeMap::new();
        buf.insert(0u64, Bytes::from(vec![1u8; 100]));
        buf.insert(100u64, Bytes::from(vec![2u8; 100]));
        // Incomplete: nothing mutated.
        assert!(take_span(&mut buf, 50, 250).is_none());
        assert_eq!(buf.len(), 2);
        // Span crossing both chunks, leaving remainders.
        let got = take_span(&mut buf, 50, 150).unwrap();
        let total: usize = got.iter().map(|b| b.len()).sum();
        assert_eq!(total, 100);
        assert_eq!(got[0][0], 1);
        assert_eq!(got[1][0], 2);
        // Remainders: [0,50) and [150,200).
        assert_eq!(take_prefix(&mut buf, 0, 50).unwrap().len(), 50);
        assert_eq!(take_prefix(&mut buf, 150, 999).unwrap().len(), 50);
        assert!(buf.is_empty());
        assert!(take_prefix(&mut buf, 0, 1).is_none());
    }

    #[test]
    fn fallback_plan_covers_the_range() {
        let p = fallback_plan(100, 500);
        assert_eq!(p.ranges, vec![(100, 400)]);
        assert_eq!(p.spans.len(), 1);
    }

    fn ctx_with(encoding: &str) -> FetchCtx {
        let pcfg: ProxyCfg = toml::from_str("listen = \"127.0.0.1:1\"").unwrap();
        let peers = vec![PeerCfg {
            name: "a".into(),
            url: "http://x:1".into(),
            tier: 1,
            encoding: encoding.into(),
        }];
        FetchCtx::new(&peers, &pcfg)
    }

    #[test]
    fn manual_encodings_are_pinned() {
        assert_eq!(ctx_with("none").zstd_level(0), None);
        assert_eq!(ctx_with("zstd:7").zstd_level(0), Some(7));
    }

    fn chunk_timed(enc_ms: u64, read_ms: u64, decode_ms: u64) -> crate::peers::Chunk {
        crate::peers::Chunk {
            bytes: Bytes::new(),
            wire: 0,
            srv_read: Duration::from_millis(read_ms),
            srv_encode: Duration::from_millis(enc_ms),
            decode: Duration::from_millis(decode_ms),
        }
    }

    #[test]
    fn auto_level_follows_the_chunk_bottleneck() {
        let ms = Duration::from_millis;
        let ctx = ctx_with("auto");
        assert_eq!(ctx.zstd_level(0), Some(3), "seed level before any signal");

        // Wire-bound with lots of encode slack: climb fast to the max.
        for _ in 0..10 {
            ctx.observe_encoding(0, ms(2000), &chunk_timed(50, 20, 10));
        }
        assert_eq!(ctx.zstd_level(0), Some(19));

        // Near the knee (enc between half of and all of transfer): hold.
        ctx.observe_encoding(0, ms(1000), &chunk_timed(400, 10, 5));
        assert_eq!(ctx.zstd_level(0), Some(19));

        // Encode-bound (the peer's CPU or its queue): shed fast, floor at 1.
        for _ in 0..12 {
            ctx.observe_encoding(0, ms(1000), &chunk_timed(700, 10, 5));
        }
        assert_eq!(ctx.zstd_level(0), Some(1));

        // Peer-disk-bound: the level can neither help nor hurt — hold, even with encode slack.
        ctx.observe_encoding(0, ms(1000), &chunk_timed(5, 800, 5));
        assert_eq!(ctx.zstd_level(0), Some(1));

        // A peer that predates the timing headers: fall back to the open-loop goodput ladder.
        ctx.set_rate(0, 1e6);
        ctx.observe_encoding(0, ms(1000), &chunk_timed(0, 0, 0));
        assert_eq!(ctx.zstd_level(0), Some(19));
        ctx.set_rate(0, 1e9);
        ctx.observe_encoding(0, ms(1000), &chunk_timed(0, 0, 0));
        assert_eq!(ctx.zstd_level(0), Some(1));
    }
}
