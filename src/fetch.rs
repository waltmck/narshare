//! The striped NAR fetch engine: one transfer = one ordered byte stream to the local nix,
//! reconstructed from an execution *plan* over the NAR's byte layout.
//!
//! With a manifest (M5), the plan knows the tree: framing literals are synthesized locally and
//! never fetched; file segments are fetched once per distinct blake3 across all holding peers and
//! *replayed* at later occurrences under a bounded retention budget (dedup.rs). Segment hashes
//! are dedup KEYS only — fetched bytes are deliberately NOT verified against them: when two
//! sources disagree about a chunk, adjudication is impossible short of hashing the complete
//! stream (a manifest can lie as easily as a byte server), so the contract is exactly one
//! guarantee — a transfer that COMPLETES is correct (the streaming NarHash gate below, plus
//! nix's own CA validation) — and availability against a peer serving wrong bytes is explicitly
//! not guaranteed. Without a manifest the plan degrades to one span — exactly the M4 behavior.
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
// (There is deliberately no per-segment verification and no segment retry budget: see the
// module doc — corruption is detected once, at the NarHash gate, without attribution.)
/// Give-up complement to the byte-progress stall: bytes prove the LINK is alive, but a peer can
/// stream bytes forever that never become completed chunks (garbage frames, wrong lengths).
/// This many consecutive chunk failures with no completion anywhere aborts the transfer; any
/// completion resets it, so flaky-but-usable links are untouched. Requeues are paced at 100 ms,
/// so this is also a floor of ~3 s on the abort.
const MAX_FAILURE_STREAK: u32 = 30;
/// Hedged exploration (docs/regret.md): when the weighted draw hands a chunk to a peer whose
/// within-set routing share p sits below the uniform share 1/N, a DUPLICATE of the chunk is
/// opportunistically dispatched to a second weighted draw with probability
///
///     h = clamp((1/N − p) / (1/N − p_floor), 0, 1)^ν
///
/// where p_floor is the share this peer WOULD have at the weight floor W_MIN given the others'
/// current weights — so h spans exactly [0, 1]: zero at or above the uniform share (including
/// the single-holder and all-equally-weak sets, where no better alternative exists), and
/// EXACTLY one at the floor (a pure ping is always insured). First arrival feeds the emitter;
/// the loser completes anyway and is recorded normally (a cancelled ping would produce no
/// measurement, and evidence-free fixed-share drift would then oscillate the weight) — so the
/// asymptotically stable weights are unchanged by hedging. ν shapes how tightly the insurance
/// concentrates on collapsed weights.
///
/// ν tuned empirically, twice. The first sweep (at SHARE=0.02, with a waste counter that
/// missed losers landing post-transfer) favored ν=1; re-measured at the adopted SHARE=0.005
/// with the launch-time hedge_bytes premium (mw_hedge_cost), the linear ramp pays a ~3.5%
/// duplicate-byte premium at WEIGHT PARITY — where the "slow" peer is not slow and duplicates
/// are full-size chunks — for zero tail benefit (0-1 tails/100 at every ν∈{1,2,3}: with the
/// drift tamed, the floor anchor h(W_MIN)=1, not ν, carries the ping insurance). ν=3
/// concentrates the premium to ~0 at parity while keeping floor pings fully insured.
const HEDGE_NU: f64 = 3.0;

fn hedge_prob(n: usize, share: f64, floor_share: f64, nu: f64) -> f64 {
    let uniform = 1.0 / n as f64;
    let num = uniform - share;
    if num <= 0.0 {
        return 0.0;
    }
    let denom = uniform - floor_share;
    if denom <= 0.0 {
        return 1.0; // below uniform yet floor-equivalent: fully insured
    }
    (num / denom).clamp(0.0, 1.0).powf(nu)
}

/// Fetch ranges are merged across non-fetch gaps (framing lits, tiny replay holes) up to this
/// size. An HTTP chunk request costs ~milliseconds regardless of size, so a tree of many small
/// files would otherwise fragment the range space at every file boundary into sub-chunk
/// requests (Hollow Knight: 1754 ranges for 4331 spans, measured) and cap throughput on request
/// overhead. Gap bytes are fetched and simply never emitted — lits and replays emit from local
/// data, and the transfer loop prunes passed buffer entries — which costs ~200 B of framing per
/// file, ≤0.01% wire overhead on real trees. Dedup survives: replay holes are segment-sized
/// (≥4 MiB from narshare peers), far above this threshold.
const RANGE_MERGE_GAP: u64 = 64 << 10;
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

    // Transfer outcomes. Every run_transfer exit increments exactly one terminal counter, so
    // `started - Σ(terminal)` is the live-transfer gauge — the status endpoint's leak check.
    pub transfers_started: AtomicU64,
    pub transfers_completed: AtomicU64,
    pub aborts_stall: AtomicU64,
    pub aborts_streak: AtomicU64,
    pub aborts_min_bandwidth: AtomicU64,
    pub aborts_hash_mismatch: AtomicU64,
    /// Plan-integrity aborts (inconsistent manifest, replay bugs) — should stay 0.
    pub aborts_other: AtomicU64,
    /// The downstream (nix) hung up mid-transfer; not our failure.
    pub clients_gone: AtomicU64,
    /// Transfers that ran from a manifest plan (vs plain striping).
    pub manifest_plans: AtomicU64,

    // Proxy lookup counters — the observable that answers "did nix even ask us, and what
    // did we say" (its absence made a production 404-vs-not-consulted question unanswerable).
    pub narinfo_requests: AtomicU64,
    pub narinfo_misses: AtomicU64,
    pub nar_requests: AtomicU64,
    pub nar_misses: AtomicU64,

    /// Hedged (duplicate) attempts launched — the insurance spend, in requests…
    pub hedges: AtomicU64,
    /// …its exact byte premium, counted at LAUNCH (one of the two copies is always
    /// discarded, so every hedged launch costs its length in duplicate wire — counting
    /// observed losers instead undercounts, because losers landing after their transfer
    /// ended are never seen by the accounting loop)…
    pub hedge_bytes: AtomicU64,
    /// …and the bytes of losing twins the transfer loop actually observed and discarded.
    pub hedged_waste_bytes: AtomicU64,
}

impl Stats {
    pub fn active_transfers(&self) -> u64 {
        let started = self.transfers_started.load(Ordering::Relaxed);
        let ended = self.transfers_completed.load(Ordering::Relaxed)
            + self.aborts_stall.load(Ordering::Relaxed)
            + self.aborts_streak.load(Ordering::Relaxed)
            + self.aborts_min_bandwidth.load(Ordering::Relaxed)
            + self.aborts_hash_mismatch.load(Ordering::Relaxed)
            + self.aborts_other.load(Ordering::Relaxed)
            + self.clients_gone.load(Ordering::Relaxed);
        started.saturating_sub(ended)
    }
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
            state: Mutex::new(LimState {
                inflight: 0,
                limit: start,
            }),
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

    fn snapshot(&self) -> (usize, usize) {
        let s = self.state.lock().unwrap();
        (s.inflight, s.limit)
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
            let pressure = if e.blocked && e.bytes == 0 {
                Pressure::ConsumerBound
            } else {
                Pressure::Network
            };
            let (ok_n, err_n) = (e.ok, e.err);
            *e = Epoch {
                started: Instant::now(),
                bytes: 0,
                ok: 0,
                err: 0,
                blocked: false,
            };
            drop(e);
            let new_limit = self
                .governor
                .lock()
                .unwrap()
                .observe(throughput, pressure, ok_n, err_n);
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
/// Climb while enc/transfer (serial peers) or enc/elapsed (pipelined peers) is below this; the
/// knee sits where they are comparable.
const ENC_CLIMB_BELOW: f64 = 0.5;
/// "Lots of slack": below this takes the fast step.
const ENC_SLACK: f64 = 0.1;
/// Pipelined peers: a stage whose busy fraction of elapsed exceeds this IS the bottleneck.
const ENC_SATURATED: f64 = 0.85;
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

/// Cumulative per-peer decision tallies — the observables regret accounting needs: every chunk
/// the scheduler routed to this peer, split by outcome, plus the bytes that came back.
#[derive(Default)]
pub struct PeerTally {
    pub chunks_ok: AtomicU64,
    pub chunks_err: AtomicU64,
    pub bytes: AtomicU64,
}

/// Everything the striped fetches share across transfers.
pub struct FetchCtx {
    pub pool: crate::pool::HostPool,
    limits: Vec<PeerLimit>,
    net: Vec<Mutex<PeerNet>>,
    tally: Vec<PeerTally>,
    encodings: Vec<String>,
    pub stats: Stats,
    /// Pinged whenever a stream slot frees anywhere, so a capacity-starved transfer relaunches
    /// immediately instead of polling — the many-small-fetches case would otherwise queue in
    /// 200 ms quanta behind one big transfer that structurally reacquires its own slots.
    slot_freed: tokio::sync::Notify,
    /// Hedging exponent ν (f64 bits; adjustable for the tuning benches).
    nu_bits: AtomicU64,
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
            limits: (0..n)
                .map(|_| PeerLimit::new(cfg.per_peer_connections.max(1)))
                .collect(),
            net: (0..n)
                .map(|_| {
                    Mutex::new(PeerNet {
                        rate: 0.0,
                        level: ENC_SEED,
                    })
                })
                .collect(),
            tally: (0..n).map(|_| PeerTally::default()).collect(),
            encodings: peer_cfgs.iter().map(|p| p.encoding.clone()).collect(),
            stats: Stats::default(),
            slot_freed: tokio::sync::Notify::new(),
            nu_bits: AtomicU64::new(HEDGE_NU.to_bits()),
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
    pub fn set_rate(&self, peer: usize, r: f64) {
        self.net[peer].lock().unwrap().rate = r;
    }

    fn nu(&self) -> f64 {
        f64::from_bits(self.nu_bits.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    pub fn set_nu(&self, nu: f64) {
        self.nu_bits.store(nu.to_bits(), Ordering::Relaxed);
    }

    fn record_rate(&self, peer: usize, bytes: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0005 {
            return;
        }
        let r = bytes as f64 / secs;
        let mut net = self.net[peer].lock().unwrap();
        net.rate = if net.rate == 0.0 {
            r
        } else {
            0.7 * net.rate + 0.3 * r
        };
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
        if c.pipelined {
            // Streaming peer: read/encode/wire overlapped, and the reported times are
            // BUSY-times (of the previous chunk, scaled). A stage is the bottleneck when its
            // busy fraction of elapsed approaches 1; if no stage does, the wire is the
            // bottleneck by elimination.
            let el = elapsed.as_secs_f64().max(1e-4);
            let (u_enc, u_read, u_dec) = (enc / el, read / el, decode / el);
            if u_enc > ENC_SATURATED {
                // The peer's encoder can barely keep ahead of the wire: shed load fast.
                net.level = (net.level - ENC_STEP_DOWN).max(1);
            } else if u_read > ENC_SATURATED {
                // The peer's disk is the pacer: the level can neither help nor hurt. Hold.
            } else if u_enc < ENC_CLIMB_BELOW && u_dec < ENC_SATURATED {
                // Wire-bound with encoder slack: buy ratio with idle CPU.
                let step = if u_enc < ENC_SLACK {
                    ENC_STEP_UP_FAST
                } else {
                    ENC_STEP_UP
                };
                net.level = (net.level + step).min(ENC_MAX);
            }
            return;
        }
        // Buffered peer (small spans, or a pre-streaming version): stages were SERIAL, so
        // wire time is what the peer's disk/CPU and our decode don't account for.
        let transfer = (elapsed.as_secs_f64() - enc - read - decode).max(1e-4);
        if enc > transfer {
            // The peer's CPU (or its encode queue) is the bottleneck: shed load fast.
            net.level = (net.level - ENC_STEP_DOWN).max(1);
        } else if read > transfer {
            // The peer's disk is the bottleneck: the level can neither help nor hurt. Hold.
        } else if enc < transfer * ENC_CLIMB_BELOW && decode < transfer {
            // The wire is the bottleneck and compression has slack: buy ratio with idle CPU.
            let step = if enc < transfer * ENC_SLACK {
                ENC_STEP_UP_FAST
            } else {
                ENC_STEP_UP
            };
            net.level = (net.level + step).min(ENC_MAX);
        }
        // Otherwise: near the knee — hold.
    }

    /// Per-chunk soft deadline: generous multiple of the expected duration, so one hung stream
    /// requeues without killing the transfer (the global stall watchdog remains authoritative).
    ///
    /// A peer with NO goodput sample gets a short fixed bound instead: the seed chunk sized in
    /// the dark divided by a made-up floor rate would exceed the default stall timeout, and a
    /// black-holing peer (accepts TCP, never answers) holding the emission frontier that long
    /// starves the window until the watchdog kills a transfer other peers could finish. 20 s is
    /// enough for the 4 MiB seed on any link ≥ ~200 KB/s; a slower honest link loses one partial
    /// chunk, gets its rate seeded from the wire progress (see the failure arm), and continues
    /// with completable carves.
    fn chunk_deadline(&self, peer: usize, len: u64) -> Duration {
        let r = self.rate_of(peer);
        if r <= 0.0 {
            return Duration::from_secs(20);
        }
        Duration::from_secs_f64((8.0 * len as f64 / r).clamp(10.0, 300.0))
    }

    pub fn set_roaming(&self) {
        *self.roaming_until.lock().unwrap() = Some(Instant::now() + ROAMING_EPOCH);
    }

    /// Point-in-time adaptive state for the status endpoint:
    /// (per-stream rate B/s, auto zstd level, streams in flight, stream limit).
    pub fn peer_net_status(&self, peer: usize) -> (f64, i32, usize, usize) {
        let net = self.net[peer].lock().unwrap();
        let (inflight, limit) = self.limits[peer].snapshot();
        (net.rate, net.level, inflight, limit)
    }

    /// (chunks_ok, chunks_err, bytes fetched) routed to this peer since startup.
    pub fn peer_tally(&self, peer: usize) -> (u64, u64, u64) {
        let t = &self.tally[peer];
        (
            t.chunks_ok.load(Ordering::Relaxed),
            t.chunks_err.load(Ordering::Relaxed),
            t.bytes.load(Ordering::Relaxed),
        )
    }

    pub fn roaming_ms_remaining(&self) -> Option<u64> {
        let now = Instant::now();
        self.roaming_until
            .lock()
            .unwrap()
            .filter(|&u| u > now)
            .map(|u| (u - now).as_millis() as u64)
    }

    /// While a roaming epoch is active, paths bigger than the floor×grace bound are refused at
    /// lookup time — exactly the ones a `min_bandwidth` abort would forfeit anyway.
    pub fn refuses_while_roaming(&self, nar_size: u64) -> bool {
        if self.cfg_min_bw == 0 {
            return false;
        }
        let active = self
            .roaming_until
            .lock()
            .unwrap()
            .is_some_and(|until| Instant::now() < until);
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
    /// Bytes fetched from peers, emitted as they stream in; buffered whole only when later
    /// occurrences will replay them.
    Fetch {
        len: u64,
        retain: Option<(usize, usize)>,
    },
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
        spans: vec![(
            start,
            SpanExec::Fetch {
                len: end - start,
                retain: None,
            },
        )],
        lits: Bytes::new(),
        ranges: vec![(start, end - start)],
    }
}

/// Turn a manifest into an execution plan: literals local, distinct segments fetched once,
/// duplicates replayed under the retention budget. `window` bounds the largest verifiable span.
fn manifest_plan(
    m: &Manifest,
    info: &RemoteNarinfo,
    budget: u64,
    window: u64,
) -> anyhow::Result<Plan> {
    if m.nar_hash != format!("sha256:{}", nixbase32::encode(&info.nar_hash)) {
        anyhow::bail!("manifest narhash disagrees with narinfo");
    }
    let layout = manifest::synth_layout(m)?;
    if layout.nar_size != info.nar_size {
        anyhow::bail!(
            "manifest NarSize {} != narinfo {}",
            layout.nar_size,
            info.nar_size
        );
    }

    // Dedup plan over the segment occurrences, in NAR order. The hashes are dedup KEYS, not
    // checked against fetched bytes (see the module doc). Two guards on the peer-supplied
    // manifest keep the DATA PATH sound regardless of what it claims:
    //   * No span may exceed the fetch window — a RETAINED span must be assembled whole for
    //     replay, and one bigger than the window could never be, stalling every transfer out.
    //   * A given segment hash must have ONE length across all its occurrences, or replay would
    //     emit the wrong number of bytes and desync emission from the layout. Reject rather
    //     than fall back — a manifest this inconsistent cannot be relied on.
    let mut keys = Vec::new();
    let mut sizes = Vec::new();
    let mut len_of: HashMap<[u8; 32], u64> = HashMap::new();
    for span in &layout.spans {
        if let SpanKind::Segment { hash } = &span.kind {
            if span.len > window {
                anyhow::bail!(
                    "manifest segment ({} B) exceeds window ({} B)",
                    span.len,
                    window
                );
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
            SpanKind::Lit { lit_off } => spans.push((
                span.nar_off,
                SpanExec::Lit {
                    lit_off: *lit_off,
                    len: span.len,
                },
            )),
            SpanKind::Segment { .. } => {
                let step = steps[seg_i];
                seg_i += 1;
                match step {
                    dedup::Step::Fetch { unique, retain_for } => {
                        spans.push((
                            span.nar_off,
                            SpanExec::Fetch {
                                len: span.len,
                                retain: (retain_for > 0).then_some((unique, retain_for)),
                            },
                        ));
                        // Coalesce adjacent fetch ranges, bridging small non-fetch gaps.
                        match ranges.last_mut() {
                            Some((o, l))
                                if span.nar_off >= *o + *l
                                    && span.nar_off - (*o + *l) <= RANGE_MERGE_GAP =>
                            {
                                *l = span.nar_off + span.len - *o;
                            }
                            _ => ranges.push((span.nar_off, span.len)),
                        }
                    }
                    dedup::Step::Cached { unique } => spans.push((
                        span.nar_off,
                        SpanExec::Replay {
                            unique,
                            len: span.len,
                        },
                    )),
                }
            }
        }
    }
    Ok(Plan {
        spans,
        lits: layout.lits,
        ranges,
    })
}

// ------------------------------------------------------------------------------------------
// The engine
// ------------------------------------------------------------------------------------------

struct Done {
    off: u64,
    len: u64,
    peer: usize,
    /// Which attempt on this range (hedged duplicates share off/len, not attempt ids).
    attempt: u64,
    result: anyhow::Result<crate::peers::Chunk>,
}

/// One in-flight RANGE: possibly several concurrent attempts (a primary and its hedge twin).
/// Requeueing happens only when the last attempt dies with nothing delivered, so ranges are
/// delivered into the buffer at most once and buffered entries stay disjoint.
struct Flight {
    /// (attempt id, that attempt's deadline) per live attempt.
    attempts: Vec<(u64, Instant)>,
    /// A copy of this range already reached the buffer; late twins are recorded, not buffered.
    delivered: bool,
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
        // Wake every capacity-starved transfer; they race try_pick and losers re-register.
        self.st.fetch.slot_freed.notify_waiters();
    }
}

enum Pump {
    NeedData,
    Finished,
    Abort(String),
}

/// Why emission stopped dead (as opposed to a Pump::Abort, which is a plan-integrity verdict).
enum EmitEnd {
    /// The downstream receiver hung up.
    ClientGone,
    /// The reconstructed stream failed the NarHash gate (already reported downstream).
    HashMismatch,
}

impl Stats {
    fn count_emit_end(&self, end: &EmitEnd) {
        match end {
            EmitEnd::ClientGone => self.clients_gone.fetch_add(1, Ordering::Relaxed),
            EmitEnd::HashMismatch => self.aborts_hash_mismatch.fetch_add(1, Ordering::Relaxed),
        };
    }
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
}

impl Emitter {
    /// Push plan progress as far as the buffered data allows, sending to `out`.
    /// Ok(Pump::NeedData) means "no more progress until more chunks land".
    async fn pump(
        &mut self,
        out: &mpsc::Sender<std::io::Result<Bytes>>,
        stats: &Stats,
    ) -> Result<Pump, EmitEnd> {
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
                    stats
                        .replayed_bytes
                        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    self.emit(out, bytes).await?;
                    self.span_i += 1;
                }
                SpanExec::Fetch { len, retain: None } => {
                    // Plain span: emit any contiguous prefix as it streams in.
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
                SpanExec::Fetch {
                    len,
                    retain: Some((unique, retain_for)),
                } => {
                    // Retained span: assembled whole so later occurrences can replay it.
                    let (len, unique, retain_for) = (*len, *unique, *retain_for);
                    let Some(slices) = take_span(&mut self.buffered, off, off + len) else {
                        return Ok(Pump::NeedData);
                    };
                    // Copy retained bytes OUT of the wire chunks: a Bytes slice would pin its
                    // whole source chunk's allocation for the retention lifetime, letting real
                    // memory exceed dedup_budget_bytes by up to chunk_size/segment_size. One
                    // memcpy per RETAINED segment only.
                    let mut owned = Vec::with_capacity(len as usize);
                    for b in &slices {
                        owned.extend_from_slice(b);
                    }
                    self.held.insert(unique, (Bytes::from(owned), retain_for));
                    for b in slices {
                        self.emit(out, b).await?;
                    }
                    self.span_i += 1;
                }
            }
        }
    }

    /// Send one piece downstream, hashing, with the final bytes of a full transfer withheld
    /// until the NarHash verifies. Err distinguishes the two dead ends (already reported
    /// downstream where applicable) so the caller can attribute the outcome.
    async fn emit(
        &mut self,
        out: &mpsc::Sender<std::io::Result<Bytes>>,
        b: Bytes,
    ) -> Result<(), EmitEnd> {
        if self.full {
            self.hasher.update(&b);
            if self.emit_pos + b.len() as u64 == self.end {
                let got = self.hasher.clone().finalize();
                if got[..] != self.nar_hash {
                    warn!("NarHash mismatch on reconstruction — aborting stream");
                    let _ = out
                        .send(Err(std::io::Error::other("NarHash mismatch")))
                        .await;
                    return Err(EmitEnd::HashMismatch);
                }
            }
        }
        self.emit_pos += b.len() as u64;
        out.send(Ok(b)).await.map_err(|_| EmitEnd::ClientGone)
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
    let avail: Vec<usize> = peer_ids
        .iter()
        .copied()
        .filter(|&p| st.peers.list[p].available())
        .collect();
    let mut tried = Vec::new();
    for _ in 0..2 {
        let candidates: Vec<usize> = avail
            .iter()
            .copied()
            .filter(|p| !tried.contains(p))
            .collect();
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
    ctx.stats.transfers_started.fetch_add(1, Ordering::Relaxed);
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
                    ctx.stats.manifest_plans.fetch_add(1, Ordering::Relaxed);
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
    };

    let (done_tx, mut done_rx) = mpsc::channel::<Done>(256);
    let mut workers = tokio::task::JoinSet::new();
    let mut requeue: BinaryHeap<Reverse<(u64, u64)>> = BinaryHeap::new();
    // Carving cursor over the fetch ranges.
    let mut range_i = 0usize;
    let mut range_pos = 0u64;
    // Byte-level liveness: workers tick this as wire bytes ARRIVE (not as chunks complete), so
    // a chunk that takes longer than stall_timeout on a slow-but-alive link never false-fires
    // the watchdog — the design's original rationale for byte-progress stall.
    let progress = Arc::new(AtomicU64::new(0));
    let mut last_seen_bytes = 0u64;
    let mut last_progress = Instant::now();
    let mut failure_streak = 0u32;
    let mut retry_gate: Option<Instant> = None;
    // Every in-flight RANGE keyed by offset (ranges are disjoint; a range may carry several
    // attempts when hedged). The stall watchdog is SUBORDINATE to the attempts' deadlines:
    // patience may only fire once no request is still within its own deadline, so the two
    // clocks compose instead of racing (the old failure mode: a legally in-flight chunk
    // starved the window past stall_timeout and the watchdog killed a transfer the other
    // holders could have finished).
    let mut inflight: HashMap<u64, Flight> = HashMap::new();
    let mut next_attempt: u64 = 0;
    // Bytes actually pulled from the network for THIS transfer (excludes local lits and replays),
    // so the min_bandwidth floor measures real link goodput, not synthesized/replayed bytes.
    let mut remote_fetched: u64 = 0;

    // Emit whatever needs no data at all (lits-first layouts, pure-replay tails).
    match em.pump(&out, &ctx.stats).await {
        Err(end) => {
            ctx.stats.count_emit_end(&end);
            return;
        }
        Ok(Pump::Finished) => {
            ctx.stats
                .transfers_completed
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        Ok(Pump::NeedData) => {}
        Ok(Pump::Abort(msg)) => {
            ctx.stats.aborts_other.fetch_add(1, Ordering::Relaxed);
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

        // Register interest in slot releases BEFORE probing for capacity: a slot freed between a
        // failed try_pick below and the select cannot then be missed (enable() is the documented
        // Notify pattern for exactly this race).
        let notified = ctx.slot_freed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let mut starved = false;

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
            let avail: Vec<usize> = peer_ids
                .iter()
                .copied()
                .filter(|&p| st.peers.list[p].available())
                .collect();
            // One weighted draw — the weights ARE the routing distribution (no capacity
            // conditioning; docs/regret.md). The hedge decision happens BEFORE the capacity
            // check: an insured chunk whose primary is busy proceeds on the partner alone
            // (a busy floor peer means a ping is already in flight there — its measurement is
            // coming; queuing more behind it would park the transfer on the least-trusted
            // peer), while an UNinsured busy draw parks — the deliberate policy for peers the
            // weights trust.
            let Some(drawn) = ctx.pool.pick_among(&avail) else {
                break;
            }; // no live holders
            let (share, floor_share) = ctx.pool.hedge_shares(&avail, drawn);
            let h = hedge_prob(avail.len(), share, floor_share, ctx.nu());
            let hedge_fired = avail.len() >= 2 && h > 0.0 && ctx.pool.chance(h);
            #[cfg_attr(not(test), allow(unused_mut))] // mutated only by the bench A/B lever
            let mut primary_slot = if ctx.limits[drawn].try_acquire() {
                Some(Slot {
                    st: st.clone(),
                    peer: drawn,
                })
            } else {
                None
            };
            let partner_slot = if hedge_fired {
                let others: Vec<usize> = avail.iter().copied().filter(|&q| q != drawn).collect();
                match ctx.pool.pick_among(&others) {
                    // Opportunistic: a busy partner skips the hedge (the insurance must
                    // never delay anything).
                    Some(q) if ctx.limits[q].try_acquire() => Some(Slot {
                        st: st.clone(),
                        peer: q,
                    }),
                    _ => None,
                }
            } else {
                None
            };
            #[cfg(test)]
            if primary_slot.is_none() && BENCH_WORK_CONSERVING.load(Ordering::Relaxed) {
                primary_slot = avail
                    .iter()
                    .copied()
                    .find(|&q| ctx.limits[q].try_acquire())
                    .map(|q| Slot {
                        st: st.clone(),
                        peer: q,
                    });
            }
            if primary_slot.is_none() && partner_slot.is_none() {
                // Every launchable path is capacity-blocked: wait for a release, not a timer.
                starved = !avail.is_empty();
                break;
            }
            // The chunk is sized for whichever peer leads the fetch.
            let lead = primary_slot
                .as_ref()
                .or(partner_slot.as_ref())
                .map(|s| s.peer)
                .expect("one slot exists");
            let len = match queued_len {
                Some(l) => {
                    requeue.pop();
                    // Re-carve an oversized requeue to the CURRENT chunk size: the original
                    // carve may predate the link (a seed that outran a thin link, a rate that
                    // collapsed), and re-flying it whole would just die on its deadline again.
                    let cs = ctx.chunk_size(lead);
                    if l > cs.saturating_mul(2) {
                        requeue.push(Reverse((off + cs, l - cs)));
                        cs
                    } else {
                        l
                    }
                }
                None => {
                    let room = ranges[range_i].1 - range_pos;
                    let l = ctx.chunk_size(lead).min(room);
                    range_pos += l;
                    l
                }
            };
            // Spawn one attempt of [off, off+len) on `peer`; returns its deadline instant.
            // Peer-level accounting (MW loss/success, rate EWMA, encoding controller, tallies,
            // governor) happens IN the worker, not the transfer loop: a hedge loser must
            // produce its measurement even if its transfer already finished — that measurement
            // is the whole point of the ping — so hedge twins are spawned DETACHED and only
            // primaries ride the JoinSet (and die with the transfer).
            let spawn_attempt = |workers: &mut tokio::task::JoinSet<()>,
                                 peer: usize,
                                 slot: Slot,
                                 attempt: u64,
                                 detached: bool|
             -> Instant {
                let url = url_of[&peer].clone();
                let dtx = done_tx.clone();
                let stc = st.clone();
                let level = ctx.zstd_level(peer);
                let deadline = ctx.chunk_deadline(peer, len);
                let deadline_at = Instant::now() + deadline;
                let prog = progress.clone();
                let fut = async move {
                    let started = Instant::now();
                    let result = match tokio::time::timeout(
                        deadline,
                        stc.peers
                            .fetch_range(peer, &url, off, off + len, level, &prog),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => {
                            // A deadline death is transport-indistinguishable from a black
                            // hole (accepts TCP, never answers): without a strike, such a
                            // peer would stay "available" forever — the breaker's only other
                            // probe is the 60 s sync loop. Honest-slow peers eat at most a
                            // couple of strikes before their seeded rate makes carves
                            // completable, and any delivered chunk resets the count.
                            stc.peers.strike(peer);
                            Err(anyhow::anyhow!("chunk deadline ({deadline:?}) exceeded"))
                        }
                    };
                    let elapsed = started.elapsed();
                    let ctx = &stc.fetch;
                    match &result {
                        Ok(chunk) => {
                            // Sub-CHUNK_MIN chunks are latency-dominated: their timing says
                            // nothing about throughput, so they don't move the adaptive state.
                            if len >= CHUNK_MIN {
                                ctx.pool.record_success(peer, len, elapsed);
                                ctx.record_rate(peer, len, elapsed);
                                ctx.observe_encoding(peer, elapsed, chunk);
                            }
                            ctx.tally[peer].chunks_ok.fetch_add(1, Ordering::Relaxed);
                            ctx.tally[peer].bytes.fetch_add(len, Ordering::Relaxed);
                            ctx.limits[peer].observe(true, len);
                            ctx.stats.remote_bytes.fetch_add(len, Ordering::Relaxed);
                            ctx.stats
                                .wire_bytes
                                .fetch_add(chunk.wire, Ordering::Relaxed);
                        }
                        Err(_) => {
                            ctx.tally[peer].chunks_err.fetch_add(1, Ordering::Relaxed);
                            ctx.pool.record_failure(peer);
                            ctx.limits[peer].observe(false, 0);
                        }
                    }
                    drop(slot); // free the slot (and notify) before reporting
                    let _ = dtx
                        .send(Done {
                            off,
                            len,
                            peer,
                            attempt,
                            result,
                        })
                        .await;
                };
                if detached {
                    tokio::spawn(fut);
                } else {
                    workers.spawn(fut);
                }
                deadline_at
            };

            let fl = inflight.entry(off).or_insert(Flight {
                attempts: Vec::new(),
                delivered: false,
            });
            // BOTH members of a hedged pair are detached: whichever loses must outlive the
            // transfer (which the winner may complete) to deliver its measurement — in the
            // common case the LOSER IS THE PRIMARY (the slow ping the partner just beat), and
            // aborting it with the JoinSet would silently discard exactly the observation the
            // ping exists to produce.
            let hedged = partner_slot.is_some();
            if let Some(slot) = primary_slot {
                next_attempt += 1;
                let peer = slot.peer;
                let d_at = spawn_attempt(&mut workers, peer, slot, next_attempt, hedged);
                fl.attempts.push((next_attempt, d_at));
            }
            if let Some(slot) = partner_slot {
                ctx.stats.hedges.fetch_add(1, Ordering::Relaxed);
                ctx.stats.hedge_bytes.fetch_add(len, Ordering::Relaxed);
                next_attempt += 1;
                let peer = slot.peer;
                let d_at = spawn_attempt(&mut workers, peer, slot, next_attempt, true);
                fl.attempts.push((next_attempt, d_at));
            }
        }

        let mut wake = last_progress + ctx.cfg_stall;
        // Subordination: never schedule the stall verdict before the latest in-flight deadline
        // — a hung request belongs to its own detector (deadline → requeue → strike), and the
        // watchdog's question ("has the WHOLE transfer gone silent past patience?") is only
        // well-posed once nothing is legally in flight.
        if let Some(d) = inflight
            .values()
            .flat_map(|f| f.attempts.iter().map(|&(_, d)| d))
            .max()
        {
            wake = wake.max(d);
        }
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
                let Some(done) = done else {
                    // Unreachable (we hold a sender), but keep the outcome accounting airtight.
                    ctx.stats.aborts_other.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                // Flight bookkeeping: retire this attempt; learn whether a twin already
                // delivered the range and whether any twin is still flying.
                let (was_delivered, twins_live) = match inflight.get_mut(&done.off) {
                    Some(fl) => {
                        fl.attempts.retain(|&(id, _)| id != done.attempt);
                        (fl.delivered, !fl.attempts.is_empty())
                    }
                    None => (true, false), // stale (should not happen); treat as covered
                };
                match done.result {
                    Ok(chunk) => {
                        // Peer-level accounting already happened in the worker; here only the
                        // TRANSFER-level state advances.
                        remote_fetched += done.len;
                        last_progress = Instant::now();
                        last_seen_bytes = progress.load(Ordering::Relaxed);
                        failure_streak = 0;
                        if was_delivered {
                            // A losing twin: fully recorded above (its completion IS the
                            // exploration measurement), bytes discarded — the winner already
                            // fed the buffer, and duplicate inserts would break the disjoint-
                            // entries invariant the emitter relies on.
                            ctx.stats
                                .hedged_waste_bytes
                                .fetch_add(done.len, Ordering::Relaxed);
                            if !twins_live {
                                inflight.remove(&done.off);
                            }
                            continue;
                        }
                        if let Some(fl) = inflight.get_mut(&done.off) {
                            fl.delivered = true;
                            if !twins_live {
                                inflight.remove(&done.off);
                            }
                        }
                        em.buffered.insert(done.off, chunk.bytes);

                        match em.pump(&out, &ctx.stats).await {
                            Err(end) => {
                                ctx.stats.count_emit_end(&end);
                                workers.abort_all();
                                return;
                            }
                            Ok(Pump::Finished) => {
                                ctx.stats.transfers_completed.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                            Ok(Pump::NeedData) => {}
                            Ok(Pump::Abort(msg)) => {
                                warn!("aborting transfer of {}: {msg}", info.store_path);
                                ctx.stats.aborts_other.fetch_add(1, Ordering::Relaxed);
                                let _ = out.send(Err(std::io::Error::other(msg))).await;
                                workers.abort_all();
                                return;
                            }
                        }
                        // Merged-gap bytes (RANGE_MERGE_GAP) are fetched but never consumed —
                        // lits and replays emit from local data — so drop whatever the emitter
                        // has fully passed, or those fragments would sit in the map forever.
                        while let Some((&k, b)) = em.buffered.first_key_value() {
                            if k + b.len() as u64 <= em.emit_pos {
                                em.buffered.remove(&k);
                            } else {
                                break;
                            }
                        }

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
                                ctx.stats.aborts_min_bandwidth.fetch_add(1, Ordering::Relaxed);
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
                        // A chunk that died on its deadline BEFORE any completion means the
                        // seed size outran the link: seed the rate estimate from raw wire
                        // progress so the next carve is completable, instead of retrying an
                        // uncompletable seed chunk forever.
                        if ctx.rate_of(done.peer) <= 0.0 {
                            let seen = progress.load(Ordering::Relaxed);
                            if seen > 0 && t0.elapsed() > Duration::from_secs(5) {
                                ctx.record_rate(done.peer, seen, t0.elapsed());
                            }
                        }
                        // Requeue only when the LAST attempt died with nothing delivered: a
                        // still-flying twin may yet deliver, and a delivered range must never
                        // be fetched again.
                        if !was_delivered && !twins_live {
                            inflight.remove(&done.off);
                            ctx.stats.requeues.fetch_add(1, Ordering::Relaxed);
                            requeue.push(Reverse((done.off, done.len)));
                            retry_gate = Some(Instant::now() + Duration::from_millis(100));
                        } else if !twins_live {
                            inflight.remove(&done.off);
                        }
                        failure_streak += 1;
                        if failure_streak >= MAX_FAILURE_STREAK {
                            warn!(
                                "transfer of {} aborted: {failure_streak} consecutive chunk \
                                 failures with no completion",
                                info.store_path
                            );
                            ctx.stats.aborts_streak.fetch_add(1, Ordering::Relaxed);
                            let _ = out
                                .send(Err(std::io::Error::other("peers failing persistently")))
                                .await;
                            workers.abort_all();
                            return;
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(stall_at) => {
                // Liveness = wire BYTES, not chunk completions: sample the counter before
                // judging (a slow chunk mid-flight keeps ticking it).
                let seen = progress.load(Ordering::Relaxed);
                let now = Instant::now();
                if seen != last_seen_bytes {
                    last_seen_bytes = seen;
                    last_progress = now;
                } else if last_progress.elapsed() >= ctx.cfg_stall
                    && !inflight
                        .values()
                        .flat_map(|f| f.attempts.iter())
                        .any(|&(_, d)| d > now)
                {
                    // Silent past patience AND nothing legally in flight (an early wake from
                    // the retry gate or repoll can land here first — the in-flight guard,
                    // not the schedule, is authoritative).
                    warn!(
                        "transfer of {} stalled ({:?} without progress)",
                        info.store_path, ctx.cfg_stall
                    );
                    ctx.stats.aborts_stall.fetch_add(1, Ordering::Relaxed);
                    let _ = out.send(Err(std::io::Error::other("transfer stalled"))).await;
                    workers.abort_all();
                    return;
                }
                retry_gate = None; // the gate expired: relaunch requeued work
            }
            // A stream slot freed somewhere (any transfer, any peer): re-run the launch loop.
            _ = &mut notified, if starved => {}
        }
    }
}

// Peer selection lives inline in run_transfer's launch loop: one weighted draw over the
// available holders — the weights ARE the routing distribution, deliberately NOT conditioned
// on capacity. An UNinsured draw landing on a busy peer launches nothing (park; a wake
// retries): waiting for a busy healthy peer costs one wake interval, while handing its chunk
// to whoever happens to be idle — the old work-conserving overflow — is how a floor-weight
// straggler ended up owning every transfer's completion tail (a constant ~slots×2 s tax per
// transfer, measured 16× at 64:1 skew; docs/regret.md). An INSURED draw whose primary is busy
// proceeds on the hedge partner alone. The accepted trade: a hung-but-breaker-closed peer the
// weights still trust can idle a transfer for up to one chunk deadline before its strikes
// open the breaker — bounded by the deadline machinery.

/// Bench-only resurrection of the pre-weight-routing overflow policy (any free peer takes a
/// busy draw's chunk), so aggregation A/B comparisons measure the real old behavior. Never
/// enabled outside benches; run those benches with a name filter — the flag is process-global.
#[cfg(test)]
pub static BENCH_WORK_CONSERVING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
    fn hedge_probability_shape() {
        let fs2 = 0.03 / 1.03; // floor share against one full-weight partner
                               // At or above the uniform share, never hedge — including the single-holder case and
                               // a set of equally-weak peers (nothing better to hedge onto).
        assert_eq!(hedge_prob(1, 1.0, 0.03, 3.0), 0.0);
        assert_eq!(hedge_prob(2, 0.5, fs2, 3.0), 0.0);
        assert_eq!(hedge_prob(4, 0.30, 0.01, 3.0), 0.0);
        assert_eq!(
            hedge_prob(2, 0.5, 0.5, 3.0),
            0.0,
            "all-floor set: numerator dies first"
        );
        // AT the weight floor: fully insured, exactly.
        assert_eq!(hedge_prob(2, fs2, fs2, 3.0), 1.0);
        // A mid-recovery peer is barely insured (ν concentrates the budget at the bottom).
        let mid = hedge_prob(2, 1.0 / 3.0, fs2, 3.0);
        assert!(mid < 0.06, "{mid}");
        // Larger ν ⇒ less mid-weight hedging; h is monotone decreasing in ν on (0,1).
        assert!(hedge_prob(2, 0.2, fs2, 6.0) < hedge_prob(2, 0.2, fs2, 1.0));
    }

    #[test]
    fn unrated_peer_deadline_stays_below_the_default_stall_timeout() {
        let ctx = ctx_with("auto");
        // No rate sample: a black-holing peer must be evicted from the emission frontier well
        // before the 60 s stall watchdog would kill the whole transfer.
        assert_eq!(ctx.chunk_deadline(0, CHUNK_SEED), Duration::from_secs(20));
        // With a rate, the deadline is 8× the expected duration, clamped to [10, 300] s.
        ctx.set_rate(0, 4e6);
        assert_eq!(ctx.chunk_deadline(0, 1 << 20), Duration::from_secs(10));
        assert_eq!(ctx.chunk_deadline(0, 512 << 20), Duration::from_secs(300));
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
            pipelined: false,
        }
    }

    fn chunk_piped(enc_ms: u64, read_ms: u64, decode_ms: u64) -> crate::peers::Chunk {
        crate::peers::Chunk {
            pipelined: true,
            ..chunk_timed(enc_ms, read_ms, decode_ms)
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

    #[test]
    fn auto_level_reads_pipelined_times_as_utilizations() {
        let ms = Duration::from_millis;
        let ctx = ctx_with("auto");

        // Overlapped stages, all with slack against elapsed: wire-bound, climb. Under the old
        // serial math enc+read+decode > elapsed would have read as encode-bound and shed.
        for _ in 0..10 {
            ctx.observe_encoding(0, ms(1000), &chunk_piped(60, 700, 400));
        }
        assert_eq!(ctx.zstd_level(0), Some(19));

        // Encoder busy ~the whole elapsed window: it is barely keeping ahead — shed fast.
        for _ in 0..12 {
            ctx.observe_encoding(0, ms(1000), &chunk_piped(900, 100, 5));
        }
        assert_eq!(ctx.zstd_level(0), Some(1));

        // Disk saturated, encoder idle: hold — the level can neither help nor hurt.
        ctx.observe_encoding(0, ms(1000), &chunk_piped(50, 900, 5));
        assert_eq!(ctx.zstd_level(0), Some(1));

        // First chunk of a NAR carries no stats: open-loop ladder, not a misread of zeros.
        ctx.set_rate(0, 1e6);
        ctx.observe_encoding(0, ms(1000), &chunk_piped(0, 0, 0));
        assert_eq!(ctx.zstd_level(0), Some(19));
    }
}
