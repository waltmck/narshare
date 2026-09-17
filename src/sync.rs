//! The mesh-index sync subsystem: two endpoints on the serve listener, one pull client, and
//! four background loops (per-peer pulls, hint fan-out, the own-db exporter, and the journal
//! catch-up engine).
//!
//! Pull is the ONLY data path. A node that has news sends a tiny hint ("pull from me"); pulls
//! carry the puller's full watermark vector, which doubles as the ack stream that lets journals
//! compact (index.rs). Pulls that insert nothing trigger no further hints, so hint cascades
//! terminate exactly when the mesh has converged; pulls that do insert re-hint, which is what
//! makes propagation transitive.
//!
//! Bodies are SINGLE-FLIGHT: each origin's suffix/snapshot stream has one server at a time
//! (a claim for the round, or the engine while a backlog is enrolled), and every other pull
//! skips it — so however many peers are configured, catch-up bytes travel once, from peers
//! chosen through the same MW pool the data plane trains.
//!
//! The own-db loop is the exporting half: an inotify watch on the Nix database directory (every
//! registration and GC touches the WAL) triggers a debounced diff of the Nix db against our
//! indexed self-holdings, emitting events to our own journal. inotify is REQUIRED: without a
//! change signal the index goes silently stale, so its absence (or death) is a hard error and
//! systemd's restart is the recovery. The only timer is the reconciliation deadline.

use crate::db::StoreDb;
use crate::index::{proto, Apply, Index};
use crate::peers::Peers;
use crate::pool::HostPool;
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Instant;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use prost::Message as _;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// Fallback pull cadence when no hints arrive. Also the reconvergence bound after a partition
/// heals with no new writes (hints only fire on changes) — and an up-to-date round trip is
/// under a kilobyte, so a tight timer costs nothing even on cellular.
const SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// While a peer's origin is entirely UNKNOWN (generation 0) and the process is young, pull on
/// this tight cadence instead. A freshly wiped cache (layout migration, cache loss, first
/// boot) otherwise leaves a multi-minute window where the proxy serves 404s for paths a
/// perfectly reachable peer holds — measured in production: a propnix FOD went to a
/// credential-demanding BUILD five minutes after a layout migration because the 60 s cadence
/// had not yet resynced the only holder. Dead peers stay cheap: the breaker still gates the
/// actual pulls, so the fast tick mostly no-ops against them.
const CATCHUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// How long after startup the catch-up cadence may apply.
const CATCHUP_WINDOW: std::time::Duration = std::time::Duration::from_secs(180);

/// Burst coalescing for db events, LEADING-edge: the first event triggers a diff after at most
/// this much quiet — the single-add case pays ~250 ms, not a fixed debounce.
const BURST_QUIET: std::time::Duration = std::time::Duration::from_millis(250);
/// …and a long registration burst (a big closure is thousands of rows over many seconds) still
/// gets a diff at least this often, so early paths of the burst don't wait for its end. A diff
/// is a full candidates + claims scan, so its cadence IS the daemon's CPU cost during a local
/// build — 5s keeps that under a few percent of a core while the mesh still learns fresh
/// paths mid-build.
const BURST_MAX: std::time::Duration = std::time::Duration::from_secs(5);
/// Sync request body cap (a clock vector is tiny).
const REQUEST_CAP: usize = 1 << 20;
/// Truncated-suffix pull rounds before giving up until the next trigger.
const MAX_ROUNDS: usize = 64;
use crate::index::DUMP_RESTART;
/// A lease older than this is void — its holder crashed mid-round or wedged. Above
/// SYNC_TIMEOUT (peers.rs) so a live-but-slow round is never poached from.
const LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(150);
/// Sync rounds at least this large on the wire train the shared MW pool; smaller exchanges
/// are latency-dominated clock chatter that would poison the throughput yardstick.
const MW_MIN_BYTES: u64 = 64 << 10;
/// Catch-up engine chunk size, in journal events. Chunks are additionally byte-capped by the
/// responder (RANGE_BYTES_CAP), so an attest-heavy interval simply comes back short and the
/// remainder is re-queued.
const CHUNK_EVENTS: u64 = 4096;
/// Range fetches in flight across ALL enrolled origins — the shared window. Bounds both the
/// parallelism and the reorder-buffer memory (window × RANGE_BYTES_CAP, decoded).
const ENGINE_WINDOW: usize = 6;
/// Consecutive failed/unreachable fetches for one origin before the engine hands it back to
/// the classic path (whose next round takes the snapshot the range asks could not).
const ENGINE_STRIKES: u32 = 3;

/// An origin's bodies flow from ONE place at a time: a classic pull round (whoever claimed it
/// for that round) or the catch-up engine. Everyone else's requests skip the origin (clock
/// lines only), so no journal or snapshot byte ever travels twice.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Holder {
    Peer(usize),
    Engine,
}

struct Lease {
    holder: Holder,
    at: Instant,
}

/// A classic round's hand-off to the engine: origin O at `generation` has a real backlog
/// reaching (at least) `target`.
struct Enroll {
    origin: String,
    generation: u64,
    target: u64,
}

/// The catch-up planner: pure bookkeeping for the windowed multi-peer journal fetch — the
/// data plane's chunk engine applied to origin journals. Per origin: a cursor (everything at
/// or below it is applied), a reorder buffer of completed chunks, and a retry queue; globally
/// one shared in-flight window. IO-free, so the scheduling is unit-testable.
#[derive(Default)]
struct Catchup {
    origins: HashMap<String, OriginPlan>,
    inflight: usize,
}

struct OriginPlan {
    generation: u64,
    /// Applied through here (mirrors the origin's clock as the engine advances it).
    cursor: u64,
    /// First seq not yet covered by any queued, in-flight, or buffered chunk.
    next: u64,
    /// Catch up through here — the highest head any peer has advertised.
    target: u64,
    /// Completed out-of-order chunks, keyed by their `after`.
    buffered: BTreeMap<u64, Vec<proto::Event>>,
    /// Intervals to (re)fetch: failures, unreachables, and byte-capped shortfalls.
    retry: VecDeque<(u64, u64)>,
    strikes: u32,
}

impl Catchup {
    /// Register an origin (or raise its target). `cursor` is its applied clock right now.
    /// False means the catch-up was CANCELLED and the caller must hand the origin back to the
    /// classic path: the origin regenerated, or — the retention-window guard — some peer
    /// advertised a head more than JOURNAL_BACKSTOP past the applied cursor, which dooms the
    /// ranges still needed (every peer's tail overtakes them within a compaction cycle; only
    /// the last JOURNAL_BACKSTOP events are guaranteed retained). Cancelling early, on the
    /// advertised clock rather than on fetch failures, keeps the cut clean: this origin
    /// restarts (as the snapshot it now requires) and no other origin's plan is touched.
    fn enroll(&mut self, origin: &str, generation: u64, cursor: u64, target: u64) -> bool {
        let p = self
            .origins
            .entry(origin.to_owned())
            .or_insert_with(|| OriginPlan {
                generation,
                cursor,
                next: cursor,
                target: cursor,
                buffered: BTreeMap::new(),
                retry: VecDeque::new(),
                strikes: 0,
            });
        if p.generation != generation {
            self.origins.remove(origin);
            return false;
        }
        p.target = p.target.max(target);
        if p.target > p.cursor.saturating_add(crate::index::JOURNAL_BACKSTOP) {
            self.origins.remove(origin);
            return false;
        }
        true
    }

    /// Next chunk to fetch, when the window has room. Retries take priority.
    fn next_ask(&mut self) -> Option<proto::RangeAsk> {
        if self.inflight >= ENGINE_WINDOW {
            return None;
        }
        for (name, p) in self.origins.iter_mut() {
            let (after, until) = if let Some(iv) = p.retry.pop_front() {
                iv
            } else if p.next < p.target {
                let after = p.next;
                let until = (after + CHUNK_EVENTS).min(p.target);
                p.next = until;
                (after, until)
            } else {
                continue;
            };
            self.inflight += 1;
            return Some(proto::RangeAsk {
                origin: name.clone(),
                generation: p.generation,
                after,
                until,
            });
        }
        None
    }

    /// Undo a dispatch that found no available peer.
    fn unpick(&mut self, ask: proto::RangeAsk) {
        self.inflight = self.inflight.saturating_sub(1);
        if let Some(p) = self.origins.get_mut(&ask.origin) {
            p.retry.push_front((ask.after, ask.until));
        }
    }

    /// A good reply landed: buffer it, re-queue any byte-capped shortfall.
    fn complete(&mut self, origin: &str, after: u64, until: u64, events: Vec<proto::Event>) {
        self.inflight = self.inflight.saturating_sub(1);
        let Some(p) = self.origins.get_mut(origin) else {
            return;
        };
        p.strikes = 0;
        let covered = events.last().map(|e| e.seq).unwrap_or(after);
        if covered < until {
            p.retry.push_back((covered, until));
        }
        if !events.is_empty() {
            p.buffered.insert(after, events);
        }
    }

    /// A fetch failed (transport, unreachable, empty, or wrong generation): re-queue and
    /// count a strike. False = give the origin back to the classic path.
    fn strike(&mut self, origin: &str, after: u64, until: u64) -> bool {
        self.inflight = self.inflight.saturating_sub(1);
        let Some(p) = self.origins.get_mut(origin) else {
            return true;
        };
        p.retry.push_back((after, until));
        p.strikes += 1;
        p.strikes < ENGINE_STRIKES
    }

    /// The contiguous head chunk, ready to apply (chunks overlapping the cursor are fine:
    /// replayed events skip inside apply_suffix).
    fn take_ready(&mut self, origin: &str) -> Option<(u64, Vec<proto::Event>)> {
        let p = self.origins.get_mut(origin)?;
        let (&after, _) = p.buffered.first_key_value()?;
        if after > p.cursor {
            return None;
        }
        let (_, events) = p.buffered.pop_first().expect("checked non-empty");
        Some((p.generation, events))
    }

    fn applied(&mut self, origin: &str, through: u64) {
        if let Some(p) = self.origins.get_mut(origin) {
            p.cursor = p.cursor.max(through);
            p.next = p.next.max(p.cursor);
        }
    }

    /// Nothing left to fetch, buffer, or apply for this origin.
    fn finished(&self, origin: &str) -> bool {
        self.origins.get(origin).is_none_or(|p| {
            p.cursor >= p.target && p.buffered.is_empty() && p.retry.is_empty()
        })
    }

    fn drop_origin(&mut self, origin: &str) {
        self.origins.remove(origin);
    }

    fn has_work(&self) -> bool {
        self.origins
            .values()
            .any(|p| !p.retry.is_empty() || p.next < p.target)
    }
}

/// The incremental differ's state: the additions watermark and the reconciliation clock.
#[derive(Clone, Copy)]
struct DiffState {
    max_id: i64,
    last_full: std::time::Instant,
}

pub struct Sync {
    pub index: Arc<Index>,
    pub peers: Arc<Peers>,
    /// The process-wide MW pool (shared with the data plane): sync routes catch-up streams by
    /// it and trains it with its transfers.
    pool: Arc<HostPool>,
    /// origin → its current body server (see Holder).
    leases: std::sync::Mutex<HashMap<String, Lease>>,
    /// Classic rounds hand real backlogs to the catch-up engine here.
    engine_tx: mpsc::UnboundedSender<Enroll>,
    engine_rx: std::sync::Mutex<Option<mpsc::UnboundedReceiver<Enroll>>>,
    /// The exporting half; None on a node with no [serve] (consume-only).
    db: Option<Arc<StoreDb>>,
    nix_db_dir: Option<PathBuf>,
    kicks: Vec<mpsc::Sender<()>>,
    kick_rxs: std::sync::Mutex<Vec<Option<mpsc::Receiver<()>>>>,
    hint_tx: mpsc::Sender<()>,
    hint_rx: std::sync::Mutex<Option<mpsc::Receiver<()>>>,
    /// Process start, for the catch-up cadence window.
    started: std::time::Instant,
    /// The incremental differ's consistency state; None forces a full reconciliation (startup).
    diff_state: std::sync::Mutex<Option<DiffState>>,
    /// Deletions and in-place db updates are detected ONLY by the periodic full
    /// reconciliation (the additions watermark cannot see them; the 410 feedback path
    /// covers fetch-facing staleness in between). Config: cache.reconcile_every.
    reconcile_every: std::time::Duration,
    /// The nix db's data_version as of the last completed diff (i64::MIN = never diffed).
    /// The differ's cheap gate: PRAGMA data_version moves only when another connection
    /// COMMITS, so timer rescans and reader-generated inotify chatter on an unchanged store
    /// cost one pragma instead of a full candidate scan.
    last_data_version: std::sync::atomic::AtomicI64,
    pub stats: SyncStats,
}

/// Cumulative sync-subsystem counters for the status endpoint.
#[derive(Default)]
pub struct SyncStats {
    pub pulls_ok: std::sync::atomic::AtomicU64,
    pub pulls_err: std::sync::atomic::AtomicU64,
    pub suffix_events_applied: std::sync::atomic::AtomicU64,
    pub snapshots_applied: std::sync::atomic::AtomicU64,
    pub self_generation_bumps: std::sync::atomic::AtomicU64,
    pub hints_received: std::sync::atomic::AtomicU64,
    pub hint_rounds_sent: std::sync::atomic::AtomicU64,
    pub exports: std::sync::atomic::AtomicU64,
    pub export_events: std::sync::atomic::AtomicU64,
    pub sync_requests_served: std::sync::atomic::AtomicU64,
}

impl Sync {
    pub fn new(
        index: Arc<Index>,
        peers: Arc<Peers>,
        pool: Arc<HostPool>,
        db: Option<Arc<StoreDb>>,
        nix_db_dir: Option<PathBuf>,
        reconcile_every: std::time::Duration,
    ) -> Arc<Self> {
        let n = peers.list.len();
        let mut kicks = Vec::with_capacity(n);
        let mut kick_rxs = Vec::with_capacity(n);
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(1);
            kicks.push(tx);
            kick_rxs.push(Some(rx));
        }
        let (hint_tx, hint_rx) = mpsc::channel(1);
        let (engine_tx, engine_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            index,
            peers,
            pool,
            leases: std::sync::Mutex::new(HashMap::new()),
            engine_tx,
            engine_rx: std::sync::Mutex::new(Some(engine_rx)),
            db,
            nix_db_dir,
            kicks,
            kick_rxs: std::sync::Mutex::new(kick_rxs),
            hint_tx,
            hint_rx: std::sync::Mutex::new(Some(hint_rx)),
            started: std::time::Instant::now(),
            diff_state: std::sync::Mutex::new(None),
            reconcile_every,
            last_data_version: std::sync::atomic::AtomicI64::new(i64::MIN),
            stats: SyncStats::default(),
        })
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/narshare/v2/sync", post(handle_sync))
            .route("/narshare/v2/sync-hint", post(handle_hint))
            .with_state(self.clone())
    }

    /// Claim unleased (or stale-leased) origins for this round and return the ones to SKIP —
    /// origins another peer's loop is actively serving. Claims live one round: settle_leases
    /// releases whatever this responder had nothing more for, so a lease never outlives its
    /// use by more than a round (or LEASE_TTL, when its holder died mid-round).
    fn claim_origins(&self, idx: usize, have: &[proto::OriginClock]) -> Vec<String> {
        let now = Instant::now();
        let mut leases = self.leases.lock().unwrap();
        let mut skip = Vec::new();
        for c in have {
            match leases.get_mut(&c.origin) {
                // Engine leases are exempt from the TTL: the engine removes them itself on
                // completion or abort, and poaching one would double-serve its ranges.
                Some(l) if l.holder == Holder::Engine => skip.push(c.origin.clone()),
                Some(l) if l.holder == Holder::Peer(idx) => l.at = now,
                Some(l) if now.duration_since(l.at) < LEASE_TTL => skip.push(c.origin.clone()),
                _ => {
                    leases.insert(
                        c.origin.clone(),
                        Lease {
                            holder: Holder::Peer(idx),
                            at: now,
                        },
                    );
                }
            }
        }
        skip
    }

    /// Round settlement: release everything this loop claimed, then hand origins with a real
    /// remaining backlog — a truncated suffix that carried events — to the catch-up engine
    /// (windowed, multi-peer, weighted per chunk; see engine_loop). Clock lines for origins
    /// the engine already owns raise its targets, so news keeps flowing while enrolled.
    /// Budget-deferred bodies (truncated but EMPTY) stay with the classic round loop: they
    /// are snapshots waiting for budget, not fetchable ranges.
    fn settle_leases(&self, idx: usize, adv: &[(String, u64, u64, bool)]) {
        let mut enrolls: Vec<Enroll> = Vec::new();
        {
            let now = Instant::now();
            let mut leases = self.leases.lock().unwrap();
            leases.retain(|_, l| l.holder != Holder::Peer(idx));
            for (origin, gen, seq, fresh_backlog) in adv {
                let engine_held =
                    leases.get(origin).map(|l| l.holder) == Some(Holder::Engine);
                if *fresh_backlog {
                    leases.insert(
                        origin.clone(),
                        Lease {
                            holder: Holder::Engine,
                            at: now,
                        },
                    );
                }
                if *fresh_backlog || engine_held {
                    enrolls.push(Enroll {
                        origin: origin.clone(),
                        generation: *gen,
                        target: *seq,
                    });
                }
            }
        }
        for e in enrolls {
            let _ = self.engine_tx.send(e);
        }
    }

    /// Give an origin back to the classic path: drop its engine lease and kick every loop so
    /// whoever is available re-serves it (usually as the snapshot the ranges could not be).
    fn unenroll(&self, origin: &str) {
        self.leases.lock().unwrap().remove(origin);
        for k in &self.kicks {
            let _ = k.try_send(());
        }
    }

    /// One full sync with a peer: pull journal suffixes / snapshots for every origin until
    /// nothing is truncated. Returns whether anything changed locally.
    pub async fn pull_from(&self, idx: usize) -> Result<bool> {
        use std::sync::atomic::Ordering::Relaxed;
        let r = self.pull_from_inner(idx).await;
        match &r {
            Ok(_) => {
                self.stats.pulls_ok.fetch_add(1, Relaxed);
            }
            Err(_) => {
                self.stats.pulls_err.fetch_add(1, Relaxed);
                // Whatever this loop was serving must not stay parked behind a broken pull:
                // release it all; the next loop to fire re-claims and re-routes.
                self.leases.lock().unwrap().retain(|_, l| l.holder != Holder::Peer(idx));
            }
        };
        r
    }

    async fn pull_from_inner(&self, idx: usize) -> Result<bool> {
        use std::sync::atomic::Ordering::Relaxed;
        let mut changed_any = false;
        for _ in 0..MAX_ROUNDS {
            let have = self.index.clock_vector()?;
            let skip_origins = self.claim_origins(idx, &have);
            let req = proto::SyncRequest {
                requester: self.index.self_name.clone(),
                have,
                // Resume a fact dump a previous pull (or round, or PROCESS) left unfinished —
                // the cursor is persisted per response below, so a pull that dies mid-dump
                // resumes later instead of dropping the tail of the responder's facts.
                atts_cursor: self.index.dump_cursor(&self.peers.list[idx].name)?,
                skip_origins,
                ranges: vec![],
            };
            let t0 = Instant::now();
            let mut resp = match self.peers.sync_pull(idx, &req).await {
                Ok((resp, wire)) => {
                    if wire >= MW_MIN_BYTES {
                        // A catch-up round is a real transfer: train the shared MW pool, so
                        // sync traffic teaches the same "which peers are fast" weights the
                        // data plane routes by. Up-to-date exchanges are latency-dominated
                        // clock chatter — recording those would poison the rate yardstick.
                        self.pool.record_success(idx, wire, t0.elapsed());
                    }
                    resp
                }
                Err(e) => {
                    // Transport failure: train the pool alongside the breaker strike that
                    // sync_pull already recorded, so routing drains off this peer quickly.
                    self.pool.record_failure(idx);
                    return Err(e);
                }
            };
            let expect = &self.peers.list[idx].name;
            if &resp.responder != expect {
                bail!(
                    "peer at {} identifies as {:?} but this config names it {:?} — origin \
                     names must agree mesh-wide",
                    self.peers.list[idx].base,
                    resp.responder,
                    expect
                );
            }
            // Facts first: a snapshot-bearing response carries a page of the responder's
            // retained attestations, and the snapshots' holdings should land on known facts.
            if !resp.attests.is_empty() {
                let index = self.index.clone();
                let atts = std::mem::take(&mut resp.attests);
                let n = tokio::task::spawn_blocking(move || index.merge_attests(&atts))
                    .await
                    .map_err(|e| anyhow::anyhow!("attest merge task died: {e}"))??;
                changed_any |= n > 0;
            }
            // A possession snapshot in this response FORFEITS journal events wholesale (the
            // apply jumps our clock for that origin), including the Attest events those
            // journals carried. Snapshots ship only on a regeneration or when compaction
            // genuinely overran our watermark — the rare recovery path, never ordinary lag —
            // so re-teach the facts from scratch, from EVERY peer: their tables differ, and
            // whichever peer happened to serve the snapshot may not be the one holding the
            // fact we dropped.
            let has_snapshot = resp
                .origins
                .iter()
                .any(|u| matches!(u.body, Some(proto::origin_update::Body::Snapshot(_))));

            // Persist the dump cursor AFTER the page merged and BEFORE applying origin
            // updates: the write is synchronous and its fsync also lands the page merge above
            // (see Index::dump_cursor), so no crash can leave the cursor ahead of its facts —
            // and a crash between an invalidation and its snapshot apply merely re-offers the
            // snapshot, which re-invalidates. Skipped when unchanged, so the steady state (no
            // dump in flight) writes nothing.
            let next = if has_snapshot {
                DUMP_RESTART.to_vec()
            } else if resp.atts_truncated {
                std::mem::take(&mut resp.atts_next)
            } else {
                Vec::new()
            };
            let restarted = next == DUMP_RESTART;
            if next != req.atts_cursor || has_snapshot {
                let index = self.index.clone();
                let peer = self.peers.list[idx].name.clone();
                tokio::task::spawn_blocking(move || -> Result<()> {
                    if next != index.dump_cursor(&peer)? {
                        index.set_dump_cursor(&peer, &next)?;
                    }
                    if has_snapshot {
                        index.restart_all_dumps()?;
                    }
                    Ok(())
                })
                .await
                .map_err(|e| anyhow::anyhow!("cursor park task died: {e}"))??;
            }
            let mut truncated = resp.atts_truncated || restarted;
            // Every known origin's advertised clock, plus whether THIS responder left it with
            // a real backlog (a truncated suffix that carried events) — the engine hand-off
            // computed at settlement below.
            let mut adv: Vec<(String, u64, u64, bool)> = Vec::new();
            for up in resp.origins {
                if up.origin == self.index.self_name {
                    // Only we author our own set — but a peer reporting a FUTURE for it means
                    // our self-clock regressed (cache restored from an image, WAL reverted by
                    // power loss, a backwards wall clock at generation mint): the mesh
                    // remembers seqs we no longer own, and anything we now publish under them
                    // would be silently ignored ("up to date") or mis-applied. Remint our
                    // generation above theirs; their next pulls snapshot-resync us cleanly.
                    let (g, s) = self.index.origin_clock(&self.index.self_name)?;
                    if up.generation > g || (up.generation == g && up.seq > s) {
                        warn!(
                            "peer {} knows a future of our own origin (gen {} seq {} vs our \
                             gen {g} seq {s}): self-clock regression — reminting generation",
                            self.peers.list[idx].name, up.generation, up.seq
                        );
                        let index = self.index.clone();
                        let floor = up.generation;
                        tokio::task::spawn_blocking(move || index.bump_self_generation(floor))
                            .await
                            .map_err(|e| anyhow::anyhow!("bump task died: {e}"))??;
                        self.stats.self_generation_bumps.fetch_add(1, Relaxed);
                        self.hint_peers();
                    }
                    continue;
                }
                if !self.index.is_known_origin(&up.origin) {
                    continue; // unknown origins are rejected
                }
                let index = self.index.clone();
                let origin = up.origin.clone();
                let oname = up.origin.clone();
                let (ogen, oseq) = (up.generation, up.seq);
                // (changed, truncated, suffix events applied, snapshot applied, had events)
                let out =
                    tokio::task::spawn_blocking(move || -> Result<(bool, bool, u64, bool, bool)> {
                        match up.body {
                            None | Some(proto::origin_update::Body::UpToDate(_)) => {
                                Ok((false, false, 0, false, false))
                            }
                            Some(proto::origin_update::Body::Suffix(sfx)) => {
                                let had = !sfx.events.is_empty();
                                match index.apply_suffix(&origin, up.generation, &sfx.events)? {
                                    Apply::Applied(n) => {
                                        Ok((n > 0, up.truncated, n as u64, false, had))
                                    }
                                    Apply::NeedSnapshot => {
                                        // Shouldn't happen against a consistent responder (it
                                        // decides suffix-vs-snapshot from OUR clock); keep the
                                        // truncated flag — a budget-deferred origin arrives as an
                                        // empty truncated suffix and must trigger the next round.
                                        // Not engine-worthy: ranges cannot connect either.
                                        warn!(
                                            "origin {origin}: suffix did not connect to our state"
                                        );
                                        Ok((false, up.truncated, 0, false, false))
                                    }
                                }
                            }
                            Some(proto::origin_update::Body::Snapshot(snap)) => {
                                let n = index.apply_snapshot(
                                    &origin,
                                    up.generation,
                                    up.seq,
                                    &snap.held,
                                )?;
                                // INFO, deliberately: snapshot applies are rare, major state
                                // transitions, and the one timestamp that answers "when did this
                                // node learn that origin" during an incident.
                                info!(
                                    "origin {origin}: snapshot applied ({n} rows, gen {}, seq {})",
                                    up.generation, up.seq
                                );
                                Ok((true, false, 0, true, false))
                            }
                        }
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("apply task died: {e}"))??;
                changed_any |= out.0;
                // Real backlogs go to the catch-up engine at settlement; only budget-deferred
                // bodies (truncated but empty — snapshots waiting their turn) keep THIS round
                // loop spinning.
                let fresh_backlog = out.1 && out.4;
                truncated |= out.1 && !out.4;
                adv.push((oname, ogen, oseq, fresh_backlog));
                self.stats.suffix_events_applied.fetch_add(out.2, Relaxed);
                if out.3 {
                    self.stats.snapshots_applied.fetch_add(1, Relaxed);
                }
            }
            self.settle_leases(idx, &adv);
            if !truncated {
                break;
            }
        }
        if changed_any {
            // Compaction rides sync REQUESTS elsewhere (handle_sync), but a consume-only node
            // never receives one — without this its relayed journals would grow forever.
            let index = self.index.clone();
            tokio::task::spawn_blocking(move || index.maybe_compact())
                .await
                .map_err(|e| anyhow::anyhow!("compact task died: {e}"))??;
        }
        Ok(changed_any)
    }

    /// Diff the Nix db against our indexed self-holdings once (the exporting half).
    ///
    /// Gated on the db's data_version: the version is sampled BEFORE the diff and stored only
    /// after a successful one, so a write landing mid-diff bumps the version again and the
    /// next trigger re-diffs — at-least-once, never lost. An unchanged version means the
    /// store is byte-for-byte as last diffed and the whole scan is skipped.
    pub async fn export_own_db(&self) -> Result<usize> {
        use std::sync::atomic::Ordering::Relaxed;
        let Some(db) = self.db.clone() else {
            return Ok(0);
        };
        let v = {
            let db = db.clone();
            tokio::task::spawn_blocking(move || db.data_version())
                .await
                .map_err(|e| anyhow::anyhow!("gate task died: {e}"))??
        };
        let st = *self.diff_state.lock().unwrap();
        // The periodic reconciliation must run even on a QUIET db: a GC's final commit makes
        // one gated-in wake (which sees no additions), and nothing bumps data_version
        // afterwards — the deletion would otherwise wait for an unrelated commit. The 60s
        // own-db timer keeps calling us; reconcile-due bypasses the gate.
        let reconcile_due = st
            .map(|s| s.last_full.elapsed() >= self.reconcile_every)
            .unwrap_or(true);
        if !reconcile_due && v == self.last_data_version.load(Relaxed) {
            return Ok(0);
        }
        let index = self.index.clone();
        let (n, new_state) = tokio::task::spawn_blocking(move || -> Result<(usize, DiffState)> {
            let now = std::time::Instant::now();
            // A full reconciliation captures its watermark BEFORE scanning, so rows committed
            // mid-scan land above it and are re-examined (idempotently) on the next wake.
            let full = |reason: &str| -> Result<(usize, DiffState)> {
                if !reason.is_empty() {
                    tracing::debug!("full reconciliation: {reason}");
                }
                let (_, max_id) = db.additions_since(i64::MAX)?;
                let n = index.sync_own_db(&db)?;
                Ok((
                    n,
                    DiffState {
                        max_id,
                        last_full: now,
                    },
                ))
            };
            let Some(mut s) = st else { return full("") };
            if reconcile_due {
                return full("periodic");
            }
            // The watermark is sound only while ids are monotone (AUTOINCREMENT): a reused id
            // would hide an addition below the watermark. Guarded per wake.
            if !db.ids_monotone()? {
                return full("ValidPaths.id is not AUTOINCREMENT on this system");
            }
            let (cands, max_id) = db.additions_since(s.max_id)?;
            let n = index.sync_own_db_incremental(&db, &cands)?;
            s.max_id = max_id;
            Ok((n, s))
        })
        .await
        .map_err(|e| anyhow::anyhow!("differ task died: {e}"))??;
        *self.diff_state.lock().unwrap() = Some(new_state);
        self.last_data_version.store(v, Relaxed);
        if n > 0 {
            self.stats.exports.fetch_add(1, Relaxed);
            self.stats.export_events.fetch_add(n as u64, Relaxed);
        }
        Ok(n)
    }

    /// Test hook: make the next wake take the full-reconciliation path.
    #[cfg(test)]
    pub fn force_reconcile(&self) {
        *self.diff_state.lock().unwrap() = None;
        self.last_data_version
            .store(i64::MIN, std::sync::atomic::Ordering::Relaxed);
    }

    /// Nudge every peer to pull from us (debounced by the hint loop).
    pub fn hint_peers(&self) {
        let _ = self.hint_tx.try_send(());
    }

    pub fn spawn_loops(self: &Arc<Self>, shutdown: watch::Receiver<()>) {
        // Per-peer pull loops.
        let rxs = std::mem::take(&mut *self.kick_rxs.lock().unwrap());
        for (idx, rx) in rxs.into_iter().enumerate() {
            let Some(rx) = rx else { continue };
            tokio::spawn(self.clone().peer_loop(idx, rx, shutdown.clone()));
        }
        // The hint fan-out loop.
        if let Some(rx) = self.hint_rx.lock().unwrap().take() {
            tokio::spawn(self.clone().hint_loop(rx, shutdown.clone()));
        }
        // The journal catch-up engine.
        if let Some(rx) = self.engine_rx.lock().unwrap().take() {
            tokio::spawn(self.clone().engine_loop(rx, shutdown.clone()));
        }
        // The own-db exporter.
        tokio::spawn(self.clone().own_db_loop(shutdown));
    }

    /// The journal catch-up engine: the data plane's windowed chunk scheduling applied to
    /// origin journals. Classic rounds enroll an origin when its suffix comes back truncated
    /// with events (a real backlog); the engine then fetches (cursor, target] as parallel
    /// seq-range chunks — each assigned per fetch through the shared MW pool, exactly like
    /// NAR chunks — reorders them in a bounded buffer, and applies the contiguous prefix in
    /// order. Failures and byte-capped shortfalls re-queue at chunk granularity; an origin
    /// whose ranges keep coming back unreachable (compacted, regenerated) goes back to the
    /// classic path, whose next round takes the snapshot. While enrolled, an origin is
    /// lease-held by the engine, so classic rounds everywhere send clock lines only and every
    /// journal byte travels exactly once, from the fastest peers the weights know about.
    async fn engine_loop(
        self: Arc<Self>,
        mut enroll_rx: mpsc::UnboundedReceiver<Enroll>,
        mut shutdown: watch::Receiver<()>,
    ) {
        let mut plan = Catchup::default();
        let (done_tx, mut done_rx) =
            mpsc::unbounded_channel::<(proto::RangeAsk, Option<proto::RangeReply>)>();
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                Some(e) = enroll_rx.recv() => {
                    match self.index.origin_clock(&e.origin) {
                        Ok((g, s)) if g == e.generation && s < e.target => {
                            // enroll() may CANCEL instead: regeneration, or the head has
                            // outrun the retention window past our cursor (any peer's clock
                            // line delivers that signal here, at any point in the catch-up).
                            if !plan.enroll(&e.origin, e.generation, s, e.target) {
                                self.unenroll(&e.origin);
                            }
                        }
                        // Wrong generation (the classic path will snapshot it) or already
                        // caught up: make sure no engine lease lingers for it.
                        _ => {
                            if !plan.origins.contains_key(&e.origin) {
                                self.unenroll(&e.origin);
                            }
                        }
                    }
                }
                Some((ask, reply)) = done_rx.recv() => {
                    let origin = ask.origin.clone();
                    match reply {
                        Some(r)
                            if r.reachable
                                && r.generation == ask.generation
                                && !r.events.is_empty() =>
                        {
                            plan.complete(&origin, ask.after, ask.until, r.events);
                            self.drain_applies(&mut plan, &origin).await;
                        }
                        _ => {
                            if !plan.strike(&origin, ask.after, ask.until) {
                                debug!(
                                    "catch-up ranges for origin {origin} keep failing: \
                                     back to the classic path"
                                );
                                plan.drop_origin(&origin);
                                self.unenroll(&origin);
                            }
                        }
                    }
                }
                // Work is queued but nothing is in flight (every peer was unavailable at the
                // last dispatch): retry on a timer rather than spinning.
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)),
                    if plan.inflight == 0 && plan.has_work() => {}
            }
            // Fill the window: one weighted draw per chunk, exactly like the data plane.
            while let Some(ask) = plan.next_ask() {
                let available: Vec<usize> = (0..self.peers.list.len())
                    .filter(|&i| self.peers.list[i].available())
                    .collect();
                let Some(peer) = self.pool.pick_among(&available) else {
                    plan.unpick(ask);
                    break;
                };
                let peers = self.peers.clone();
                let pool = self.pool.clone();
                let requester = self.index.self_name.clone();
                let tx = done_tx.clone();
                tokio::spawn(async move {
                    let req = proto::SyncRequest {
                        requester,
                        have: vec![],
                        atts_cursor: Vec::new(),
                        skip_origins: vec![],
                        ranges: vec![ask.clone()],
                    };
                    let t0 = Instant::now();
                    let reply = match peers.sync_pull(peer, &req).await {
                        Ok((resp, wire)) => {
                            match resp
                                .range_replies
                                .into_iter()
                                .find(|r| r.origin == ask.origin && r.after == ask.after)
                            {
                                Some(r) => {
                                    if wire >= MW_MIN_BYTES {
                                        pool.record_success(peer, wire, t0.elapsed());
                                    }
                                    Some(r)
                                }
                                None => {
                                    // Ranges shipped as a flag day: every mesh node answers
                                    // them. A response without ours is a broken (or ancient)
                                    // peer, not a condition to quietly work around.
                                    warn!(
                                        "peer {} ignored a journal-range ask — mixed \
                                         narshare versions do not sync",
                                        peers.list[peer].name
                                    );
                                    pool.record_failure(peer);
                                    None
                                }
                            }
                        }
                        Err(_) => {
                            pool.record_failure(peer);
                            None
                        }
                    };
                    let _ = tx.send((ask, reply));
                });
            }
        }
    }

    /// Apply every contiguous chunk at the head of an origin's reorder buffer, in order.
    /// Chunks overlapping the cursor are fine — replayed events skip inside apply_suffix.
    async fn drain_applies(&self, plan: &mut Catchup, origin: &str) {
        use std::sync::atomic::Ordering::Relaxed;
        let mut applied_any = false;
        while let Some((generation, events)) = plan.take_ready(origin) {
            let last = events.last().map(|e| e.seq).unwrap_or(0);
            let index = self.index.clone();
            let o = origin.to_owned();
            let out =
                tokio::task::spawn_blocking(move || index.apply_suffix(&o, generation, &events))
                    .await;
            match out {
                Ok(Ok(Apply::Applied(n))) => {
                    self.stats.suffix_events_applied.fetch_add(n as u64, Relaxed);
                    applied_any |= n > 0;
                    plan.applied(origin, last);
                }
                // A gap (regeneration, concurrent surgery) or a store error: the classic
                // path re-learns this origin wholesale.
                _ => {
                    plan.drop_origin(origin);
                    self.unenroll(origin);
                    break;
                }
            }
        }
        if plan.finished(origin) {
            plan.drop_origin(origin);
            self.unenroll(origin);
        }
        if applied_any {
            self.hint_peers(); // news travels transitively, however it arrived
        }
    }

    async fn peer_loop(
        self: Arc<Self>,
        idx: usize,
        mut kick: mpsc::Receiver<()>,
        mut shutdown: watch::Receiver<()>,
    ) {
        let mut was_ok = true;
        loop {
            if self.peers.list[idx].available() {
                match self.pull_from(idx).await {
                    Ok(changed) => {
                        if !was_ok {
                            info!("sync with {} recovered", self.peers.list[idx].name);
                        }
                        was_ok = true;
                        if changed {
                            self.hint_peers(); // news travels transitively
                        }
                    }
                    Err(e) => {
                        // WARN on the TRANSITION into failure only (a dead peer's steady
                        // failures stay at debug): a pull that reaches the peer but dies in
                        // decode/apply was previously invisible at info — which made a
                        // production "the index stayed empty for 5+ minutes while the peer
                        // was reachable" incident undiagnosable from the journal.
                        if was_ok {
                            warn!("sync with {} failing: {e:#}", self.peers.list[idx].name);
                        } else {
                            debug!("sync with {}: {e:#}", self.peers.list[idx].name);
                        }
                        was_ok = false;
                    }
                }
            }
            // Catch-up: an origin we know NOTHING about yet gets chased tightly while the
            // process is young (see CATCHUP_INTERVAL).
            let interval = if self.started.elapsed() < CATCHUP_WINDOW
                && self
                    .index
                    .origin_clock(&self.peers.list[idx].name)
                    .map(|(g, _)| g == 0)
                    .unwrap_or(false)
            {
                CATCHUP_INTERVAL
            } else {
                SYNC_INTERVAL
            };
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(interval) => {}
                Some(()) = kick.recv() => {
                    // Pull immediately; queued repeats coalesce (an up-to-date pull is <1 KB,
                    // so an extra round costs nothing).
                    while kick.try_recv().is_ok() {}
                }
            }
        }
    }

    async fn hint_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<()>,
        mut shutdown: watch::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                msg = rx.recv() => {
                    if msg.is_none() { return; }
                    // Leading edge, CONCURRENT fan-out: a dead peer's 5 s hint timeout must
                    // not delay anyone else's. Repeats queued meanwhile coalesce into the
                    // channel's single slot and trigger one more (cheap) round. Breaker-open
                    // peers are skipped — a hint is an optimization, not a probe; they catch
                    // up on their own sync timer once they recover.
                    self.stats
                        .hint_rounds_sent
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    for idx in 0..self.peers.list.len() {
                        if !self.peers.list[idx].available() {
                            continue;
                        }
                        let peers = self.peers.clone();
                        let from = self.index.self_name.clone();
                        tokio::spawn(async move { peers.hint(idx, &from).await });
                    }
                }
            }
        }
    }

    async fn own_db_loop(self: Arc<Self>, mut shutdown: watch::Receiver<()>) {
        if self.db.is_none() {
            return;
        }
        // inotify on the Nix db directory: registrations and GC both touch the WAL. Watch the
        // DIRECTORY — the -wal file itself is checkpointed away and recreated. MANDATORY:
        // narshare without a change signal serves a silently stale index, which is worse than
        // not running; systemd restarts us into an environment where it hopefully works.
        let mut events = match self.nix_db_dir.as_ref().map(|dir| {
            let inotify = inotify::Inotify::init()?;
            inotify.watches().add(
                dir,
                inotify::WatchMask::MODIFY
                    | inotify::WatchMask::CREATE
                    | inotify::WatchMask::DELETE
                    | inotify::WatchMask::MOVED_TO,
            )?;
            let stream = inotify.into_event_stream(vec![0u8; 4096])?;
            tracing::info!("mesh index: watching {} for store changes", dir.display());
            Ok::<_, std::io::Error>(stream)
        }) {
            Some(Ok(s)) => Some(s),
            Some(Err(e)) => {
                tracing::error!("inotify on the nix db is REQUIRED and unavailable ({e}): exiting");
                std::process::exit(1);
            }
            None => None,
        };
        let mut err_streak = 0u32;
        loop {
            match self.export_own_db().await {
                Ok(n) if n > 0 => {
                    info!("mesh index: exported {n} local change(s)");
                    self.hint_peers();
                }
                Ok(_) => {}
                Err(e) => warn!("mesh index: own-db diff failed: {e:#}"),
            }
            // Wait for the next trigger: an inotify event (burst-coalesced, leading edge) or
            // the reconciliation deadline — the ONLY timer, needed because a quiet db emits
            // no events yet deletions/in-place updates still owe their periodic detection.
            let next_reconcile = {
                let due = self
                    .diff_state
                    .lock()
                    .unwrap()
                    .map(|s| s.last_full + self.reconcile_every)
                    .unwrap_or_else(std::time::Instant::now);
                tokio::time::Instant::from_std(
                    due.max(std::time::Instant::now() + std::time::Duration::from_secs(1)),
                )
            };
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep_until(next_reconcile) => {}
                item = async {
                    match events.as_mut() {
                        Some(s) => {
                            use tokio_stream::StreamExt as _;
                            s.next().await
                        }
                        None => std::future::pending().await,
                    }
                } => {
                    // A dead or ended stream must not become a hot loop of instant wakeups —
                    // fall back to the timer, which the loop already supports.
                    match &item {
                        None => {
                            tracing::error!(
                                "mesh index: inotify stream ended — a dead watch means a \
                                 silently stale index; exiting for a clean restart"
                            );
                            std::process::exit(1);
                        }
                        Some(Err(e)) => {
                            err_streak += 1;
                            if err_streak >= 3 {
                                tracing::error!(
                                    "mesh index: inotify erroring persistently ({e}); exiting \
                                     for a clean restart"
                                );
                                std::process::exit(1);
                            }
                        }
                        Some(Ok(_)) => err_streak = 0,
                    }
                    if let Some(s) = events.as_mut() {
                        use tokio_stream::StreamExt as _;
                        let deadline = tokio::time::Instant::now() + BURST_MAX;
                        while tokio::time::Instant::now() < deadline {
                            match tokio::time::timeout(BURST_QUIET, s.next()).await {
                                Ok(Some(Ok(_))) => continue, // still bursting
                                _ => break,                  // quiet or erroring — go diff
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn handle_sync(State(s): State<Arc<Sync>>, body: bytes::Bytes) -> Response {
    if body.len() > REQUEST_CAP {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Ok(req) = proto::SyncRequest::decode(&body[..]) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if req.requester == s.index.self_name || !s.index.is_known_origin(&req.requester) {
        warn!("sync request from unknown node {:?} refused", req.requester);
        return StatusCode::FORBIDDEN.into_response();
    }
    let index = s.index.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        // The request's clock vector IS the ack stream: record it, then answer, then use the
        // fresh watermarks to compact opportunistically.
        index.record_watermarks(&req.requester, &req.have)?;
        let bundle = index.respond(&req)?;
        let resp = proto::SyncResponse {
            responder: index.self_name.clone(),
            origins: bundle.origins,
            attests: bundle.attests,
            atts_truncated: bundle.atts_next.is_some(),
            atts_next: bundle.atts_next.unwrap_or_default(),
            range_replies: bundle.ranges,
        };
        let z = zstd::stream::encode_all(&resp.encode_to_vec()[..], 3)
            .context("compressing sync response")?;
        index.maybe_compact()?;
        Ok(z)
    })
    .await
    .unwrap_or_else(|e| Err(anyhow::anyhow!("sync respond task died: {e}")));
    match out {
        Ok(z) => {
            s.stats
                .sync_requests_served
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ([(header::CONTENT_TYPE, "application/x-narshare-sync")], z).into_response()
        }
        Err(e) => {
            warn!("sync response failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "sync failed\n").into_response()
        }
    }
}

async fn handle_hint(State(s): State<Arc<Sync>>, body: bytes::Bytes) -> StatusCode {
    if body.len() > 4096 {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    let Ok(hint) = proto::SyncHint::decode(&body[..]) else {
        return StatusCode::BAD_REQUEST;
    };
    if let Some(idx) = s.peers.idx_of(&hint.from) {
        s.stats
            .hints_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = s.kicks[idx].try_send(());
    }
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64) -> proto::Event {
        proto::Event { seq, op: None }
    }

    fn evs(range: std::ops::RangeInclusive<u64>) -> Vec<proto::Event> {
        range.map(ev).collect()
    }

    #[test]
    fn catchup_chunks_window_and_orders_applies() {
        let mut c = Catchup::default();
        c.enroll("a", 1, 0, 10_000);
        // Chunks come out CHUNK_EVENTS at a time, window-capped.
        let a1 = c.next_ask().unwrap();
        assert_eq!((a1.after, a1.until), (0, CHUNK_EVENTS));
        let a2 = c.next_ask().unwrap();
        assert_eq!((a2.after, a2.until), (CHUNK_EVENTS, 2 * CHUNK_EVENTS));
        let a3 = c.next_ask().unwrap();
        assert_eq!((a3.after, a3.until), (2 * CHUNK_EVENTS, 10_000));
        assert!(c.next_ask().is_none(), "no work past the target");

        // Out-of-order completion: nothing is ready until the head chunk lands.
        c.complete("a", a2.after, a2.until, evs(a2.after + 1..=a2.until));
        assert!(c.take_ready("a").is_none());
        c.complete("a", a1.after, a1.until, evs(1..=a1.until));
        let (generation, events) = c.take_ready("a").unwrap();
        assert_eq!(generation, 1);
        assert_eq!(events.last().unwrap().seq, a1.until);
        c.applied("a", a1.until);
        // Now the buffered second chunk is contiguous.
        let (_, events) = c.take_ready("a").unwrap();
        assert_eq!(events.last().unwrap().seq, a2.until);
        c.applied("a", a2.until);
        assert!(!c.finished("a"), "third chunk still in flight");
        c.complete("a", a3.after, a3.until, evs(a3.after + 1..=a3.until));
        let (_, events) = c.take_ready("a").unwrap();
        c.applied("a", events.last().unwrap().seq);
        assert!(c.finished("a"));
        assert_eq!(c.inflight, 0);
    }

    #[test]
    fn catchup_requeues_shortfalls_and_failures() {
        let mut c = Catchup::default();
        c.enroll("a", 1, 0, 2 * CHUNK_EVENTS);
        let a1 = c.next_ask().unwrap();
        // Byte-capped short reply: the remainder is re-queued and served before new ground.
        c.complete("a", a1.after, a1.until, evs(1..=100));
        let retry = c.next_ask().unwrap();
        assert_eq!((retry.after, retry.until), (100, CHUNK_EVENTS));
        // Failure re-queues too; three consecutive strikes abort.
        assert!(c.strike("a", retry.after, retry.until));
        assert!(c.strike("a", retry.after, retry.until));
        assert!(!c.strike("a", retry.after, retry.until), "third strike aborts");
        // A window slot that found no peer goes back to the FRONT.
        let again = c.next_ask().unwrap();
        c.unpick(again.clone());
        let front = c.next_ask().unwrap();
        assert_eq!((front.after, front.until), (again.after, again.until));
        assert_eq!(c.inflight, 1);
    }

    #[test]
    fn catchup_window_cap_and_regen() {
        let mut c = Catchup::default();
        assert!(c.enroll("a", 1, 0, 50_000));
        for _ in 0..ENGINE_WINDOW {
            assert!(c.next_ask().is_some());
        }
        assert!(c.next_ask().is_none(), "the shared window caps in-flight");
        // Enrolling a NEW generation voids the plan.
        assert!(!c.enroll("a", 2, 0, 10));
        assert!(c.finished("a"), "a regenerated origin leaves the engine");
    }

    #[test]
    fn catchup_cancels_past_the_retention_window() {
        let backstop = crate::index::JOURNAL_BACKSTOP;
        let mut c = Catchup::default();
        // A fresh enrollment already beyond the window never starts: the ranges it needs
        // will be compacted away everywhere before they can land.
        assert!(!c.enroll("a", 1, 0, backstop + 1));
        assert!(c.finished("a"));
        // A running catch-up cancels the moment ANY peer's clock line advertises a head
        // beyond cursor + retention — and only that origin.
        assert!(c.enroll("a", 1, 0, 10_000));
        assert!(c.enroll("b", 1, 0, 10_000));
        assert!(c.next_ask().is_some());
        assert!(!c.enroll("a", 1, 0, backstop + 1));
        assert!(c.finished("a"));
        assert!(!c.finished("b"), "other origins' plans are untouched");
        // Progress slides the window: an advanced cursor tolerates the same head.
        assert!(c.enroll("c", 1, 60_000, 60_000 + backstop));
    }
}
