//! The mesh-index sync subsystem: two endpoints on the serve listener, one pull client, and
//! three background loops.
//!
//! Pull is the ONLY data path. A node that has news sends a tiny hint ("pull from me"); pulls
//! carry the puller's full watermark vector, which doubles as the ack stream that lets journals
//! compact (index.rs). Pulls that insert nothing trigger no further hints, so hint cascades
//! terminate exactly when the mesh has converged; pulls that do insert re-hint, which is what
//! makes propagation transitive.
//!
//! The own-db loop is the exporting half: an inotify watch on the Nix database directory (every
//! registration and GC touches the WAL) triggers a debounced diff of the Nix db against our
//! indexed self-holdings, emitting add/remove events to our own journal — with a timer fallback
//! where inotify is unavailable.

use crate::db::StoreDb;
use crate::index::{proto, Apply, Index};
use crate::peers::Peers;
use anyhow::{bail, Context, Result};
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
/// Own-db diff cadence when inotify is unavailable (and the safety-net re-scan besides).
const OWN_DB_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
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

pub struct Sync {
    pub index: Arc<Index>,
    pub peers: Arc<Peers>,
    /// The exporting half; None on a node with no [serve] (consume-only).
    db: Option<Arc<StoreDb>>,
    nix_db_dir: Option<PathBuf>,
    kicks: Vec<mpsc::Sender<()>>,
    kick_rxs: std::sync::Mutex<Vec<Option<mpsc::Receiver<()>>>>,
    hint_tx: mpsc::Sender<()>,
    hint_rx: std::sync::Mutex<Option<mpsc::Receiver<()>>>,
    /// Process start, for the catch-up cadence window.
    started: std::time::Instant,
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
        db: Option<Arc<StoreDb>>,
        nix_db_dir: Option<PathBuf>,
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
        Arc::new(Self {
            index,
            peers,
            db,
            nix_db_dir,
            kicks,
            kick_rxs: std::sync::Mutex::new(kick_rxs),
            hint_tx,
            hint_rx: std::sync::Mutex::new(Some(hint_rx)),
            started: std::time::Instant::now(),
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

    /// One full sync with a peer: pull journal suffixes / snapshots for every origin until
    /// nothing is truncated. Returns whether anything changed locally.
    pub async fn pull_from(&self, idx: usize) -> Result<bool> {
        use std::sync::atomic::Ordering::Relaxed;
        let r = self.pull_from_inner(idx).await;
        match &r {
            Ok(_) => self.stats.pulls_ok.fetch_add(1, Relaxed),
            Err(_) => self.stats.pulls_err.fetch_add(1, Relaxed),
        };
        r
    }

    async fn pull_from_inner(&self, idx: usize) -> Result<bool> {
        use std::sync::atomic::Ordering::Relaxed;
        let mut changed_any = false;
        for _ in 0..MAX_ROUNDS {
            let req = proto::SyncRequest {
                requester: self.index.self_name.clone(),
                have: self.index.clock_vector()?,
            };
            let mut resp = self.peers.sync_pull(idx, &req).await?;
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
            // Facts first: a snapshot-bearing response carries the responder's retained
            // attestations, and the snapshots' holdings should land on known facts.
            if !resp.attests.is_empty() {
                let index = self.index.clone();
                let atts = std::mem::take(&mut resp.attests);
                let n = tokio::task::spawn_blocking(move || index.merge_attests(&atts))
                    .await
                    .map_err(|e| anyhow::anyhow!("attest merge task died: {e}"))??;
                changed_any |= n > 0;
            }
            let mut truncated = false;
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
                // (changed, truncated, suffix events applied, snapshot applied)
                let out =
                    tokio::task::spawn_blocking(move || -> Result<(bool, bool, u64, bool)> {
                        match up.body {
                            None | Some(proto::origin_update::Body::UpToDate(_)) => {
                                Ok((false, false, 0, false))
                            }
                            Some(proto::origin_update::Body::Suffix(sfx)) => {
                                match index.apply_suffix(&origin, up.generation, &sfx.events)? {
                                    Apply::Applied(n) => Ok((n > 0, up.truncated, n as u64, false)),
                                    Apply::NeedSnapshot => {
                                        // Shouldn't happen against a consistent responder (it
                                        // decides suffix-vs-snapshot from OUR clock); keep the
                                        // truncated flag — a budget-deferred origin arrives as an
                                        // empty truncated suffix and must trigger the next round.
                                        warn!(
                                            "origin {origin}: suffix did not connect to our state"
                                        );
                                        Ok((false, up.truncated, 0, false))
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
                                Ok((true, false, 0, true))
                            }
                        }
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("apply task died: {e}"))??;
                changed_any |= out.0;
                truncated |= out.1;
                self.stats.suffix_events_applied.fetch_add(out.2, Relaxed);
                if out.3 {
                    self.stats.snapshots_applied.fetch_add(1, Relaxed);
                }
            }
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
        if v == self.last_data_version.load(Relaxed) {
            return Ok(0);
        }
        let index = self.index.clone();
        let n = tokio::task::spawn_blocking(move || index.sync_own_db(&db))
            .await
            .map_err(|e| anyhow::anyhow!("differ task died: {e}"))??;
        self.last_data_version.store(v, Relaxed);
        if n > 0 {
            self.stats.exports.fetch_add(1, Relaxed);
            self.stats.export_events.fetch_add(n as u64, Relaxed);
        }
        Ok(n)
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
        // The own-db exporter.
        tokio::spawn(self.clone().own_db_loop(shutdown));
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
        // DIRECTORY — the -wal file itself is checkpointed away and recreated.
        let mut events = self.nix_db_dir.as_ref().and_then(|dir| {
            let inotify = inotify::Inotify::init().ok()?;
            inotify
                .watches()
                .add(
                    dir,
                    inotify::WatchMask::MODIFY
                        | inotify::WatchMask::CREATE
                        | inotify::WatchMask::DELETE
                        | inotify::WatchMask::MOVED_TO,
                )
                .ok()?;
            let stream = inotify.into_event_stream(vec![0u8; 4096]).ok()?;
            info!("mesh index: watching {} for store changes", dir.display());
            Some(stream)
        });
        if events.is_none() {
            info!("mesh index: inotify unavailable; polling every {OWN_DB_INTERVAL:?}");
        }
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
            // Wait for the next trigger. On an event, coalesce the burst LEADING-edge: diff
            // after at most BURST_QUIET of silence, but never later than BURST_MAX — a single
            // add pays ~100 ms while a long registration burst still diffs about once a second.
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(OWN_DB_INTERVAL) => {}
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
                            warn!("mesh index: inotify stream ended; polling every {OWN_DB_INTERVAL:?}");
                            events = None;
                            continue;
                        }
                        Some(Err(_)) => {
                            err_streak += 1;
                            if err_streak >= 3 {
                                warn!("mesh index: inotify erroring persistently; polling every {OWN_DB_INTERVAL:?}");
                                events = None;
                                continue;
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
