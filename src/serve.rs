//! The serve listener: a standard Nix binary-cache over the local store.
//!
//!   GET /nix-cache-info
//!   GET|HEAD /<hashpart>.narinfo     (metadata from the Nix db, Sig/CA passed through)
//!   GET /nar/<nix32 narhash>.nar     (full or Range; streamed from the seek table, never
//!                                     materialized)
//!
//! Seek tables are cached per narhash in an in-memory LRU; narshare writes nothing to disk.

use crate::config::ServeCfg;
use crate::db::{PathInfo, StoreDb};
use crate::io::SegmentReader;
use crate::manifest;
use crate::nar::{self, SeekTable, Slice};
use crate::narinfo::format_narinfo;
use crate::nixbase32;
use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info_span, warn};

/// Emission granularity for file spans; also the per-send unit for literals.
const READ_CHUNK: u64 = 256 * 1024;
/// Reads in flight per streaming response (each ≤ READ_CHUNK): the response-internal queue
/// depth. 16 × 256 KiB = 4 MiB in flight per response.
const READ_AHEAD: usize = 16;
/// Largest span the chunk-encoding path will compress (anything bigger falls back to the raw
/// stream). Encoded spans STREAM — memory per job is the encoder window plus a few pieces, not
/// the span — so this bounds only how long one encode job can monopolize its permit.
const MAX_ENCODED_SPAN: u64 = 256 << 20;
/// Encoder output accumulates to this granularity before it is flushed to the response body:
/// big enough to amortize channel and HTTP framing, small enough that the first bytes hit the
/// wire while the rest of the span is still being read and compressed.
const ENCODE_FLUSH_BYTES: usize = 128 * 1024;
/// Byte budget for cached seek tables (a table is ~lits + 56B/segment; big trees reach tens of
/// MB). Entry counts are the wrong unit — budget the bytes.
const TABLE_BUDGET: u64 = 256 * 1024 * 1024;
/// Entry cap is a backstop only; the byte budget is the real limit.
const TABLE_ENTRIES: usize = 4096;
/// Concurrent chunk-encode jobs — the serve side's CPU budget for wire compression, sized to
/// the machine. Each job is one single-threaded zstd encode (streaming jobs hold their permit
/// for the response's lifetime, mostly idle on backpressure — the permit bounds encoder THREADS,
/// which is the resource that matters), and the serve listener is mesh-exposed — bound the
/// aggregate. A FULL pool doubles as the "compression, not the wire, is the bottleneck" signal
/// for the adaptive encoding's CPU half (see get_nar).
fn encode_permits() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
        .clamp(2, 8)
}
/// Concurrent manifest builds. Each is a whole-tree hashing read (minutes for a game tree); two
/// permits let a small burst overlap without a fleet of peers saturating the disk.
const MANIFEST_BUILD_CONCURRENCY: usize = 2;
/// A narhash that resolved to nothing is not re-probed for this long. The hash column is
/// unindexed, so every miss is a full ValidPaths scan — and restart-recovery probes for a NAR we
/// never held fan in from every peer.
const NAR_NEGATIVE_TTL: Duration = Duration::from_secs(10);
const NAR_NEGATIVE_ENTRIES: usize = 4096;

pub struct ServeState {
    /// Demand-driven deletion feedback: a NAR request for content the db no longer has
    /// answers 410 Gone and retracts our Have for that hash (see Index::retract_hold).
    /// None only in fixtures that exercise serving alone.
    pub index: Option<Arc<crate::index::Index>>,
    db: Arc<StoreDb>,
    reader: SegmentReader,
    cfg: ServeCfg,
    nars: Mutex<NarCache>,
    /// narhash → rendered manifest JSON; None = known unmanifestable (e.g. non-UTF-8 names).
    /// Manifests are KB–MB; entry count is a fine unit.
    manifests: Mutex<LruCache<[u8; 32], Option<Bytes>>>,
    /// narhash → in-flight manifest build. Waiters watch for the sender to drop, then re-read
    /// the manifests cache; the build itself is a detached task (see spawn_manifest_build).
    building: Mutex<HashMap<[u8; 32], watch::Receiver<()>>>,
    /// Bounds concurrent manifest builds.
    manifest_sem: Arc<tokio::sync::Semaphore>,
    /// narhash → when a lookup found nothing (valid for NAR_NEGATIVE_TTL).
    nar_negative: Mutex<LruCache<[u8; 32], Instant>>,
    /// Bounds concurrent chunk-encode jobs (m4). Arc'd so streaming responses can carry an
    /// owned permit for their whole lifetime.
    encode_sem: Arc<tokio::sync::Semaphore>,
    /// A separate lane for SMALL spans: tokio's semaphore is FIFO, so a 50 KB NAR's single
    /// chunk would otherwise queue behind a fleet of long-lived streaming encodes — exactly
    /// the many-small-concurrent-fetches case a nixpkgs rebuild produces. Same permit count;
    /// bounded extra memory (permits × SMALL_ENCODE_SPAN).
    encode_sem_small: Arc<tokio::sync::Semaphore>,
    pub stats: ServeStats,
}

/// Cumulative serve-side counters for the status endpoint.
#[derive(Default)]
pub struct ServeStats {
    pub narinfo_requests: std::sync::atomic::AtomicU64,
    pub nar_requests: std::sync::atomic::AtomicU64,
    pub nar_misses: std::sync::atomic::AtomicU64,
    pub manifest_requests: std::sync::atomic::AtomicU64,
    pub chunks_encoded: std::sync::atomic::AtomicU64,
    /// Total time chunk requests spent WAITING for an encode permit — the serve side's
    /// CPU-saturation signal (it is also folded per-chunk into x-narshare-encode-us).
    pub encode_wait_us: std::sync::atomic::AtomicU64,
}

/// Spans at or below this use the small-encode lane.
const SMALL_ENCODE_SPAN: u64 = 1 << 20;

struct NarCache {
    lru: LruCache<[u8; 32], Arc<NarEntry>>,
    table_bytes: u64,
}

impl NarCache {
    /// Insert an entry, absorbing whatever the entry cap displaces into the byte accounting —
    /// a silent capacity eviction that carried a built table would otherwise leave its bytes
    /// counted forever.
    fn insert(&mut self, hash: [u8; 32], entry: Arc<NarEntry>) {
        if let Some((_, displaced)) = self.lru.push(hash, entry) {
            self.forget(&displaced);
        }
    }

    fn forget(&mut self, evicted: &Arc<NarEntry>) {
        if let Some(t) = evicted.table.get() {
            self.table_bytes = self.table_bytes.saturating_sub(t.approx_bytes());
        }
    }

    /// Account a freshly built table and evict least-recently-used entries until within budget.
    /// Counted ONLY while `entry` is still the resident entry for `hash`: a table whose entry
    /// was evicted (or replaced) mid-build can never be subtracted back out, so counting it
    /// would inflate table_bytes forever and shrink the effective budget. The just-used entry
    /// is MRU, so it survives even if it alone exceeds the budget.
    fn account(&mut self, hash: &[u8; 32], entry: &Arc<NarEntry>, built: u64) {
        match self.lru.peek(hash) {
            Some(resident) if Arc::ptr_eq(resident, entry) => {}
            _ => return,
        }
        self.table_bytes += built;
        while self.table_bytes > TABLE_BUDGET && self.lru.len() > 1 {
            let Some((_, evicted)) = self.lru.pop_lru() else {
                break;
            };
            self.forget(&evicted);
        }
    }
}

struct NarEntry {
    info: PathInfo,
    table: tokio::sync::OnceCell<Arc<SeekTable>>,
    /// Busy-times of the most recently COMPLETED streaming encode of this NAR. A streaming
    /// response can't know its own read/encode cost before its headers go out, so each chunk
    /// reports the previous one's, scaled to its span (the requester's level controller
    /// integrates over many chunks; one chunk of staleness is immaterial).
    enc_stats: Mutex<Option<EncStats>>,
}

#[derive(Clone, Copy)]
struct EncStats {
    read_us: u64,
    encode_us: u64,
    span: u64,
}

impl ServeState {
    pub fn new(
        db: Arc<StoreDb>,
        reader: SegmentReader,
        cfg: ServeCfg,
        index: Option<Arc<crate::index::Index>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            index,
            db,
            reader,
            cfg,
            nars: Mutex::new(NarCache {
                lru: LruCache::new(NonZeroUsize::new(TABLE_ENTRIES).unwrap()),
                table_bytes: 0,
            }),
            manifests: Mutex::new(LruCache::new(NonZeroUsize::new(64).unwrap())),
            building: Mutex::new(HashMap::new()),
            manifest_sem: Arc::new(tokio::sync::Semaphore::new(MANIFEST_BUILD_CONCURRENCY)),
            nar_negative: Mutex::new(LruCache::new(
                NonZeroUsize::new(NAR_NEGATIVE_ENTRIES).unwrap(),
            )),
            encode_sem: Arc::new(tokio::sync::Semaphore::new(encode_permits())),
            encode_sem_small: Arc::new(tokio::sync::Semaphore::new(encode_permits())),
            stats: ServeStats::default(),
        })
    }

    /// (big-lane permits free, small-lane permits free) — for the status endpoint.
    pub fn encode_permits_free(&self) -> (usize, usize) {
        (
            self.encode_sem.available_permits(),
            self.encode_sem_small.available_permits(),
        )
    }
}

pub fn router(state: Arc<ServeState>) -> Router {
    Router::new()
        .route("/nix-cache-info", get(cache_info))
        .route("/nar/{file}", get(get_nar))
        .route("/narshare/v1/manifest/{hash}", get(get_manifest))
        .route("/{file}", get(get_narinfo))
        .with_state(state)
}

/// The segment manifest for a narhash: computed on first request, cached in memory for the life
/// of the process. Builds are single-flighted per narhash, bounded by MANIFEST_BUILD_CONCURRENCY,
/// and DETACHED from any one request: a huge tree hashes for minutes while requesters time out
/// and disconnect (axum cancels their handlers) — the result must land in the cache anyway so a
/// later transfer finds it, instead of every retry restarting the read from scratch.
async fn get_manifest(
    State(st): State<Arc<ServeState>>,
    UrlPath(hash): UrlPath<String>,
) -> Response {
    st.stats
        .manifest_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let Some(nar_hash) = nixbase32::decode(&hash, 32).map(|v| <[u8; 32]>::try_from(v).unwrap())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let respond = |cached: Option<Bytes>| -> Response {
        match cached {
            Some(json) => ([(header::CONTENT_TYPE, "application/json")], json).into_response(),
            // A path that cannot be manifested (e.g. a non-UTF-8 filename, which NARs allow and
            // the NAR walk serves fine) is an ABSENCE of a manifest, not a server fault: answer
            // 404 so the consumer degrades to plain striping instead of striking a healthy peer.
            // The NAR itself still serves normally.
            None => StatusCode::NOT_FOUND.into_response(),
        }
    };
    if let Some(cached) = st.manifests.lock().unwrap().get(&nar_hash).cloned() {
        return respond(cached);
    }
    let entry = match nar_entry(&st, nar_hash).await {
        Ok(Some(e)) => e,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return err500("manifest lookup", e),
    };
    loop {
        if let Some(cached) = st.manifests.lock().unwrap().get(&nar_hash).cloned() {
            return respond(cached);
        }
        // Join the in-flight build for this narhash, or become the one that starts it.
        let waiter = {
            let mut building = st.building.lock().unwrap();
            match building.get(&nar_hash) {
                Some(rx) => Some(rx.clone()),
                None => {
                    let (tx, rx) = watch::channel(());
                    building.insert(nar_hash, rx);
                    spawn_manifest_build(&st, nar_hash, &entry, tx);
                    None
                }
            }
        };
        if let Some(mut rx) = waiter {
            // The build task drops its sender after writing the cache; the closed channel
            // (changed() returning Err) is the completion signal, not an error.
            let _ = rx.changed().await;
        }
        // Loop: re-read the cache — either our build finished or the one we joined did.
    }
}

/// Start one detached, semaphore-bounded manifest build; publishes its outcome (including
/// failure, so unmanifestable paths are not re-read per request) to the manifests cache, then
/// removes the building entry and drops `tx` to wake every waiter.
fn spawn_manifest_build(
    st: &Arc<ServeState>,
    nar_hash: [u8; 32],
    entry: &Arc<NarEntry>,
    tx: watch::Sender<()>,
) {
    let st = st.clone();
    let root = std::path::PathBuf::from(&entry.info.path);
    let path = entry.info.path.clone();
    let (nh, ns, sb) = (
        entry.info.nar_hash,
        entry.info.nar_size,
        st.cfg.segment_bytes.0,
    );
    tokio::spawn(async move {
        let _permit = st
            .manifest_sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        let built = match tokio::task::spawn_blocking(move || {
            manifest::build_manifest(&root, &nh, ns, sb)
                .and_then(|m| serde_json::to_vec(&m).map_err(Into::into))
        })
        .await
        {
            Ok(r) => r,
            // A panic must still run the cleanup below, or waiters would spin on a dead entry.
            Err(join_err) => Err(anyhow::anyhow!("manifest build panicked: {join_err}")),
        };
        let outcome = match built {
            Ok(json) => Some(Bytes::from(json)),
            Err(e) => {
                debug!("no manifest for {path}: {e:#}");
                None
            }
        };
        // Publish before waking waiters — the cache read is their next step.
        st.manifests.lock().unwrap().put(nar_hash, outcome);
        st.building.lock().unwrap().remove(&nar_hash);
        drop(tx);
    });
}

fn err500(context: &str, e: anyhow::Error) -> Response {
    error!("{context}: {e:#}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error\n").into_response()
}

/// A request for content we may have CLAIMED but no longer have (GC'd between
/// reconciliations): 410 Gone — distinct from 404 so the peer skips us without a breaker
/// strike — and retract our Have for the hash point-wise. The requester's hash IS the
/// resolution; no scan needed. A bogus hash retracts nothing (is_held gate).
fn content_gone(st: &Arc<ServeState>, nar_hash: [u8; 32]) -> Response {
    if let Some(index) = st.index.clone() {
        tokio::task::spawn_blocking(move || match index.retract_hold(nar_hash) {
            Ok(true) => tracing::info!(
                "retracted stale hold for {} after a peer's request (GC'd?)",
                crate::nixbase32::encode(&nar_hash)
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!("could not retract stale hold: {e:#}"),
        });
    }
    StatusCode::GONE.into_response()
}

async fn cache_info(State(st): State<Arc<ServeState>>) -> Response {
    let body = format!(
        "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
        st.db.store_dir, st.cfg.priority
    );
    ([(header::CONTENT_TYPE, "text/x-nix-cache-info")], body).into_response()
}

async fn get_narinfo(
    State(st): State<Arc<ServeState>>,
    UrlPath(file): UrlPath<String>,
) -> Response {
    st.stats
        .narinfo_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let Some(hash_part) = file.strip_suffix(".narinfo").map(str::to_owned) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let db = st.db.clone();
    let looked_up = tokio::task::spawn_blocking(move || db.by_hash_part(&hash_part))
        .await
        .unwrap();
    match looked_up {
        Ok(Some(info)) => (
            [(header::CONTENT_TYPE, "text/x-nix-narinfo")],
            format_narinfo(&info, &st.db.store_dir),
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => err500("narinfo lookup", e),
    }
}

async fn get_nar(
    State(st): State<Arc<ServeState>>,
    UrlPath(file): UrlPath<String>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    // nar/<52 nix32 chars>.nar
    let nar_hash: [u8; 32] = match file
        .strip_suffix(".nar")
        .and_then(|h| nixbase32::decode(h, 32))
        .map(|v| <[u8; 32]>::try_from(v).unwrap())
    {
        Some(h) => h,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    st.stats
        .nar_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let entry = match nar_entry(&st, nar_hash).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            st.stats
                .nar_misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return content_gone(&st, nar_hash);
        }
        Err(e) => return err500("nar lookup", e),
    };
    let table = match seek_table(&st, nar_hash, &entry).await {
        Ok(t) => t,
        Err(e) => return err500("seek table", e),
    };

    let size = table.nar_size;
    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
    let (start, end, status) = match parse_range(range, size) {
        RangeSpec::Full => (0, size, StatusCode::OK),
        RangeSpec::Partial(s, e) => (s, e, StatusCode::PARTIAL_CONTENT),
        RangeSpec::Unsatisfiable => {
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, format!("bytes */{size}"))],
            )
                .into_response();
        }
    };

    let span = info_span!("nar", path = %entry.info.path, start, end);
    let _g = span.enter();
    debug!("serving {} bytes", end - start);

    // narshare chunk-encoding extension: a ranged request may ask for the span as one zstd frame
    // (`x-narshare-accept: zstd:<level>`). Ranges are ADDRESSED uncompressed; only the wire
    // representation changes. Bounded: only for spans we are willing to buffer.
    if status == StatusCode::PARTIAL_CONTENT && method != Method::HEAD {
        if let Some(level) = headers
            .get("x-narshare-accept")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("zstd:"))
            .and_then(|l| l.parse::<i32>().ok())
        {
            if end - start <= SMALL_ENCODE_SPAN {
                let level = level.clamp(1, st.cfg.max_zstd_level.max(1));
                // Small spans buffer: the whole read+encode is milliseconds, so the exact
                // per-chunk timing headers are cheap to keep and the streaming machinery
                // would be pure overhead. The WAIT for a permit is an honest CPU-pressure
                // signal, so it is reported to the requester folded into the encode time.
                let waited = std::time::Instant::now();
                let _permit = st
                    .encode_sem_small
                    .acquire()
                    .await
                    .expect("semaphore closed");
                let wait = waited.elapsed();
                st.stats
                    .chunks_encoded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                st.stats.encode_wait_us.fetch_add(
                    wait.as_micros() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                return match encode_span(&st, &table, start, end, level).await {
                    Ok((frame, read_d, enc_d)) => Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header(header::CONTENT_TYPE, "application/x-narshare-chunk")
                        .header(header::CONTENT_LENGTH, frame.len())
                        .header(
                            header::CONTENT_RANGE,
                            format!("bytes {}-{}/{}", start, end - 1, size),
                        )
                        .header("x-narshare-encoding", "zstd")
                        // Where this chunk's service time went, for the requester's bottleneck
                        // classification: disk vs CPU (pool wait + encode). Wire time is what
                        // remains of the requester's own elapsed measurement.
                        .header("x-narshare-read-us", read_d.as_micros().to_string())
                        .header(
                            "x-narshare-encode-us",
                            (wait + enc_d).as_micros().to_string(),
                        )
                        .body(Body::from(frame))
                        .unwrap(),
                    Err(e) => err500("chunk encode", e),
                };
            }
            if end - start <= MAX_ENCODED_SPAN {
                let level = level.clamp(1, st.cfg.max_zstd_level.max(1));
                let waited = std::time::Instant::now();
                let permit = st
                    .encode_sem
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore closed");
                let wait = waited.elapsed();
                st.stats
                    .chunks_encoded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                st.stats.encode_wait_us.fetch_add(
                    wait.as_micros() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                let mut resp = Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(header::CONTENT_TYPE, "application/x-narshare-chunk")
                    .header(
                        header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", start, end - 1, size),
                    )
                    .header("x-narshare-encoding", "zstd")
                    // Read/encode/wire OVERLAP on this path; the requester's controller must
                    // compare busy-times against elapsed as utilizations, not subtract them.
                    .header("x-narshare-timing", "pipelined");
                // Previous completed chunk's busy-times, scaled to this span, with the LIVE
                // permit wait folded in so pool pressure is never stale. The first chunk of a
                // NAR carries no timing headers and the requester falls back to its open-loop
                // goodput ladder for that one observation.
                if let Some(s) = *entry.enc_stats.lock().unwrap() {
                    let scale = (end - start) as f64 / s.span.max(1) as f64;
                    resp = resp
                        .header(
                            "x-narshare-read-us",
                            (((s.read_us as f64) * scale) as u64).to_string(),
                        )
                        .header(
                            "x-narshare-encode-us",
                            (((s.encode_us as f64) * scale) as u64 + wait.as_micros() as u64)
                                .to_string(),
                        );
                }
                let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
                let stc = st.clone();
                let tbl = table.clone();
                let ent = entry.clone();
                tokio::spawn(async move {
                    stream_encode(stc, tbl, ent, start, end, level, tx).await;
                    drop(permit);
                });
                return resp
                    .body(Body::from_stream(ReceiverStream::new(rx)))
                    .unwrap();
            }
        }
    }

    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/x-nix-nar")
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, end - start);
    if status == StatusCode::PARTIAL_CONTENT {
        resp = resp.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end - 1, size),
        );
    }

    // HEAD gets the exact GET headers with no emit task spawned.
    if method == Method::HEAD {
        return resp.body(Body::empty()).unwrap();
    }

    let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
    let reader = st.reader.clone();
    let stream_table = table.clone();
    tokio::spawn(async move {
        emit(stream_table, reader, start, end, tx).await;
    });
    resp.body(Body::from_stream(ReceiverStream::new(rx)))
        .unwrap()
}

/// Resolve narhash → PathInfo, LRU-cached both ways (the hash column is unindexed in the Nix db,
/// so a miss is a full ValidPaths scan: recent misses are cached for NAR_NEGATIVE_TTL).
async fn nar_entry(st: &Arc<ServeState>, nar_hash: [u8; 32]) -> Result<Option<Arc<NarEntry>>> {
    if let Some(e) = st.nars.lock().unwrap().lru.get(&nar_hash) {
        return Ok(Some(e.clone()));
    }
    if let Some(at) = st.nar_negative.lock().unwrap().get(&nar_hash) {
        if at.elapsed() < NAR_NEGATIVE_TTL {
            return Ok(None);
        }
    }
    let db = st.db.clone();
    let info = tokio::task::spawn_blocking(move || db.by_nar_hash(&nar_hash))
        .await
        .unwrap()?;
    let Some(info) = info else {
        st.nar_negative
            .lock()
            .unwrap()
            .put(nar_hash, Instant::now());
        return Ok(None);
    };
    st.nar_negative.lock().unwrap().pop(&nar_hash);
    let mut cache = st.nars.lock().unwrap();
    // Re-check under the lock: a concurrent request may have inserted while we scanned. Sharing
    // the resident entry means sharing its OnceCell — one table build, one accounting.
    if let Some(e) = cache.lru.get(&nar_hash) {
        return Ok(Some(e.clone()));
    }
    let entry = Arc::new(NarEntry {
        info,
        table: tokio::sync::OnceCell::new(),
        enc_stats: Mutex::new(None),
    });
    cache.insert(nar_hash, entry.clone());
    Ok(Some(entry))
}

/// Build (once per entry) the seek table, and check it against the db's NarSize — a mismatch means
/// the store content does not correspond to the registered NAR (corruption / mutation): answer 500,
/// never serve garbage.
async fn seek_table(
    st: &Arc<ServeState>,
    nar_hash: [u8; 32],
    entry: &Arc<NarEntry>,
) -> Result<Arc<SeekTable>> {
    entry
        .table
        .get_or_try_init(|| async {
            let path = std::path::PathBuf::from(&entry.info.path);
            let table = tokio::task::spawn_blocking(move || nar::build(&path))
                .await
                .unwrap()
                .with_context(|| format!("walking {}", entry.info.path))?;
            if table.nar_size != entry.info.nar_size {
                bail!(
                    "NAR size mismatch for {}: walk says {}, db says {} — refusing to serve",
                    entry.info.path,
                    table.nar_size,
                    entry.info.nar_size
                );
            }
            let table = Arc::new(table);
            st.nars
                .lock()
                .unwrap()
                .account(&nar_hash, entry, table.approx_bytes());
            Ok(table)
        })
        .await
        .cloned()
}

/// One ready-to-emit unit of a range response, in NAR order.
enum PieceDesc {
    Lit(Bytes),
    Read {
        path: Arc<std::path::PathBuf>,
        off: u64,
        len: u64,
    },
}

/// Walks [start, end) of a seek table as READ_CHUNK-sized pieces.
struct Pieces<'a> {
    table: &'a SeekTable,
    i: usize,
    start: u64,
    end: u64,
    /// Remaining part of the file slice currently being cut into READ_CHUNK pieces.
    file: Option<(Arc<std::path::PathBuf>, u64, u64)>,
}

impl<'a> Pieces<'a> {
    fn new(table: &'a SeekTable, start: u64, end: u64) -> Self {
        Self {
            table,
            i: table.first_seg(start),
            start,
            end,
            file: None,
        }
    }
}

impl Iterator for Pieces<'_> {
    type Item = PieceDesc;
    fn next(&mut self) -> Option<PieceDesc> {
        if let Some((path, off, len)) = self.file.take() {
            let n = len.min(READ_CHUNK);
            if len > n {
                self.file = Some((path.clone(), off + n, len - n));
            }
            return Some(PieceDesc::Read { path, off, len: n });
        }
        let slice = self.table.seg_slice(self.i, self.start, self.end)?;
        self.i += 1;
        match slice {
            Slice::Lit(b) => Some(PieceDesc::Lit(b)),
            Slice::File { path, off, len } => {
                self.file = Some((path, off, len));
                self.next()
            }
        }
    }
}

/// A piece either ready (framing) or being read concurrently.
enum Fetched {
    Lit(Bytes),
    Read(tokio::task::JoinHandle<Result<Bytes>>),
}

fn start_piece(reader: &SegmentReader, d: PieceDesc) -> Fetched {
    match d {
        PieceDesc::Lit(b) => Fetched::Lit(b),
        PieceDesc::Read { path, off, len } => {
            let r = reader.clone();
            Fetched::Read(tokio::spawn(async move {
                r.read(path, off, len as usize).await
            }))
        }
    }
}

/// Stream [start, end) in order with READ_AHEAD reads in flight. Per-op latency through the io
/// pool is milliseconds-scale, so a serial read loop caps a response at queue depth 1 (~150 MB/s
/// measured against a >3 GB/s disk path); queue depth must come from WITHIN a response, not only
/// from concurrent requests. Ordering is preserved by awaiting in submission order.
async fn emit(
    table: Arc<SeekTable>,
    reader: SegmentReader,
    start: u64,
    end: u64,
    tx: mpsc::Sender<std::io::Result<Bytes>>,
) {
    let mut pieces = Pieces::new(&table, start, end);
    let mut q: std::collections::VecDeque<Fetched> = std::collections::VecDeque::new();
    loop {
        while q.len() < READ_AHEAD {
            let Some(d) = pieces.next() else { break };
            q.push_back(start_piece(&reader, d));
        }
        let Some(next) = q.pop_front() else { return };
        let res = match next {
            Fetched::Lit(b) => Ok(b),
            Fetched::Read(h) => h.await.expect("read task panicked"),
        };
        match res {
            Ok(b) => {
                if tx.send(Ok(b)).await.is_err() {
                    break; // client went away
                }
            }
            Err(e) => {
                // GC'd or corrupted mid-stream: abort the response so the client sees a
                // transfer failure rather than short/garbage data.
                warn!("aborting NAR stream: {e:#}");
                let _ = tx.send(Err(std::io::Error::other(format!("{e:#}")))).await;
                break;
            }
        }
    }
    for p in q {
        if let Fetched::Read(h) = p {
            h.abort();
        }
    }
}

pub(crate) enum RangeSpec {
    Full,
    /// [start, end)
    Partial(u64, u64),
    Unsatisfiable,
}

/// Single-range `bytes=` parsing. Malformed or multi-range headers are ignored (200 full body,
/// which is always legal); syntactically valid but unsatisfiable ranges get 416.
pub(crate) fn parse_range(header: Option<&str>, size: u64) -> RangeSpec {
    let Some(h) = header else {
        return RangeSpec::Full;
    };
    let Some(spec) = h.strip_prefix("bytes=") else {
        return RangeSpec::Full;
    };
    if spec.contains(',') {
        return RangeSpec::Full;
    }
    let spec = spec.trim();
    let Some((a, b)) = spec.split_once('-') else {
        return RangeSpec::Full;
    };
    match (a, b) {
        ("", n) => {
            // suffix: last n bytes
            let Ok(n) = n.parse::<u64>() else {
                return RangeSpec::Full;
            };
            if n == 0 || size == 0 {
                return RangeSpec::Unsatisfiable;
            }
            RangeSpec::Partial(size.saturating_sub(n), size)
        }
        (a, "") => {
            let Ok(a) = a.parse::<u64>() else {
                return RangeSpec::Full;
            };
            if a >= size {
                return RangeSpec::Unsatisfiable;
            }
            RangeSpec::Partial(a, size)
        }
        (a, b) => {
            let (Ok(a), Ok(b)) = (a.parse::<u64>(), b.parse::<u64>()) else {
                return RangeSpec::Full;
            };
            // saturating_add so bytes=N-18446744073709551615 clamps to `size` rather than wrapping
            // to 0 (which would give end < start → CONTENT_LENGTH underflow / handler panic).
            let end = b.saturating_add(1).min(size);
            if a > b || a >= size || end <= a {
                return RangeSpec::Unsatisfiable;
            }
            RangeSpec::Partial(a, end)
        }
    }
}

/// Materialize [start, end) into memory and compress it as one zstd frame. Returns the frame
/// plus how long the two stages took (read from disk; encode, including blocking-pool queueing)
/// — the serve side's half of the adaptive-encoding timing breakdown.
/// Stream [start, end) as ONE zstd frame produced incrementally: pieces are read with the same
/// lookahead as the raw path and fed to an encoder thread whose output flushes to the body as it
/// is produced, so read, encode, and wire overlap. The buffered predecessor serialized all three
/// per chunk, which capped a stream's throughput at wire/(read+encode+wire) — measured as a >2x
/// loss against a single raw stream on a shaped sub-gigabit path (tests/perf.nix).
///
/// Backpressure chains end to end: a slow reader stalls `tx`, which blocks the encoder thread,
/// which fills `feed`, which parks the read loop — memory per job stays at a few pieces plus the
/// encoder window regardless of span.
async fn stream_encode(
    st: Arc<ServeState>,
    table: Arc<SeekTable>,
    entry: Arc<NarEntry>,
    start: u64,
    end: u64,
    level: i32,
    tx: mpsc::Sender<std::io::Result<Bytes>>,
) {
    let (feed_tx, mut feed_rx) = mpsc::channel::<Bytes>(4);
    let out = tx.clone();
    let encoder = tokio::task::spawn_blocking(move || -> Result<Duration> {
        // Wire compression is strictly background work: soak idle cycles, never compete with
        // interactive processes for them. The requester's closed-loop level controller already
        // adapts to whatever CPU this thread ends up getting, so deprioritizing degrades the
        // compression ratio gracefully instead of degrading the machine.
        let _nice = NiceGuard::lower(10);
        let mut busy = Duration::ZERO;
        let mut w = ChannelWriter {
            tx: out,
            buf: Vec::with_capacity(ENCODE_FLUSH_BYTES * 2),
        };
        let mut enc = zstd::stream::write::Encoder::new(&mut w, level).context("zstd encoder")?;
        while let Some(b) = feed_rx.blocking_recv() {
            let t = Instant::now();
            std::io::Write::write_all(&mut enc, &b).context("zstd write")?;
            busy += t.elapsed();
        }
        let t = Instant::now();
        enc.finish().context("zstd finish")?;
        busy += t.elapsed();
        w.flush_all()?;
        Ok(busy)
    });

    // The feeder: identical lookahead discipline to emit(). read_busy is time the pipeline
    // actually WAITED on the disk — with READ_AHEAD in flight, cached reads cost ~zero here.
    let mut read_busy = Duration::ZERO;
    let mut pieces = Pieces::new(&table, start, end);
    let mut q: std::collections::VecDeque<Fetched> = std::collections::VecDeque::new();
    let mut failed = false;
    loop {
        while q.len() < READ_AHEAD {
            let Some(d) = pieces.next() else { break };
            q.push_back(start_piece(&st.reader, d));
        }
        let Some(next) = q.pop_front() else { break };
        let res = match next {
            Fetched::Lit(b) => Ok(b),
            Fetched::Read(h) => {
                let t = Instant::now();
                let r = h.await.expect("read task panicked");
                read_busy += t.elapsed();
                r
            }
        };
        match res {
            Ok(b) => {
                if feed_tx.send(b).await.is_err() {
                    // Encoder died (its error already went to the body) or the client left.
                    failed = true;
                    break;
                }
            }
            Err(e) => {
                warn!("aborting encoded NAR stream: {e:#}");
                let _ = tx.send(Err(std::io::Error::other(format!("{e:#}")))).await;
                failed = true;
                break;
            }
        }
    }
    drop(feed_tx);
    for p in q {
        if let Fetched::Read(h) = p {
            h.abort();
        }
    }
    match encoder.await.expect("encode task panicked") {
        Ok(encode_busy) if !failed => {
            *entry.enc_stats.lock().unwrap() = Some(EncStats {
                read_us: read_busy.as_micros() as u64,
                encode_us: encode_busy.as_micros() as u64,
                span: end - start,
            });
        }
        Ok(_) => {}
        Err(e) => {
            warn!("chunk encode stream: {e:#}");
            let _ = tx.send(Err(std::io::Error::other(format!("{e:#}")))).await;
        }
    }
}

/// std::io::Write bridge from the encoder thread into the response body channel. `flush` is a
/// deliberate no-op — zstd flushes internally at block boundaries, and honoring those would
/// fragment the body into tiny frames; ENCODE_FLUSH_BYTES is the real granularity.
struct ChannelWriter {
    tx: mpsc::Sender<std::io::Result<Bytes>>,
    buf: Vec<u8>,
}

impl ChannelWriter {
    fn flush_all(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let b = Bytes::from(std::mem::take(&mut self.buf));
        self.buf.reserve(ENCODE_FLUSH_BYTES * 2);
        self.tx
            .blocking_send(Ok(b))
            .map_err(|_| std::io::Error::other("client went away"))
    }
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, d: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(d);
        if self.buf.len() >= ENCODE_FLUSH_BYTES {
            self.flush_all()?;
        }
        Ok(d.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Scoped per-thread nice(): lowers this thread's scheduling priority by `by`, restoring the
/// previous value on drop (the thread returns to a shared blocking pool — a leaked nice would
/// deprioritize whatever unrelated work lands on it next).
struct NiceGuard {
    tid: libc::pid_t,
    prev: i32,
}

impl NiceGuard {
    fn lower(by: i32) -> Option<Self> {
        unsafe {
            let tid = libc::gettid();
            *libc::__errno_location() = 0;
            let prev = libc::getpriority(libc::PRIO_PROCESS, tid as libc::id_t);
            if prev == -1 && *libc::__errno_location() != 0 {
                return None;
            }
            if libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, (prev + by).min(19)) != 0 {
                return None;
            }
            Some(Self { tid, prev })
        }
    }
}

impl Drop for NiceGuard {
    fn drop(&mut self) {
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, self.tid as libc::id_t, self.prev);
        }
    }
}

async fn encode_span(
    st: &Arc<ServeState>,
    table: &Arc<SeekTable>,
    start: u64,
    end: u64,
    level: i32,
) -> Result<(Vec<u8>, Duration, Duration)> {
    let t0 = Instant::now();
    // All reads in flight at once (only SMALL_ENCODE_SPAN spans buffer, so a handful of
    // pieces); the io pool's own semaphore is the actual concurrency bound. Assembled in order.
    let started: Vec<Fetched> = Pieces::new(table, start, end)
        .map(|d| start_piece(&st.reader, d))
        .collect();
    let mut raw = Vec::with_capacity((end - start) as usize);
    for p in started {
        match p {
            Fetched::Lit(b) => raw.extend_from_slice(&b),
            Fetched::Read(h) => raw.extend_from_slice(&h.await.expect("read task panicked")?),
        }
    }
    let read_d = t0.elapsed();
    let t1 = Instant::now();
    let frame = tokio::task::spawn_blocking(move || {
        zstd::stream::encode_all(&raw[..], level).context("zstd encode")
    })
    .await
    .expect("encode task panicked")?;
    Ok((frame, read_d, t1.elapsed()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        use RangeSpec::*;
        let p = |h: Option<&str>, size| match parse_range(h, size) {
            Full => (u64::MAX, u64::MAX),
            Partial(a, b) => (a, b),
            Unsatisfiable => (u64::MAX - 1, u64::MAX - 1),
        };
        assert_eq!(p(None, 100), (u64::MAX, u64::MAX));
        assert_eq!(p(Some("bytes=0-99"), 100), (0, 100));
        assert_eq!(p(Some("bytes=0-9"), 100), (0, 10));
        assert_eq!(p(Some("bytes=90-"), 100), (90, 100));
        assert_eq!(p(Some("bytes=-10"), 100), (90, 100));
        assert_eq!(p(Some("bytes=50-200"), 100), (50, 100)); // clamp
        assert_eq!(p(Some("bytes=100-"), 100), (u64::MAX - 1, u64::MAX - 1)); // 416
        assert_eq!(p(Some("bytes=5-4"), 100), (u64::MAX - 1, u64::MAX - 1)); // 416
                                                                             // u64::MAX end must clamp, not wrap to 0 (would be end < start → panic/underflow).
        assert_eq!(p(Some("bytes=5-18446744073709551615"), 100), (5, 100));
        assert_eq!(p(Some("bytes=0-18446744073709551615"), 100), (0, 100));
        assert_eq!(p(Some("bytes=0-1,5-6"), 100), (u64::MAX, u64::MAX)); // multi → full
        assert_eq!(p(Some("cubits=1-2"), 100), (u64::MAX, u64::MAX)); // nonsense → full
    }
}
