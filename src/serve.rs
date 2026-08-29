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
/// Largest span the chunk-encoding path will buffer for compression (proxies chunk well below
/// this; anything bigger falls back to the raw stream).
const MAX_ENCODED_SPAN: u64 = 64 << 20;
/// Byte budget for cached seek tables (a table is ~lits + 56B/segment; big trees reach tens of
/// MB). Entry counts are the wrong unit — budget the bytes.
const TABLE_BUDGET: u64 = 256 * 1024 * 1024;
/// Entry cap is a backstop only; the byte budget is the real limit.
const TABLE_ENTRIES: usize = 4096;
/// Concurrent buffered chunk-encode jobs — the serve side's CPU budget for wire compression,
/// sized to the machine. Each job pins up to MAX_ENCODED_SPAN of memory plus one single-threaded
/// zstd encode, and the serve listener is mesh-exposed — bound the aggregate. A FULL pool doubles
/// as the "compression, not the wire, is the bottleneck" signal for the adaptive encoding's CPU
/// half (see get_nar).
fn encode_permits() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8).clamp(2, 8)
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
    /// Bounds concurrent buffered chunk-encode jobs (m4).
    encode_sem: tokio::sync::Semaphore,
}

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
            let Some((_, evicted)) = self.lru.pop_lru() else { break };
            self.forget(&evicted);
        }
    }
}

struct NarEntry {
    info: PathInfo,
    table: tokio::sync::OnceCell<Arc<SeekTable>>,
}

impl ServeState {
    pub fn new(db: Arc<StoreDb>, reader: SegmentReader, cfg: ServeCfg) -> Arc<Self> {
        Arc::new(Self {
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
            encode_sem: tokio::sync::Semaphore::new(encode_permits()),
        })
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
async fn get_manifest(State(st): State<Arc<ServeState>>, UrlPath(hash): UrlPath<String>) -> Response {
    let Some(nar_hash) = nixbase32::decode(&hash, 32).map(|v| <[u8; 32]>::try_from(v).unwrap())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let respond = |cached: Option<Bytes>| -> Response {
        match cached {
            Some(json) => {
                ([(header::CONTENT_TYPE, "application/json")], json).into_response()
            }
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
    let (nh, ns, sb) = (entry.info.nar_hash, entry.info.nar_size, st.cfg.segment_bytes.0);
    tokio::spawn(async move {
        let _permit =
            st.manifest_sem.clone().acquire_owned().await.expect("semaphore closed");
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

async fn cache_info(State(st): State<Arc<ServeState>>) -> Response {
    let body = format!(
        "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
        st.db.store_dir, st.cfg.priority
    );
    ([(header::CONTENT_TYPE, "text/x-nix-cache-info")], body).into_response()
}

async fn get_narinfo(State(st): State<Arc<ServeState>>, UrlPath(file): UrlPath<String>) -> Response {
    let Some(hash_part) = file.strip_suffix(".narinfo").map(str::to_owned) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let db = st.db.clone();
    let looked_up =
        tokio::task::spawn_blocking(move || db.by_hash_part(&hash_part)).await.unwrap();
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

    let entry = match nar_entry(&st, nar_hash).await {
        Ok(Some(e)) => e,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
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
            if end - start <= MAX_ENCODED_SPAN {
                let level = level.clamp(1, st.cfg.max_zstd_level.max(1));
                // The CPU half of adaptive encoding. An instantly-available permit means the
                // encode pool has headroom: spend the requested level. A full pool means
                // compression, not the wire, is the bottleneck (one encode is mid-flight per
                // core): wait for the slot but do HALF the requested level, so the queue drains
                // instead of stacking 19s behind 19s. Frames are self-describing, so requesters
                // decode whatever level was actually spent; the halving is per-chunk against the
                // REQUESTED level, never compounded — pressure gone, the next chunk is back to
                // full. This also breaks the requester-side feedback trap where a CPU-capped
                // server reads as a thin link (low goodput → even higher requested level).
                let (_permit, level) = match st.encode_sem.try_acquire() {
                    Ok(p) => (p, level),
                    Err(_) => {
                        let p = st.encode_sem.acquire().await.expect("semaphore closed");
                        let degraded = (level / 2).max(1);
                        debug!("encode pool saturated: zstd level {level} → {degraded}");
                        (p, degraded)
                    }
                };
                return match encode_span(&st, &table, start, end, level).await {
                    Ok(frame) => Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header(header::CONTENT_TYPE, "application/x-narshare-chunk")
                        .header(header::CONTENT_LENGTH, frame.len())
                        .header(
                            header::CONTENT_RANGE,
                            format!("bytes {}-{}/{}", start, end - 1, size),
                        )
                        .header("x-narshare-encoding", "zstd")
                        .body(Body::from(frame))
                        .unwrap(),
                    Err(e) => err500("chunk encode", e),
                };
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
    resp.body(Body::from_stream(ReceiverStream::new(rx))).unwrap()
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
    let info = tokio::task::spawn_blocking(move || db.by_nar_hash(&nar_hash)).await.unwrap()?;
    let Some(info) = info else {
        st.nar_negative.lock().unwrap().put(nar_hash, Instant::now());
        return Ok(None);
    };
    st.nar_negative.lock().unwrap().pop(&nar_hash);
    let mut cache = st.nars.lock().unwrap();
    // Re-check under the lock: a concurrent request may have inserted while we scanned. Sharing
    // the resident entry means sharing its OnceCell — one table build, one accounting.
    if let Some(e) = cache.lru.get(&nar_hash) {
        return Ok(Some(e.clone()));
    }
    let entry = Arc::new(NarEntry { info, table: tokio::sync::OnceCell::new() });
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
            st.nars.lock().unwrap().account(&nar_hash, entry, table.approx_bytes());
            Ok(table)
        })
        .await
        .cloned()
}

async fn emit(
    table: Arc<SeekTable>,
    reader: SegmentReader,
    start: u64,
    end: u64,
    tx: mpsc::Sender<std::io::Result<Bytes>>,
) {
    let mut i = table.first_seg(start);
    while let Some(slice) = table.seg_slice(i, start, end) {
        i += 1;
        match slice {
            Slice::Lit(b) => {
                if tx.send(Ok(b)).await.is_err() {
                    return; // client went away
                }
            }
            Slice::File { path, off, len } => {
                let mut off = off;
                let mut remaining = len;
                while remaining > 0 {
                    let n = remaining.min(READ_CHUNK);
                    match reader.read(path.clone(), off, n as usize).await {
                        Ok(b) => {
                            if tx.send(Ok(b)).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            // GC'd or corrupted mid-stream: abort the response so the client sees
                            // a transfer failure rather than short/garbage data.
                            warn!("aborting NAR stream: {e:#}");
                            let _ = tx.send(Err(std::io::Error::other(format!("{e:#}")))).await;
                            return;
                        }
                    }
                    off += n;
                    remaining -= n;
                }
            }
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
    let Some(h) = header else { return RangeSpec::Full };
    let Some(spec) = h.strip_prefix("bytes=") else { return RangeSpec::Full };
    if spec.contains(',') {
        return RangeSpec::Full;
    }
    let spec = spec.trim();
    let Some((a, b)) = spec.split_once('-') else { return RangeSpec::Full };
    match (a, b) {
        ("", n) => {
            // suffix: last n bytes
            let Ok(n) = n.parse::<u64>() else { return RangeSpec::Full };
            if n == 0 || size == 0 {
                return RangeSpec::Unsatisfiable;
            }
            RangeSpec::Partial(size.saturating_sub(n), size)
        }
        (a, "") => {
            let Ok(a) = a.parse::<u64>() else { return RangeSpec::Full };
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

/// Materialize [start, end) into memory and compress it as one zstd frame.
async fn encode_span(
    st: &Arc<ServeState>,
    table: &Arc<SeekTable>,
    start: u64,
    end: u64,
    level: i32,
) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity((end - start) as usize);
    let mut i = table.first_seg(start);
    while let Some(slice) = table.seg_slice(i, start, end) {
        i += 1;
        match slice {
            Slice::Lit(b) => raw.extend_from_slice(&b),
            Slice::File { path, off, len } => {
                let mut o = off;
                let mut remaining = len;
                while remaining > 0 {
                    let n = remaining.min(READ_CHUNK);
                    let b = st.reader.read(path.clone(), o, n as usize).await?;
                    raw.extend_from_slice(&b);
                    o += n;
                    remaining -= n;
                }
            }
        }
    }
    tokio::task::spawn_blocking(move || {
        zstd::stream::encode_all(&raw[..], level).context("zstd encode")
    })
    .await
    .expect("encode task panicked")
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
