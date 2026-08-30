//! The proxy listener: the substituter the local nix talks to (loopback).
//!
//!   GET|HEAD /<hashpart>.narinfo   → tiered, hedged, coalesced peer fan-out; rewritten narinfo
//!                                    (our URL; upstream Sigs relayed verbatim); the relay gate
//!                                    enforced (CA, or — under "ca-or-signed" — a signature
//!                                    verified against the downloader's trusted keys, so
//!                                    untrusted paths cost no NAR bandwidth); negatives cached
//!                                    on definitive 404s and unrelayable answers
//!   GET /nix-cache-info
//!   GET /nar/<narhash>.nar         → relay from a holding peer with source failover at request
//!                                    time and a byte-progress stall watchdog on the stream
//!
//! M3 semantics: first positive answers nix immediately; peers that miss their adaptive hedge
//! deadline are "late", not "failed" — their lookups run on to the cap, and late positives still
//! widen the holder map and clear the negative cache (the drainer). Only hard errors feed the
//! breakers (peers.rs). Striping and reconstruction land in M4/M5 behind the same routes.

use crate::config::{self, ProxyCfg};
use crate::fetch::{self, FetchCtx};
use crate::narinfo::{rewrite_for_client, RemoteNarinfo};
use crate::nixbase32;
use crate::peers::{Answer, Peers};
use crate::serve::{parse_range, RangeSpec};
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tracing::{debug, warn};

/// Cached path→upstream mappings and negative answers. Entry counts, not bytes: these are tiny.
const HOLDERS_LRU: usize = 16 * 1024;
const NEGATIVE_LRU: usize = 64 * 1024;
/// Bound on concurrent upstream fan-outs (nix mass queries must not become a lookup storm;
/// followers coalesce onto leaders and don't consume this budget).
const FANOUT_CONCURRENCY: usize = 64;

pub struct ProxyState {
    pub peers: Peers,
    pub fetch: FetchCtx,
    cfg: ProxyCfg,
    /// The downloader's trust anchor, for relay = "ca-or-signed" (empty under "ca-only").
    trusted: crate::sig::TrustedKeys,
    /// narhash → everything we know about where the NAR lives.
    holders: Mutex<LruCache<[u8; 32], HolderSet>>,
    /// hash part → when a definitive negative was recorded (valid for `negative_ttl`).
    negative: Mutex<LruCache<String, Instant>>,
    /// In-flight narinfo lookups; followers wait on the leader's result.
    pending: Mutex<HashMap<String, Vec<oneshot::Sender<Option<RemoteNarinfo>>>>>,
    fanout_sem: Semaphore,
}

#[derive(Clone)]
pub(crate) struct HolderSet {
    pub(crate) info: RemoteNarinfo,
    /// True when `info` was synthesized by discover_nar from HEAD probes (placeholder StorePath,
    /// no CA). Replaced by the first real narinfo that agrees on the size.
    synthetic: bool,
    /// (peer index, that peer's NAR url), in discovery order.
    pub(crate) sources: Vec<(usize, String)>,
}

impl ProxyState {
    pub fn new(peers: Peers, peer_cfgs: &[config::Peer], cfg: ProxyCfg) -> Arc<Self> {
        // The relay gate's trust anchor: explicit config, else the local nix.conf — the same
        // list the consuming nix will enforce at ingestion. Empty (explicitly, or because
        // nix.conf is unreadable) means only content-addressed paths relay.
        let trusted = match &cfg.trusted_public_keys {
            Some(list) => crate::sig::TrustedKeys::parse(list),
            None => crate::sig::TrustedKeys::from_nix_conf(std::path::Path::new(
                "/etc/nix/nix.conf",
            ))
            .unwrap_or_else(|e| {
                warn!("/etc/nix/nix.conf is unreadable ({e}); relaying CA paths only");
                crate::sig::TrustedKeys::none()
            }),
        };
        debug!("relay trust anchor: {} key(s)", trusted.len());
        Arc::new(Self {
            fetch: FetchCtx::new(peer_cfgs, &cfg),
            peers,
            cfg,
            trusted,
            holders: Mutex::new(LruCache::new(NonZeroUsize::new(HOLDERS_LRU).unwrap())),
            negative: Mutex::new(LruCache::new(NonZeroUsize::new(NEGATIVE_LRU).unwrap())),
            pending: Mutex::new(HashMap::new()),
            fanout_sem: Semaphore::new(FANOUT_CONCURRENCY),
        })
    }

    /// Accept a peer as a holder of a path, enforcing the content-addressing and representation
    /// gates. Returns the CANONICAL narinfo for the hash — the one the stored holder set (and
    /// thus every NAR transfer) is sized against — so a client can never be told a NarSize or
    /// StorePath that disagrees with the set the fetch will use; None means refused, nothing
    /// registered. The stored source URL is ALWAYS the canonical `nar/<narhash>.nar` relative to
    /// the peer's base — NEVER the peer's advertised `URL:`, which via RFC-3986 resolution could
    /// resolve to an arbitrary host. Deriving the URL from the content hash keeps the fetch
    /// target a pure function of the request.
    fn accept_holder(&self, info: &RemoteNarinfo, peer_idx: usize) -> Option<RemoteNarinfo> {
        // The relay gate: content-addressed (self-authenticating), or carrying a signature that
        // VERIFIES under the downloader's trusted keys. Verified here so an untrusted-key path
        // is refused at narinfo time, never after a wasted transfer.
        if info.ca.is_none() && !self.trusted.any_sig_valid(info) {
            return None;
        }
        if info.compression != "none" {
            warn!(
                "peer {} serves {} with Compression: {} — unsupported",
                self.peers.list[peer_idx].name, info.store_path, info.compression
            );
            return None;
        }
        let nar_url = format!("nar/{}.nar", nixbase32::encode(&info.nar_hash));
        let mut holders = self.holders.lock().unwrap();
        match holders.get_mut(&info.nar_hash) {
            Some(set) => {
                if set.synthetic {
                    if set.info.nar_size != info.nar_size {
                        // A real narinfo outranks a HEAD-probed placeholder; the old sources
                        // answered for a different size, so they don't carry over.
                        warn!(
                            "peer {}: narinfo for {} (NarSize {}) supersedes a rediscovered set \
                             of {} bytes; rebuilding",
                            self.peers.list[peer_idx].name,
                            info.store_path,
                            info.nar_size,
                            set.info.nar_size
                        );
                        *set = HolderSet {
                            info: info.clone(),
                            synthetic: false,
                            sources: vec![(peer_idx, nar_url)],
                        };
                        return Some(info.clone());
                    }
                    set.info = info.clone();
                    set.synthetic = false;
                } else if set.info.nar_size != info.nar_size {
                    warn!(
                        "peer {} disagrees about {} (NarSize {} vs {}); keeping first",
                        self.peers.list[peer_idx].name,
                        info.store_path,
                        info.nar_size,
                        set.info.nar_size
                    );
                    // Servable via the existing holders: answer with THEIR info, not the
                    // outlier's — the outlier is not added as a source.
                    return Some(set.info.clone());
                }
                if !set.sources.iter().any(|(i, _)| *i == peer_idx) {
                    set.sources.push((peer_idx, nar_url));
                }
                Some(set.info.clone())
            }
            None => {
                holders.put(
                    info.nar_hash,
                    HolderSet {
                        info: info.clone(),
                        synthetic: false,
                        sources: vec![(peer_idx, nar_url)],
                    },
                );
                Some(info.clone())
            }
        }
    }
}

/// Rebuild a holder set for a narhash by HEAD-probing every available peer's /nar endpoint.
/// The synthesized narinfo carries no CA — that is fine: this path only serves content nix
/// addresses (and verifies) by hash.
async fn discover_nar(st: &Arc<ProxyState>, nar_hash: [u8; 32]) -> Option<HolderSet> {
    let nar_url = format!("nar/{}.nar", nixbase32::encode(&nar_hash));
    let mut set = tokio::task::JoinSet::new();
    for (idx, peer) in st.peers.list.iter().enumerate() {
        if !peer.available() {
            continue;
        }
        let st = st.clone();
        let url = nar_url.clone();
        set.spawn(async move { (idx, st.peers.head_nar(idx, &url).await) });
    }
    let mut size: Option<u64> = None;
    let mut sources = Vec::new();
    while let Some(res) = set.join_next().await {
        let Ok((idx, Some(len))) = res else { continue };
        match size {
            None => {
                size = Some(len);
                sources.push((idx, nar_url.clone()));
            }
            Some(s) if s == len => sources.push((idx, nar_url.clone())),
            Some(s) => warn!(
                "peer {} reports {} bytes for {}, others say {}; skipping it",
                st.peers.list[idx].name, len, nar_url, s
            ),
        }
    }
    let nar_size = size?;
    let info = RemoteNarinfo {
        store_path: format!("<rediscovered {}>", nar_url),
        compression: "none".into(),
        nar_hash,
        nar_size,
        references: Vec::new(),
        deriver: None,
        ca: None,
        sigs: Vec::new(),
    };
    let set = HolderSet { info, synthetic: true, sources };
    st.holders.lock().unwrap().put(nar_hash, set.clone());
    Some(set)
}

/// The 32-char hash part of a full store path ("/nix/store/<hash>-<name>"). `store_path` is
/// peer-controlled, so this MUST NOT byte-slice: `get(..32)` respects char boundaries and returns
/// None (→ the whole basename) rather than panicking on a multibyte char straddling byte 32.
fn hash_part_of(store_path: &str) -> &str {
    let base = store_path.rsplit('/').next().unwrap_or(store_path);
    base.get(..32).unwrap_or(base)
}

pub fn router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/nix-cache-info", get(cache_info))
        .route("/nar/{file}", get(get_nar))
        .route("/{file}", get(get_narinfo))
        .with_state(state)
}

async fn cache_info(State(st): State<Arc<ProxyState>>) -> Response {
    let body = format!(
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: {}\n",
        st.cfg.priority
    );
    ([(header::CONTENT_TYPE, "text/x-nix-cache-info")], body).into_response()
}

async fn get_narinfo(State(st): State<Arc<ProxyState>>, UrlPath(file): UrlPath<String>) -> Response {
    let Some(hash_part) = file.strip_suffix(".narinfo") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if hash_part.len() != 32 || !hash_part.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(at) = st.negative.lock().unwrap().get(hash_part) {
        if at.elapsed() < st.cfg.negative_ttl {
            return StatusCode::NOT_FOUND.into_response();
        }
    }

    match resolve(&st, hash_part).await {
        Some(info) => {
            // Roaming epoch: a recent min_bandwidth abort means big paths should go straight to
            // the builder — refuse at lookup time, without caching a negative (the path exists).
            if st.fetch.refuses_while_roaming(info.nar_size) {
                debug!("roaming epoch: refusing {} ({} bytes)", info.store_path, info.nar_size);
                return StatusCode::NOT_FOUND.into_response();
            }
            ([(header::CONTENT_TYPE, "text/x-nix-narinfo")], rewrite_for_client(&info))
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Coalescing wrapper: one leader fans out per hash part; concurrent identical requests wait for
/// the leader's result. The leader's WORK runs in a detached task: axum cancels handler futures
/// when clients disconnect, and a cancelled in-handler leader would strand every follower (and
/// every future request for the hash) on a lookup that never completes.
async fn resolve(st: &Arc<ProxyState>, hash_part: &str) -> Option<RemoteNarinfo> {
    let (tx, rx) = oneshot::channel();
    let is_leader = {
        let mut pending = st.pending.lock().unwrap();
        match pending.get_mut(hash_part) {
            Some(waiters) => {
                waiters.push(tx);
                false
            }
            None => {
                pending.insert(hash_part.to_owned(), vec![tx]);
                true
            }
        }
    };
    if is_leader {
        let st = st.clone();
        let hash = hash_part.to_owned();
        tokio::spawn(async move {
            // A drop guard removes the pending entry and fires the waiters however this task ends,
            // INCLUDING a panic inside fan_out. Without it, a panic would leave the entry in the
            // map forever and every future request for this hash would become a follower that
            // hangs (the failure mode the char-boundary bug in hash_part_of could trigger).
            struct Fire {
                st: Arc<ProxyState>,
                hash: String,
                result: Option<RemoteNarinfo>,
            }
            impl Drop for Fire {
                fn drop(&mut self) {
                    let waiters =
                        self.st.pending.lock().unwrap().remove(&self.hash).unwrap_or_default();
                    for w in waiters {
                        let _ = w.send(self.result.clone());
                    }
                }
            }
            let mut fire = Fire { st: st.clone(), hash: hash.clone(), result: None };
            fire.result = fan_out(&st, &hash).await;
        });
    }
    rx.await.unwrap_or(None)
}

/// Tiered, hedged fan-out. Within a tier: query all available peers in parallel, answer on the
/// first positive, stop waiting at the max adaptive deadline; a drainer keeps consuming late
/// answers. Lower tiers are only consulted when no lower tier holds the path.
async fn fan_out(st: &Arc<ProxyState>, hash_part: &str) -> Option<RemoteNarinfo> {
    let _permit = st.fanout_sem.acquire().await.expect("semaphore closed");

    let mut tiers: Vec<u32> =
        st.peers.list.iter().filter(|p| p.available()).map(|p| p.tier).collect();
    tiers.sort_unstable();
    tiers.dedup();

    let mut consulted_any = false;
    let mut saw_404 = false;
    let mut saw_unrelayable = false;

    for tier in tiers {
        let candidates: Vec<usize> = st
            .peers
            .list
            .iter()
            .enumerate()
            .filter(|(_, p)| p.tier == tier && p.available())
            .map(|(i, _)| i)
            .collect();
        if candidates.is_empty() {
            continue;
        }
        consulted_any = true;

        let (tx, mut rx) = mpsc::channel::<(usize, Answer)>(candidates.len());
        for idx in &candidates {
            let idx = *idx;
            let st = st.clone();
            let hash = hash_part.to_owned();
            let tx = tx.clone();
            tokio::spawn(async move {
                let ans = st.peers.lookup(idx, &hash).await;
                let _ = tx.send((idx, ans)).await;
            });
        }
        drop(tx);

        let wait = candidates
            .iter()
            .map(|&i| st.peers.list[i].deadline(st.peers.cap))
            .max()
            .unwrap();
        let deadline = tokio::time::Instant::now() + wait;

        let mut outstanding = candidates.len();
        let mut accepted: Option<RemoteNarinfo> = None;
        while outstanding > 0 {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some((idx, Answer::Found(info))) => {
                        outstanding -= 1;
                        // Gates are decided per ANSWER, not per tier: a signature one peer's db
                        // retained, another's may lack, so an unusable answer keeps the wait
                        // going for the remaining candidates. A StorePath naming a different
                        // hash is likewise no usable answer (and keeps our caches keyed by the
                        // REQUESTED hash part, never a peer-controlled string).
                        if hash_part_of(&info.store_path) != hash_part {
                            warn!(
                                "peer {} answered {hash_part} with unrelated path {}",
                                st.peers.list[idx].name, info.store_path
                            );
                        } else if let Some(canonical) = st.accept_holder(&info, idx) {
                            accepted = Some(canonical);
                            break;
                        } else {
                            debug!(
                                "peer {}: {} not relayable (no CA, no trusted signature)",
                                st.peers.list[idx].name, info.store_path
                            );
                            saw_unrelayable = true;
                        }
                    }
                    Some((_, Answer::NotFound)) => {
                        saw_404 = true;
                        outstanding -= 1;
                    }
                    Some((_, Answer::Unknown)) => outstanding -= 1,
                    None => { outstanding = 0; }
                },
                _ = tokio::time::sleep_until(deadline) => {
                    debug!("narinfo {hash_part}: {outstanding} peer(s) late in tier {tier}");
                    break;
                }
            }
        }

        // Whatever is still outstanding keeps running; late positives land via the drainer,
        // which applies the SAME gates as the leader and clears the negative by the REQUESTED
        // hash part (never the peer-controlled StorePath).
        if outstanding > 0 || accepted.is_some() {
            let st = st.clone();
            let hp = hash_part.to_owned();
            tokio::spawn(async move {
                while let Some((idx, ans)) = rx.recv().await {
                    if let Answer::Found(info) = ans {
                        if hash_part_of(&info.store_path) == hp
                            && st.accept_holder(&info, idx).is_some()
                        {
                            st.negative.lock().unwrap().pop(&hp);
                        }
                    }
                }
            });
        }

        if let Some(canonical) = accepted {
            st.negative.lock().unwrap().pop(hash_part);
            return Some(canonical);
        }
    }

    // Cache the miss only on evidence: a definitive 404, or answers that exist but cannot be
    // relayed (no CA, no trusted signature). All-errors (mesh down) is not evidence about the
    // path; leaving it uncached makes recovery immediate. An unrelayable verdict can be
    // peer-specific (signatures live in each peer's db), so negative_ttl bounds how long a
    // better-provisioned peer's answer is masked.
    if consulted_any && (saw_404 || saw_unrelayable) {
        st.negative.lock().unwrap().put(hash_part.to_owned(), Instant::now());
    }
    None
}

async fn get_nar(
    State(st): State<Arc<ProxyState>>,
    UrlPath(file): UrlPath<String>,
    method: axum::http::Method,
    headers: HeaderMap,
) -> Response {
    let nar_hash: [u8; 32] = match file
        .strip_suffix(".nar")
        .and_then(|h| nixbase32::decode(h, 32))
        .map(|v| <[u8; 32]>::try_from(v).unwrap())
    {
        Some(h) => h,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let cached = st.holders.lock().unwrap().get(&nar_hash).cloned();
    // A miss here is NOT re-resolvable by nix: it caches narinfos client-side and treats a
    // missing NAR as a hard cache error. Happens after a proxy restart or holder eviction —
    // recover by discovering the NAR directly by hash (content-addressed by construction; nix
    // verifies the NarHash it already holds).
    let set = match cached {
        Some(s) => s,
        None => match discover_nar(&st, nar_hash).await {
            Some(s) => s,
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };

    let size = set.info.nar_size;
    if st.fetch.refuses_while_roaming(size) {
        return StatusCode::NOT_FOUND.into_response();
    }
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

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/x-nix-nar")
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, end - start);
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end - 1, size),
        );
    }
    if method == axum::http::Method::HEAD {
        return builder.body(Body::empty()).unwrap();
    }

    let (tx, rx) = mpsc::channel::<std::io::Result<bytes::Bytes>>(8);
    tokio::spawn(fetch::run_transfer(
        st.clone(),
        set.info.clone(),
        set.sources.clone(),
        start,
        end,
        tx,
    ));
    builder
        .body(Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ServeCfg};
    use crate::db::StoreDb;
    use crate::io::SegmentReader;
    use crate::{nar, serve};
    use axum::routing::any;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    async fn spawn_router(router: Router) -> String {
        spawn_router_killable(router).await.0
    }

    async fn spawn_router_killable(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        (format!("http://{addr}"), handle)
    }

    /// A serve state over a store with one big compressible CA path, returning (router-factory
    /// data) so several independent serve listeners can share it.
    fn sized_store(dir: &Path, hash_part: &str, bytes: usize) -> (Arc<StoreDb>, ServeCfg, u64, [u8; 32]) {
        let store = dir.join("bigstore");
        let path = store.join(format!("{hash_part}-big-1.0"));
        std::fs::create_dir_all(&path).unwrap();
        // Compressible but not trivial: repeated 4KiB pattern.
        let pattern: Vec<u8> = (0..4096u32).flat_map(|i| (i % 251) .to_le_bytes()).collect();
        let blob: Vec<u8> = pattern.iter().cycle().take(bytes).copied().collect();
        std::fs::write(path.join("blob"), &blob).unwrap();
        let table = nar::build(&path).unwrap();
        let nar_hash = nar_hash_of(&path);
        let store_dir = store.to_str().unwrap().to_owned();
        let db_path = crate::db::tests::fake_db(
            dir,
            &[(
                &format!("{store_dir}/{hash_part}-big-1.0"),
                nar_hash,
                table.nar_size,
                Some("fixed:r:sha256:dummy"),
            )],
        );
        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let db = Arc::new(StoreDb::open(&db_path, &store_dir).unwrap());
        (db, scfg, table.nar_size, nar_hash)
    }

    /// ~3MB: below MANIFEST_MIN, so transfers use plain striping (the M4 shape).
    fn big_store(dir: &Path) -> (Arc<StoreDb>, ServeCfg, u64, [u8; 32]) {
        sized_store(dir, "gggggggggggggggggggggggggggggggg", 3 << 20)
    }

    fn serve_router_for(db: Arc<StoreDb>, scfg: &ServeCfg) -> Router {
        let scfg2: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {:?}\ndb_path = {:?}",
            scfg.store_dir.to_str().unwrap(),
            scfg.db_path.to_str().unwrap()
        ))
        .unwrap();
        serve::router(serve::ServeState::new(db, SegmentReader::for_tests(), scfg2))
    }

    fn sample_store(root: &Path) -> (String, u64, [u8; 32]) {
        let store = root.join("store");
        let path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-game-1.0");
        std::fs::create_dir_all(path.join("data")).unwrap();
        std::fs::write(path.join("data/blob.bin"), vec![0x5au8; 20_000]).unwrap();
        std::fs::write(path.join("readme"), b"hello\n").unwrap();
        let table = nar::build(&path).unwrap();
        (store.to_str().unwrap().to_owned(), table.nar_size, nar_hash_of(&path))
    }

    /// Real sha256 of a tree's NAR, so the engine's streaming hash check passes on fixtures.
    pub(crate) fn nar_hash_of(root: &Path) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let table = nar::build(root).unwrap();
        let mut h = Sha256::new();
        for s in table.slices(0, table.nar_size) {
            match s {
                crate::nar::Slice::Lit(b) => h.update(&b),
                crate::nar::Slice::File { path, off, len } => {
                    use std::os::unix::fs::FileExt;
                    let f = std::fs::File::open(path.as_path()).unwrap();
                    let mut buf = vec![0u8; len as usize];
                    f.read_exact_at(&mut buf, off).unwrap();
                    h.update(&buf);
                }
            }
        }
        h.finalize().into()
    }

    /// Serve router over a fresh fake store with one CA path and one non-CA path.
    async fn spawn_fake_serve(dir: &Path) -> (String, u64, [u8; 32]) {
        let (store_dir, nar_size, nar_hash) = sample_store(dir);
        let ca_path = format!("{store_dir}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-game-1.0");
        let noca = format!("{store_dir}/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-tool-1.0");
        std::fs::create_dir_all(&noca).unwrap();
        std::fs::write(format!("{noca}/f"), b"x").unwrap();
        let noca_size = nar::build(Path::new(&noca)).unwrap().nar_size;
        let db_path = crate::db::tests::fake_db(
            dir,
            &[
                (&ca_path, nar_hash, nar_size, Some("fixed:r:sha256:dummy")),
                (&noca, [8u8; 32], noca_size, None),
            ],
        );
        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let db = Arc::new(StoreDb::open(&db_path, &store_dir).unwrap());
        let state = serve::ServeState::new(db, SegmentReader::for_tests(), scfg);
        (spawn_router(serve::router(state)).await, nar_size, nar_hash)
    }

    fn proxy_config(peer_urls: &[(&str, &str)], extra: &str) -> (Config, ProxyCfg) {
        let peers = peer_urls
            .iter()
            .map(|(n, u)| format!("[[peers]]\nname = \"{n}\"\nurl = \"{u}\"\n"))
            .collect::<String>();
        // Hermetic by default: an unset trust anchor would read the HOST's /etc/nix/nix.conf.
        let keys = if extra.contains("trusted_public_keys") {
            ""
        } else {
            "trusted_public_keys = []\n"
        };
        let cfg: Config = toml::from_str(&format!(
            "[proxy]\nlisten = \"127.0.0.1:0\"\n{keys}{extra}\n{peers}"
        ))
        .unwrap();
        let pcfg: ProxyCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\n{keys}{extra}"
        ))
        .unwrap();
        (cfg, pcfg)
    }

    async fn spawn_proxy(peer_urls: &[(&str, &str)], extra: &str) -> (String, Arc<ProxyState>) {
        let (cfg, pcfg) = proxy_config(peer_urls, extra);
        let peers = Peers::new(&cfg.peers, &pcfg).unwrap();
        let state = ProxyState::new(peers, &cfg.peers, pcfg);
        (spawn_router(router(state.clone())).await, state)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_passthrough_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let (serve_url, nar_size, nar_hash) = spawn_fake_serve(dir.path()).await;
        let (proxy_url, _) = spawn_proxy(&[("test", &serve_url)], "negative_ttl = \"1h\"").await;
        let client = reqwest::Client::new();

        let ci = client.get(format!("{proxy_url}/nix-cache-info")).send().await.unwrap();
        assert!(ci.text().await.unwrap().contains("WantMassQuery: 1"));

        let ni = client
            .get(format!("{proxy_url}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let text = ni.text().await.unwrap();
        assert!(text.contains("CA: fixed:r:sha256:dummy"));
        assert!(!text.contains("Sig:"));
        let nar32 = crate::nixbase32::encode(&nar_hash);
        assert!(text.contains(&format!("URL: nar/{nar32}.nar")));

        // Relay-gate refusal: no CA, no trusted signature.
        let no = client
            .get(format!("{proxy_url}/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(no.status(), 404);

        // Misses, twice (second via negative cache).
        for _ in 0..2 {
            let miss = client
                .get(format!("{proxy_url}/cccccccccccccccccccccccccccccccc.narinfo"))
                .send()
                .await
                .unwrap();
            assert_eq!(miss.status(), 404);
        }

        // NAR via proxy == direct; ranges work.
        let direct = client
            .get(format!("{serve_url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let relayed =
            client.get(format!("{proxy_url}/nar/{nar32}.nar")).send().await.unwrap();
        assert_eq!(relayed.status(), 200);
        let relayed = relayed.bytes().await.unwrap();
        assert_eq!(direct, relayed);
        assert_eq!(relayed.len() as u64, nar_size);

        let part = client
            .get(format!("{proxy_url}/nar/{nar32}.nar"))
            .header(header::RANGE, "bytes=100-4200")
            .send()
            .await
            .unwrap();
        assert_eq!(part.status(), 206);
        assert_eq!(part.bytes().await.unwrap(), direct.slice(100..4201));

        let nar9 = crate::nixbase32::encode(&[9u8; 32]);
        let miss = client.get(format!("{proxy_url}/nar/{nar9}.nar")).send().await.unwrap();
        assert_eq!(miss.status(), 404);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn breaker_opens_on_hard_errors_and_failover_works() {
        let dir = tempfile::tempdir().unwrap();
        let (serve_url, _, _) = spawn_fake_serve(dir.path()).await;

        // A peer that always 500s, counting hits.
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let bad = Router::new().route(
            "/{*any}",
            any(move || {
                let h = h.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        );
        let bad_url = spawn_router(bad).await;

        let (proxy_url, _) = spawn_proxy(
            &[("bad", &bad_url), ("good", &serve_url)],
            "breaker_failures = 3\nbreaker_cooldown = \"1h\"\nnegative_ttl = \"1ms\"",
        )
        .await;
        let client = reqwest::Client::new();

        // Three misses strike the bad peer out...
        for _ in 0..3 {
            client
                .get(format!("{proxy_url}/cccccccccccccccccccccccccccccccc.narinfo"))
                .send()
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        let after_three = hits.load(Ordering::SeqCst);
        assert_eq!(after_three, 3);

        // ...after which it stops being consulted, while the good peer still answers.
        for _ in 0..3 {
            let r = client
                .get(format!("{proxy_url}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo"))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200);
        }
        assert_eq!(hits.load(Ordering::SeqCst), after_three, "breaker did not open");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_lookups_coalesce() {
        // A slow 404-ing peer that counts narinfo hits.
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let slow = Router::new().route(
            "/{*any}",
            any(move || {
                let h = h.clone();
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    StatusCode::NOT_FOUND
                }
            }),
        );
        let slow_url = spawn_router(slow).await;
        let (proxy_url, _) = spawn_proxy(&[("slow", &slow_url)], "").await;

        let client = reqwest::Client::new();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let c = client.clone();
            let u = format!("{proxy_url}/dddddddddddddddddddddddddddddddd.narinfo");
            set.spawn(async move { c.get(u).send().await.unwrap().status() });
        }
        while let Some(s) = set.join_next().await {
            assert_eq!(s.unwrap(), 404);
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "lookups did not coalesce");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_stall_watchdog_aborts() {
        // A peer whose narinfo is fine but whose NAR stream sends one chunk and hangs.
        let nar32 = crate::nixbase32::encode(&[7u8; 32]);
        let narinfo_text = format!(
            "StorePath: /nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-x\nURL: nar/{nar32}.nar\n\
             Compression: none\nNarHash: sha256:{nar32}\nNarSize: 1000000\nReferences: \n\
             CA: fixed:r:sha256:dummy\n"
        );
        let hang = Router::new()
            .route(
                "/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.narinfo",
                get(move || {
                    let t = narinfo_text.clone();
                    async move { ([(header::CONTENT_TYPE, "text/x-nix-narinfo")], t) }
                }),
            )
            .route(
                "/nar/{f}",
                get(|| async {
                    let (tx, rx) = mpsc::channel::<std::io::Result<bytes::Bytes>>(1);
                    tx.send(Ok(bytes::Bytes::from(vec![0u8; 1024]))).await.unwrap();
                    // Leak the sender so the stream hangs open forever.
                    std::mem::forget(tx);
                    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
                        .into_response()
                }),
            );
        let hang_url = spawn_router(hang).await;
        let (proxy_url, _) =
            spawn_proxy(&[("hang", &hang_url)], "stall_timeout = \"300ms\"").await;

        let client = reqwest::Client::new();
        let ni = client
            .get(format!("{proxy_url}/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);

        let started = Instant::now();
        let resp = client.get(format!("{proxy_url}/nar/{nar32}.nar")).send().await.unwrap();
        let body = resp.bytes().await;
        assert!(body.is_err(), "stalled relay should abort the body");
        let waited = started.elapsed();
        assert!(waited < std::time::Duration::from_secs(5), "watchdog too slow: {waited:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn late_positive_clears_negative() {
        // A peer whose narinfo answers are delayed by a mutable amount and whose path set is
        // toggleable: train fast latency first, then answer slowly WITH the path.
        #[derive(Clone)]
        struct S {
            delay_ms: Arc<AtomicU64>,
            has_path: Arc<std::sync::atomic::AtomicBool>,
        }
        let s = S {
            delay_ms: Arc::new(AtomicU64::new(0)),
            has_path: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let nar32 = crate::nixbase32::encode(&[6u8; 32]);
        let narinfo_text = format!(
            "StorePath: /nix/store/ffffffffffffffffffffffffffffffff-y\nURL: nar/{nar32}.nar\n\
             Compression: none\nNarHash: sha256:{nar32}\nNarSize: 10\nReferences: \n\
             CA: fixed:r:sha256:dummy\n"
        );
        let st = s.clone();
        let peer = Router::new().route(
            "/{f}",
            get(move |UrlPath(f): UrlPath<String>| {
                let s = st.clone();
                let text = narinfo_text.clone();
                async move {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        s.delay_ms.load(Ordering::SeqCst),
                    ))
                    .await;
                    if f == "ffffffffffffffffffffffffffffffff.narinfo"
                        && s.has_path.load(Ordering::SeqCst)
                    {
                        ([(header::CONTENT_TYPE, "text/x-nix-narinfo")], text).into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
            }),
        );
        let peer_url = spawn_router(peer).await;
        let (proxy_url, _) =
            spawn_proxy(&[("moody", &peer_url)], "negative_ttl = \"1h\"").await;
        let client = reqwest::Client::new();

        // Train latency with two fast misses (deadline collapses to ~100ms floor).
        for _ in 0..2 {
            client
                .get(format!("{proxy_url}/cccccccccccccccccccccccccccccccc.narinfo"))
                .send()
                .await
                .unwrap();
        }

        // Now the peer HAS the path but answers slowly: the hedged responder gives up (404),
        // and the drainer's late positive clears the negative for the next query.
        s.delay_ms.store(600, Ordering::SeqCst);
        s.has_path.store(true, Ordering::SeqCst);
        let first = client
            .get(format!("{proxy_url}/ffffffffffffffffffffffffffffffff.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), 404, "hedged responder should not wait 600ms");

        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        s.delay_ms.store(0, Ordering::SeqCst);
        let second = client
            .get(format!("{proxy_url}/ffffffffffffffffffffffffffffffff.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 200, "late positive should have cleared the negative");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn striped_fetch_across_two_peers() {
        let dir = tempfile::tempdir().unwrap();
        let (db, scfg, nar_size, nar_hash) = big_store(dir.path());
        let (url_a, _) = spawn_router_killable(serve_router_for(db.clone(), &scfg)).await;
        let (url_b, _) = spawn_router_killable(serve_router_for(db.clone(), &scfg)).await;
        let (proxy_url, state) = spawn_proxy(
            &[("a", &url_a), ("b", &url_b)],
            "chunk_max = \"256KiB\"\nwindow_bytes = \"2MiB\"",
        )
        .await;
        let client = reqwest::Client::new();

        let ni = client
            .get(format!("{proxy_url}/gggggggggggggggggggggggggggggggg.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        // Give the drainer a beat so BOTH peers land in the holder set.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let nar32 = crate::nixbase32::encode(&nar_hash);
        let direct = client
            .get(format!("{url_a}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let striped = client
            .get(format!("{proxy_url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(striped.len() as u64, nar_size);
        assert_eq!(striped, direct);

        // Exactly the NAR's bytes were fetched remotely (no duplication, no loss)…
        let remote = state.fetch.stats.remote_bytes.load(Ordering::SeqCst);
        assert_eq!(remote, nar_size);
        // …and the compressible content traveled compressed (auto encoding defaults on).
        let wire = state.fetch.stats.wire_bytes.load(Ordering::SeqCst);
        assert!(wire < remote / 2, "expected compression: wire {wire} vs remote {remote}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kill_a_peer_mid_transfer_and_finish_via_the_other() {
        let dir = tempfile::tempdir().unwrap();
        let (db, scfg, nar_size, nar_hash) = big_store(dir.path());
        let (url_a, handle_a) = spawn_router_killable(serve_router_for(db.clone(), &scfg)).await;
        let (url_b, _) = spawn_router_killable(serve_router_for(db.clone(), &scfg)).await;
        let (proxy_url, _) = spawn_proxy(
            &[("a", &url_a), ("b", &url_b)],
            "chunk_max = \"256KiB\"\nwindow_bytes = \"1MiB\"\nstall_timeout = \"10s\"",
        )
        .await;
        let client = reqwest::Client::new();
        let ni = client
            .get(format!("{proxy_url}/gggggggggggggggggggggggggggggggg.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let nar32 = crate::nixbase32::encode(&nar_hash);
        let killer = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            handle_a.abort(); // peer a dies mid-transfer; its in-flight chunks fail
        });
        let striped = client
            .get(format!("{proxy_url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        killer.await.unwrap();
        assert_eq!(striped.len() as u64, nar_size, "transfer must complete via peer b");
        use sha2::{Digest, Sha256};
        let got: [u8; 32] = Sha256::digest(&striped).into();
        assert_eq!(got, nar_hash, "bytes must be intact after failover");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hash_mismatch_aborts_the_stream() {
        // The db (and thus the peer's narinfo) claims a WRONG narhash for real content: the
        // engine must withhold the final chunk so the client sees a short-body error.
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, nar_size, _real_hash) = sample_store(dir.path());
        let ca_path = format!("{store_dir}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-game-1.0");
        let wrong = [0xabu8; 32];
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[(&ca_path, wrong, nar_size, Some("fixed:r:sha256:dummy"))],
        );
        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let db = Arc::new(StoreDb::open(&db_path, &store_dir).unwrap());
        let serve_url =
            spawn_router(serve::router(serve::ServeState::new(db, SegmentReader::for_tests(), scfg)))
                .await;
        let (proxy_url, _) = spawn_proxy(&[("test", &serve_url)], "").await;
        let client = reqwest::Client::new();
        let ni = client
            .get(format!("{proxy_url}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let nar32 = crate::nixbase32::encode(&wrong);
        let resp = client.get(format!("{proxy_url}/nar/{nar32}.nar")).send().await.unwrap();
        let body = resp.bytes().await;
        assert!(body.is_err(), "hash mismatch must abort the body, got {} bytes ok", body.map(|b| b.len()).unwrap_or(0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn min_bandwidth_aborts_and_roaming_epoch_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let (db, scfg, _nar_size, nar_hash) = big_store(dir.path());
        let (url_a, _) = spawn_router_killable(serve_router_for(db.clone(), &scfg)).await;
        // A floor no loopback debug build reaches, and a grace so short every transfer exceeds
        // it: threshold = 1GiB/s x 1ms ~= 1.07MB, below the 3MB path -> the roaming epoch bites.
        let (proxy_url, state) = spawn_proxy(
            &[("a", &url_a)],
            "chunk_max = \"256KiB\"\nmin_bandwidth = \"1GiB\"\nmin_bandwidth_grace = \"1ms\"",
        )
        .await;
        let client = reqwest::Client::new();
        let ni = client
            .get(format!("{proxy_url}/gggggggggggggggggggggggggggggggg.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let resp = client.get(format!("{proxy_url}/nar/{nar32}.nar")).send().await.unwrap();
        assert!(resp.bytes().await.is_err(), "below-floor transfer must abort");
        assert!(state.fetch.refuses_while_roaming(3 << 20));
        assert!(!state.fetch.refuses_while_roaming(100 << 10), "small paths still substitute");
        let again = client
            .get(format!("{proxy_url}/gggggggggggggggggggggggggggggggg.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(again.status(), 404, "roaming epoch must refuse the oversized path");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn manifest_dedup_fetches_each_distinct_blob_once() {
        // Three identical 4MiB files + one distinct 4MiB file, at the default 4MiB segment size:
        // the duplicated content must cross the wire ONCE; framing must not cross it at all.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("dstore");
        let path = store.join("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-dup-1.0");
        std::fs::create_dir_all(&path).unwrap();
        let x: Vec<u8> = (0..4u32 << 20).map(|i| (i % 249) as u8).collect();
        let d: Vec<u8> = (0..4u32 << 20).map(|i| (i % 247).wrapping_add(13) as u8).collect();
        std::fs::write(path.join("a-copy1"), &x).unwrap();
        std::fs::write(path.join("b-copy2"), &x).unwrap();
        std::fs::write(path.join("c-copy3"), &x).unwrap();
        std::fs::write(path.join("d-unique"), &d).unwrap();
        let table = nar::build(&path).unwrap();
        let nar_hash = nar_hash_of(&path);
        let store_dir = store.to_str().unwrap().to_owned();
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[(
                &format!("{store_dir}/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-dup-1.0"),
                nar_hash,
                table.nar_size,
                Some("fixed:r:sha256:dummy"),
            )],
        );
        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let db = Arc::new(StoreDb::open(&db_path, &store_dir).unwrap());
        let serve_url = spawn_router(serve::router(serve::ServeState::new(
            db,
            SegmentReader::for_tests(),
            scfg,
        )))
        .await;
        let (proxy_url, state) =
            spawn_proxy(&[("test", &serve_url)], "chunk_max = \"1MiB\"").await;
        let client = reqwest::Client::new();

        let ni = client
            .get(format!("{proxy_url}/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);

        let nar32 = crate::nixbase32::encode(&nar_hash);
        let direct = client
            .get(format!("{serve_url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let deduped = client
            .get(format!("{proxy_url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(deduped, direct, "dedup reconstruction must be byte-exact");
        assert_eq!(deduped.len() as u64, table.nar_size);

        let remote = state.fetch.stats.remote_bytes.load(Ordering::SeqCst);
        let replayed = state.fetch.stats.replayed_bytes.load(Ordering::SeqCst);
        let lits = state.fetch.stats.lit_bytes.load(Ordering::SeqCst);
        // Distinct content = 8MiB (x once, d once). Framing rides for free.
        assert_eq!(remote, 8 << 20, "each distinct blob crosses the wire exactly once");
        assert_eq!(replayed, 8 << 20, "the two duplicate occurrences replay from retention");
        assert!(lits > 0, "framing must be synthesized locally");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serve_manifest_endpoint_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let (serve_url, _, nar_hash) = spawn_fake_serve(dir.path()).await;
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let client = reqwest::Client::new();
        let m: crate::manifest::Manifest = client
            .get(format!("{serve_url}/narshare/v1/manifest/{nar32}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(m.version, crate::manifest::VERSION);
        let layout = crate::manifest::synth_layout(&m).unwrap();
        assert_eq!(layout.nar_size, m.nar_size);
        // Unknown narhash → 404.
        let nar9 = crate::nixbase32::encode(&[9u8; 32]);
        let miss = client
            .get(format!("{serve_url}/narshare/v1/manifest/{nar9}"))
            .send()
            .await
            .unwrap();
        assert_eq!(miss.status(), 404);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nar_fetch_survives_proxy_restart() {
        // nix caches narinfos client-side: after a proxy restart it GETs the NAR directly.
        // A FRESH proxy (empty holder map) must discover the NAR by hash and serve it.
        let dir = tempfile::tempdir().unwrap();
        let (serve_url, nar_size, nar_hash) = spawn_fake_serve(dir.path()).await;
        let (proxy_url, _) = spawn_proxy(&[("test", &serve_url)], "").await;
        let client = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        // No narinfo request first — straight to the NAR.
        let resp = client.get(format!("{proxy_url}/nar/{nar32}.nar")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.bytes().await.unwrap();
        assert_eq!(body.len() as u64, nar_size);
        use sha2::{Digest, Sha256};
        let got: [u8; 32] = Sha256::digest(&body).into();
        assert_eq!(got, nar_hash);
    }

    #[test]
    fn hash_part_of_never_panics_on_multibyte() {
        // A peer-supplied store path with a multibyte char straddling byte 32 must not panic.
        let odd = format!("/nix/store/{}\u{e9}rest", "a".repeat(31)); // 31 ascii + 2-byte char
        let _ = super::hash_part_of(&odd); // must return without panicking
        assert_eq!(
            super::hash_part_of("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-name"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_decode_output_is_rejected() {
        use axum::routing::any;
        // A peer returns a valid narinfo, but every chunk is a small zstd frame that decompresses
        // to far more than the requested length. The length-bounded decoder must reject it without
        // allocating the full output, so the chunk fails and the transfer ends promptly.
        let nar32 = crate::nixbase32::encode(&[42u8; 32]);
        let narinfo_text = format!(
            "StorePath: /nix/store/iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii-oversized\nURL: nar/{nar32}.nar\n\
             Compression: none\nNarHash: sha256:{nar32}\nNarSize: 1048576\nReferences: \n\
             CA: fixed:r:sha256:x\n"
        );
        // A ~4 MiB run of zeros compresses to a few KB; decompressing bounded to want+1 stops early.
        let frame = zstd::stream::encode_all(&vec![0u8; 4 << 20][..], 3).unwrap();
        let frame = std::sync::Arc::new(frame);
        let peer = Router::new()
            .route(
                "/iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii.narinfo",
                get(move || {
                    let t = narinfo_text.clone();
                    async move { ([(header::CONTENT_TYPE, "text/x-nix-narinfo")], t) }
                }),
            )
            .route(
                "/nar/{f}",
                any(move |hdrs: HeaderMap| {
                    let frame = frame.clone();
                    async move {
                        // Honor the requested range span in Content-Range, but the body
                        // decompresses well beyond the requested length.
                        let range = hdrs
                            .get(header::RANGE)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("bytes=0-262143")
                            .trim_start_matches("bytes=")
                            .to_owned();
                        Response::builder()
                            .status(StatusCode::PARTIAL_CONTENT)
                            .header(header::CONTENT_TYPE, "application/x-narshare-chunk")
                            .header("x-narshare-encoding", "zstd")
                            .header(header::CONTENT_RANGE, format!("bytes {range}/1048576"))
                            .body(Body::from(frame.to_vec()))
                            .unwrap()
                    }
                }),
            );
        let peer_url = spawn_router(peer).await;
        let (proxy_url, _) = spawn_proxy(
            &[("over", &peer_url)],
            "chunk_max = \"256KiB\"\nstall_timeout = \"1s\"",
        )
        .await;
        let client = reqwest::Client::new();
        let ni = client
            .get(format!("{proxy_url}/iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let started = Instant::now();
        let resp = client.get(format!("{proxy_url}/nar/{nar32}.nar")).send().await.unwrap();
        assert!(
            resp.bytes().await.is_err(),
            "an over-expanding chunk must not yield a successful body"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(8), "must end promptly");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transfer_degrades_when_the_manifest_endpoint_hangs() {
        // acquire_manifest runs BEFORE the transfer's stall watchdog exists: a peer that sends
        // manifest headers and then dribbles nothing must cost at most the narinfo cap, after
        // which the transfer proceeds as plain striping.
        let dir = tempfile::tempdir().unwrap();
        let (db, scfg, nar_size, nar_hash) =
            sized_store(dir.path(), "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk", 6 << 20);
        let hang = Router::new()
            .route(
                "/narshare/v1/manifest/{h}",
                get(|| async {
                    let (tx, rx) = mpsc::channel::<std::io::Result<bytes::Bytes>>(1);
                    tx.send(Ok(bytes::Bytes::from_static(b"{"))).await.unwrap();
                    std::mem::forget(tx); // headers sent; the body never completes
                    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
                        .into_response()
                }),
            )
            .fallback_service(serve_router_for(db.clone(), &scfg));
        let peer_url = spawn_router(hang).await;
        let (proxy_url, _) = spawn_proxy(
            &[("hangman", &peer_url)],
            "narinfo_timeout = \"500ms\"\nchunk_max = \"1MiB\"",
        )
        .await;
        let client = reqwest::Client::new();
        let ni = client
            .get(format!("{proxy_url}/kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let started = Instant::now();
        let body = client
            .get(format!("{proxy_url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.len() as u64, nar_size, "must degrade to plain striping and finish");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "a hung manifest body must not stall the transfer: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn narinfo_after_nar_rediscovery_serves_the_real_info() {
        // Restart recovery creates a placeholder holder set (no StorePath/CA). A later narinfo
        // lookup must serve the peer's REAL narinfo, never the placeholder.
        let dir = tempfile::tempdir().unwrap();
        let (serve_url, _nar_size, nar_hash) = spawn_fake_serve(dir.path()).await;
        let (proxy_url, _) = spawn_proxy(&[("test", &serve_url)], "").await;
        let client = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        // NAR first: a fresh proxy discovers holders by hash (synthetic set).
        let resp = client.get(format!("{proxy_url}/nar/{nar32}.nar")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let _ = resp.bytes().await.unwrap();
        // Then the narinfo: the real one must be adopted and served.
        let ni = client
            .get(format!("{proxy_url}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let text = ni.text().await.unwrap();
        assert!(text.contains("CA: fixed:r:sha256:dummy"), "real narinfo expected, got:\n{text}");
        assert!(!text.contains("<rediscovered"), "placeholder leaked to the client:\n{text}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nar_size_disagreement_answers_with_the_first_holders_info() {
        // Once a holder set exists, a peer claiming a different NarSize for the same narhash must
        // not change what clients are told: the narinfo served must match the set transfers use.
        let nar32 = crate::nixbase32::encode(&[7u8; 32]);
        let mk = |size: u64| {
            format!(
                "StorePath: /nix/store/jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj-z\nURL: nar/{nar32}.nar\n\
                 Compression: none\nNarHash: sha256:{nar32}\nNarSize: {size}\nReferences: \n\
                 CA: fixed:r:sha256:dummy\n"
            )
        };
        let peer = |text: String, on: Arc<std::sync::atomic::AtomicBool>| {
            Router::new().route(
                "/{f}",
                get(move |UrlPath(f): UrlPath<String>| {
                    let text = text.clone();
                    let on = on.clone();
                    async move {
                        if f == "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj.narinfo"
                            && on.load(Ordering::SeqCst)
                        {
                            ([(header::CONTENT_TYPE, "text/x-nix-narinfo")], text).into_response()
                        } else {
                            StatusCode::NOT_FOUND.into_response()
                        }
                    }
                }),
            )
        };
        let a_on = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let b_on = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let url_a = spawn_router(peer(mk(1000), a_on.clone())).await;
        let url_b = spawn_router(peer(mk(2000), b_on.clone())).await;
        let (proxy_url, _) =
            spawn_proxy(&[("a", &url_a), ("b", &url_b)], "negative_ttl = \"1ms\"").await;
        let client = reqwest::Client::new();

        let first = client
            .get(format!("{proxy_url}/jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), 200);
        assert!(first.text().await.unwrap().contains("NarSize: 1000"));

        a_on.store(false, Ordering::SeqCst);
        b_on.store(true, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let second = client
            .get(format!("{proxy_url}/jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), 200);
        let text = second.text().await.unwrap();
        assert!(
            text.contains("NarSize: 1000"),
            "must answer with the first holder's info, got:\n{text}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unmanifestable_path_404s_manifest_but_serves_the_nar() {
        // NARs allow non-UTF-8 names and symlink targets; JSON manifests don't. Such a path must
        // 404 its manifest (cached, so repeats don't re-read the tree) while the NAR serves
        // normally. A non-UTF-8 symlink TARGET is used because it is link content, not a
        // directory entry — filesystems with utf8only reject the latter.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("weird");
        let path = store.join("mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm-weird-1.0");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("plain"), b"payload").unwrap();
        use std::os::unix::ffi::OsStrExt;
        let bad_target = std::ffi::OsStr::from_bytes(b"t\xff");
        if std::os::unix::fs::symlink(bad_target, path.join("link")).is_err() {
            eprintln!("skipping: filesystem refuses non-UTF-8 symlink targets");
            return;
        }
        let table = nar::build(&path).unwrap();
        let nar_hash = nar_hash_of(&path);
        let store_dir = store.to_str().unwrap().to_owned();
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[(
                &format!("{store_dir}/mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm-weird-1.0"),
                nar_hash,
                table.nar_size,
                Some("fixed:r:sha256:dummy"),
            )],
        );
        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let db = Arc::new(StoreDb::open(&db_path, &store_dir).unwrap());
        let url = spawn_router(serve::router(serve::ServeState::new(
            db,
            SegmentReader::for_tests(),
            scfg,
        )))
        .await;
        let client = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        for _ in 0..2 {
            // The second hit exercises the cached-failure path.
            let m = client
                .get(format!("{url}/narshare/v1/manifest/{nar32}"))
                .send()
                .await
                .unwrap();
            assert_eq!(m.status(), 404, "non-UTF-8 names cannot be manifested");
        }
        let nar = client.get(format!("{url}/nar/{nar32}.nar")).send().await.unwrap();
        assert_eq!(nar.status(), 200);
        assert_eq!(nar.bytes().await.unwrap().len() as u64, table.nar_size);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_non_ca_path_relays_only_under_a_trusted_key() {
        use base64::Engine as _;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

        // An input-addressed path (no CA) with real content.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("sstore");
        let path_dir = store.join("ssssssssssssssssssssssssssssssss-signed-tool-1.0");
        std::fs::create_dir_all(&path_dir).unwrap();
        std::fs::write(path_dir.join("payload"), vec![0x42u8; 100_000]).unwrap();
        let table = nar::build(&path_dir).unwrap();
        let nar_hash = nar_hash_of(&path_dir);
        let store_dir = store.to_str().unwrap().to_owned();
        let full_path =
            format!("{store_dir}/ssssssssssssssssssssssssssssssss-signed-tool-1.0");
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[(&full_path, nar_hash, table.nar_size, None)],
        );

        // Sign its fingerprint with a fresh key, exactly as `nix store sign` would.
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([9u8; 32]));
        let info = crate::narinfo::RemoteNarinfo {
            store_path: full_path.clone(),
            compression: "none".into(),
            nar_hash,
            nar_size: table.nar_size,
            references: Vec::new(),
            deriver: None,
            ca: None,
            sigs: Vec::new(),
        };
        let fp = crate::sig::fingerprint(&info);
        let sig = format!("mesh-test-1:{}", b64(&*kp.sk.sign(fp.as_bytes(), None)));
        crate::db::tests::set_sigs(&db_path, &full_path, &sig);

        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let db = Arc::new(StoreDb::open(&db_path, &store_dir).unwrap());
        let serve_url = spawn_router(serve::router(serve::ServeState::new(
            db,
            SegmentReader::for_tests(),
            scfg,
        )))
        .await;
        let client = reqwest::Client::new();

        // Trusting proxy: relays the narinfo with the Sig intact, and serves the NAR.
        let pk = format!("mesh-test-1:{}", b64(&*kp.pk));
        let (proxy_url, _) =
            spawn_proxy(&[("t", &serve_url)], &format!("trusted_public_keys = [{pk:?}]")).await;
        let ni = client
            .get(format!("{proxy_url}/ssssssssssssssssssssssssssssssss.narinfo"))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let text = ni.text().await.unwrap();
        assert!(text.contains("Sig: mesh-test-1:"), "signature must be relayed:\n{text}");
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let body = client
            .get(format!("{proxy_url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.len() as u64, table.nar_size);

        // A proxy trusting a DIFFERENT key under the same name: refused at narinfo time —
        // the bandwidth-saving property (no NAR transfer ever starts).
        let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([1u8; 32]));
        let opk = format!("mesh-test-1:{}", b64(&*other.pk));
        let (untrusting, _) =
            spawn_proxy(&[("t", &serve_url)], &format!("trusted_public_keys = [{opk:?}]")).await;
        let code = client
            .get(format!("{untrusting}/ssssssssssssssssssssssssssssssss.narinfo"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(code, 404, "an untrusted signature must be refused before any transfer");

        // Empty trust anchor: CA-only behavior.
        let (ca_only, _) = spawn_proxy(&[("t", &serve_url)], "trusted_public_keys = []").await;
        let code = client
            .get(format!("{ca_only}/ssssssssssssssssssssssssssssssss.narinfo"))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(code, 404);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_manifest_requests_coalesce_on_one_build() {
        let dir = tempfile::tempdir().unwrap();
        let (serve_url, _, nar_hash) = spawn_fake_serve(dir.path()).await;
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let client = reqwest::Client::new();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let c = client.clone();
            let u = format!("{serve_url}/narshare/v1/manifest/{nar32}");
            set.spawn(async move { c.get(u).send().await.unwrap().bytes().await.unwrap() });
        }
        let mut bodies = Vec::new();
        while let Some(b) = set.join_next().await {
            bodies.push(b.unwrap());
        }
        assert_eq!(bodies.len(), 8);
        assert!(
            bodies.windows(2).all(|w| w[0] == w[1]),
            "every waiter must be served the same manifest"
        );
        let m: crate::manifest::Manifest = serde_json::from_slice(&bodies[0]).unwrap();
        assert!(crate::manifest::synth_layout(&m).is_ok());
    }
}
