//! The proxy listener: the substituter the local nix talks to (loopback). Lookups are LOCAL:
//! answered from the replicated mesh index (index.rs), which knows both the feasible narinfos
//! and which peers currently hold them, kept current by the sync subsystem (sync.rs). A hit
//! costs zero RTT; a miss costs a database read — nix falls through to its other substituters
//! or the builder immediately. The fan-out era's hedging, coalescing, negative cache, and
//! NAR-by-hash discovery are gone; the index answers NAR requests after a restart too, because
//! it persists.
//!
//!   GET /nix-cache-info
//!   GET|HEAD /<hashpart>.narinfo   → index lookup; narinfo composed from the FEASIBLE row
//!                                    (CA or trusted-signed; sigs relayed verbatim)
//!   GET /nar/<narhash>.nar         → index lookup by narhash → striped fetch from holders

use crate::config::{self, ProxyCfg};
use crate::fetch::{self, FetchCtx};
use crate::index::{Found, Index};
use crate::narinfo::rewrite_for_client;
use crate::nixbase32;
use crate::peers::Peers;
use crate::serve::{parse_range, RangeSpec};
use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::error;

pub struct ProxyState {
    pub peers: Arc<Peers>,
    pub fetch: FetchCtx,
    pub index: Arc<Index>,
    cfg: ProxyCfg,
}

impl ProxyState {
    pub fn new(
        peers: Arc<Peers>,
        index: Arc<Index>,
        peer_cfgs: &[config::Peer],
        cfg: ProxyCfg,
    ) -> Arc<Self> {
        let st = Arc::new(Self {
            fetch: FetchCtx::new(peer_cfgs, &cfg),
            peers,
            index,
            cfg,
        });
        // Warm-start the MW pool from the last run's weights (staleness-decayed by the
        // loader), so a mesh whose link shape was learned an hour ago starts learned.
        let names: Vec<String> = peer_cfgs.iter().map(|p| p.name.clone()).collect();
        match st.index.load_mw(&names) {
            Ok(Some((weights, best_rate, avg_loss))) => {
                st.fetch.pool.restore(&weights, best_rate, avg_loss);
                tracing::debug!("restored MW weights: {weights:?}");
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("could not restore MW weights: {e:#}"),
        }
        st
    }

    /// Persist the MW pool periodically (and once at shutdown) whenever observations were
    /// folded in — one shared pool serves every concurrent transfer, so this is the whole
    /// process's learned state.
    pub fn spawn_weight_saver(self: &Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<()>) {
        let st = self.clone();
        tokio::spawn(async move {
            let names: Vec<String> = st.peers.list.iter().map(|p| p.name.clone()).collect();
            if names.is_empty() {
                return;
            }
            let mut saved_at_obs = 0u64;
            loop {
                let stop = tokio::select! {
                    _ = shutdown.changed() => true,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => false,
                };
                let (weights, best_rate, avg_loss, obs) = st.fetch.pool.snapshot();
                if obs != saved_at_obs {
                    saved_at_obs = obs;
                    let index = st.index.clone();
                    let names = names.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        index.save_mw(&names, &weights, best_rate, avg_loss)
                    })
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("save task died: {e}")));
                    if let Err(e) = res {
                        tracing::warn!("could not persist MW weights: {e:#}");
                    }
                }
                if stop {
                    return;
                }
            }
        });
    }

    /// Fetchable sources for a found narinfo: holders that are configured peers (never self —
    /// nix checked its own store before asking us) whose breaker is not open RIGHT NOW,
    /// restricted to the lowest tier present among those (higher tiers are only consulted when
    /// no lower-tier peer can serve the path).
    ///
    /// Filtering breaker-open holders here — before any 200 is committed — is the "do no harm"
    /// gate: all-holders-dead becomes an instant 404 (nix falls through to its other
    /// substituters) instead of a transfer that coasts to the stall timeout, and a live tier-2
    /// holder covers for a dead tier-1 one. Recovery is ambient: breakers half-open after the
    /// cooldown, and the sync loops probe every peer regardless.
    fn sources_of(&self, found: &Found) -> Vec<(usize, String)> {
        let url = format!("nar/{}.nar", nixbase32::encode(&found.info.nar_hash));
        let mut v: Vec<(usize, String)> = found
            .holders
            .iter()
            .filter(|h| **h != self.index.self_name)
            .filter_map(|h| self.peers.idx_of(h))
            .filter(|i| self.peers.list[*i].available())
            .map(|i| (i, url.clone()))
            .collect();
        if let Some(min_tier) = v.iter().map(|(i, _)| self.peers.list[*i].tier).min() {
            v.retain(|(i, _)| self.peers.list[*i].tier == min_tier);
        }
        v
    }
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

async fn get_narinfo(
    State(st): State<Arc<ProxyState>>,
    UrlPath(file): UrlPath<String>,
) -> Response {
    st.fetch
        .stats
        .narinfo_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let miss = || {
        st.fetch
            .stats
            .narinfo_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        StatusCode::NOT_FOUND.into_response()
    };
    let Some(hash_part) = file.strip_suffix(".narinfo") else {
        return miss();
    };
    if hash_part.len() != 32 || !hash_part.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return miss();
    }
    let rows = {
        let index = st.index.clone();
        let hp = hash_part.to_owned();
        match tokio::task::spawn_blocking(move || index.lookup_hash_part(&hp))
            .await
            .unwrap()
        {
            Ok(rows) => rows,
            Err(e) => {
                // The index is disposable state and this substituter is consulted FIRST: a 500
                // makes nix retry with backoff, a 404 falls through to its other substituters
                // instantly. Log loudly, degrade to a miss.
                error!("index lookup failed (answering 404): {e:#}");
                return miss();
            }
        }
    };
    // The same store path can exist with different content (a non-reproducible rebuild):
    // answer with the copy the most peers can actually serve.
    let best = rows
        .iter()
        .map(|r| (r, st.sources_of(r).len()))
        .filter(|(_, n)| *n > 0)
        .max_by_key(|(_, n)| *n);
    match best {
        Some((row, _)) => {
            // Roaming epoch: a recent min_bandwidth abort means big paths should go straight
            // to the builder — refuse at lookup time.
            if st.fetch.refuses_while_roaming(row.info.nar_size) {
                return miss();
            }
            (
                [(header::CONTENT_TYPE, "text/x-nix-narinfo")],
                rewrite_for_client(&row.info),
            )
                .into_response()
        }
        None => miss(),
    }
}

async fn get_nar(
    State(st): State<Arc<ProxyState>>,
    UrlPath(file): UrlPath<String>,
    method: axum::http::Method,
    headers: HeaderMap,
) -> Response {
    st.fetch
        .stats
        .nar_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let miss = || {
        st.fetch
            .stats
            .nar_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        StatusCode::NOT_FOUND.into_response()
    };
    let nar_hash: [u8; 32] = match file
        .strip_suffix(".nar")
        .and_then(|h| nixbase32::decode(h, 32))
        .map(|v| <[u8; 32]>::try_from(v).unwrap())
    {
        Some(h) => h,
        None => return miss(),
    };
    let rows = {
        let index = st.index.clone();
        match tokio::task::spawn_blocking(move || index.lookup_nar_hash(&nar_hash))
            .await
            .unwrap()
        {
            Ok(rows) => rows,
            Err(e) => {
                error!("index lookup failed (answering 404): {e:#}");
                return miss();
            }
        }
    };
    // Different store paths can share identical content (same narhash): any holder of any of
    // them is a byte source for the same NAR. Union the sources; take metadata from the row
    // with the widest holder set.
    let Some(best) = rows.iter().max_by_key(|r| r.holders.len()) else {
        return miss();
    };
    let mut sources = Vec::new();
    for row in &rows {
        for s in st.sources_of(row) {
            if !sources.iter().any(|(i, _): &(usize, String)| *i == s.0) {
                sources.push(s);
            }
        }
    }
    if sources.is_empty() {
        return miss();
    }

    let size = best.info.nar_size;
    if st.fetch.refuses_while_roaming(size) {
        return miss();
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
        best.info.clone(),
        sources,
        start,
        end,
        tx,
    ));
    builder
        .body(Body::from_stream(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ServeCfg};
    use crate::db::StoreDb;
    use crate::index::proto;
    use crate::io::SegmentReader;
    use crate::sig::TrustedKeys;
    use crate::{nar, serve, sync};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    fn open_test_index(
        cache: &Path,
        name: &str,
        peer_names: &[String],
        keys: TrustedKeys,
    ) -> Arc<Index> {
        let store = Arc::new(crate::store::rocks::RocksStore::open(cache).unwrap());
        Arc::new(Index::open(store, name, peer_names, keys, std::time::Duration::ZERO).unwrap())
    }

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

    /// A full mesh node for tests: its own store, Nix db, index (exported once), and a serve
    /// listener with the sync endpoints merged — everything a peer is.
    pub(crate) struct TestNode {
        pub url: String,
        pub index: Arc<Index>,
        pub db: Arc<StoreDb>,
        pub handle: tokio::task::JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    pub(crate) async fn spawn_node(
        name: &'static str,
        all: &[&str],
        store_dir: &str,
        db_path: &Path,
        keys: TrustedKeys,
    ) -> TestNode {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(StoreDb::open(db_path, store_dir).unwrap());
        let peer_names: Vec<String> = all
            .iter()
            .filter(|n| **n != name)
            .map(|s| s.to_string())
            .collect();
        let index = open_test_index(&dir.path().join("cache"), name, &peer_names, keys);
        index.sync_own_db(&db).unwrap();
        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let serve_state = serve::ServeState::new(
            db.clone(),
            SegmentReader::for_tests(),
            scfg,
            Some(index.clone()),
        );
        let peers = Arc::new(
            Peers::new(
                &[],
                std::time::Duration::from_secs(5),
                3,
                std::time::Duration::from_secs(15),
                8,
            )
            .unwrap(),
        );
        let s = sync::Sync::new(
            index.clone(),
            peers,
            Some(db.clone()),
            None,
            std::time::Duration::from_secs(3600),
        );
        let status = crate::status::router(Arc::new(crate::status::StatusCtx {
            name: name.to_owned(),
            started: Instant::now(),
            index: index.clone(),
            proxy: None,
            sync: Some(s.clone()),
            serve: Some(serve_state.clone()),
        }));
        let (url, handle) =
            spawn_router_killable(serve::router(serve_state).merge(s.router()).merge(status)).await;
        TestNode {
            url,
            index,
            db,
            handle,
            _dir: dir,
        }
    }

    /// The consuming side: a proxy backed by its own index, syncing from the given nodes.
    pub(crate) struct TestClient {
        pub url: String,
        pub state: Arc<ProxyState>,
        pub sync: Arc<sync::Sync>,
        pub index: Arc<Index>,
        pub dir: tempfile::TempDir,
        pub handle: tokio::task::JoinHandle<()>,
    }

    pub(crate) async fn spawn_client(
        name: &'static str,
        nodes: &[(&str, &str)], // (name, url)
        extra: &str,
        keys: TrustedKeys,
    ) -> TestClient {
        let dir = tempfile::tempdir().unwrap();
        spawn_client_at(name, nodes, extra, keys, dir).await
    }

    pub(crate) async fn spawn_client_at(
        name: &'static str,
        nodes: &[(&str, &str)],
        extra: &str,
        keys: TrustedKeys,
        dir: tempfile::TempDir,
    ) -> TestClient {
        let peers_toml = nodes
            .iter()
            .map(|(n, u)| format!("[[peers]]\nname = \"{n}\"\nurl = \"{u}\"\n"))
            .collect::<String>();
        let cfg: Config = toml::from_str(&format!(
            "name = \"{name}\"\n[proxy]\nlisten = \"127.0.0.1:0\"\n{extra}\n{peers_toml}"
        ))
        .unwrap();
        let pcfg = cfg.proxy.as_ref().unwrap();
        let peers = Arc::new(
            Peers::new(
                &cfg.peers,
                pcfg.narinfo_timeout,
                pcfg.breaker_failures,
                pcfg.breaker_cooldown,
                pcfg.per_peer_connections,
            )
            .unwrap(),
        );
        let peer_names: Vec<String> = cfg.peers.iter().map(|p| p.name.clone()).collect();
        let index = open_test_index(&dir.path().join("cache"), name, &peer_names, keys);
        let s = sync::Sync::new(
            index.clone(),
            peers.clone(),
            None,
            None,
            std::time::Duration::from_secs(3600),
        );
        let state = ProxyState::new(
            peers,
            index.clone(),
            &cfg.peers,
            toml::from_str(&format!("listen = \"127.0.0.1:0\"\n{extra}")).unwrap(),
        );
        let status = crate::status::router(Arc::new(crate::status::StatusCtx {
            name: name.to_owned(),
            started: Instant::now(),
            index: index.clone(),
            proxy: Some(state.clone()),
            sync: Some(s.clone()),
            serve: None,
        }));
        let (url, handle) = spawn_router_killable(router(state.clone()).merge(status)).await;
        TestClient {
            url,
            state,
            sync: s,
            index,
            dir,
            handle,
        }
    }

    impl TestClient {
        /// Pull from every peer once — the deterministic stand-in for the background loops.
        pub(crate) async fn sync_all(&self) {
            for i in 0..self.state.peers.list.len() {
                let _ = self.sync.pull_from(i).await;
            }
        }

        /// A REAL restart: kill the server task and drop every Arc so the rocksdb store's
        /// process-exclusive lock is released before the same cache dir is reopened. (The v1
        /// sqlite layout tolerated concurrent opens; rocksdb correctly does not.)
        pub(crate) async fn shutdown(self) -> tempfile::TempDir {
            self.handle.abort();
            let _ = self.handle.await;
            self.dir
        }
    }

    fn sample_store(root: &Path) -> (String, u64, [u8; 32]) {
        let store = root.join("store");
        let path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-game-1.0");
        std::fs::create_dir_all(path.join("data")).unwrap();
        std::fs::write(path.join("data/blob.bin"), vec![0x5au8; 20_000]).unwrap();
        std::fs::write(path.join("readme"), b"hello\n").unwrap();
        let table = nar::build(&path).unwrap();
        (
            store.to_str().unwrap().to_owned(),
            table.nar_size,
            nar_hash_of(&path),
        )
    }

    /// One CA path and one non-CA path, in a fresh fake store.
    fn fake_store(dir: &Path) -> (String, PathBuf, u64, [u8; 32]) {
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
        (store_dir, db_path, nar_size, nar_hash)
    }

    /// A big compressible CA store shared by several nodes (same content => same store path).
    fn big_store(dir: &Path, bytes: usize) -> (String, PathBuf, u64, [u8; 32]) {
        let store = dir.join("bigstore");
        let path = store.join("gggggggggggggggggggggggggggggggg-big-1.0");
        std::fs::create_dir_all(&path).unwrap();
        let pattern: Vec<u8> = (0..4096u32).flat_map(|i| (i % 251).to_le_bytes()).collect();
        let blob: Vec<u8> = pattern.iter().cycle().take(bytes).copied().collect();
        std::fs::write(path.join("blob"), &blob).unwrap();
        let table = nar::build(&path).unwrap();
        let nar_hash = nar_hash_of(&path);
        let store_dir = store.to_str().unwrap().to_owned();
        let db_path = crate::db::tests::fake_db(
            dir,
            &[(
                &format!("{store_dir}/gggggggggggggggggggggggggggggggg-big-1.0"),
                nar_hash,
                table.nar_size,
                Some("fixed:r:sha256:dummy"),
            )],
        );
        (store_dir, db_path, table.nar_size, nar_hash)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_end_to_end_via_the_index() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, nar_size, nar_hash) = fake_store(dir.path());
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client("c", &[("a", &node.url)], "", TrustedKeys::none()).await;
        client.sync_all().await;
        let http = reqwest::Client::new();

        let ci = http
            .get(format!("{}/nix-cache-info", client.url))
            .send()
            .await
            .unwrap();
        assert!(ci.text().await.unwrap().contains("WantMassQuery: 1"));

        // The CA path resolves LOCALLY (the node could even be down for this part).
        let ni = http
            .get(format!(
                "{}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo",
                client.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let text = ni.text().await.unwrap();
        assert!(text.contains("CA: fixed:r:sha256:dummy"));
        let nar32 = crate::nixbase32::encode(&nar_hash);
        assert!(text.contains(&format!("URL: nar/{nar32}.nar")));

        // The non-CA unsigned path was never exported: infeasible, free local miss.
        let no = http
            .get(format!(
                "{}/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.narinfo",
                client.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(no.status(), 404);
        // Unknown path: also a free local miss.
        let miss = http
            .get(format!(
                "{}/cccccccccccccccccccccccccccccccc.narinfo",
                client.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(miss.status(), 404);

        // NAR via proxy == direct; ranges work.
        let direct = http
            .get(format!("{}/nar/{nar32}.nar", node.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let relayed = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap();
        assert_eq!(relayed.status(), 200);
        let relayed = relayed.bytes().await.unwrap();
        assert_eq!(direct, relayed);
        assert_eq!(relayed.len() as u64, nar_size);

        let part = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .header(header::RANGE, "bytes=100-4200")
            .send()
            .await
            .unwrap();
        assert_eq!(part.status(), 206);
        assert_eq!(part.bytes().await.unwrap(), direct.slice(100..4201));

        let nar9 = crate::nixbase32::encode(&[9u8; 32]);
        let miss = http
            .get(format!("{}/nar/{nar9}.nar", client.url))
            .send()
            .await
            .unwrap();
        assert_eq!(miss.status(), 404);
    }

    // ---------------------------------------------------------------------------------
    // MW regret bench (ignored; run with: cargo test --release mw_regret -- --ignored
    // --nocapture). A "fluid link" serializes every request through a shared byte rate, so
    // concurrency cannot multiply capacity and the configured rates ARE the ground-truth
    // counterfactuals classic regret needs.
    // ---------------------------------------------------------------------------------

    struct FluidLink {
        rate: std::sync::atomic::AtomicU64,
        next_free: tokio::sync::Mutex<tokio::time::Instant>,
    }

    impl FluidLink {
        fn new(rate: u64) -> Arc<Self> {
            Arc::new(Self {
                rate: std::sync::atomic::AtomicU64::new(rate),
                next_free: tokio::sync::Mutex::new(tokio::time::Instant::now()),
            })
        }
    }

    fn throttled_peer(link: Arc<FluidLink>, payload: bytes::Bytes) -> Router {
        Router::new().route(
            "/nar/{f}",
            get(move |headers: HeaderMap| {
                let link = link.clone();
                let payload = payload.clone();
                async move {
                    let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
                    let (start, end) = match parse_range(range, payload.len() as u64) {
                        RangeSpec::Partial(s, e) => (s, e),
                        _ => (0, payload.len() as u64),
                    };
                    let rate = link.rate.load(Ordering::Relaxed) as f64;
                    let finish = {
                        let mut nf = link.next_free.lock().await;
                        let now = tokio::time::Instant::now();
                        let begin = if *nf > now { *nf } else { now };
                        let fin =
                            begin + std::time::Duration::from_secs_f64((end - start) as f64 / rate);
                        *nf = fin;
                        fin
                    };
                    tokio::time::sleep_until(finish).await;
                    Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .body(Body::from(payload.slice(start as usize..end as usize)))
                        .unwrap()
                }
            }),
        )
    }

    /// Seed one narinfo for `payload`, held by BOTH origins a and b. Returns the nar32 name.
    fn seed_two_holders(client: &TestClient, payload: &bytes::Bytes, name: &str) -> String {
        use sha2::{Digest, Sha256};
        let h: [u8; 32] = Sha256::digest(payload).into();
        let att = proto::Attestation {
            store_path: format!("/nix/store/{}-{name}", "r".repeat(32)),
            nar_hash: h.to_vec(),
            nar_size: payload.len() as u64,
            references: vec![],
            ca: "fixed:r:sha256:dummy".into(),
            sigs: vec![],
        };
        client.index.seed_fact("a", att.clone());
        client.index.seed_fact("b", att);
        crate::nixbase32::encode(&h)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // measurement bench, not a correctness test
    async fn mw_regret_sequential_and_tracking() {
        const MB: u64 = 1_000_000;
        let link_a = FluidLink::new(64 * MB);
        let link_b = FluidLink::new(MB);
        let payload = bytes::Bytes::from(vec![0x42u8; 256 * 1024]);
        let url_a = spawn_router(throttled_peer(link_a.clone(), payload.clone())).await;
        let url_b = spawn_router(throttled_peer(link_b.clone(), payload.clone())).await;
        let client = spawn_client(
            "c",
            &[("a", &url_a), ("b", &url_b)],
            "",
            TrustedKeys::none(),
        )
        .await;
        let nar32 = seed_two_holders(&client, &payload, "seq");
        let http = reqwest::Client::new();
        let url = format!("{}/nar/{nar32}.nar", client.url);
        let tally = |i: usize| client.state.fetch.peer_tally(i);

        // S1 — static 64:1, unsaturated (one decision per fetch): bandit decision regret
        // against the hindsight-best peer, with ground-truth counterfactual losses.
        const T1: usize = 300;
        let mut picks_b_at = Vec::with_capacity(T1);
        for _ in 0..T1 {
            let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
            assert_eq!(b.len(), payload.len());
            picks_b_at.push(tally(1).0);
        }
        // Let detached hedge losers land their tallies before reading them.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let (ok_a, err_a, _) = tally(0);
        let (ok_b, err_b, _) = tally(1);
        assert_eq!(err_a + err_b, 0, "the fluid links never fail");
        // Hedged fetches complete TWICE (the loser is recorded by design), so completions
        // exceed decisions. Attribution stays exact: the slow peer is never a hedge partner
        // (partners are drawn for below-uniform primaries, and the slow peer is the only one
        // below uniform here), so ok_b counts exactly the slow-primary decisions.
        assert!(
            (ok_a + ok_b) as usize >= T1,
            "at least one completion per fetch"
        );
        let ok_b = picks_b_at[T1 - 1]; // slow picks at the moment the burst ended
        let loss_b = 1.0 - 1.0 / 64.0;
        let regret = ok_b as f64 * loss_b;
        let hedge_ref = (T1 as f64 / 2.0 * 2f64.ln()).sqrt();
        let first25 = picks_b_at[24];
        let last100 = picks_b_at[T1 - 1] - picks_b_at[T1 - 101];
        println!(
            "[regret] S1 static 64:1 — T={T1}: slow-peer picks {ok_b} \
             (first25={first25}, last100={last100})"
        );
        println!(
            "[regret] S1 cumulative regret {regret:.1} (per-decision {:.4}) vs \
             Hedge sqrt-ref {hedge_ref:.1}; exploration floor W_MIN≈0.03",
            regret / T1 as f64
        );
        assert!(
            (last100 as f64) < 15.0,
            "steady-state slow share must sit near the exploration floor: {last100}/100"
        );

        // S2 — the links swap capabilities: tracking (the fixed-share raison d'être).
        link_a.rate.store(MB, Ordering::Relaxed);
        link_b.rate.store(64 * MB, Ordering::Relaxed);
        const T2: usize = 300;
        let (base_a, base_b) = (tally(0).0, tally(1).0);
        let mut blocks = Vec::new();
        let mut prev_b = base_b;
        for i in 0..T2 {
            http.get(&url).send().await.unwrap().bytes().await.unwrap();
            if (i + 1) % 25 == 0 {
                let nb = tally(1).0;
                blocks.push(nb - prev_b);
                prev_b = nb;
            }
        }
        let stale_picks = tally(0).0 - base_a;
        let flip = blocks
            .iter()
            .position(|&n| n >= 13)
            .map(|i| (i + 1) * 25)
            .unwrap_or(usize::MAX);
        println!("[regret] S2 swap — new-best picks per 25-block: {blocks:?}");
        println!(
            "[regret] S2 majority flipped within ≤{flip} decisions; post-swap tracking \
             regret {:.1} ({stale_picks} stale picks of the collapsed peer)",
            stale_picks as f64 * loss_b
        );
        let late: u64 = blocks[blocks.len() - 4..].iter().sum();
        assert!(
            late as f64 / 100.0 > 0.7,
            "the pool must track the swap: new-best share in the last 100 was {late}/100"
        );
    }

    /// One aggregation measurement: spawn two fluid-link peers, LEARN weights over 8 warmup
    /// fetches of a 32 MiB NAR, then take the median of 5 measured fetches. Returns
    /// (median MB/s, slow-peer byte share % over the measured fetches, learned weights).
    async fn aggregation_run(ra: u64, rb: Option<u64>) -> (f64, f64, Vec<f64>) {
        const MB: u64 = 1_000_000;
        let link_a = FluidLink::new(ra);
        let payload = bytes::Bytes::from(vec![0x51u8; 32 * 1024 * 1024]);
        let url_a = spawn_router(throttled_peer(link_a.clone(), payload.clone())).await;
        let (client, nar32);
        if let Some(rb) = rb {
            let link_b = FluidLink::new(rb);
            let url_b = spawn_router(throttled_peer(link_b, payload.clone())).await;
            client = spawn_client(
                "c",
                &[("a", &url_a), ("b", &url_b)],
                "",
                TrustedKeys::none(),
            )
            .await;
            nar32 = seed_two_holders(&client, &payload, "agg");
        } else {
            client = spawn_client("c", &[("a", &url_a)], "", TrustedKeys::none()).await;
            use sha2::{Digest, Sha256};
            let h: [u8; 32] = Sha256::digest(&payload).into();
            client.index.seed_fact(
                "a",
                proto::Attestation {
                    store_path: format!("/nix/store/{}-agg", "r".repeat(32)),
                    nar_hash: h.to_vec(),
                    nar_size: payload.len() as u64,
                    references: vec![],
                    ca: "fixed:r:sha256:dummy".into(),
                    sigs: vec![],
                },
            );
            nar32 = crate::nixbase32::encode(&h);
        }
        let http = reqwest::Client::new();
        let url = format!("{}/nar/{nar32}.nar", client.url);
        for _ in 0..8 {
            let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
            assert_eq!(b.len(), payload.len());
        }
        let base_b = client
            .state
            .fetch
            .peer_tally(1.min(client.state.peers.list.len() - 1))
            .2;
        let base_a = client.state.fetch.peer_tally(0).2;
        let mut walls = Vec::new();
        for _ in 0..5 {
            let t0 = Instant::now();
            let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
            assert_eq!(b.len(), payload.len());
            walls.push(t0.elapsed().as_secs_f64());
        }
        walls.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let median = walls[2];
        let da = client.state.fetch.peer_tally(0).2 - base_a;
        let db = if client.state.peers.list.len() > 1 {
            client.state.fetch.peer_tally(1).2 - base_b
        } else {
            0
        };
        let share_b = 100.0 * db as f64 / (da + db).max(1) as f64;
        let weights: Vec<f64> = client
            .state
            .fetch
            .pool
            .snapshot()
            .0
            .iter()
            .map(|w| (w * 1000.0).round() / 1000.0)
            .collect();
        (
            (payload.len() as f64 / MB as f64) / median,
            share_b,
            weights,
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hedged_ping_is_insured_and_still_measured() {
        // A floor-weight peer's pings must (a) not gate the fetches that draw them — the
        // duplicate wins — and (b) still produce measurements: the detached loser completes
        // and records itself even though its transfer already returned.
        const MB: u64 = 1_000_000;
        let link_a = FluidLink::new(64 * MB);
        let link_b = FluidLink::new(MB / 2);
        let payload = bytes::Bytes::from(vec![0x66u8; 256 * 1024]);
        let url_a = spawn_router(throttled_peer(link_a, payload.clone())).await;
        let url_b = spawn_router(throttled_peer(link_b, payload.clone())).await;
        let client = spawn_client(
            "c",
            &[("a", &url_a), ("b", &url_b)],
            "",
            TrustedKeys::none(),
        )
        .await;
        let nar32 = seed_two_holders(&client, &payload, "hedge");
        client.state.fetch.pool.restore(&[1.0, 0.03], 64e6, 0.05);
        client.state.fetch.set_rate(0, 64e6);
        client.state.fetch.set_rate(1, 5e5);
        let http = reqwest::Client::new();
        let url = format!("{}/nar/{nar32}.nar", client.url);
        let t0 = Instant::now();
        for _ in 0..200 {
            let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
            assert_eq!(b.len(), payload.len());
        }
        let wall = t0.elapsed();
        // Let detached losers land their measurements.
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        let hedges = client.state.fetch.stats.hedges.load(Ordering::Relaxed);
        let (ok_b, err_b, _) = client.state.fetch.peer_tally(1);
        assert!(hedges >= 1, "floor-weight pings must be insured");
        assert!(ok_b + err_b >= 1, "the losing twin must still be measured");
        // Mechanism test only: the burst's THROUGHPUT under drift is a tuning quantity the
        // mw_tune_sweep bench measures (fixed-share drift lifts the slow weight between
        // pings, and mid-weight draws are only partially insured). This bound is a hang guard.
        assert!(wall < std::time::Duration::from_secs(90), "hung: {wall:?}");
    }

    /// One (η, ν) sweep cell over the fluid 64:1 pair, sequential regime:
    /// returns (slow picks in first 50, slow share % of last 100, tail fetches >150 ms in last
    /// 100, decisions to majority-flip after a capability swap, stale picks after the swap).
    async fn tune_seq_cell(eta: f64, nu: f64, share: f64) -> (u64, f64, usize, usize, u64) {
        const MB: u64 = 1_000_000;
        let link_a = FluidLink::new(64 * MB);
        let link_b = FluidLink::new(MB);
        let payload = bytes::Bytes::from(vec![0x42u8; 256 * 1024]);
        let url_a = spawn_router(throttled_peer(link_a.clone(), payload.clone())).await;
        let url_b = spawn_router(throttled_peer(link_b.clone(), payload.clone())).await;
        let client = spawn_client(
            "c",
            &[("a", &url_a), ("b", &url_b)],
            "",
            TrustedKeys::none(),
        )
        .await;
        client.state.fetch.pool.set_eta(eta);
        client.state.fetch.pool.set_share(share);
        client.state.fetch.set_nu(nu);
        let nar32 = seed_two_holders(&client, &payload, "seq");
        let http = reqwest::Client::new();
        let url = format!("{}/nar/{nar32}.nar", client.url);
        let slow_picks = |i: usize| {
            let (ok, err, _) = client.state.fetch.peer_tally(i);
            ok + err
        };
        const T: usize = 200;
        let mut b_at = Vec::with_capacity(T);
        let mut tails_last100 = 0usize;
        for i in 0..T {
            let t0 = Instant::now();
            let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
            assert_eq!(b.len(), payload.len());
            if i >= T - 100 && t0.elapsed().as_millis() > 150 {
                tails_last100 += 1;
            }
            b_at.push(slow_picks(1));
        }
        let first50 = b_at[49];
        let last100 = b_at[T - 1] - b_at[T - 101];

        // Swap capabilities; measure tracking.
        link_a.rate.store(MB, Ordering::Relaxed);
        link_b.rate.store(64 * MB, Ordering::Relaxed);
        let (base_a, base_b) = (slow_picks(0), slow_picks(1));
        let mut flip = usize::MAX;
        let mut prev_b = base_b;
        for i in 0..T {
            http.get(&url).send().await.unwrap().bytes().await.unwrap();
            if (i + 1) % 25 == 0 {
                let nb = slow_picks(1);
                if flip == usize::MAX && nb - prev_b >= 13 {
                    flip = i + 1;
                }
                prev_b = nb;
            }
        }
        let stale = slow_picks(0) - base_a;
        (first50, last100 as f64, tails_last100, flip, stale)
    }

    /// One (η, ν) sweep cell, striped regime with LEARNED weights: returns
    /// (median % of single-best, worst wall s, learned slow weight, hedge waste % of remote).
    async fn tune_striped_cell(
        eta: f64,
        nu: f64,
        share: f64,
        ra: u64,
        rb: u64,
        warmups: usize,
    ) -> (f64, f64, f64, f64) {
        const MB: u64 = 1_000_000;
        let link_a = FluidLink::new(ra);
        let link_b = FluidLink::new(rb);
        let payload = bytes::Bytes::from(vec![0x43u8; 32 * 1024 * 1024]);
        let url_a = spawn_router(throttled_peer(link_a, payload.clone())).await;
        let url_b = spawn_router(throttled_peer(link_b, payload.clone())).await;
        let client = spawn_client(
            "c",
            &[("a", &url_a), ("b", &url_b)],
            "",
            TrustedKeys::none(),
        )
        .await;
        client.state.fetch.pool.set_eta(eta);
        client.state.fetch.pool.set_share(share);
        client.state.fetch.set_nu(nu);
        let nar32 = seed_two_holders(&client, &payload, "str");
        let http = reqwest::Client::new();
        let url = format!("{}/nar/{nar32}.nar", client.url);
        for _ in 0..warmups {
            let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
            assert_eq!(b.len(), payload.len());
        }
        let mut walls = Vec::new();
        for _ in 0..5 {
            let t0 = Instant::now();
            let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
            assert_eq!(b.len(), payload.len());
            walls.push(t0.elapsed().as_secs_f64());
        }
        let mut sorted = walls.clone();
        sorted.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let size_mb = payload.len() as f64 / MB as f64;
        let median_pct = 100.0 * (size_mb / sorted[2]) / (ra as f64 / MB as f64);
        let worst = sorted[4];
        let w_slow = client.state.fetch.pool.snapshot().0[1];
        let s = &client.state.fetch.stats;
        // Premium counted at hedge LAUNCH: observed-loser bytes undercount (losers landing
        // after their transfer ended are invisible to the accounting loop).
        let waste_pct = 100.0 * s.hedge_bytes.load(Ordering::Relaxed) as f64
            / s.remote_bytes.load(Ordering::Relaxed).max(1) as f64;
        (median_pct, worst, w_slow, waste_pct)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // measurement bench: cargo test --release mw_hedge_cost -- --ignored --nocapture
    async fn mw_hedge_cost() {
        // The insurance premium near WEIGHT PARITY: with the linear ramp (nu=1), a peer whose
        // weight jitters microscopically below uniform still hedges a few percent of draws —
        // and near parity the "slow" peer is not slow, so duplicates are full-size chunks.
        // Measured with the launch-time hedge_bytes counter (the sweep's original waste
        // column undercounted: losers landing post-transfer were never observed).
        const MB: u64 = 1_000_000;
        for nu in [1.0f64, 2.0, 3.0] {
            let link_a = FluidLink::new(32 * MB);
            let link_b = FluidLink::new(32 * MB);
            let small = bytes::Bytes::from(vec![0x37u8; 256 * 1024]);
            let url_a = spawn_router(throttled_peer(link_a.clone(), small.clone())).await;
            let url_b = spawn_router(throttled_peer(link_b.clone(), small.clone())).await;
            let client = spawn_client(
                "c",
                &[("a", &url_a), ("b", &url_b)],
                "",
                TrustedKeys::none(),
            )
            .await;
            client.state.fetch.set_nu(nu);
            let nar32 = seed_two_holders(&client, &small, "par");
            let http = reqwest::Client::new();
            let url = format!("{}/nar/{nar32}.nar", client.url);
            for _ in 0..300 {
                let b = http.get(&url).send().await.unwrap().bytes().await.unwrap();
                assert_eq!(b.len(), small.len());
            }
            let s = &client.state.fetch.stats;
            let seq_premium = 100.0 * s.hedge_bytes.load(Ordering::Relaxed) as f64
                / s.remote_bytes.load(Ordering::Relaxed).max(1) as f64;
            let (med11, _, _, striped_premium) =
                tune_striped_cell(0.7, nu, 0.005, 32 * MB, 32 * MB, 3).await;
            let (_, _, tails, _, _) = tune_seq_cell(0.7, nu, 0.005).await;
            println!(
                "[hedge] nu={nu}: parity premium seq {seq_premium:.2}% / striped-1:1 \
                 {striped_premium:.2}% (med {med11:.0}% of single); 64:1 tails {tails}/100"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // tuning sweep — run alone: cargo test --release mw_tune -- --ignored --nocapture
    async fn mw_tune_sweep() {
        let run = |eta: f64, nu: f64, sh: f64| async move {
            let (first50, slow_share, tails, flip, stale) = tune_seq_cell(eta, nu, sh).await;
            let (med64, worst64, _w64, waste64) =
                tune_striped_cell(eta, nu, sh, 64_000_000, 1_000_000, 3).await;
            let (med21, worst21, w21, _) =
                tune_striped_cell(eta, nu, sh, 32_000_000, 16_000_000, 5).await;
            println!(
                "[tune] eta={eta} nu={nu} share={sh} | seq64: first50={first50} \
                 slow={slow_share}/100 tails={tails}/100 | swap: flip<={flip} stale={stale} | \
                 striped64: med={med64:.0}% worst={worst64:.2}s waste={waste64:.1}% | 2:1: \
                 med={med21:.0}% worst={worst21:.2}s w_slow={w21:.2}"
            );
        };
        for eta in [0.4, 0.7, 1.2] {
            for nu in [1.0, 3.0, 6.0] {
                run(eta, nu, 0.02).await;
            }
        }
        // Supplementary (outside the asked scope, but the binding constraint the grid
        // exposes): the fixed-share drift rate sets the steady slow share and the tail rate
        // far more than eta/nu do — measure it at the provisional center.
        for sh in [0.005, 0.001] {
            run(0.7, 3.0, sh).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // measurement bench — run ALONE (name filter): it toggles a process-global flag
    async fn mw_aggregation_ab() {
        const MB: u64 = 1_000_000;
        // Reference: the fast peer alone, through the same proxy path (the fair single-best).
        let (solo, _, _) = aggregation_run(32 * MB, None).await;
        println!("[agg] solo 32 MB/s peer through the proxy: {solo:.1} MB/s (fluid ideal 32)");

        for (ra, rb, tag) in [
            (32 * MB, 32 * MB, "1:1"),
            (32 * MB, 16 * MB, "2:1"),
            (32 * MB, 8 * MB, "4:1"),
        ] {
            for wc in [false, true] {
                crate::fetch::BENCH_WORK_CONSERVING.store(wc, Ordering::SeqCst);
                let (mbps, share_b, weights) = aggregation_run(ra, Some(rb)).await;
                let policy = if wc {
                    "work-conserving(old)"
                } else {
                    "proportional(new)"
                };
                println!(
                    "[agg] {tag} {policy}: median {mbps:.1} MB/s (fluid single-best {}, \
                     sum {}); slow byte share {share_b:.1}%; learned weights {weights:?}",
                    ra / MB,
                    (ra + rb) / MB
                );
            }
        }
        crate::fetch::BENCH_WORK_CONSERVING.store(false, Ordering::SeqCst);
        // 64:1 proportional for the same table (old policy at 64:1 is the known 4 MB/s
        // catastrophe; re-measuring it costs minutes, so it is cited, not re-run).
        let (mbps, share_b, weights) = aggregation_run(64 * MB, Some(MB)).await;
        println!(
            "[agg] 64:1 proportional(new): median {mbps:.1} MB/s (fluid single-best 64); \
             slow byte share {share_b:.1}%; learned weights {weights:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // measurement bench, not a correctness test
    async fn mw_regret_striped_skew() {
        const MB: u64 = 1_000_000;
        for (ra, rb, tag, floor) in [(64 * MB, MB, "64:1", 0.8), (32 * MB, 8 * MB, "4:1", 0.7)] {
            let link_a = FluidLink::new(ra);
            let link_b = FluidLink::new(rb);
            let payload = bytes::Bytes::from(vec![(ra % 251) as u8; 32 * 1024 * 1024]);
            let url_a = spawn_router(throttled_peer(link_a.clone(), payload.clone())).await;
            let url_b = spawn_router(throttled_peer(link_b.clone(), payload.clone())).await;
            let client = spawn_client(
                "c",
                &[("a", &url_a), ("b", &url_b)],
                "",
                TrustedKeys::none(),
            )
            .await;
            let nar32 = seed_two_holders(&client, &payload, "striped");
            let http = reqwest::Client::new();
            let size_mb = payload.len() as f64 / MB as f64;
            let single = ra as f64 / MB as f64;
            let sum = (ra + rb) as f64 / MB as f64;
            let url = format!("{}/nar/{nar32}.nar", client.url);
            let fetch = |url: String| {
                let http = http.clone();
                async move {
                    let t0 = Instant::now();
                    let body = http.get(url).send().await.unwrap().bytes().await.unwrap();
                    (body.len(), t0.elapsed().as_secs_f64())
                }
            };

            // Cold: uniform weights — the learning cost, reported but not asserted
            // (accepted: paid once per weight lifetime, amortized over the whole burst).
            let (n, cold_wall) = fetch(url.clone()).await;
            assert_eq!(n, payload.len());
            println!(
                "[regret] S3 {tag} cold (uniform weights): {:.1} MB/s (wall {cold_wall:.2}s)",
                size_mb / cold_wall
            );

            // THE CONSTRAINT: at asymptotically stable weights, throughput must stay near
            // the fastest peer's — the only residual cost being the W_MIN re-discovery
            // ping. Install the asymptotic state deterministically (collapsed weight,
            // learned rates) and take the median of 5 fetches: a ~W_MIN-probability draw
            // still hands the slow peer one ~2 s chunk — that IS the ping — so single
            // fetches have a deliberate fat tail the median ignores.
            client
                .state
                .fetch
                .pool
                .restore(&[1.0, 0.03], ra as f64, 0.05);
            client.state.fetch.set_rate(0, ra as f64);
            client.state.fetch.set_rate(1, rb as f64);
            let mut walls = Vec::new();
            for _ in 0..5 {
                let (n, w) = fetch(url.clone()).await;
                assert_eq!(n, payload.len());
                walls.push(w);
            }
            let mut sorted = walls.clone();
            sorted.sort_by(|x, y| x.partial_cmp(y).unwrap());
            let median = sorted[2];
            let achieved = size_mb / median;
            let (_, _, bytes_a) = client.state.fetch.peer_tally(0);
            let (_, _, bytes_b) = client.state.fetch.peer_tally(1);
            let share_b = 100.0 * bytes_b as f64 / (bytes_a + bytes_b) as f64;
            println!(
                "[regret] S3 {tag} warm: median {achieved:.1} MB/s = {:.0}% of single-best \
                 {single:.0} (capacity-sum {sum:.0}); walls {walls:?}; slow byte share \
                 (incl. cold fetch) {share_b:.1}%",
                100.0 * achieved / single
            );
            assert!(
                achieved > floor * single,
                "{tag}: median {achieved:.1} MB/s violates the {floor}x-single-best floor \
                 at asymptotic weights (walls {walls:?})"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn status_endpoint_reports_the_whole_story() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, nar_size, nar_hash) = fake_store(dir.path());
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client("c", &[("a", &node.url)], "", TrustedKeys::none()).await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let body = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.len() as u64, nar_size);

        let fetch_status = |url: String| {
            let http = http.clone();
            async move {
                let text = http
                    .get(format!("{url}/narshare/v1/status"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    text.headers()[reqwest::header::CONTENT_TYPE],
                    "application/json"
                );
                serde_json::from_str::<serde_json::Value>(&text.text().await.unwrap()).unwrap()
            }
        };
        // The completed-counter increment races the last body byte by a hair: poll briefly.
        let mut st = fetch_status(client.url.clone()).await;
        for _ in 0..50 {
            if st["proxy"]["transfers"]["active"] == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            st = fetch_status(client.url.clone()).await;
        }
        assert_eq!(st["name"], "c");
        let t = &st["proxy"]["transfers"];
        assert_eq!(t["active"], 0, "no leaked transfers: {t}");
        assert_eq!(t["completed"], 1);
        assert_eq!(t["aborted"]["stall"], 0);
        let peer = &st["proxy"]["peers"][0];
        assert_eq!(peer["name"], "a");
        assert_eq!(peer["available"], true);
        assert_eq!(peer["breaker"]["opens_total"], 0);
        assert!(st["proxy"]["bytes"]["remote"].as_u64().unwrap() >= nar_size);
        assert!(st["sync"]["pulls_ok"].as_u64().unwrap() >= 1);
        assert!(
            st["sync"]["snapshots_applied"].as_u64().unwrap() >= 1,
            "first contact"
        );
        assert!(
            st["serve"].is_null(),
            "a proxy-only node reports no serve section"
        );

        // The holder's view: serve counters moved, sync requests were served, and the index
        // identity (per-origin generation/seq) agrees exactly with the client's — the
        // convergence check the VM suite leans on.
        let ns = fetch_status(node.url.clone()).await;
        assert!(ns["serve"]["nar_requests"].as_u64().unwrap() >= 1);
        assert!(ns["sync"]["sync_requests_served"].as_u64().unwrap() >= 1);
        let find = |v: &serde_json::Value, name: &str| -> serde_json::Value {
            v["index"]["origins"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["name"] == name)
                .unwrap()
                .clone()
        };
        let (ca, na) = (find(&st, "a"), find(&ns, "a"));
        assert_eq!(ca["generation"], na["generation"]);
        assert_eq!(ca["seq"], na["seq"]);
        assert_eq!(st["index"]["narinfos"], ns["index"]["narinfos"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn breaker_open_holders_yield_fast_404s_until_recovery() {
        // "Do no harm": when every holder of a path is breaker-open, both the narinfo and the
        // nar must 404 instantly — nix falls through to its other substituters — instead of
        // committing a 200 and coasting to the stall timeout.
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, _nar_size, nar_hash) = fake_store(dir.path());
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client(
            "c",
            &[("a", &node.url)],
            "breaker_failures = 1\nbreaker_cooldown = \"300ms\"",
            TrustedKeys::none(),
        )
        .await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let url = format!("{}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo", client.url);
        assert_eq!(http.get(&url).send().await.unwrap().status(), 200);

        client.state.peers.strike(0); // the only holder trips its breaker
        assert_eq!(http.get(&url).send().await.unwrap().status(), 404);
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let nar = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap();
        assert_eq!(nar.status(), 404);

        // Cooldown elapsed: half-open counts as available, the path serves again.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(http.get(&url).send().await.unwrap().status(), 200);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn index_persists_across_proxy_restart() {
        // nix caches narinfos client-side and requests NARs directly after a proxy restart:
        // the persistent index answers by narhash with no peer round-trip.
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, nar_size, nar_hash) = fake_store(dir.path());
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let first = spawn_client("c", &[("a", &node.url)], "", TrustedKeys::none()).await;
        first.sync_all().await;
        let cache_dir = first.shutdown().await;

        // "Restart": same cache dir, fresh everything else, NO sync.
        let second =
            spawn_client_at("c", &[("a", &node.url)], "", TrustedKeys::none(), cache_dir).await;
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let http = reqwest::Client::new();
        let resp = http
            .get(format!("{}/nar/{nar32}.nar", second.url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.bytes().await.unwrap().len() as u64, nar_size);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mw_weights_warm_start_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, _sz, _hash) = fake_store(dir.path());
        let node = spawn_node(
            "a",
            &["a", "b", "c"],
            &store_dir,
            &db_path,
            TrustedKeys::none(),
        )
        .await;
        // Two peers so relative weights exist (the pool renormalizes max → 1.0): "b" is dead.
        let peers: [(&str, &str); 2] = [("a", &node.url), ("b", "http://127.0.0.1:9")];
        let first = spawn_client("c", &peers, "", TrustedKeys::none()).await;
        for _ in 0..8 {
            first
                .state
                .fetch
                .pool
                .record_success(0, 8 << 20, std::time::Duration::from_secs(1));
            first.state.fetch.pool.record_failure(1);
        }
        let (w, br, al, _) = first.state.fetch.pool.snapshot();
        assert!(w[1] < 0.1, "precondition: b collapsed: {w:?}");
        first
            .index
            .save_mw(&["a".to_string(), "b".to_string()], &w, br, al)
            .unwrap();
        let cache = first.shutdown().await;

        // "Restart": same cache dir. The pool must start already knowing b is bad.
        let second = spawn_client_at("c", &peers, "", TrustedKeys::none(), cache).await;
        let (w2, br2, _, obs) = second.state.fetch.pool.snapshot();
        assert_eq!(
            obs, 0,
            "no observations yet — this is purely restored state"
        );
        assert!(
            w2[1] < 0.1,
            "restored weights must reflect the learned collapse: {w2:?}"
        );
        assert!((w2[0] - 1.0).abs() < 0.01);
        assert!(br2 > 0.0, "the yardstick survives (staleness-decayed)");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gc_on_the_holder_propagates_to_a_404() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, _nar_size, _nar_hash) = fake_store(dir.path());
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client("c", &[("a", &node.url)], "", TrustedKeys::none()).await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let ok = http
            .get(format!(
                "{}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo",
                client.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);

        // "GC" the path on the holder: delete the db row, re-diff, re-sync.
        crate::db::tests::delete_path(
            &db_path,
            &format!("{store_dir}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-game-1.0"),
        );
        assert!(node.index.sync_own_db(&node.db).unwrap() > 0);
        client.sync_all().await;
        let gone = http
            .get(format!(
                "{}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo",
                client.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            gone.status(),
            404,
            "a GC'd path must disappear from the mesh index"
        );
        // The fact lost its last holder; the (paced in production, explicit here) reaper
        // removes it under the test fixtures' zero grace.
        client.index.compact().unwrap();
        assert_eq!(client.index.count_attestations(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn incremental_export_defers_gc_and_signing_to_reconciliation() {
        // The differ's contract: additions ride the id watermark per wake (O(new));
        // deletions and in-place signing are INVISIBLE until a reconciliation (hourly in
        // production, forced here) — with the 410 feedback path covering the fetch-facing
        // staleness in between (tested separately).
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let p1 = format!("{}/{}-one", store.display(), "1".repeat(32));
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[(&p1, [1u8; 32], 10, Some("fixed:r:sha256:x"))],
        );
        let db = Arc::new(StoreDb::open(&db_path, store.to_str().unwrap()).unwrap());
        let index = open_test_index(
            &dir.path().join("cache"),
            "a",
            &["b".to_string()],
            TrustedKeys::none(),
        );
        let peers = Arc::new(
            Peers::new(
                &[],
                std::time::Duration::from_secs(5),
                3,
                std::time::Duration::from_secs(15),
                8,
            )
            .unwrap(),
        );
        let s = sync::Sync::new(
            index.clone(),
            peers,
            Some(db.clone()),
            None,
            std::time::Duration::from_secs(3600),
        );

        assert_eq!(
            s.export_own_db().await.unwrap(),
            2,
            "startup full: attest + have"
        );
        assert_eq!(s.export_own_db().await.unwrap(), 0, "quiet wake is gated");

        // Additions: exactly the new row's events, incrementally.
        let p2 = format!("{}/{}-two", store.display(), "2".repeat(32));
        crate::db::tests::insert_path(&db_path, &p2, [2u8; 32], 20, Some("fixed:r:sha256:y"));
        assert_eq!(s.export_own_db().await.unwrap(), 2);
        assert_eq!(index.holdings_of("a").len(), 2);

        // In-place signing: invisible to the watermark — deferred to reconciliation.
        crate::db::tests::set_sigs(&db_path, &p1, "cache.example-1:AAAA");
        assert_eq!(s.export_own_db().await.unwrap(), 0, "not yet visible");
        s.force_reconcile();
        assert_eq!(
            s.export_own_db().await.unwrap(),
            1,
            "reconciliation attests the sig"
        );
        let rows = index.lookup_hash_part(&"1".repeat(32)).unwrap();
        assert!(rows[0]
            .info
            .sigs
            .contains(&"cache.example-1:AAAA".to_string()));

        // GC: likewise deferred.
        crate::db::tests::delete_path(&db_path, &p2);
        assert_eq!(s.export_own_db().await.unwrap(), 0, "not yet visible");
        s.force_reconcile();
        assert_eq!(
            s.export_own_db().await.unwrap(),
            1,
            "reconciliation drops possession"
        );
        assert_eq!(index.holdings_of("a").len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stale_hold_answers_410_and_retracts_without_breaker_strike() {
        // Between reconciliations a GC'd path is still advertised. A peer's fetch must get
        // 410 Gone (no breaker strike — a strike would blank the holder's other content),
        // and the holder must retract its Have point-wise from the request's hash alone.
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, _nar_size, nar_hash) = fake_store(dir.path());
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client("c", &[("a", &node.url)], "", TrustedKeys::none()).await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);

        // GC the path on the holder WITHOUT letting its differ notice (deferred by design).
        crate::db::tests::delete_path(
            &db_path,
            &format!("{store_dir}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-game-1.0"),
        );
        let resp = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap();
        // The proxy commits its 200 before streaming; the sole holder's 410 aborts the body.
        assert!(
            resp.bytes().await.is_err(),
            "sole holder lost the bytes: the transfer must fail"
        );
        // The holder answered 410: no strike, breaker stays closed.
        assert!(
            client.state.peers.list[0].available(),
            "410 must not open the breaker"
        );
        // ...and it retracted its own Have from the request alone (no scan, no differ run).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if !node.index.holdings_of("a").contains(&nar_hash) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "hold was not retracted"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // After the client's next pull, the mesh index agrees: clean 404, not 410 noise.
        client.sync_all().await;
        let gone = http
            .get(format!(
                "{}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo",
                client.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(gone.status(), 404);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transitive_propagation_through_a_relay() {
        // a → b → c: c never talks to a, but learns a's holdings through b's cache.
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, _sz, nar_hash) = fake_store(dir.path());
        let all = ["a", "b", "c"];
        let a = spawn_node("a", &all, &store_dir, &db_path, TrustedKeys::none()).await;

        // b: a node with an EMPTY store of its own that syncs from a.
        let bdir = tempfile::tempdir().unwrap();
        let empty_db = crate::db::tests::fake_db(bdir.path(), &[]);
        let bstore = bdir.path().join("empty");
        std::fs::create_dir_all(&bstore).unwrap();
        let b = spawn_node(
            "b",
            &all,
            bstore.to_str().unwrap(),
            &empty_db,
            TrustedKeys::none(),
        )
        .await;
        // Drive b's pull from a deterministically.
        let b_peers = Arc::new(
            Peers::new(
                &[config::Peer {
                    name: "a".into(),
                    url: a.url.clone(),
                    tier: 1,
                    encoding: "auto".into(),
                }],
                std::time::Duration::from_secs(5),
                3,
                std::time::Duration::from_secs(15),
                8,
            )
            .unwrap(),
        );
        let b_sync = sync::Sync::new(
            b.index.clone(),
            b_peers,
            Some(b.db.clone()),
            None,
            std::time::Duration::from_secs(3600),
        );
        assert!(b_sync.pull_from(0).await.unwrap());

        // c CONFIGURES a (the origin universe is the configured mesh) but cannot reach it —
        // a dead address — and must still learn a's holdings through b's cache.
        let c = spawn_client(
            "c",
            &[("a", "http://127.0.0.1:9"), ("b", &b.url)],
            "",
            TrustedKeys::none(),
        )
        .await;
        let b_idx = c.state.peers.idx_of("b").unwrap();
        c.sync.pull_from(b_idx).await.unwrap();
        let rows = c.index.lookup_nar_hash(&nar_hash).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].holders, vec!["a".to_string()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn striped_fetch_across_two_holders() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, nar_size, nar_hash) = big_store(dir.path(), 3 << 20);
        let all = ["a", "b", "c"];
        let a = spawn_node("a", &all, &store_dir, &db_path, TrustedKeys::none()).await;
        let b = spawn_node("b", &all, &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client(
            "c",
            &[("a", &a.url), ("b", &b.url)],
            "chunk_max = \"256KiB\"\nwindow_bytes = \"2MiB\"",
            TrustedKeys::none(),
        )
        .await;
        client.sync_all().await;
        // This test asserts BYTE-EXACT striping accounting; hedged duplicates (which fire
        // stochastically even near weight parity and double-fetch a chunk by design) would
        // flake it. Hedging has its own tests — disable it here: h = ratio^∞ is 0 below the
        // floor anchor, and the exact-floor case cannot occur with a fresh pool.
        client.state.fetch.set_nu(f64::INFINITY);
        let http = reqwest::Client::new();

        let nar32 = crate::nixbase32::encode(&nar_hash);
        let direct = http
            .get(format!("{}/nar/{nar32}.nar", a.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let striped = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(striped.len() as u64, nar_size);
        assert_eq!(striped, direct);

        let remote = client.state.fetch.stats.remote_bytes.load(Ordering::SeqCst);
        assert_eq!(remote, nar_size);
        let wire = client.state.fetch.stats.wire_bytes.load(Ordering::SeqCst);
        assert!(
            wire < remote / 2,
            "expected compression: wire {wire} vs remote {remote}"
        );
        // Both holders were known to the index (striping had two sources).
        let rows = client.index.lookup_nar_hash(&nar_hash).unwrap();
        assert_eq!(rows[0].holders.len(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kill_a_holder_mid_transfer_and_finish_via_the_other() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, nar_size, nar_hash) = big_store(dir.path(), 3 << 20);
        let all = ["a", "b", "c"];
        let a = spawn_node("a", &all, &store_dir, &db_path, TrustedKeys::none()).await;
        let b = spawn_node("b", &all, &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client(
            "c",
            &[("a", &a.url), ("b", &b.url)],
            "chunk_max = \"256KiB\"\nwindow_bytes = \"1MiB\"\nstall_timeout = \"10s\"",
            TrustedKeys::none(),
        )
        .await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let killer = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            a.handle.abort();
        });
        let striped = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        killer.await.unwrap();
        assert_eq!(
            striped.len() as u64,
            nar_size,
            "transfer must complete via peer b"
        );
        use sha2::{Digest, Sha256};
        let got: [u8; 32] = Sha256::digest(&striped).into();
        assert_eq!(got, nar_hash, "bytes must be intact after failover");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hash_mismatch_aborts_the_stream() {
        // The holder's db claims a WRONG narhash for real content: the engine must withhold
        // the final chunk so the client sees a short-body error.
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, _sz, _real) = sample_store(dir.path());
        let ca_path = format!("{store_dir}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-game-1.0");
        let wrong = [0xabu8; 32];
        let nar_size = nar::build(Path::new(&ca_path)).unwrap().nar_size;
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[(&ca_path, wrong, nar_size, Some("fixed:r:sha256:dummy"))],
        );
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client("c", &[("a", &node.url)], "", TrustedKeys::none()).await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&wrong);
        let resp = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap();
        let body = resp.bytes().await;
        assert!(body.is_err(), "hash mismatch must abort the body");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn min_bandwidth_aborts_and_roaming_epoch_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, _sz, nar_hash) = big_store(dir.path(), 3 << 20);
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client(
            "c",
            &[("a", &node.url)],
            // The floor must be unreachable even by a RELEASE build on loopback (measured
            // 1.1–1.3 GB/s on fast hardware — 1GiB was a boundary flake), and a zero grace
            // makes the first completed chunk trip it deterministically.
            "chunk_max = \"256KiB\"\nmin_bandwidth = \"1TiB\"\nmin_bandwidth_grace = \"0s\"",
            TrustedKeys::none(),
        )
        .await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let resp = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap();
        assert!(
            resp.bytes().await.is_err(),
            "below-floor transfer must abort"
        );
        assert!(client.state.fetch.refuses_while_roaming(3 << 20));
        let again = http
            .get(format!(
                "{}/gggggggggggggggggggggggggggggggg.narinfo",
                client.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            again.status(),
            404,
            "roaming epoch must refuse the oversized path"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn manifest_dedup_fetches_each_distinct_blob_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("dstore");
        let path = store.join("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-dup-1.0");
        std::fs::create_dir_all(&path).unwrap();
        let x: Vec<u8> = (0..4u32 << 20).map(|i| (i % 249) as u8).collect();
        let d: Vec<u8> = (0..4u32 << 20)
            .map(|i| (i % 247).wrapping_add(13) as u8)
            .collect();
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
        let node = spawn_node("a", &["a", "c"], &store_dir, &db_path, TrustedKeys::none()).await;
        let client = spawn_client(
            "c",
            &[("a", &node.url)],
            "chunk_max = \"1MiB\"",
            TrustedKeys::none(),
        )
        .await;
        client.sync_all().await;
        let http = reqwest::Client::new();

        let nar32 = crate::nixbase32::encode(&nar_hash);
        let direct = http
            .get(format!("{}/nar/{nar32}.nar", node.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let deduped = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(deduped, direct, "dedup reconstruction must be byte-exact");

        let remote = client.state.fetch.stats.remote_bytes.load(Ordering::SeqCst);
        let replayed = client
            .state
            .fetch
            .stats
            .replayed_bytes
            .load(Ordering::SeqCst);
        let lits = client.state.fetch.stats.lit_bytes.load(Ordering::SeqCst);
        assert_eq!(
            remote,
            8 << 20,
            "each distinct blob crosses the wire exactly once"
        );
        assert_eq!(
            replayed,
            8 << 20,
            "the two duplicate occurrences replay from retention"
        );
        assert!(lits > 0, "framing must be synthesized locally");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_stall_watchdog_aborts() {
        // The case the watchdog legitimately OWNS: bytes flowed, then the only holder died and
        // stays dead (here: instant 5xx, so failures clear immediately and nothing is left
        // legally in flight). Patience from the last byte, then a clean mid-stream abort.
        let nar32 = crate::nixbase32::encode(&[7u8; 32]);
        let served = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let served2 = served.clone();
        let die = Router::new().route(
            "/nar/{f}",
            get(move |headers: HeaderMap| {
                let served = served2.clone();
                async move {
                    // First request: one valid 256 KiB chunk. Everything after: 500.
                    if served.fetch_add(1, Ordering::SeqCst) > 0 {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    let len = headers
                        .get(header::RANGE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|r| {
                            let (a, b) = r.strip_prefix("bytes=")?.split_once('-')?;
                            Some(b.parse::<u64>().ok()? - a.parse::<u64>().ok()? + 1)
                        })
                        .unwrap_or(0) as usize;
                    Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .body(Body::from(vec![0u8; len]))
                        .unwrap()
                }
            }),
        );
        let die_url = spawn_router(die).await;
        let client = spawn_client(
            "c",
            &[("die", &die_url)],
            "stall_timeout = \"300ms\"\nchunk_max = \"256KiB\"",
            TrustedKeys::none(),
        )
        .await;
        client.index.seed_fact(
            "die",
            proto::Attestation {
                store_path: "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-x".into(),
                nar_hash: vec![7u8; 32],
                nar_size: 1_000_000,
                references: vec![],
                ca: "fixed:r:sha256:dummy".into(),
                sigs: vec![],
            },
        );

        let http = reqwest::Client::new();
        let started = Instant::now();
        let resp = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap();
        assert!(
            resp.bytes().await.is_err(),
            "stalled relay should abort the body"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the watchdog, not a 20 s chunk deadline, must own this abort"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inflight_request_subordinates_the_stall_watchdog() {
        // Patience is subordinate to liveness BY CONSTRUCTION: a request that sits silent for
        // longer than stall_timeout but is still within its own per-peer deadline must not be
        // killed by the watchdog — the transfer completes when the response finally lands.
        // (Regression: the two clocks used to free-run and race; with stall_timeout below the
        // chunk deadline the watchdog aborted transfers whose only fault was a slow first
        // byte, e.g. a loaded holder's encode-pool wait.)
        const SIZE: usize = 100_000;
        use sha2::{Digest, Sha256};
        let nar_hash: [u8; 32] = Sha256::digest(vec![0x55u8; SIZE]).into();
        let slow_start = Router::new().route(
            "/nar/{f}",
            get(|| async {
                // Four stall periods of pure silence before any byte moves.
                tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .body(Body::from(vec![0x55u8; SIZE]))
                    .unwrap()
            }),
        );
        let url = spawn_router(slow_start).await;
        let client = spawn_client(
            "c",
            &[("slow", &url)],
            "stall_timeout = \"300ms\"",
            TrustedKeys::none(),
        )
        .await;
        client.index.seed_fact(
            "slow",
            proto::Attestation {
                store_path: "/nix/store/ffffffffffffffffffffffffffffffff-y".into(),
                nar_hash: nar_hash.to_vec(),
                nar_size: SIZE as u64,
                references: vec![],
                ca: "fixed:r:sha256:dummy".into(),
                sigs: vec![],
            },
        );

        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let body = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .expect("a silent-but-in-deadline wait must not be stalled out");
        assert_eq!(body.len(), SIZE);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn slow_but_alive_link_does_not_false_stall() {
        // The stall watchdog judges wire BYTES, not chunk completions: one chunk that takes
        // several stall periods to trickle in — the 500 kbit cellular case scaled down — must
        // complete, not abort. (Regression: completion-based liveness false-fired here, killing
        // any transfer whose first seed chunk outlasted stall_timeout.)
        const SIZE: usize = 100_000;
        use sha2::{Digest, Sha256};
        let sha_hex = {
            let d: [u8; 32] = Sha256::digest(vec![0x77u8; SIZE]).into();
            hex::encode(d)
        };
        let nar_hash: [u8; 32] = Sha256::digest(vec![0x77u8; SIZE]).into();

        let trickle = Router::new().route(
            "/nar/{f}",
            get(|| async {
                let (tx, rx) = mpsc::channel::<std::io::Result<bytes::Bytes>>(4);
                tokio::spawn(async move {
                    let payload = vec![0x77u8; SIZE];
                    for chunk in payload.chunks(2_000) {
                        if tx
                            .send(Ok(bytes::Bytes::copy_from_slice(chunk)))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                    }
                });
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .body(Body::from_stream(
                        tokio_stream::wrappers::ReceiverStream::new(rx),
                    ))
                    .unwrap()
            }),
        );
        let peer_url = spawn_router(trickle).await;
        // ~50 KB/s wire vs a 500 ms stall: the single 100 KB chunk needs ~2 s — four stall
        // periods — and must survive them all.
        let client = spawn_client(
            "c",
            &[("drip", &peer_url)],
            "stall_timeout = \"500ms\"",
            TrustedKeys::none(),
        )
        .await;
        client.index.seed_fact(
            "drip",
            proto::Attestation {
                store_path: "/nix/store/dddddddddddddddddddddddddddddddd-slow".into(),
                nar_hash: nar_hash.to_vec(),
                nar_size: SIZE as u64,
                references: vec![],
                ca: "fixed:r:sha256:dummy".into(),
                sigs: vec![],
            },
        );
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let body = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .expect("a slow-but-alive transfer must complete, not stall out");
        assert_eq!(body.len(), SIZE);
        assert_eq!(
            hex::encode::<[u8; 32]>(Sha256::digest(&body).into()),
            sha_hex
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_decode_output_is_rejected() {
        use axum::routing::any;
        // A holder whose chunks decompress far beyond the requested length: the bounded
        // decoder must reject without allocating the full output.
        let frame = zstd::stream::encode_all(&vec![0u8; 4 << 20][..], 3).unwrap();
        let frame = std::sync::Arc::new(frame);
        let peer = Router::new().route(
            "/nar/{f}",
            any(move |hdrs: HeaderMap| {
                let frame = frame.clone();
                async move {
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
        let client = spawn_client(
            "c",
            &[("over", &peer_url)],
            "chunk_max = \"256KiB\"\nstall_timeout = \"1s\"",
            TrustedKeys::none(),
        )
        .await;
        client.index.seed_fact(
            "over",
            proto::Attestation {
                store_path: "/nix/store/iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii-oversized".into(),
                nar_hash: vec![42u8; 32],
                nar_size: 1_048_576,
                references: vec![],
                ca: "fixed:r:sha256:x".into(),
                sigs: vec![],
            },
        );
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&[42u8; 32]);
        let started = Instant::now();
        let resp = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap();
        assert!(
            resp.bytes().await.is_err(),
            "an over-expanding chunk must not succeed"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(8));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn transfer_degrades_when_the_manifest_endpoint_hangs() {
        // acquire_manifest runs BEFORE the transfer's stall watchdog exists: a peer that sends
        // manifest headers and then dribbles nothing must cost at most the request cap, after
        // which the transfer proceeds as plain striping.
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, nar_size, nar_hash) = big_store(dir.path(), 6 << 20);
        let db = Arc::new(StoreDb::open(&db_path, &store_dir).unwrap());
        let index = open_test_index(
            &dir.path().join("cache"),
            "hangman",
            &["c".to_string()],
            TrustedKeys::none(),
        );
        index.sync_own_db(&db).unwrap();
        let scfg: ServeCfg = toml::from_str(&format!(
            "listen = \"127.0.0.1:0\"\nstore_dir = {store_dir:?}\ndb_path = {:?}",
            db_path.to_str().unwrap()
        ))
        .unwrap();
        let serve_state = serve::ServeState::new(
            db.clone(),
            SegmentReader::for_tests(),
            scfg,
            Some(index.clone()),
        );
        let peers0 = Arc::new(
            Peers::new(
                &[],
                std::time::Duration::from_secs(5),
                3,
                std::time::Duration::from_secs(15),
                8,
            )
            .unwrap(),
        );
        let s = sync::Sync::new(
            index,
            peers0,
            Some(db),
            None,
            std::time::Duration::from_secs(3600),
        );
        let inner = serve::router(serve_state).merge(s.router());
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
            .fallback_service(inner);
        let url = spawn_router(hang).await;
        let client = spawn_client(
            "c",
            &[("hangman", &url)],
            "narinfo_timeout = \"500ms\"\nchunk_max = \"1MiB\"",
            TrustedKeys::none(),
        )
        .await;
        client.sync_all().await;
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let started = Instant::now();
        let body = http
            .get(format!("{}/nar/{nar32}.nar", client.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(
            body.len() as u64,
            nar_size,
            "must degrade to plain striping and finish"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unmanifestable_path_404s_manifest_but_serves_the_nar() {
        // NARs allow non-UTF-8 names and symlink targets; JSON manifests don't. Such a path
        // must 404 its manifest (cached, so repeats don't re-read the tree) while the NAR
        // serves normally. A non-UTF-8 symlink TARGET is used because it is link content, not
        // a directory entry — filesystems with utf8only reject the latter.
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
            None,
        )))
        .await;
        let http = reqwest::Client::new();
        let nar32 = crate::nixbase32::encode(&nar_hash);
        for _ in 0..2 {
            let m = http
                .get(format!("{url}/narshare/v1/manifest/{nar32}"))
                .send()
                .await
                .unwrap();
            assert_eq!(m.status(), 404, "non-UTF-8 names cannot be manifested");
        }
        let nar = http
            .get(format!("{url}/nar/{nar32}.nar"))
            .send()
            .await
            .unwrap();
        assert_eq!(nar.status(), 200);
        assert_eq!(nar.bytes().await.unwrap().len() as u64, table.nar_size);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_manifest_requests_coalesce_on_one_build() {
        let dir = tempfile::tempdir().unwrap();
        let (store_dir, db_path, _sz, nar_hash) = fake_store(dir.path());
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
            None,
        )))
        .await;
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let http = reqwest::Client::new();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let c = http.clone();
            let u = format!("{url}/narshare/v1/manifest/{nar32}");
            set.spawn(async move { c.get(u).send().await.unwrap().bytes().await.unwrap() });
        }
        let mut bodies = Vec::new();
        while let Some(b) = set.join_next().await {
            bodies.push(b.unwrap());
        }
        assert_eq!(bodies.len(), 8);
        assert!(bodies.windows(2).all(|w| w[0] == w[1]));
        let m: crate::manifest::Manifest = serde_json::from_slice(&bodies[0]).unwrap();
        assert!(crate::manifest::synth_layout(&m).is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_non_ca_path_syncs_only_under_a_trusted_key() {
        use base64::Engine as _;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("sstore");
        let path_dir = store.join("ssssssssssssssssssssssssssssssss-signed-tool-1.0");
        std::fs::create_dir_all(&path_dir).unwrap();
        std::fs::write(path_dir.join("payload"), vec![0x42u8; 100_000]).unwrap();
        let table = nar::build(&path_dir).unwrap();
        let nar_hash = nar_hash_of(&path_dir);
        let store_dir = store.to_str().unwrap().to_owned();
        let full_path = format!("{store_dir}/ssssssssssssssssssssssssssssssss-signed-tool-1.0");
        let db_path =
            crate::db::tests::fake_db(dir.path(), &[(&full_path, nar_hash, table.nar_size, None)]);
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
        let pk = format!("mesh-test-1:{}", b64(&*kp.pk));
        let keys = || TrustedKeys::parse(std::slice::from_ref(&pk));

        let node = spawn_node("a", &["a", "c", "d"], &store_dir, &db_path, keys()).await;
        let http = reqwest::Client::new();

        // A trusting client: the row syncs, the narinfo relays the Sig, the NAR serves.
        let trusting = spawn_client("c", &[("a", &node.url)], "", keys()).await;
        trusting.sync_all().await;
        let ni = http
            .get(format!(
                "{}/ssssssssssssssssssssssssssssssss.narinfo",
                trusting.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(ni.status(), 200);
        let text = ni.text().await.unwrap();
        assert!(
            text.contains("Sig: mesh-test-1:"),
            "signature must be relayed:\n{text}"
        );
        let nar32 = crate::nixbase32::encode(&nar_hash);
        let body = http
            .get(format!("{}/nar/{nar32}.nar", trusting.url))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.len() as u64, table.nar_size);

        // An untrusting client stores the well-formed fact for faithful relay but re-verifies
        // at USE: the path costs a local miss, not a transfer — and re-adding the key later
        // would wake the row without any resync.
        let untrusting = spawn_client("d", &[("a", &node.url)], "", TrustedKeys::none()).await;
        untrusting.sync_all().await;
        assert_eq!(
            untrusting.index.count_attestations(),
            1,
            "stored for relay, inert at use"
        );
        let no = http
            .get(format!(
                "{}/ssssssssssssssssssssssssssssssss.narinfo",
                untrusting.url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(no.status(), 404);
    }
}
