mod config;
mod db;
mod dedup;
mod fetch;
mod governor;
mod index;
mod io;
mod manifest;
mod nar;
mod narinfo;
mod nixbase32;
mod peers;
mod pool;
mod proxy;
mod serve;
mod sig;
mod status;
mod store;
mod sync;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "narshare",
    version,
    about = "Self-contained mesh Nix substituter"
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short = 'c', long = "config", global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (the default).
    Serve,
    /// Validate the config file and print the parsed result.
    Check,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg_path = cli.config.context("missing -c/--config <file>")?;
    let cfg = config::load(&cfg_path)?;
    match cli.cmd.unwrap_or(Cmd::Serve) {
        Cmd::Check => {
            println!("{cfg:#?}");
            Ok(())
        }
        Cmd::Serve => run(cfg).await,
    }
}

async fn run(cfg: config::Config) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "narshare=info".into()),
        )
        .init();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    tokio::spawn(async move {
        // systemd stops units with SIGTERM; Ctrl-C covers interactive runs.
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        info!("shutting down");
        let _ = shutdown_tx.send(());
        // Graceful shutdown drains in-flight connections with no deadline of its own, and one
        // peer mid-download (or a hung sync request) would otherwise hold the process until
        // systemd's SIGKILL — and tokio's registered handlers would swallow every further
        // signal. Bound the drain, and honor an impatient second signal immediately. State is
        // safe either way: the weight saver flushes on the shutdown edge, sqlite is
        // transactional, and everything else is re-learnable from the mesh.
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("second signal: exiting now"),
            _ = term.recv() => info!("second signal: exiting now"),
            _ = tokio::time::sleep(Duration::from_secs(20)) => {
                info!("drain deadline reached: exiting");
            }
        }
        std::process::exit(0);
    });

    // The mesh trust anchor and the replicated index — shared by every role.
    let trusted = sig::TrustedKeys::load(&cfg.trusted_public_keys);
    let peer_names: Vec<String> = cfg.peers.iter().map(|p| p.name.clone()).collect();
    let idx_store: Arc<dyn store::SyncStore> = match &cfg.cache.postgres {
        Some(url) => Arc::new(
            store::postgres::PgStore::connect(url, "narshare", false)
                .context("opening the postgres mesh index (cache.postgres)")?,
        ),
        None => Arc::new(
            store::rocks::RocksStore::open(&cfg.cache.dir.join("index")).with_context(|| {
                format!(
                    "opening the mesh index under {} (is [cache] dir writable?)",
                    cfg.cache.dir.display()
                )
            })?,
        ),
    };
    let idx = Arc::new(index::Index::open(
        idx_store,
        &cfg.name,
        &peer_names,
        trusted,
        cfg.cache.attestation_grace,
    )?);

    let peers = if cfg.peers.is_empty() {
        None
    } else {
        let (cap, bf, bc, idle) = match &cfg.proxy {
            Some(p) => (
                p.narinfo_timeout,
                p.breaker_failures,
                p.breaker_cooldown,
                p.per_peer_connections,
            ),
            None => (Duration::from_secs(5), 3, Duration::from_secs(15), 8),
        };
        Some(Arc::new(peers::Peers::new(&cfg.peers, cap, bf, bc, idle)?))
    };

    let mut tasks: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();
    let mut serve_db: Option<Arc<db::StoreDb>> = None;
    let mut nix_db_dir: Option<PathBuf> = None;
    let mut serve_parts = None;

    if let Some(scfg) = cfg.serve {
        let listen = scfg.listen;
        let store_dir = scfg
            .store_dir
            .to_str()
            .context("store_dir must be valid UTF-8")?
            .to_owned();
        let db = Arc::new(db::StoreDb::open(&scfg.db_path, &store_dir)?);
        nix_db_dir = scfg.db_path.parent().map(|p| p.to_path_buf());
        serve_db = Some(db.clone());
        let reader = io::SegmentReader::new(&cfg.io)?;
        let state = serve::ServeState::new(db, reader, scfg, Some(idx.clone()));
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding serve listener {listen}"))?;
        info!("serving {store_dir} as a binary cache on http://{listen}");
        serve_parts = Some((listener, state));
    }

    // ONE multiplicative-weights pool arbitrates peers for the whole process: the data plane
    // trains it with chunk transfers, the sync plane with catch-up rounds, and both route by
    // it. (Persistence rides the proxy's weight saver; a proxy-less node starts uniform.)
    let pool = Arc::new(pool::HostPool::new(cfg.peers.len().max(1)));

    // The sync subsystem exists whenever there are peers; its endpoints ride the serve
    // listener (a node without [serve] consumes the mesh but cannot export or relay).
    let sync_ctx = peers.as_ref().map(|p| {
        sync::Sync::new(
            idx.clone(),
            p.clone(),
            pool.clone(),
            serve_db.clone(),
            nix_db_dir.clone(),
            cfg.cache.reconcile_every,
        )
    });

    let mut proxy_parts = None;
    if let Some(pcfg) = cfg.proxy {
        let listen = pcfg.listen;
        let peers = peers.clone().context("[proxy] requires [[peers]]")?;
        let n = peers.list.len();
        let state = proxy::ProxyState::new(peers, idx.clone(), pool.clone(), &cfg.peers, pcfg);
        state.spawn_weight_saver(shutdown_rx.clone());
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding proxy listener {listen}"))?;
        info!("proxying the mesh index over {n} peer(s) as a substituter on http://{listen}");
        proxy_parts = Some((listener, state));
    }

    // The status endpoint rides BOTH listeners: loopback via the proxy, mesh-visible via
    // serve (the mesh is the trust boundary; peers reading each other's state is a feature).
    let status_ctx = Arc::new(status::StatusCtx {
        name: cfg.name.clone(),
        started: std::time::Instant::now(),
        index: idx.clone(),
        proxy: proxy_parts.as_ref().map(|(_, st)| st.clone()),
        sync: sync_ctx.clone(),
        serve: serve_parts.as_ref().map(|(_, st)| st.clone()),
    });

    if let Some((listener, state)) = serve_parts {
        let mut router = serve::router(state).merge(status::router(status_ctx.clone()));
        if let Some(s) = &sync_ctx {
            router = router.merge(s.router());
        }
        let mut rx = shutdown_rx.clone();
        tasks.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await
                .context("serve listener failed")
        });
    }

    if let Some((listener, state)) = proxy_parts {
        let router = proxy::router(state).merge(status::router(status_ctx.clone()));
        let mut rx = shutdown_rx.clone();
        tasks.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await
                .context("proxy listener failed")
        });
    }

    if let Some(s) = &sync_ctx {
        s.spawn_loops(shutdown_rx.clone());
    }

    while let Some(res) = tasks.join_next().await {
        res.expect("listener task panicked")?;
    }
    Ok(())
}
