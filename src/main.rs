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
mod sync;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[derive(Parser)]
#[command(name = "narshare", version, about = "Self-contained mesh Nix substituter")]
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
    });

    // The mesh trust anchor and the replicated index — shared by every role.
    let trusted = sig::TrustedKeys::load(&cfg.trusted_public_keys);
    let peer_names: Vec<String> = cfg.peers.iter().map(|p| p.name.clone()).collect();
    let idx = Arc::new(
        index::Index::open(&cfg.cache.dir, &cfg.name, &peer_names, trusted).with_context(
            || {
                format!(
                    "opening the mesh index under {} (is [cache] dir writable?)",
                    cfg.cache.dir.display()
                )
            },
        )?,
    );

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
        let store_dir =
            scfg.store_dir.to_str().context("store_dir must be valid UTF-8")?.to_owned();
        let db = Arc::new(db::StoreDb::open(&scfg.db_path, &store_dir)?);
        nix_db_dir = scfg.db_path.parent().map(|p| p.to_path_buf());
        serve_db = Some(db.clone());
        let reader = io::SegmentReader::new(&cfg.io)?;
        let state = serve::ServeState::new(db, reader, scfg);
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding serve listener {listen}"))?;
        info!("serving {store_dir} as a binary cache on http://{listen}");
        serve_parts = Some((listener, serve::router(state)));
    }

    // The sync subsystem exists whenever there are peers; its endpoints ride the serve
    // listener (a node without [serve] consumes the mesh but cannot export or relay).
    let sync_ctx = peers
        .as_ref()
        .map(|p| sync::Sync::new(idx.clone(), p.clone(), serve_db.clone(), nix_db_dir.clone()));

    if let Some((listener, mut router)) = serve_parts {
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

    if let Some(pcfg) = cfg.proxy {
        let listen = pcfg.listen;
        let peers = peers.clone().context("[proxy] requires [[peers]]")?;
        let n = peers.list.len();
        let state = proxy::ProxyState::new(peers, idx.clone(), &cfg.peers, pcfg);
        state.spawn_weight_saver(shutdown_rx.clone());
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding proxy listener {listen}"))?;
        info!("proxying the mesh index over {n} peer(s) as a substituter on http://{listen}");
        let mut rx = shutdown_rx.clone();
        tasks.spawn(async move {
            axum::serve(listener, proxy::router(state))
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
