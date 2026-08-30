mod config;
mod db;
mod dedup;
mod fetch;
mod governor;
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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
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

    let mut tasks: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();

    if let Some(scfg) = cfg.serve {
        let listen = scfg.listen;
        let store_dir =
            scfg.store_dir.to_str().context("store_dir must be valid UTF-8")?.to_owned();
        let db = Arc::new(db::StoreDb::open(&scfg.db_path, &store_dir)?);
        let reader = io::SegmentReader::new(&cfg.io)?;
        let state = serve::ServeState::new(db, reader, scfg);
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding serve listener {listen}"))?;
        info!("serving {store_dir} as a binary cache on http://{listen}");
        let mut rx = shutdown_rx.clone();
        tasks.spawn(async move {
            axum::serve(listener, serve::router(state))
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await
                .context("serve listener failed")
        });
    }

    if let Some(pcfg) = cfg.proxy {
        let listen = pcfg.listen;
        let peers = peers::Peers::new(&cfg.peers, &pcfg)?;
        let n = peers.list.len();
        let state = proxy::ProxyState::new(peers, &cfg.peers, pcfg);
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding proxy listener {listen}"))?;
        info!("proxying {n} peer(s) as a substituter on http://{listen}");
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

    while let Some(res) = tasks.join_next().await {
        res.expect("listener task panicked")?;
    }
    Ok(())
}
