//! The observability endpoint: GET /narshare/v1/status → one JSON document carrying every
//! subsystem's cumulative counters and point-in-time state. Strictly machine-ingestible (no
//! HTML, no scripts): monitoring scrapes it, the VM suite asserts on it, humans pipe it
//! through jq. Served on both listeners — loopback via the proxy, mesh-visible via serve
//! (the mesh is the trust boundary; peers reading each other's state is a feature).
//!
//! Shape notes for consumers: `index.origins[*].{generation,seq}` across nodes is the
//! convergence identity — two synced nodes must agree exactly; `proxy.transfers.active` is a
//! leak gauge that must return to 0 at rest; every `aborted.*` counter names the mechanism
//! that fired, so failures are attributable after the fact.

use crate::index::Index;
use crate::proxy::ProxyState;
use crate::serve::ServeState;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

pub struct StatusCtx {
    pub name: String,
    pub started: std::time::Instant,
    pub index: Arc<Index>,
    pub proxy: Option<Arc<ProxyState>>,
    pub sync: Option<Arc<crate::sync::Sync>>,
    pub serve: Option<Arc<ServeState>>,
}

pub fn router(ctx: Arc<StatusCtx>) -> Router {
    Router::new()
        .route("/narshare/v1/status", get(status))
        .with_state(ctx)
}

async fn status(State(ctx): State<Arc<StatusCtx>>) -> Response {
    let index = ctx.index.clone();
    let index_status = tokio::task::spawn_blocking(move || index.status())
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("status task died: {e}")))
        .unwrap_or_else(|e| serde_json::json!({ "error": format!("{e:#}") }));

    let proxy = ctx.proxy.as_ref().map(|st| {
        let s = &st.fetch.stats;
        let (weights, best_rate, avg_loss, observations) = st.fetch.pool.snapshot();
        let peers: Vec<serde_json::Value> = st
            .peers
            .list
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let b = p.breaker_status();
                let (rate, level, inflight, limit) = st.fetch.peer_net_status(i);
                let (chunks_ok, chunks_err, bytes) = st.fetch.peer_tally(i);
                serde_json::json!({
                    "name": p.name,
                    "url": p.base.as_str(),
                    "tier": p.tier,
                    "available": p.available(),
                    "mw_weight": weights.get(i).copied().unwrap_or(1.0),
                    "rate_bps": rate,
                    "auto_zstd_level": level,
                    "chunks_ok": chunks_ok,
                    "chunks_err": chunks_err,
                    "bytes_fetched": bytes,
                    "streams": { "inflight": inflight, "limit": limit },
                    "breaker": {
                        "strikes": b.strikes,
                        "open_ms_remaining": b.open_ms_remaining,
                        "opens_total": b.opens_total,
                    },
                })
            })
            .collect();
        serde_json::json!({
            "peers": peers,
            "pool": {
                "best_rate_bps": best_rate,
                "avg_loss": avg_loss,
                "observations": observations,
            },
            "roaming_ms_remaining": st.fetch.roaming_ms_remaining(),
            "lookups": {
                "narinfo": s.narinfo_requests.load(Relaxed),
                "narinfo_misses": s.narinfo_misses.load(Relaxed),
                "nar": s.nar_requests.load(Relaxed),
                "nar_misses": s.nar_misses.load(Relaxed),
            },
            "transfers": {
                "active": s.active_transfers(),
                "started": s.transfers_started.load(Relaxed),
                "completed": s.transfers_completed.load(Relaxed),
                "manifest_plans": s.manifest_plans.load(Relaxed),
                "clients_gone": s.clients_gone.load(Relaxed),
                "hedges": s.hedges.load(Relaxed),
                "hedge_bytes": s.hedge_bytes.load(Relaxed),
                "hedged_waste_bytes": s.hedged_waste_bytes.load(Relaxed),
                "aborted": {
                    "stall": s.aborts_stall.load(Relaxed),
                    "streak": s.aborts_streak.load(Relaxed),
                    "min_bandwidth": s.aborts_min_bandwidth.load(Relaxed),
                    "hash_mismatch": s.aborts_hash_mismatch.load(Relaxed),
                    "other": s.aborts_other.load(Relaxed),
                },
            },
            "bytes": {
                "remote": s.remote_bytes.load(Relaxed),
                "wire": s.wire_bytes.load(Relaxed),
                "replayed": s.replayed_bytes.load(Relaxed),
                "lit": s.lit_bytes.load(Relaxed),
            },
            "requeues": s.requeues.load(Relaxed),
        })
    });

    let sync = ctx.sync.as_ref().map(|s| {
        let st = &s.stats;
        serde_json::json!({
            "pulls_ok": st.pulls_ok.load(Relaxed),
            "pulls_err": st.pulls_err.load(Relaxed),
            "suffix_events_applied": st.suffix_events_applied.load(Relaxed),
            "snapshots_applied": st.snapshots_applied.load(Relaxed),
            "self_generation_bumps": st.self_generation_bumps.load(Relaxed),
            "hints_received": st.hints_received.load(Relaxed),
            "hint_rounds_sent": st.hint_rounds_sent.load(Relaxed),
            "exports": st.exports.load(Relaxed),
            "export_events": st.export_events.load(Relaxed),
            "sync_requests_served": st.sync_requests_served.load(Relaxed),
        })
    });

    let serve = ctx.serve.as_ref().map(|s| {
        let st = &s.stats;
        let (free_big, free_small) = s.encode_permits_free();
        serde_json::json!({
            "narinfo_requests": st.narinfo_requests.load(Relaxed),
            "nar_requests": st.nar_requests.load(Relaxed),
            "nar_misses": st.nar_misses.load(Relaxed),
            "manifest_requests": st.manifest_requests.load(Relaxed),
            "chunks_encoded": st.chunks_encoded.load(Relaxed),
            "encode_wait_us": st.encode_wait_us.load(Relaxed),
            "encode_permits_free": { "big": free_big, "small": free_small },
        })
    });

    let body = serde_json::json!({
        "name": ctx.name,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_ms": ctx.started.elapsed().as_millis() as u64,
        "index": index_status,
        "proxy": proxy,
        "sync": sync,
        "serve": serve,
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}
