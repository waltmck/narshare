# Empirical MW regret

The peer pool (pool.rs) is a multiplicative-weights heuristic, not textbook Hedge: feedback is
bandit (only the chosen peer's loss is observed, with no importance weighting), a `W_MIN = 0.03`
floor forces exploration, and a Herbster–Warmuth fixed-share term (`SHARE = 0.02`) drifts
weights toward the mean for tracking. None of the classical regret bounds apply as theorems, so
the bench measures regret empirically against ground-truth counterfactuals.

**Instrument**: `cargo test --release mw_regret -- --ignored --nocapture`. Peers are in-process
servers behind a *fluid link* — every request serializes through a shared byte rate, so
concurrency cannot multiply capacity and the configured rates ARE the counterfactual losses
(`loss_i = 1 − R_i/R_max`). Per-peer decision tallies come from the same counters the status
endpoint exposes (`proxy.peers[*].{chunks_ok,chunks_err,bytes_fetched}`).

Numbers below from an M-class laptop, release build (2026-08-30).

## S1 — static 64:1, sequential (pure decision regret)

One 256 KiB chunk per fetch, T = 300, fast peer 64 MB/s vs slow 1 MB/s:

| metric | measured |
|---|---|
| slow-peer picks | 31/300 (first 25: 5 — cold start; last 100: 9) |
| cumulative regret (Σ loss vs best-fixed) | 30.5 |
| per-decision regret slope, steady state | ≈ 0.10 |
| Hedge √-reference √(T/2 · ln 2) at T=300 | 10.2 |

Reading: regret is **linear by design**, at ~3× the `W_MIN` exploration floor. The floor alone
predicts a ~3% steady-state slow share; the measured ~9–10% is the **fixed-share drift**: every
observation pulls the collapsed weight ~1% of the way back toward the mean, and with the slow
peer sampled only every ~10 draws, its weight sawtooths up to ~0.1 before the next bad sample
knocks it down. That extra 6–7% share is the price paid for S2's tracking speed — the classic
static-vs-tracking-regret tradeoff, now with a measured exchange rate.

## S2 — capabilities swap mid-run (tracking regret)

Same run, rates swapped (fast↔slow), 300 more decisions:

| metric | measured |
|---|---|
| new-best picks per 25-block | 17, 25, 22, 24, 23, 22, 24, 22, 21, 22, … |
| majority flip | within the FIRST 25-decision block |
| stale picks of the collapsed peer, total | 33 (tracking regret ≈ 32) |

Reading: tracking is excellent — the drift that costs 6% share in S1 buys majority handoff in
under 25 decisions here. Mechanism: the old best's weight collapses in ~3 bad samples
(η = 0.7), the renormalization then lifts the floor-bound peer to parity, and its first few
successes finish the job — recovery does NOT wait on 1/W_MIN sampling luck.

## S3 — striped transfers (completion-time regret, where it actually hurts)

One 32 MiB NAR striped across both peers; oracles are "fast peer alone" and "capacity sum".

**History — the work-conserving era.** Selection originally overflowed onto any peer with a
free stream slot whenever the weighted draw landed on a busy one. That made the slow peer's
share an *in-flight-time* share, decoupled from both its weight and its capacity: it held its
~2 slots continuously, each chunk engineered to take ~2 s regardless of peer speed, delivery
in-order, assignment irrevocable (deadlines fire at 8× expected — never, for a correctly-rated
peer). Net: a constant **≈ slots × 2 s completion tax per transfer**, independent of skew and
of the weights being correct — measured 4.0 MB/s vs 64 single-best at 64:1 (16×), and the same
signature on the VM's shaped links.

**Current policy — weights ARE the routing distribution.** `try_pick` makes one weighted draw
over the available holders, NOT conditioned on capacity: if the drawn peer is busy, nothing
launches this attempt (park; a wake retries). A floor-weight peer now receives only ~`W_MIN`
of *decisions* — the periodic re-discovery ping — and since chunks are time-normalized its
byte share is `W_MIN · R_slow/R_fast` ≈ noise. Measured (cold = uniform weights, reported but
unasserted; warm = asymptotic weights installed, median of 5 fetches):

| skew | cold | warm median | % of single-best | slow byte share |
|---|---|---|---|---|
| 4:1 (32/8 MB/s) | 12.5 MB/s | 29.4 MB/s | **92%** | 18.8% (incl. cold) |
| 64:1 (64/1 MB/s) | 2.7 MB/s | 54.1 MB/s | **85%** | 8.2% (incl. cold) |

The warm walls at 64:1 — [0.60, 0.62, **4.07**, 0.64, 0.62] s — show the design contract
exactly: most fetches ride the fast peer; ~`W_MIN`-per-decision, one fetch in a handful hands
the slow peer a single ~2 s chunk (the ping itself, with its frontier stall). The residual gap
to 100% in the medians is chunk-granularity/pipeline overhead on a 2–3-chunk transfer, not
slow-peer bytes. What was given up, deliberately: capacity aggregation no longer chases the
sum (4:1 achieves 92% of single-best, not 125%), and a hung-but-breaker-closed peer can idle a
transfer for up to one chunk deadline before its strikes open the breaker — bounded by the
deadline machinery.

## Verdict

- Decision-level: near-floor regret, linear at ~0.10/decision under 64:1 — acceptable and
  intentional (the slope is the exploration+tracking budget; tune η/W_MIN/SHARE next).
- Tracking: majority flip ≤ 25 decisions — the design goal, confirmed.
- Completion-time at asymptotic weights: **85–92% of the fastest peer** (bench floors: 0.8×
  at 64:1, 0.7× at 4:1), vs 6% before the policy change. Remaining polish, if ever needed:
  tail re-dispatch to shave the ping's 2 s chunk and the last few percent of median overhead.
