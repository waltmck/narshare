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

## S4 — aggregation A/B: what did dropping work conservation actually cost?

`mw_aggregation_ab` (run it ALONE — it toggles a process-global policy flag) resurrects the
old overflow policy behind a bench lever and measures both policies with **learned** weights
(8 warmup fetches, then median of 5) across capacity ratios. Reference: the 32 MB/s peer
*alone* through the same proxy path measures 28.8 MB/s — the fair single-best.

| ratio | proportional (new) | work-conserving (old) | learned slow weight | capacity share |
|---|---|---|---|---|
| 1:1 (32/32) | **54.2 MB/s** | 54.6 MB/s | ~0.9 | 0.50 |
| 2:1 (32/16) | 29.2 MB/s | 28.9 MB/s | **0.17** | 0.33 |
| 4:1 (32/8) | 29.8 MB/s | 29.2 MB/s | 0.09 | 0.20 |
| 64:1 (64/1) | 55.8 MB/s (87% of 64) | 4.0 MB/s (prior measurement) | 0.10 | 0.015 |

Two findings. First, **the policy change cost ~nothing**: at every ratio the two policies land
within noise of each other — except 64:1, where the new one is 14× better. The old policy's
extra slow-peer traffic (30% byte share at 2:1 vs 10%) bought zero wall-clock: those bytes
just moved the completion tail onto the slow peer.

Second, the painful case is real but it is **not new**: *neither* policy aggregates unequal
peers. 1:1 aggregates beautifully under both (≈ 1.9× solo — equal chunk durations mean no
straggler), but 2:1 and 4:1 both sit at single-best. Two independent causes:
(a) **the learned weight is not a capacity share** — MW weights are exponential in loss-vs-best,
so a half-speed peer (loss ≈ 0.5/observation at η = 0.7) collapses to w ≈ 0.17 against a 0.33
capacity share, and proportional routing under-feeds it; and (b) **the tail** — a slower peer's
time-normalized ~2 s chunk near the end of a ~1 s transfer erases exactly the gains its
mid-transfer bytes bought (in-order emission). Recovering unequal-peer aggregation therefore
needs a rate-proportional share estimator (a learning-dynamics question: η shapes how hard
sub-best peers collapse) *and* tail insurance — which is what hedged exploration below
provides. Neither is a regression of the routing change.

## Hedged exploration (implemented)

The residual variance cost of weight routing was the ping itself: a floor-probability draw
handed the slow peer one ~2 s chunk and that fetch's completion waited for it. Now, after the
weighted draw picks primary `i`, a DUPLICATE of the chunk is dispatched to a second weighted
draw with probability

    h = clamp((1/N − p) / (1/N − p_floor), 0, 1)^ν

where p is i's within-holder-set routing share and p_floor the share it WOULD have at the
weight floor W_MIN given the others' current weights — so h spans exactly [0, 1]: zero at or
above the uniform share (single holders and all-equally-weak sets are never hedged: there is
no better alternative), and exactly one at the floor (a pure ping is always insured). First
arrival feeds the emitter.

Two properties were load-bearing enough to get dedicated machinery:

- **The loser completes and is recorded.** Both members of a hedged pair run DETACHED from the
  transfer (in the common case the loser is the slow primary the partner just beat, and the
  transfer usually finishes before it does). A cancelled ping would produce no measurement, so
  a floored weight would rise on evidence-free drift until it won real traffic — oscillation.
  Letting losers finish preserves the per-observation dynamics, so hedging leaves the
  asymptotically stable weights unchanged. (First implementation aborted winners' twins with
  the transfer; the sweep caught it as `tails == slow picks` — insured pings were invisible in
  the tallies.)
- **The hedge is decided BEFORE the capacity check.** An insured chunk whose primary has no
  free slot proceeds on the partner alone (a busy floor peer means a ping is already in flight
  there); an UNinsured busy draw parks, which is the deliberate policy for peers the weights
  trust. Without this, detached losers occupying the slow peer's slots made later draws park
  behind the least-trusted peer.

Ranges are tracked as flights keyed by offset with per-attempt ids: a range requeues only when
its LAST attempt dies undelivered, and a losing twin's bytes are dropped (counted under
`hedged_waste_bytes` in the status endpoint) rather than re-buffered.

## Tuning (η, ν, and the drift that turned out to matter more)

`mw_tune_sweep` (fluid links, learned weights; per cell: sequential 64:1 steady state + a
capability swap + warm striped 64:1 and 2:1): grid η ∈ {0.4, 0.7, 1.2} × ν ∈ {1, 3, 6}, plus
supplementary fixed-share rows.

- **ν = 3** — a conclusion that took two rounds of measurement to get right. The first sweep
  (at SHARE = 0.02, with a waste counter that missed losers landing after their transfer
  ended) favored ν = 1: the linear ramp cut tails 1 vs 4 vs 8 per 100 because drift-inflated
  mid-weights dominated. Re-measured at the adopted SHARE = 0.005 with the launch-time
  `hedge_bytes` premium (`mw_hedge_cost`), ν = 1 pays a **3.5% duplicate-byte premium at
  weight parity** — where the "slow" peer is not slow and duplicates are full-size chunks;
  it first surfaced as a byte-exact accounting test flaking on a double-fetched chunk — for
  zero tail benefit (0–1 tails/100 at every ν ∈ {1,2,3}: with the drift tamed, the floor
  anchor h(W_MIN) = 1, not ν, carries the ping insurance). ν = 3 concentrates the premium to
  ~0 at parity while keeping floor pings fully insured.
- **η = 0.7** stands: 1.2 collapses and tracks faster (stale picks 12 vs 18) but dents the
  warm striped median (79–83%); 0.4 loses to drift everywhere.
- **The binding constraint was the fixed-share drift, not η or ν.** At SHARE = 0.02 with two
  peers, a floored weight climbs w ← 0.99w + 0.01 to ~0.28 within ~30 observations — so slow
  picks concentrated exactly where insurance is weakest (draw probability and hedge
  probability are complementary by construction). SHARE = 0.005 cuts steady slow picks ~2×
  and uninsured tails to ~1/100 with swap tracking UNHARMED (flip ≤ 25 — recovery rides
  η-collapse of the stale best plus renormalization, not drift). Adopted: **η = 0.7, ν = 1,
  SHARE = 0.005**.

Post-tuning instrument readings: S1 steady slow share **3/100 — the exploration floor
itself** (was ~10), per-decision regret 0.046 (was 0.10); S2 flip ≤ 25 with post-swap blocks
saturating at 25/25; S3 warm 64:1 median 87% of single-best with walls [0.58–0.65 s] — the
4 s uninsured-ping outlier is gone; 4:1 91–92% with uniformly tight walls.

## Verdict

- Decision-level: steady slow share at the W_MIN floor (3/100), per-decision regret 0.046 —
  within 1.4× the Hedge √-reference at T=300 despite bandit feedback and tracking machinery.
- Tracking: majority flip ≤ 25 decisions, saturating immediately after.
- Completion-time at asymptotic weights: 87–92% of the fastest peer with NO fat tail — every
  floor ping is insured; the residual gap is chunk-granularity overhead on 2–3-chunk
  transfers.
- Aggregation: equal peers ≈ 1.9× solo; unequal peers sit at single-best (pre-existing under
  both policies; the fix path is rate-shaped shares, a learning-dynamics question).
