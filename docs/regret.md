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

## Proposed (not yet implemented): hedged exploration

The residual variance cost of weight routing is the ping itself: a `W_MIN`-probability draw
hands the slow peer one ~2 s chunk and that fetch's completion waits for it. Threshold hacks
("if w < 0.1, also try someone else") are ugly; the continuous rule falls out of the pool's
own invariant. The pool renormalizes so the best weight is 1.0, making `w_i` read as "relative
confidence that routing to i costs nothing vs best". So:

> After drawing primary `i` (∝ w), dispatch a **duplicate** of the same chunk to a second peer
> `j` (drawn ∝ w over the rest) with probability `h_i = 1 − w_i`. First arrival feeds the
> emitter; the loser **completes anyway and is recorded normally**, its bytes discarded.

Properties, in the order they matter:
- **Asymptotically stable weights are unchanged.** Updates are per-completion; hedging changes
  which bytes are *used*, never which requests complete. The crux is not cancelling the loser:
  a cancelled ping produces no observation, so a floored peer would rise on fixed-share drift
  alone (evidence-free) until it won real traffic — oscillation. Letting the loser finish
  preserves the exact measurement the ping exists for.
- **Continuous, knob-free, N-ary.** Best peer: h = 0, never hedged. Floor peer: h ≈ 0.97,
  nearly always insured. Mid-recovery peer (w = 0.5): half its chunks carry a backup — paying
  duplicate bytes exactly while the scheduler is uncertain about it. Arbitrary weight
  distributions need no special-casing because h is defined pointwise against the renormalized
  max. (If linear over/under-hedges mid-weights in practice, `h = (1−w)^γ` is the one-knob
  generalization — a learning-dynamics tuning question.)
- **Cost is the complement of confidence.** Expected duplicate bytes per decision =
  Σ pᵢ(1−wᵢ)sᵢ; at asymptotic weights that is ≈ W_MIN · s_slow per ~30 decisions — noise. It
  also degrades gracefully: the more the pool trusts a peer, the less it spends insuring it.
- **What it fixes beyond the ping tail**: the S4 tail cause (b) — a slow-but-useful peer's
  final chunk is hedged with probability 1−w, so unequal-peer aggregation stops being gated by
  its straggler. What it deliberately does NOT fix: a *high*-weight frozen peer (h ≈ 0) still
  parks a fresh transfer until its deadline strikes — that is the accepted
  weights-were-wrong tradeoff, bounded by the deadline machinery.
- **Bookkeeping it requires**: in-flight tracking keyed by (offset, attempt) instead of offset
  (two copies of one range fly concurrently); the loser's Err must not requeue a range the
  winner already delivered; loser bytes counted under a `hedged_waste` observable.

## Verdict

- Decision-level: near-floor regret, linear at ~0.10/decision under 64:1 — acceptable and
  intentional (the slope is the exploration+tracking budget; tune η/W_MIN/SHARE next).
- Tracking: majority flip ≤ 25 decisions — the design goal, confirmed.
- Completion-time at asymptotic weights: **85–92% of the fastest peer** (bench floors: 0.8×
  at 64:1, 0.7× at 4:1), vs 6% before the policy change.
- Aggregation: equal peers ≈ 1.9× solo under both policies; unequal peers sit at single-best
  under both — an open (pre-existing) limitation whose fix path is rate-shaped shares +
  hedged exploration, not admission policy.
