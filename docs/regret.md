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

One 32 MiB NAR striped across both peers; oracles are "fast peer alone" and "capacity sum":

| skew | achieved | single-best | capacity-sum | slow byte share | time regret |
|---|---|---|---|---|---|
| 4:1 (32/8 MB/s) | 29.3 MB/s | 32 | 40 | 25.0% | +0.10 s |
| 64:1 (64/1 MB/s) | **4.0 MB/s** | 64 | 65 | 25.0% | **+7.96 s** |

Reading: this is where the real regret lives, and it is not a weights problem. The MW share of
the slow peer is tiny, but selection is **work-conserving** — `try_pick` samples the weights
*conditioned on free stream capacity*, so whenever the fast peer's slots are momentarily full
(mid-transfer: always), the conditional support collapses to the slow peer and it gets the
chunk with probability 1. The slow peer therefore holds its ~2 slots continuously (25% byte
share at BOTH skews — an in-flight-time share, decoupled from capacity share), and because
delivery to nix is in-order, its 2-second chunks repeatedly gate the emission frontier. At 4:1
that costs ~nothing (+0.10 s); at 64:1 the transfer completes **16× slower than ignoring the
slow peer entirely**. The VM suite's shaped-topology numbers show the same signature (striping
across the 20 Mbit peer vs the fast peer alone). This is a POLICY cost, not a mechanism bug:
work conservation itself is what feeds the straggler.

## Verdict and the open fix

- Decision-level: near-floor regret, linear at ~0.10/decision under 64:1 — acceptable and
  intentional (the slope is the exploration+tracking budget).
- Tracking: majority flip ≤ 25 decisions — the design goal, confirmed.
- Completion-time under extreme skew: **measured deficiency**. Candidate mitigations, in rough
  order of appeal: (a) *tail re-dispatch / hedging* — once carving is exhausted and a fast peer
  has idle slots, re-issue the slowest in-flight ranges to it and let the first arrival win
  (bounds the tax at ~one slow chunk, keeps work conservation); (b) weight-scaled slot budgets
  (a floor-weight peer gets slots only when nobody else has capacity AND the window is not
  near the frontier); (c) a latency-aware assignment gate (never hand a peer a chunk whose
  expected service time exceeds the projected remainder of the transfer). The striped-skew
  bench's catastrophe guard (currently 0.04× single-best) is the acceptance test to tighten
  when one of these lands.
