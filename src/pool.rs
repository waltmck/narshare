//! Which peer to ask next — multiplicative weights over observed throughput.
//!
//! Ported from propnix pin/hosts.rs (same author), where it arbitrates CDN hosts; here it
//! arbitrates mesh peers, restricted per transfer to the peers that hold the path
//! (`pick_among`). The design, unchanged:
//!
//!   * Each observation becomes a loss in [0,1] — 0 for "as fast as the best transfer seen
//!     lately", 1 for a failure — and the peer's weight is scaled by `exp(-ETA * (loss - avg))`,
//!     judged against the running mean so successes can climb, not just failures sink.
//!   * Weights renormalize so the best sits at 1.0, then clamp to a floor `W_MIN`: a collapsed
//!     peer keeps a few percent of the draws, which is what lets it be re-discovered when it
//!     recovers.
//!   * A Herbster–Warmuth fixed-share term drifts every weight toward the pool mean, bounding how
//!     long stale evidence dominates — a recovered peer converges back to parity geometrically.
//!   * Sampling is randomized, not argmax: concurrent workers must not stampede the single best
//!     peer.

use std::sync::Mutex;
use std::time::Duration;

/// Learning rate. Large enough that a dead peer is effectively out after ~3 observations, small
/// enough that normal rate jitter between healthy peers does not thrash the distribution.
const ETA: f64 = 0.7;
/// Weight floor, relative to the best peer — the exploration/recovery share.
const W_MIN: f64 = 0.03;
/// Per-update decay of the throughput yardstick, so `best_rate` tracks reality, not a lucky peak.
const BEST_DECAY: f64 = 0.999;
/// EWMA rate for the mean loss the update is measured against.
const AVG_ALPHA: f64 = 0.1;
/// Fixed-share mixing rate: each update pulls every weight this far toward the pool mean.
const SHARE: f64 = 0.02;

pub struct HostPool {
    state: Mutex<State>,
}

struct State {
    weight: Vec<f64>,
    best_rate: f64,
    avg_loss: f64,
    rng: u64,
}

impl HostPool {
    pub fn new(n: usize) -> Self {
        let n = n.max(1);
        Self {
            state: Mutex::new(State {
                weight: vec![1.0; n],
                best_rate: 0.0,
                avg_loss: 0.0,
                // Fixed seed: peer choice cannot affect output hashes, and a fixed seed makes a
                // bad run reproducible.
                rng: 0x9E3779B97F4A7C15,
            }),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.state.lock().unwrap().weight.len()
    }

    /// Sample among `allowed` indices proportional to weight. None iff `allowed` is empty.
    pub fn pick_among(&self, allowed: &[usize]) -> Option<usize> {
        if allowed.is_empty() {
            return None;
        }
        let mut st = self.state.lock().unwrap();
        let total: f64 = allowed.iter().map(|&i| st.weight[i]).sum();
        #[allow(clippy::neg_cmp_op_on_partial_ord)] // deliberate: NaN must take this branch
        if !(total > 0.0) {
            let n = allowed.len();
            return Some(allowed[(next_u64(&mut st.rng) % n as u64) as usize]);
        }
        let mut r = unit_f64(next_u64(&mut st.rng)) * total;
        for &i in allowed {
            r -= st.weight[i];
            if r <= 0.0 {
                return Some(i);
            }
        }
        Some(*allowed.last().unwrap()) // float drift on the last bucket
    }

    /// A completed transfer: `bytes` (uncompressed goodput) moved in `elapsed`.
    pub fn record_success(&self, idx: usize, bytes: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        // A transfer too small or too fast to time says nothing; don't move the yardstick.
        if bytes == 0 || secs <= 0.0005 {
            return;
        }
        let rate = bytes as f64 / secs;
        let mut st = self.state.lock().unwrap();
        st.best_rate = (st.best_rate * BEST_DECAY).max(rate);
        let loss = if st.best_rate > 0.0 {
            (1.0 - rate / st.best_rate).clamp(0.0, 1.0)
        } else {
            0.0
        };
        st.apply(idx, loss);
    }

    /// A failed transfer — maximum loss.
    pub fn record_failure(&self, idx: usize) {
        let mut st = self.state.lock().unwrap();
        st.apply(idx, 1.0);
    }

    #[cfg(test)]
    fn weights(&self) -> Vec<f64> {
        self.state.lock().unwrap().weight.clone()
    }
}

impl State {
    fn apply(&mut self, idx: usize, loss: f64) {
        if idx >= self.weight.len() {
            return;
        }
        self.weight[idx] *= (-ETA * (loss - self.avg_loss)).exp();
        self.avg_loss += AVG_ALPHA * (loss - self.avg_loss);
        // Rescale so the best sits at 1.0 (bounded range whatever the run length; the floor
        // becomes "relative to the best").
        let max = self.weight.iter().cloned().fold(0.0f64, f64::max);
        if max > 0.0 {
            for w in self.weight.iter_mut() {
                *w /= max;
            }
        } else {
            for w in self.weight.iter_mut() {
                *w = 1.0;
            }
        }
        // Fixed share: drift toward the mean, then re-floor.
        let n = self.weight.len() as f64;
        let mean = self.weight.iter().sum::<f64>() / n;
        for w in self.weight.iter_mut() {
            *w = ((1.0 - SHARE) * *w + SHARE * mean).max(W_MIN);
        }
    }
}

/// SplitMix64 — a few lines, no dependency, plenty for choosing a peer.
fn next_u64(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *s;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn unit_f64(x: u64) -> f64 {
    (x >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share_all(pool: &HostPool, draws: usize) -> Vec<f64> {
        let all: Vec<usize> = (0..pool.len()).collect();
        let mut counts = vec![0usize; pool.len()];
        for _ in 0..draws {
            counts[pool.pick_among(&all).unwrap()] += 1;
        }
        counts.iter().map(|c| *c as f64 / draws as f64).collect()
    }

    #[test]
    fn starts_uniform() {
        let pool = HostPool::new(4);
        for s in share_all(&pool, 20_000) {
            assert!((s - 0.25).abs() < 0.03, "expected ~uniform, got {s}");
        }
    }

    #[test]
    fn a_dead_peer_collapses_but_keeps_a_recovery_share() {
        let pool = HostPool::new(2);
        for _ in 0..8 {
            pool.record_success(0, 8 << 20, Duration::from_secs(1));
            pool.record_failure(1);
        }
        let w = pool.weights();
        assert!(w[1] < 0.05, "dead peer should collapse to near the floor, got {w:?}");
        let s = share_all(&pool, 20_000);
        assert!(s[1] < 0.06, "dead peer should get a small share, got {}", s[1]);
        assert!(s[1] > 0.0, "…but never zero, or it could never be found healthy again");
    }

    #[test]
    fn a_recovered_peer_climbs_back() {
        let pool = HostPool::new(2);
        for _ in 0..8 {
            pool.record_success(0, 8 << 20, Duration::from_secs(1));
            pool.record_failure(1);
        }
        assert!(pool.weights()[1] < 0.05, "precondition: must have collapsed");
        for _ in 0..10 {
            pool.record_success(1, 8 << 20, Duration::from_secs(1));
        }
        assert!(pool.weights()[1] > W_MIN * 2.0, "should be climbing after 10 successes");
        for _ in 0..40 {
            pool.record_success(1, 8 << 20, Duration::from_secs(1));
        }
        assert!(pool.weights()[1] > 0.9, "a healthy peer must return to full weight");
    }

    #[test]
    fn a_faster_peer_wins_more_traffic() {
        let pool = HostPool::new(2);
        for _ in 0..30 {
            pool.record_success(0, 16 << 20, Duration::from_secs(1));
            pool.record_success(1, 2 << 20, Duration::from_secs(1));
        }
        let s = share_all(&pool, 20_000);
        assert!(s[0] > s[1] * 3.0, "fast peer should dominate: {s:?}");
    }

    #[test]
    fn restriction_to_holders_respects_weights() {
        let pool = HostPool::new(3);
        for _ in 0..30 {
            pool.record_success(0, 16 << 20, Duration::from_secs(1));
            pool.record_success(1, 16 << 20, Duration::from_secs(1));
            pool.record_success(2, 1 << 20, Duration::from_secs(1));
        }
        // Restricted to {1, 2}: peer 0's dominance is irrelevant; 1 should beat 2.
        let mut counts = [0usize; 3];
        for _ in 0..20_000 {
            counts[pool.pick_among(&[1, 2]).unwrap()] += 1;
        }
        assert_eq!(counts[0], 0);
        assert!(counts[1] > counts[2] * 3, "restricted sampling ignored weights: {counts:?}");
        assert!(counts[2] > 0, "floor must survive restriction");
        assert!(pool.pick_among(&[]).is_none());
    }

    #[test]
    fn untimeable_transfers_do_not_move_the_yardstick() {
        let pool = HostPool::new(2);
        pool.record_success(0, 700, Duration::from_micros(10));
        for _ in 0..5 {
            pool.record_success(0, 8 << 20, Duration::from_secs(1));
            pool.record_success(1, 8 << 20, Duration::from_secs(1));
        }
        for w in pool.weights() {
            assert!(w > 0.9, "healthy peers must not be punished by an untimeable sample");
        }
    }
}
