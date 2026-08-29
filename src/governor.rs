//! How many streams to keep open per peer — hill-climbing on measured throughput.
//!
//! Ported from propnix pin/concurrency.rs (same author) essentially verbatim; there it sized
//! chunk concurrency against per-connection-throttled CDNs, here it sizes streams-per-peer so a
//! 10 GbE link climbs toward `per_peer_connections` while a 500 kbit cellular hop settles at 1–2
//! streams instead of drowning in competing flows.
//!
//! The method: HOLD the limit still for `PROBE_EPOCHS`, take the MEDIAN of those epochs as the
//! rung's reading, then move one multiplicative step — continuing if the reading improved,
//! reversing if it got worse or stopped changing. Two overrides sit on top:
//!
//!   * **Error RATE means back off, immediately** (multiplicative decrease, faster than the
//!     climb) — but only a rate over a real sample; one or two failed events are noise.
//!   * **Being blocked by the consumer is not a throughput ceiling**: a window-bound epoch
//!     measures the consumer, not the network. Hold, and never use such an epoch as a baseline.

/// Fractional throughput change treated as noise rather than signal.
const NOISE: f64 = 0.03;
/// Epochs to HOLD the limit still while measuring it. Real link throughput is noisy enough that
/// comparing single samples makes the climb chase its own variance; the median of five ignores
/// even an 8x outlier.
const PROBE_EPOCHS: usize = 5;
/// Multiplicative probe step.
pub const STEP_UP: f64 = 1.3;
/// Backoff on errors — faster than the climb, so a struggling link sheds load quickly.
const BACKOFF: f64 = 0.7;
/// Fraction of an epoch's requests that must FAIL before the far end counts as pushing back.
/// Ordinary background failure rates (propnix measured 1–8% on healthy CDNs) must not move the
/// limit; only when a quarter of transfers are being thrown away is the far end plausibly
/// refusing load.
const ERROR_RATE_BACKOFF: f64 = 0.25;
/// Completed requests an epoch needs before its error RATE is trusted at all.
const MIN_RATE_ATTEMPTS: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Pressure {
    /// Workers were free to fetch; measured throughput is a real network reading.
    Network,
    /// Workers spent the epoch parked on the byte window — the consumer is behind, not the
    /// network.
    ConsumerBound,
}

pub struct Governor {
    limit: f64,
    min: f64,
    max: f64,
    /// +1 climbing, -1 backing off.
    dir: f64,
    /// Throughput samples collected at the CURRENT limit.
    samples: Vec<f64>,
    /// The previous rung's reading — what the next decision is judged against.
    prev: Option<f64>,
}

impl Governor {
    pub fn new(start: usize, min: usize, max: usize) -> Self {
        let min = min.max(1) as f64;
        let max = (max as f64).max(min);
        Self {
            limit: (start as f64).clamp(min, max),
            min,
            max,
            dir: 1.0,
            samples: Vec::with_capacity(PROBE_EPOCHS),
            prev: None,
        }
    }

    pub fn limit(&self) -> usize {
        self.limit.round().max(1.0) as usize
    }

    /// Fold in one epoch's observations and return the new limit. `ok` and `errors` are the
    /// epoch's SUCCEEDED and FAILED request counts — both, because pushback is a rate.
    pub fn observe(&mut self, throughput: f64, pressure: Pressure, ok: u64, errors: u64) -> usize {
        // PRESSURE FIRST: a consumer-bound epoch completes almost nothing by construction, so
        // judging its error rate would read 1.0 off a single event.
        if pressure == Pressure::ConsumerBound {
            // Hold; and a consumer-bound reading must never be compared against, or averaged
            // with, a network-bound one.
            self.prev = None;
            self.samples.clear();
            return self.limit();
        }
        let attempts = ok + errors;
        let error_rate = if attempts >= MIN_RATE_ATTEMPTS {
            errors as f64 / attempts as f64
        } else {
            0.0
        };
        if error_rate > ERROR_RATE_BACKOFF {
            self.limit = (self.limit * BACKOFF).clamp(self.min, self.max);
            self.dir = -1.0;
            // Measured under failure: neither a baseline nor a sample.
            self.prev = None;
            self.samples.clear();
            return self.limit();
        }

        self.samples.push(throughput);
        if self.samples.len() < PROBE_EPOCHS {
            return self.limit();
        }
        let reading = median(&mut self.samples);
        self.samples.clear();

        if let Some(prev) = self.prev {
            let change = if prev > 0.0 { (reading - prev) / prev } else { 1.0 };
            if change < -NOISE {
                self.dir = -self.dir; // that step made things worse — turn round
            } else if change.abs() <= NOISE {
                // At the knee: keep nudging so a moving optimum is tracked, but oscillate.
                self.dir = -self.dir;
            }
        }
        self.prev = Some(reading);

        let factor = if self.dir > 0.0 { STEP_UP } else { 1.0 / STEP_UP };
        let mut next = self.limit * factor;
        // A probe must move the thing it measures: the workers use the ROUNDED limit, so where a
        // multiplicative step rounds to the same integer, force the integer to move — otherwise
        // the floor is an inescapable 1.0 ↔ 1.3 two-cycle (verified in propnix: 20000 clean
        // epochs stuck at one connection).
        if next.round() == self.limit.round() {
            next = self.limit + self.dir.signum();
        }
        self.limit = next.clamp(self.min, self.max);
        self.limit()
    }
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link whose throughput rises with concurrency until `knee`, then flattens.
    fn simulate(knee: usize, limit: usize) -> f64 {
        9.0 * limit.min(knee) as f64
    }

    #[test]
    fn climbs_toward_the_knee_and_settles_near_it() {
        let knee = 40;
        let mut g = Governor::new(4, 1, 256);
        for _ in 0..60 {
            let t = simulate(knee, g.limit());
            g.observe(t, Pressure::Network, 32, 0);
        }
        let settled = g.limit();
        assert!(settled >= knee / 2 && settled <= knee * 3, "expected ~{knee}, got {settled}");
    }

    #[test]
    fn does_not_run_away_when_more_connections_stop_helping() {
        let mut g = Governor::new(4, 1, 512);
        for _ in 0..80 {
            g.observe(simulate(16, g.limit()), Pressure::Network, 32, 0);
        }
        assert!(g.limit() < 128, "ran away to {}", g.limit());
    }

    #[test]
    fn survives_a_noisy_link_without_running_away() {
        let knee = 16;
        let mut g = Governor::new(4, 1, 256);
        let noise = [1.0, 0.05, 0.15, 1.0, 8.0, 0.2, 1.0, 3.0, 0.1, 1.0, 0.5, 6.0];
        for i in 0..200 {
            let truth = simulate(knee, g.limit());
            g.observe(truth * noise[i % noise.len()], Pressure::Network, 32, 0);
        }
        assert!(g.limit() < 64, "noise pushed the limit to {}", g.limit());
    }

    #[test]
    fn errors_back_off_faster_than_the_climb() {
        let mut g = Governor::new(64, 1, 256);
        let before = g.limit();
        g.observe(50.0, Pressure::Network, 0, 8);
        let after = g.limit();
        assert!(after < before);
        assert!((before as f64 / after as f64) > STEP_UP * 0.9);
    }

    #[test]
    fn a_consumer_bound_epoch_holds_the_limit_and_is_no_baseline() {
        let mut g = Governor::new(32, 1, 256);
        let before = g.limit();
        for _ in 0..5 {
            g.observe(1.0, Pressure::ConsumerBound, 32, 0);
        }
        assert_eq!(g.limit(), before);

        let mut g = Governor::new(32, 1, 256);
        g.observe(100.0, Pressure::Network, 32, 0);
        g.observe(1.0, Pressure::ConsumerBound, 32, 0);
        let l1 = g.limit();
        g.observe(100.0, Pressure::Network, 32, 0);
        let moved = (g.limit() as f64 / l1 as f64).max(l1 as f64 / g.limit() as f64);
        assert!(moved <= STEP_UP + 0.01, "went {l1} -> {}", g.limit());
    }

    #[test]
    fn escapes_the_floor_on_a_healthy_link() {
        let knee = 32;
        let mut g = Governor::new(1, 1, 256);
        for _ in 0..200 {
            g.observe(simulate(knee, g.limit()), Pressure::Network, 32, 0);
        }
        assert!(g.limit() >= knee / 2, "stuck at {}", g.limit());
    }

    #[test]
    fn a_background_error_rate_does_not_collapse_the_limit() {
        let knee = 32;
        let mut g = Governor::new(6, 1, 256);
        for _ in 0..400 {
            let t = simulate(knee, g.limit());
            let attempts = 10 * g.limit() as u64;
            let errors = (attempts as f64 * 0.08).round() as u64;
            g.observe(t, Pressure::Network, attempts - errors, errors);
        }
        assert!(g.limit() >= knee / 2, "collapsed to {}", g.limit());
    }

    #[test]
    fn a_high_error_rate_still_backs_off() {
        let mut g = Governor::new(64, 1, 256);
        let before = g.limit();
        for _ in 0..5 {
            g.observe(10.0, Pressure::Network, 10, 10);
        }
        assert!(g.limit() < before);
    }

    #[test]
    fn a_tiny_epoch_does_not_trigger_backoff() {
        let mut g = Governor::new(32, 1, 256);
        for _ in 0..10 {
            g.observe(50.0, Pressure::Network, 0, 1);
        }
        assert!(g.limit() >= 24, "a 1-event epoch must not back off, fell to {}", g.limit());
    }

    #[test]
    fn a_consumer_bound_epoch_with_errors_still_holds() {
        let mut g = Governor::new(32, 1, 256);
        let before = g.limit();
        for _ in 0..10 {
            g.observe(1.0, Pressure::ConsumerBound, 0, 9);
        }
        assert_eq!(g.limit(), before);
    }

    #[test]
    fn respects_its_bounds() {
        let mut g = Governor::new(1, 1, 4);
        for _ in 0..50 {
            g.observe(simulate(1000, g.limit()), Pressure::Network, 32, 0);
        }
        assert!(g.limit() <= 4);

        let mut g = Governor::new(4, 2, 8);
        for _ in 0..50 {
            g.observe(1.0, Pressure::Network, 0, 9);
        }
        assert!(g.limit() >= 2);
    }
}
