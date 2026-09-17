//! Memory-pressure-responsive cache budgets.
//!
//! Every byte narshare caches is an accelerator, never state: seek tables rebuild from the NAR,
//! block-cache pages re-read from the SSTs. Under memory pressure they are therefore exactly
//! the right thing to hand back — but a budget sampled once at startup cannot do that. The
//! ceiling that is right on an idle 2 GiB NAS is wrong the moment a build starts, and the
//! budget that is right during the build wastes cache for the rest of the day.
//!
//! The controller is AIMD with the same asymmetry as the stream governor: HALVE on pressure —
//! and shrinking evicts immediately, rather than waiting for the next insert to notice — then
//! climb back a quarter per tick once things are calm. Signals, strongest wins:
//!
//!   * PSI for our own cgroup: WE are the ones stalling on memory.
//!   * PSI for the machine: someone else is stalling, and a cache is a rude thing to be
//!     holding while a build swaps (narshare exists to make builds faster, not to compete
//!     with them for RAM).
//!   * cgroup fill — memory.current against memory.high/max — the kernel's own headroom view,
//!     which is also the only signal that sees narshare's OWN growth on a limited unit.
//!   * MemAvailable, the fallback for kernels built without PSI (CONFIG_PSI=n).
//!
//! Every signal degrades to "calm" when unreadable, so a hardened unit that cannot see one of
//! them simply runs on the others. Sampling is four small procfs/sysfs reads on a 10 s tick
//! (the window PSI's avg10 already integrates over) — tens of microseconds, no IO wait, which
//! is why it runs inline rather than on a blocking task.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info};

/// Sampling cadence — matched to PSI's avg10 window: sampling faster only re-reads the same
/// average, and the signal itself cannot be fresher than the window that produced it.
const TICK: Duration = Duration::from_secs(10);
/// Severity at or above which the budget halves.
const SHRINK_AT: f64 = 0.5;
/// …and below which it holds rather than climbing (the hysteresis band that keeps a cache
/// from sawtoothing against mild, steady pressure).
const HOLD_AT: f64 = 0.2;
/// Minimum climb per calm tick, so a budget that collapsed to its floor still recovers on a
/// machine where a quarter of the floor rounds to nothing.
const CLIMB_FLOOR: u64 = 1 << 20;

/// A cache whose size the memory governor may drive.
pub trait Shrinkable: Send + Sync {
    /// For logs — which cache moved.
    fn name(&self) -> &'static str;
    /// The most this cache may hold when memory is plentiful.
    fn ceiling(&self) -> u64;
    /// The least that keeps it a cache rather than a thrash generator: below this, rebuilding
    /// what was evicted costs more CPU (and IO) than the memory was worth.
    fn floor(&self) -> u64;
    /// Apply a budget, evicting IMMEDIATELY when it shrinks.
    fn set_budget(&self, bytes: u64);
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// `some avg10=1.23 avg60=… ` → 1.23, from a PSI file's `some` or `full` line.
fn psi_avg10(text: &str, kind: &str) -> Option<f64> {
    text.lines()
        .find(|l| l.starts_with(kind))?
        .split_whitespace()
        .find_map(|f| f.strip_prefix("avg10="))?
        .parse()
        .ok()
}

/// This process's unified-hierarchy cgroup path ("/system.slice/narshare.service").
pub fn cgroup_path() -> Option<String> {
    read("/proc/self/cgroup")?
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_owned))
}

/// The memory ceiling the kernel imposes on us: the smaller of memory.max and memory.high,
/// when either is set ("max" = unlimited, and an unset limit reads as None).
pub fn cgroup_limit() -> Option<u64> {
    let path = cgroup_path()?;
    let one = |f: &str| -> Option<u64> {
        read(&format!("/sys/fs/cgroup{path}/{f}"))?.trim().parse().ok()
    };
    match (one("memory.max"), one("memory.high")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Total machine memory.
fn mem_total_bytes() -> Option<u64> {
    meminfo_kib(&read("/proc/meminfo")?, "MemTotal:").map(|k| k * 1024)
}

fn meminfo_kib(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key))?
        .trim()
        .trim_end_matches(" kB")
        .parse()
        .ok()
}

/// The memory this process should consider available to it: the machine's RAM, or the cgroup
/// limit when one is set and smaller. Used for the static ceiling (serve.rs) as well.
pub fn available_to_us() -> u64 {
    mem_total_bytes()
        .unwrap_or(u64::MAX)
        .min(cgroup_limit().unwrap_or(u64::MAX))
}

/// Linear ramp: `at_zero` → 0.0, `at_one` → 1.0, clamped to [0,1] (and tolerant of a
/// descending ramp, where the signal falls as pressure rises).
fn ramp(v: f64, at_zero: f64, at_one: f64) -> f64 {
    ((v - at_zero) / (at_one - at_zero)).clamp(0.0, 1.0)
}

/// Memory-pressure severity in [0,1]: 0 = calm, 1 = give it all back. Pure, so the mapping is
/// testable against captured signal values.
fn severity(
    own_psi: Option<f64>,
    sys_psi: Option<f64>,
    cg_fill: Option<f64>,
    avail_frac: Option<f64>,
) -> f64 {
    let mut p: f64 = 0.0;
    // Our own cgroup stalling is the strongest evidence: a few tenths of a percent is normal
    // warm-up noise, 5% of wall time stalled on memory is us being the problem.
    if let Some(v) = own_psi {
        p = p.max(ramp(v, 0.5, 5.0));
    }
    // The machine stalling is weaker evidence (it may be nothing to do with us) and noisier —
    // an ordinarily busy laptop idles around half a percent — so the ramp starts well clear.
    if let Some(v) = sys_psi {
        p = p.max(ramp(v, 2.0, 20.0));
    }
    // Against a real cgroup limit, fill is the earliest signal of all: it rises BEFORE the
    // stalls do, and it is the only one that notices narshare's own growth.
    if let Some(r) = cg_fill {
        p = p.max(ramp(r, 0.75, 0.95));
    }
    // PSI-less kernels: fall back to how little of the machine is reclaimable.
    if let Some(a) = avail_frac {
        p = p.max(ramp(a, 0.10, 0.05));
    }
    p
}

/// Sample every signal available on this host.
pub fn pressure() -> f64 {
    let cg = cgroup_path();
    let own_psi = cg
        .as_ref()
        .and_then(|p| read(&format!("/sys/fs/cgroup{p}/memory.pressure")))
        .and_then(|t| psi_avg10(&t, "some"));
    let sys_psi = read("/proc/pressure/memory").and_then(|t| psi_avg10(&t, "some"));
    let cg_fill = match (
        cg.as_ref()
            .and_then(|p| read(&format!("/sys/fs/cgroup{p}/memory.current")))
            .and_then(|t| t.trim().parse::<u64>().ok()),
        cgroup_limit(),
    ) {
        (Some(cur), Some(lim)) if lim > 0 => Some(cur as f64 / lim as f64),
        _ => None,
    };
    let avail_frac = read("/proc/meminfo").and_then(|t| {
        let total = meminfo_kib(&t, "MemTotal:")?;
        let avail = meminfo_kib(&t, "MemAvailable:")?;
        (total > 0).then(|| avail as f64 / total as f64)
    });
    severity(own_psi, sys_psi, cg_fill, avail_frac)
}

/// One controller step. Halving is deliberately far faster than the climb: memory has to come
/// back while it is still wanted, whereas a cache that refills a quarter slower than it could
/// have costs nobody anything.
pub fn next_budget(current: u64, ceiling: u64, floor: u64, pressure: f64) -> u64 {
    let floor = floor.min(ceiling);
    let next = if pressure >= SHRINK_AT {
        current / 2
    } else if pressure >= HOLD_AT {
        current
    } else {
        current.saturating_add(current / 4).saturating_add(CLIMB_FLOOR)
    };
    next.clamp(floor, ceiling)
}

/// Drive every registered cache from the pressure signal until shutdown.
pub fn spawn_governor(caches: Vec<Arc<dyn Shrinkable>>, mut shutdown: watch::Receiver<()>) {
    if caches.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut budgets: Vec<u64> = caches.iter().map(|c| c.ceiling()).collect();
        let mut squeezed = false;
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(TICK) => {}
            }
            let p = pressure();
            // INFO on the transitions only: "narshare gave memory back" is the line that
            // explains a latency blip during an incident, while per-tick adjustments are
            // ordinary control-loop chatter.
            if p >= SHRINK_AT && !squeezed {
                info!("memory pressure {p:.2}: shrinking caches");
                squeezed = true;
            } else if p < HOLD_AT && squeezed {
                info!("memory pressure eased ({p:.2}): caches may grow back");
                squeezed = false;
            }
            for (c, b) in caches.iter().zip(budgets.iter_mut()) {
                let next = next_budget(*b, c.ceiling(), c.floor(), p);
                if next != *b {
                    debug!(
                        "{}: budget {} -> {} MiB (pressure {p:.2})",
                        c.name(),
                        *b >> 20,
                        next >> 20
                    );
                    *b = next;
                    c.set_budget(next);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSI: &str = "some avg10=1.25 avg60=0.47 avg300=0.41 total=626468217\n\
                       full avg10=0.61 avg60=0.46 avg300=0.37 total=565096056\n";

    #[test]
    fn parses_psi_and_meminfo() {
        assert_eq!(psi_avg10(PSI, "some"), Some(1.25));
        assert_eq!(psi_avg10(PSI, "full"), Some(0.61));
        assert_eq!(psi_avg10("garbage", "some"), None);
        let mi = "MemTotal:       24108672 kB\nMemAvailable:    9457408 kB\n";
        assert_eq!(meminfo_kib(mi, "MemTotal:"), Some(24_108_672));
        assert_eq!(meminfo_kib(mi, "Missing:"), None);
    }

    #[test]
    fn severity_maps_each_signal() {
        // An ordinary busy machine (the values measured on walt-laptop) is calm.
        assert_eq!(severity(Some(0.0), Some(0.61), None, Some(0.39)), 0.0);
        // Our own cgroup stalling dominates, and saturates at 5%.
        assert!(severity(Some(2.75), None, None, None) > 0.4);
        assert_eq!(severity(Some(5.0), None, None, None), 1.0);
        // A machine-wide stall is weighed more gently: the same 5% is not yet severe.
        assert!(severity(None, Some(5.0), None, None) < 0.3);
        // Fill against a real limit rises before any stall does.
        assert_eq!(severity(None, None, Some(0.75), None), 0.0);
        assert_eq!(severity(None, None, Some(0.95), None), 1.0);
        // PSI-less fallback: MemAvailable is a DESCENDING signal.
        assert_eq!(severity(None, None, None, Some(0.10)), 0.0);
        assert_eq!(severity(None, None, None, Some(0.05)), 1.0);
        // Nothing readable at all reads as calm, never as panic.
        assert_eq!(severity(None, None, None, None), 0.0);
    }

    #[test]
    fn budget_halves_fast_and_climbs_slowly() {
        let (ceil, floor) = (256 << 20, 32 << 20);
        // Severe: halve, per tick, down to the floor and no further.
        let mut b = ceil;
        for want in [128, 64, 32, 32] {
            b = next_budget(b, ceil, floor, 1.0);
            assert_eq!(b >> 20, want);
        }
        // Mild: hold — no sawtooth against steady, unremarkable pressure.
        assert_eq!(next_budget(b, ceil, floor, 0.3), b);
        // Calm: climb a quarter per tick, and stop at the ceiling.
        b = next_budget(b, ceil, floor, 0.0);
        assert_eq!(b >> 20, 41);
        assert_eq!(next_budget(ceil, ceil, floor, 0.0), ceil);
        // A floor above the ceiling (a tiny host) still yields a sane budget.
        assert_eq!(next_budget(ceil, 8 << 20, 32 << 20, 1.0), 8 << 20);
    }
}
