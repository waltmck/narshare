//! Fetch each distinct segment ONCE — the static retention planner.
//!
//! Ported from propnix pin/dedup.rs (same author). Given the ordered occurrence list of segment
//! hashes and a byte budget, decide up front, all-or-nothing per distinct segment: either every
//! later occurrence replays a retained copy, or every occurrence fetches — such that retained
//! bytes never exceed the budget at any moment of the in-order emission. Static planning keeps
//! peak memory and the fetch work-list exact; nothing adapts mid-run, so nothing can drift.
//!
//! narshare's emitter executes the plan differently from propnix (retention is captured at
//! emission time and replay spans are simply never fetched), but the plan itself is identical.

use std::collections::HashMap;
use std::hash::Hash;

/// What happens at one in-order occurrence.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Step {
    /// Fetch this occurrence; retain the bytes for `retain_for` later occurrences (0 = don't).
    Fetch { unique: usize, retain_for: usize },
    /// Serve the retained copy of `unique`; the last replay frees it.
    Cached { unique: usize },
}

/// Plan retention for `keys[i]`/`sizes[i]` (one entry per occurrence, in emission order), holding
/// at most `budget` bytes at any moment. Greedy first-come: favors short residencies by arrival
/// order. Returns one Step per occurrence.
pub fn plan<K: Eq + Hash>(keys: &[K], sizes: &[u64], budget: u64) -> Vec<Step> {
    // Pass 1: identity — dense ids, occurrence counts, last positions.
    let mut id_of: HashMap<&K, usize> = HashMap::new();
    let mut unique_at: Vec<usize> = Vec::with_capacity(keys.len());
    let mut occurrences: Vec<usize> = Vec::new();
    let mut last_pos: Vec<usize> = Vec::new();
    let mut size_of: Vec<u64> = Vec::new();
    for (p, k) in keys.iter().enumerate() {
        let next_id = occurrences.len();
        let id = *id_of.entry(k).or_insert(next_id);
        if id == next_id {
            occurrences.push(0);
            last_pos.push(0);
            size_of.push(sizes[p]);
        }
        occurrences[id] += 1;
        last_pos[id] = p;
        unique_at.push(id);
    }

    // Pass 2: residency under the budget.
    let mut resident = vec![false; occurrences.len()];
    let mut seen = vec![false; occurrences.len()];
    let mut resident_bytes = 0u64;
    let mut steps = Vec::with_capacity(keys.len());
    for (p, &u) in unique_at.iter().enumerate() {
        if !seen[u] {
            seen[u] = true;
            let later = occurrences[u] - 1;
            let retain_for = if later > 0 && resident_bytes + size_of[u] <= budget {
                resident[u] = true;
                resident_bytes += size_of[u];
                later
            } else {
                0
            };
            steps.push(Step::Fetch {
                unique: u,
                retain_for,
            });
        } else if resident[u] {
            steps.push(Step::Cached { unique: u });
            if p == last_pos[u] {
                resident[u] = false;
                resident_bytes -= size_of[u];
            }
        } else {
            // A duplicate the budget could not hold: fetched again, exactly as without dedup.
            steps.push(Step::Fetch {
                unique: u,
                retain_for: 0,
            });
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch_positions(steps: &[Step]) -> Vec<usize> {
        steps
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s, Step::Fetch { .. }))
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn duplicates_replay_when_they_fit() {
        let keys = [7u8, 1, 7, 2, 7];
        let steps = plan(&keys, &[4; 5], 1 << 20);
        assert_eq!(fetch_positions(&steps), vec![0, 1, 3]);
        assert_eq!(
            steps[0],
            Step::Fetch {
                unique: 0,
                retain_for: 2
            }
        );
        assert_eq!(steps[2], Step::Cached { unique: 0 });
        assert_eq!(steps[4], Step::Cached { unique: 0 });
    }

    #[test]
    fn unique_segments_pass_straight_through() {
        let steps = plan(&[1u8, 2, 3, 4], &[8; 4], 1 << 20);
        assert_eq!(fetch_positions(&steps), vec![0, 1, 2, 3]);
        assert!(steps
            .iter()
            .all(|s| matches!(s, Step::Fetch { retain_for: 0, .. })));
    }

    #[test]
    fn a_duplicate_past_the_budget_is_refetched_not_pinned() {
        // Two duplicated 100-byte segments but 100 bytes of budget: only the first is retained.
        let steps = plan(&[1u8, 2, 1, 2], &[100; 4], 100);
        assert_eq!(fetch_positions(&steps), vec![0, 1, 3]);
        assert_eq!(
            steps[0],
            Step::Fetch {
                unique: 0,
                retain_for: 1
            }
        );
        assert_eq!(
            steps[1],
            Step::Fetch {
                unique: 1,
                retain_for: 0
            }
        );
        assert_eq!(
            steps[3],
            Step::Fetch {
                unique: 1,
                retain_for: 0
            }
        );
    }

    #[test]
    fn budget_frees_when_a_segments_last_occurrence_passes() {
        // Sequential residencies fit in one 100-byte budget.
        let steps = plan(&[1u8, 1, 2, 2], &[100; 4], 100);
        assert_eq!(fetch_positions(&steps), vec![0, 2]);
    }

    #[test]
    fn a_zero_budget_disables_retention_but_plans_correctly() {
        let steps = plan(&[5u8, 5, 5], &[10; 3], 0);
        assert_eq!(fetch_positions(&steps), vec![0, 1, 2]);
    }
}
