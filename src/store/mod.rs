//! The mesh-index storage abstraction: one logical schema, two backends (rocksdb, postgres).
//!
//! The index (index.rs) owns every protocol decision — feasibility, sequence-gap handling,
//! generation adoption, budgets, retention policy. What a backend owns is DURABLE STATE plus
//! the atomicity of a handful of coarse composite operations. The split matters because the
//! two backends achieve atomicity in unrelated ways (a WriteBatch under a writer lock vs a
//! SQL transaction), so anything finer-grained than these composites could not be made atomic
//! behind a common interface.
//!
//! The logical schema, shared verbatim by both backends:
//!
//!   meta          key → value                      (self generation, backend layout marker)
//!   clocks        origin → (generation, seq, tail_seq)
//!   journal       (origin, seq) → encoded mesh.v2 Event, the origin's totally-ordered history
//!   holdings      (origin, nar_hash)               possession: who has which bytes
//!   attestations  (hash_part, nar_hash) → body + sigs + unheld_since
//!   watermarks    (peer, origin) → seq             what each peer proved it has seen
//!   mw_state      peer → (weight, updated)         the MW pool's persisted learning
//!
//! Attestations are grow-only facts: bodies last-writer-win, signature sets only ever union,
//! and deletion happens exclusively through the retention reaper (`reap_attestations`), driven
//! by the `unheld_since` stamp that backends maintain as holdings change. Concurrent writers
//! must converge: both backends guarantee that the effect of racing `apply_events` calls for
//! DIFFERENT origins is their sequential composition (rocksdb by a store-wide writer lock,
//! postgres by row-level locking), while racing calls for the SAME origin are arbitrated by
//! the `expect` clock check.
//!
//! All methods are synchronous by design: every index call site already runs under
//! spawn_blocking, so an async trait would only add ceremony (and the postgres crate's
//! blocking client is exactly this shape).

pub mod postgres;
pub mod rocks;

use crate::index::proto;
use anyhow::Result;

/// A retained attestation paired with the origins currently holding its bytes.
pub type FoundRow = (proto::Attestation, Vec<String>);
/// Slim differ row: (store_path, nar_hash, sigs).
pub type ClaimRow = (String, Vec<u8>, Vec<String>);
/// Persisted MW pool rows: (peer, weight, updated).
pub type MwRows = Vec<(String, f64, u64)>;

/// An origin's clock as stored: its generation, the highest seq applied, and the journal tail
/// (the seq at/before which history has been compacted away — suffixes can only start there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Clock {
    pub generation: u64,
    pub seq: u64,
    pub tail_seq: u64,
}

/// One possession change to materialize, pre-validated by the index.
#[derive(Debug, Clone, Copy)]
pub enum HoldOp {
    Add([u8; 32]),
    Drop([u8; 32]),
}

/// The hash part of a store path ("/nix/store/<32 chars>-name" → the 32 chars); empty when
/// malformed. Both backends key attestations by it because narinfo lookups arrive as bare
/// hash parts.
pub fn hash_part_of(store_path: &str) -> &str {
    store_path
        .rsplit('/')
        .next()
        .unwrap_or("")
        .get(..32)
        .unwrap_or("")
}

pub trait SyncStore: Send + Sync {
    // ---- meta ----
    fn meta_get(&self, key: &str) -> Result<Option<String>>;
    fn meta_put(&self, key: &str, value: &str) -> Result<()>;

    // ---- clocks ----
    /// Zero clock when the origin has never been written.
    fn clock(&self, origin: &str) -> Result<Clock>;
    /// Set the generation, keeping seq/tail_seq (self-generation stamping and reminting).
    fn set_generation(&self, origin: &str, generation: u64) -> Result<()>;

    // ---- the atomic composites ----
    /// Atomically: verify the origin's clock equals `expect` (generation, seq); if so, append
    /// the encoded journal rows, materialize the possession ops, merge the attestations, set
    /// the clock to `set` (generation, seq), and return true. If the clock moved — a
    /// concurrent apply for the same origin won the race — do nothing and return false.
    ///
    /// Possession side effects on retention stamps: a Drop that removes the LAST holder of a
    /// hash stamps every attestation of that hash `unheld_since = now`; an Add clears the
    /// stamp on every attestation of its hash.
    ///
    /// `durable`: commit synchronously (fsync / synchronous_commit=on). The index passes true
    /// exactly for SELF-origin transactions — a seq a peer observed must never be reissued
    /// with different events, and only the origin can reissue. Replicas of other origins can
    /// only FORGET on a crash (single writer: their content at a (gen, seq) is immutable
    /// mesh-wide), which the next pull re-learns — so everything else commits asynchronously.
    #[allow(clippy::too_many_arguments)]
    fn apply_events(
        &self,
        origin: &str,
        expect: (u64, u64),
        set: (u64, u64),
        journal: &[(u64, Vec<u8>)],
        holds: &[HoldOp],
        attests: &[proto::Attestation],
        now: u64,
        durable: bool,
    ) -> Result<bool>;

    /// Snapshot recovery: unless stale (generation below the current one, or equal generation
    /// with seq below the current seq), wipe-replace the origin's possession set, empty its
    /// journal, and set clock = (generation, seq, tail_seq = seq). Returns whether it applied.
    /// Retention stamps are maintained exactly as for apply_events.
    ///
    /// NOT atomic against readers: a snapshot spans a peer's whole store, so backends commit
    /// it in bounded chunks (memory stays O(chunk)) under their writer exclusion, with the
    /// clock written last. Readers may briefly see a partial possession set (a lookup miss
    /// falls back upstream — this is a cache); a crash mid-apply leaves the clock unmoved,
    /// so the next pull re-offers the same snapshot wholesale.
    fn replace_holdings(
        &self,
        origin: &str,
        generation: u64,
        seq: u64,
        held: &[[u8; 32]],
        now: u64,
    ) -> Result<bool>;

    /// Merge attestation facts (the snapshot-response dump): grow-only dedup by
    /// (hash_part, nar_hash), signature sets unioned, bodies last-writer-win. Returns how many
    /// were new or changed.
    fn merge_attestations(&self, attests: &[proto::Attestation], now: u64) -> Result<usize>;

    // ---- journal / snapshot serving ----
    /// Encoded events with seq > `after`, in seq order, stopping (truncated = true) before the
    /// event that would exceed `max_bytes` — but never truncating to zero events.
    fn journal_suffix(
        &self,
        origin: &str,
        after: u64,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool)>;
    /// The origin's complete current possession set.
    fn holdings(&self, origin: &str) -> Result<Vec<[u8; 32]>>;
    /// One page of the retained attestation dump (the recovery path; includes grace-retained
    /// unheld facts), in a stable storage order, starting strictly after `cursor` (empty =
    /// from the start). The page stops before the attestation whose encoded size would push
    /// it past `max_bytes` — but never truncates to zero rows. Returns the page and the
    /// cursor to resume from; None means the dump is complete. Cursors are opaque to callers
    /// and remain valid across concurrent merges and reaps (rows added or removed mid-dump
    /// are over- or under-delivered, which grow-only dedup and re-teaching make harmless).
    /// Memory on both sides of the trait is O(page), never O(table).
    fn attestation_page(
        &self,
        cursor: &[u8],
        max_bytes: usize,
    ) -> Result<(Vec<proto::Attestation>, Option<Vec<u8>>)>;

    // ---- maintenance ----
    /// Drop journal rows with seq <= floor and raise tail_seq to floor. No-op when
    /// floor <= tail_seq.
    fn compact_journal(&self, origin: &str, floor: u64) -> Result<()>;
    /// Reap attestations whose unheld_since stamp is <= cutoff. Returns how many died.
    fn reap_attestations(&self, cutoff: u64) -> Result<usize>;
    /// Drop all per-origin state (holdings, journal, clock) for origins not in `keep`, plus
    /// watermark rows whose peer or origin is not in `keep`. Attestations whose last holder
    /// departs are stamped `unheld_since = now`.
    fn retain_origins(&self, keep: &[String], now: u64) -> Result<()>;

    // ---- lookups ----
    /// Attestations whose store path has this hash part, each with the current holders of its
    /// nar hash. Rows nobody holds are omitted: they name bytes no one can serve.
    fn lookup_hash_part(&self, hash_part: &str) -> Result<Vec<(proto::Attestation, Vec<String>)>>;
    /// Attestations for this nar hash, each with its current holders; same no-holder rule.
    fn lookup_nar_hash(&self, nar_hash: &[u8; 32]) -> Result<Vec<FoundRow>>;
    /// Stream the differ's slim view — (store_path, nar_hash, sigs) — of every retained
    /// attestation, one row at a time in storage order. Streaming, deliberately: the full
    /// claim set is O(mesh), and materializing it per differ cycle was measured at ~400 MiB
    /// of transient heap at production scale — heap that glibc then largely kept.
    fn for_each_claim(&self, f: &mut dyn FnMut(ClaimRow) -> Result<()>) -> Result<()>;
    /// One fact's signature set, or None if the fact is not retained — the incremental
    /// differ's point-wise change test (a handful of new rows must not cost a table scan).
    fn attestation_sigs(&self, hash_part: &str, nar_hash: &[u8]) -> Result<Option<Vec<String>>>;
    /// Does `origin` hold this hash? Point-wise possession test for the incremental differ.
    fn is_held(&self, origin: &str, nar_hash: &[u8; 32]) -> Result<bool>;

    // ---- watermarks ----
    /// Record that `peer` has seen `origin` up to `seq`; keeps the max of old and new.
    fn advance_watermark(&self, peer: &str, origin: &str, seq: u64) -> Result<()>;
    fn watermarks(&self) -> Result<Vec<(String, String, u64)>>;

    // ---- MW pool state ----
    fn mw_save(&self, rows: &[(String, f64)], updated: u64, globals: &str) -> Result<()>;
    /// (per-peer rows, globals string). Empty rows = nothing ever saved.
    fn mw_load(&self) -> Result<(MwRows, Option<String>)>;
    /// Reap MW rows for peers not in `keep`.
    fn mw_prune(&self, keep: &[String]) -> Result<()>;
    /// Test support: shift every persisted MW stamp (rows and globals) backwards by `secs`.
    /// (Dead in release builds by design — only the index's cfg(test) hook calls it.)
    #[allow(dead_code)]
    fn mw_shift_updated(&self, secs: i64) -> Result<()>;

    // ---- status ----
    /// (journal_len, holdings count) of one origin.
    fn origin_stats(&self, origin: &str) -> Result<(u64, u64)>;
    /// Number of retained attestations.
    fn count_attestations(&self) -> Result<u64>;

    // ---- memory ----
    /// The backend's in-process block-cache ceiling, or 0 when it holds no cache this process
    /// can resize (postgres caches in the SERVER, whose memory is that server's business).
    fn cache_ceiling(&self) -> u64 {
        0
    }
    /// Resize that cache, evicting immediately when it shrinks. See mem.rs.
    fn set_cache_capacity(&self, _bytes: u64) {}
}

/// Control-plane cost at realistic scale, run identically against every backend — the numbers
/// that decide whether the index is battery-safe. The pre-v2 single-file sqlite layout died on
/// exactly this: background CPU from the differ/sync loops churning the index. Steady-state
/// idle is gated elsewhere (one PRAGMA per inotify burst), so the figures that matter are the
/// PER-STORE-CHANGE costs: a differ cycle's scans, a lookup, an apply.
///
/// Run: cargo test --release -- --ignored --nocapture bench_control
#[cfg(test)]
pub mod bench {
    use super::*;
    use crate::index::proto;
    use std::time::Instant;

    const FACTS: usize = 320_000;
    const HELD: usize = 200_000;
    const LOOKUPS: usize = 20_000;

    fn h(i: usize) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&(i as u64).to_le_bytes());
        b[8] = 0x5a;
        b
    }

    /// Shaped like a production fact: a full store path, a dozen reference basenames, one
    /// binary-cache signature. Row size drives every scan/dump figure, so it must be honest.
    fn att(i: usize) -> proto::Attestation {
        proto::Attestation {
            store_path: format!("/nix/store/{:032x}-pkg-{i}", i),
            nar_hash: h(i).to_vec(),
            nar_size: 4096,
            references: (0..12)
                .map(|r| format!("{:032x}-dependency-{r}-1.2.{i}", i.wrapping_mul(31) + r))
                .collect(),
            ca: String::new(),
            sigs: vec![format!("cache.example.org-1:{i:086}")],
        }
    }

    /// This process's resident set, for the per-phase memory report — the number that decides
    /// whether the control plane fits small hosts.
    fn rss_mib() -> f64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        s.lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches(" kB").parse::<f64>().ok())
            .unwrap_or(0.0)
            / 1024.0
    }

    /// Per-phase resource meter: wall clock, this process's CPU (user+sys via getrusage) and
    /// block-level IO (/proc/self/io read_bytes/write_bytes — actual storage traffic, i.e. the
    /// amplification the battery and the SSD see), plus the summed IO of external `postgres`
    /// backends when measuring that store (the server does its IO out-of-process).
    struct Meter {
        t: Instant,
        cpu: f64,
        io: (u64, u64),
        ext: Option<(u64, u64)>,
        track_ext: bool,
    }

    fn cpu_secs() -> f64 {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        tv(ru.ru_utime) + tv(ru.ru_stime)
    }

    fn io_of(path: &str) -> (u64, u64) {
        let Ok(s) = std::fs::read_to_string(path) else {
            return (0, 0);
        };
        let field = |k: &str| {
            s.lines()
                .find_map(|l| l.strip_prefix(k))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        (field("read_bytes:"), field("write_bytes:"))
    }

    fn postgres_io() -> (u64, u64) {
        let mut r = 0u64;
        let mut w = 0u64;
        for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
            let p = e.path();
            if std::fs::read_to_string(p.join("comm")).is_ok_and(|c| c.trim() == "postgres") {
                let (pr, pw) = io_of(&p.join("io").to_string_lossy());
                r += pr;
                w += pw;
            }
        }
        (r, w)
    }

    impl Meter {
        fn start(track_ext: bool) -> Self {
            Self {
                t: Instant::now(),
                cpu: cpu_secs(),
                io: io_of("/proc/self/io"),
                ext: track_ext.then(postgres_io),
                track_ext,
            }
        }

        /// Print the phase line; `logical` is the payload byte count, when write amplification
        /// is meaningful for the phase.
        fn stop(self, label: &str, ops: usize, logical: Option<u64>) {
            let wall = self.t.elapsed();
            let cpu = cpu_secs() - self.cpu;
            let now = io_of("/proc/self/io");
            let (mut dr, mut dw) = (now.0 - self.io.0, now.1 - self.io.1);
            if self.track_ext {
                let e0 = self.ext.unwrap_or((0, 0));
                let e1 = postgres_io();
                dr += e1.0.saturating_sub(e0.0);
                dw += e1.1.saturating_sub(e0.1);
            }
            let amp = logical
                .filter(|l| *l > 0)
                .map(|l| format!(", write-amp {:.2}x", dw as f64 / l as f64))
                .unwrap_or_default();
            println!(
                "[bench]   {label}: wall {wall:?}, cpu {cpu:.3}s, io r/w {}/{} KiB{amp}, {:.1} µs/op ({ops} ops), rss {:.0} MiB",
                dr / 1024,
                dw / 1024,
                wall.as_secs_f64() * 1e6 / ops.max(1) as f64,
                rss_mib()
            );
        }
    }

    pub fn run(label: &str, s: &dyn SyncStore) {
        use prost::Message as _;
        let ext = label.starts_with("postgres");
        println!("[bench] === {label} ===");

        // Fact ingest (mesh resync order of magnitude), chunked like real snapshot merges.
        let logical: u64 = (0..FACTS).map(|i| att(i).encoded_len() as u64).sum();
        let m = Meter::start(ext);
        for chunk in (0..FACTS).collect::<Vec<_>>().chunks(10_000) {
            let atts: Vec<proto::Attestation> = chunk.iter().map(|i| att(*i)).collect();
            s.merge_attestations(&atts, 1).unwrap();
        }
        m.stop("fact ingest", FACTS, Some(logical));

        // Snapshot apply: a peer's complete possession set, wipe-replace.
        let held: Vec<[u8; 32]> = (0..HELD).map(h).collect();
        let m = Meter::start(ext);
        assert!(s.replace_holdings("peer-a", 1, 1, &held, 1).unwrap());
        m.stop("snapshot apply (holdings)", HELD, Some(32 * HELD as u64));

        // Journal suffix apply: incremental possession churn from another origin.
        let mut seq = 0u64;
        let m = Meter::start(ext);
        for chunk in (0..50_000usize).collect::<Vec<_>>().chunks(5_000) {
            let expect = (if seq == 0 { 0 } else { 1 }, seq);
            let journal: Vec<(u64, Vec<u8>)> = chunk
                .iter()
                .map(|i| (seq + 1 + (i % 5_000) as u64, vec![0u8; 40]))
                .collect();
            let holds: Vec<HoldOp> = chunk.iter().map(|i| HoldOp::Add(h(*i))).collect();
            seq += chunk.len() as u64;
            assert!(s
                .apply_events("peer-b", expect, (1, seq), &journal, &holds, &[], 1, false)
                .unwrap());
        }
        m.stop("journal apply (peer, async)", 50_000, Some(72 * 50_000));

        // Lookups, hits then misses — the proxy's per-substitution cost.
        let m = Meter::start(ext);
        let mut found = 0usize;
        for i in 0..LOOKUPS {
            // Stay within the HELD range: holderless facts are (correctly) invisible.
            let hp = format!("{:032x}", i * (HELD / LOOKUPS));
            found += usize::from(!s.lookup_hash_part(&hp).unwrap().is_empty());
        }
        m.stop("lookup HIT", LOOKUPS, None);
        assert_eq!(found, LOOKUPS, "every held fact must resolve");
        let m = Meter::start(ext);
        for i in 0..LOOKUPS {
            let hp = format!("{:032x}", FACTS + i);
            assert!(s.lookup_hash_part(&hp).unwrap().is_empty());
        }
        m.stop("lookup MISS", LOOKUPS, None);

        // The differ's per-cycle scans.
        let m = Meter::start(ext);
        let mut n = 0usize;
        s.for_each_claim(&mut |_| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, FACTS);
        m.stop("claims stream", n, None);
        let m = Meter::start(ext);
        let held = s.holdings("peer-a").unwrap();
        let n = held.len();
        m.stop("holdings scan", n, None);

        // Maintenance passes.
        let m = Meter::start(ext);
        s.compact_journal("peer-b", seq).unwrap();
        m.stop("compact_journal", 50_000, None);
        let m = Meter::start(ext);
        let reaped = s.reap_attestations(0).unwrap();
        assert_eq!(reaped, 0);
        m.stop("reap scan (nothing due)", FACTS, None);

        // The recovery dump, as sync.rs drives it: page from the store, encode, compress,
        // release — per-page memory, whatever the table size.
        let m = Meter::start(ext);
        let mut cursor: Vec<u8> = Vec::new();
        let (mut pages, mut rows, mut wire, mut zbytes) = (0usize, 0usize, 0usize, 0usize);
        loop {
            let (page, next) = s.attestation_page(&cursor, 8 << 20).unwrap();
            rows += page.len();
            let mut buf = Vec::new();
            for a in &page {
                a.encode_length_delimited(&mut buf).unwrap();
            }
            wire += buf.len();
            zbytes += zstd::stream::encode_all(&buf[..], 3).unwrap().len();
            pages += 1;
            match next {
                Some(c) => cursor = c,
                None => break,
            }
        }
        assert_eq!(rows, FACTS);
        println!(
            "[bench]   fact dump: {pages} pages, wire {} MiB, zstd {} MiB",
            wire >> 20,
            zbytes >> 20
        );
        m.stop("paged fact dump", FACTS, None);
    }
}

/// The behavioral contract, run identically against every backend (each backend's test module
/// calls into this with a store factory). index.rs tests cover the protocol logic above the
/// trait; these pin the storage semantics themselves.
#[cfg(test)]
pub mod conformance {
    use super::*;
    use crate::index::proto;

    fn att(name: &str, hash: u8, sigs: &[&str]) -> proto::Attestation {
        proto::Attestation {
            store_path: format!(
                "/nix/store/{}-{name}",
                name.repeat(32 / name.len().max(1))[..32].to_owned()
            ),
            nar_hash: vec![hash; 32],
            nar_size: 100,
            references: vec!["aaa-dep".into(), "zzz-dep".into()],
            ca: "fixed:r:sha256:dummy".into(),
            sigs: sigs.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn ev(seq: u64, bytes: usize) -> (u64, Vec<u8>) {
        (seq, vec![0u8; bytes])
    }

    pub fn run_all(mk: &dyn Fn(&str) -> Box<dyn SyncStore>) {
        meta_roundtrip(&*mk("meta"));
        clocks_and_expect_gate(&*mk("clocks"));
        journal_suffix_and_compaction(&*mk("journal"));
        holdings_replace_and_staleness(&*mk("holdings"));
        attestations_merge_union_and_lookup(&*mk("attest"));
        attestation_paging(&*mk("paging"));
        retention_stamps_and_reaper(&*mk("retention"));
        watermarks_and_retain_origins(&*mk("wm"));
        mw_state_roundtrip(&*mk("mw"));
    }

    fn meta_roundtrip(s: &dyn SyncStore) {
        assert_eq!(s.meta_get("k").unwrap(), None);
        s.meta_put("k", "v1").unwrap();
        s.meta_put("k", "v2").unwrap();
        assert_eq!(s.meta_get("k").unwrap(), Some("v2".into()));
    }

    fn clocks_and_expect_gate(s: &dyn SyncStore) {
        assert_eq!(s.clock("a").unwrap(), Clock::default());
        // Happy path: expect (0,0), set (1,2).
        assert!(s
            .apply_events(
                "a",
                (0, 0),
                (1, 2),
                &[ev(1, 4), ev(2, 4)],
                &[HoldOp::Add(h(1))],
                &[],
                10,
                false
            )
            .unwrap());
        assert_eq!(
            s.clock("a").unwrap(),
            Clock {
                generation: 1,
                seq: 2,
                tail_seq: 0
            }
        );
        // The durable (self-origin) flavor commits too.
        assert!(s
            .apply_events("a", (1, 2), (1, 3), &[ev(3, 4)], &[], &[], 10, true)
            .unwrap());
        assert_eq!(s.clock("a").unwrap().seq, 3);
        // A racing apply based on the stale clock must be refused wholesale.
        assert!(!s
            .apply_events(
                "a",
                (0, 0),
                (1, 1),
                &[ev(1, 4)],
                &[HoldOp::Add(h(9))],
                &[],
                10,
                false
            )
            .unwrap());
        assert_eq!(s.clock("a").unwrap().seq, 3);
        assert!(s.holdings("a").unwrap().contains(&h(1)));
        assert!(!s.holdings("a").unwrap().contains(&h(9)));
        s.set_generation("a", 7).unwrap();
        assert_eq!(
            s.clock("a").unwrap(),
            Clock {
                generation: 7,
                seq: 3,
                tail_seq: 0
            }
        );
    }

    fn journal_suffix_and_compaction(s: &dyn SyncStore) {
        let rows: Vec<(u64, Vec<u8>)> = (1..=5).map(|i| ev(i, 10)).collect();
        assert!(s
            .apply_events("a", (0, 0), (1, 5), &rows, &[], &[], 0, false)
            .unwrap());
        let (all, trunc) = s.journal_suffix("a", 0, usize::MAX).unwrap();
        assert_eq!(all.len(), 5);
        assert!(!trunc);
        let (some, trunc) = s.journal_suffix("a", 2, usize::MAX).unwrap();
        assert_eq!(some.len(), 3);
        assert!(!trunc);
        // Byte cap: never zero events, truncated flagged.
        let (capped, trunc) = s.journal_suffix("a", 0, 15).unwrap();
        assert_eq!(
            capped.len(),
            1,
            "one event fits ten bytes in, the second would exceed"
        );
        assert!(trunc);
        assert_eq!(s.origin_stats("a").unwrap().0, 5);
        s.compact_journal("a", 3).unwrap();
        assert_eq!(s.clock("a").unwrap().tail_seq, 3);
        let (rest, _) = s.journal_suffix("a", 3, usize::MAX).unwrap();
        assert_eq!(rest.len(), 2);
        assert_eq!(s.origin_stats("a").unwrap().0, 2);
        // floor <= tail is a no-op.
        s.compact_journal("a", 2).unwrap();
        assert_eq!(s.clock("a").unwrap().tail_seq, 3);
    }

    fn holdings_replace_and_staleness(s: &dyn SyncStore) {
        assert!(s.replace_holdings("a", 1, 10, &[h(1), h(2)], 0).unwrap());
        assert_eq!(
            s.clock("a").unwrap(),
            Clock {
                generation: 1,
                seq: 10,
                tail_seq: 10
            }
        );
        let mut held = s.holdings("a").unwrap();
        held.sort();
        assert_eq!(held, vec![h(1), h(2)]);
        // Stale snapshot (same gen, lower seq): refused.
        assert!(!s.replace_holdings("a", 1, 9, &[h(3)], 0).unwrap());
        assert_eq!(s.holdings("a").unwrap().len(), 2);
        // Equal seq re-applies (idempotent recovery), higher generation replaces wholesale.
        assert!(s.replace_holdings("a", 1, 10, &[h(1), h(2)], 0).unwrap());
        assert!(s.replace_holdings("a", 2, 1, &[h(3)], 0).unwrap());
        assert_eq!(s.holdings("a").unwrap(), vec![h(3)]);
        assert_eq!(
            s.origin_stats("a").unwrap(),
            (0, 1),
            "snapshot empties the journal"
        );
    }

    fn attestations_merge_union_and_lookup(s: &dyn SyncStore) {
        // A fact arrives with one sig; the same fact from elsewhere brings another: union.
        let a1 = att("p", 1, &["k1:AAA"]);
        assert_eq!(
            s.merge_attestations(std::slice::from_ref(&a1), 0).unwrap(),
            1
        );
        assert_eq!(
            s.merge_attestations(std::slice::from_ref(&a1), 0).unwrap(),
            0,
            "exact dup is a no-op"
        );
        let mut a2 = a1.clone();
        a2.sigs = vec!["k2:BBB".into()];
        assert_eq!(s.merge_attestations(&[a2], 0).unwrap(), 1);
        // Nobody holds the hash: lookups must omit the row.
        let hp = hash_part_of(&a1.store_path).to_owned();
        assert!(s.lookup_hash_part(&hp).unwrap().is_empty());
        // Two holders appear.
        assert!(s
            .apply_events(
                "x",
                (0, 0),
                (1, 1),
                &[ev(1, 1)],
                &[HoldOp::Add(h(1))],
                &[],
                0,
                false
            )
            .unwrap());
        assert!(s
            .apply_events(
                "y",
                (0, 0),
                (1, 1),
                &[ev(1, 1)],
                &[HoldOp::Add(h(1))],
                &[],
                0,
                false
            )
            .unwrap());
        let rows = s.lookup_hash_part(&hp).unwrap();
        assert_eq!(rows.len(), 1);
        let (found, mut holders) = rows.into_iter().next().unwrap();
        holders.sort();
        assert_eq!(holders, vec!["x".to_string(), "y".to_string()]);
        let mut sigs = found.sigs.clone();
        sigs.sort();
        assert_eq!(sigs, vec!["k1:AAA".to_string(), "k2:BBB".to_string()]);
        assert_eq!(
            found.references, a1.references,
            "reference order is signature-exact"
        );
        // Same rows by nar hash.
        assert_eq!(s.lookup_nar_hash(&h(1)).unwrap().len(), 1);
        assert!(s.lookup_nar_hash(&h(9)).unwrap().is_empty());
        // Point lookups agree with the scans.
        assert_eq!(
            s.attestation_sigs(&hp, &a1.nar_hash).unwrap().map(|mut v| {
                v.sort();
                v
            }),
            Some(vec!["k1:AAA".to_string(), "k2:BBB".to_string()])
        );
        assert!(s.attestation_sigs(&hp, &h(9)).unwrap().is_none());
        assert!(s.is_held("x", &h(1)).unwrap());
        assert!(!s.is_held("x", &h(9)).unwrap());
        assert!(!s.is_held("nobody", &h(1)).unwrap());
        // Distinct (path, hash) facts coexist; the claims stream sees both.
        let b = att("p", 2, &[]);
        s.merge_attestations(&[b], 0).unwrap();
        assert_eq!(s.count_attestations().unwrap(), 2);
        let mut claims = 0usize;
        s.for_each_claim(&mut |_| {
            claims += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(claims, 2);
        let (page, next) = s.attestation_page(b"", usize::MAX).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(next, None);
    }

    fn attestation_paging(s: &dyn SyncStore) {
        let atts: Vec<proto::Attestation> = (0..7).map(|i| att("pg", i, &["k:S"])).collect();
        s.merge_attestations(&atts, 0).unwrap();
        // Tiny budget: pages never truncate to zero rows, cursors resume without overlap or
        // loss, and the final page reports completion.
        let mut cursor: Vec<u8> = Vec::new();
        let mut seen: Vec<Vec<u8>> = Vec::new();
        loop {
            let (page, next) = s.attestation_page(&cursor, 1).unwrap();
            assert!(!page.is_empty(), "a page under budget must still progress");
            seen.extend(page.iter().map(|a| a.nar_hash.clone()));
            match next {
                Some(c) => cursor = c,
                None => break,
            }
        }
        let mut want: Vec<Vec<u8>> = atts.iter().map(|a| a.nar_hash.clone()).collect();
        want.sort();
        let mut got = seen.clone();
        got.sort();
        assert_eq!(got, want, "paging covers every row exactly once");
        assert_eq!(seen.len(), 7);
        // A roomy budget takes the whole table in one page.
        let (page, next) = s.attestation_page(b"", usize::MAX).unwrap();
        assert_eq!(page.len(), 7);
        assert_eq!(next, None);
    }

    fn retention_stamps_and_reaper(s: &dyn SyncStore) {
        let a = att("q", 4, &["k:XYZ"]);
        // Held from the start: no stamp, reaper spares it.
        assert!(s
            .apply_events(
                "x",
                (0, 0),
                (1, 1),
                &[ev(1, 1)],
                &[HoldOp::Add(h(4))],
                std::slice::from_ref(&a),
                100,
                false
            )
            .unwrap());
        assert_eq!(s.reap_attestations(u64::MAX).unwrap(), 0);
        // Last holder drops at t=200: stamped, retained through the grace window…
        assert!(s
            .apply_events(
                "x",
                (1, 1),
                (1, 2),
                &[ev(2, 1)],
                &[HoldOp::Drop(h(4))],
                &[],
                200,
                false
            )
            .unwrap());
        assert_eq!(s.reap_attestations(199).unwrap(), 0);
        assert_eq!(s.count_attestations().unwrap(), 1);
        // …a re-appearing holder clears the stamp…
        assert!(s
            .apply_events(
                "y",
                (0, 0),
                (1, 1),
                &[ev(1, 1)],
                &[HoldOp::Add(h(4))],
                &[],
                300,
                false
            )
            .unwrap());
        assert_eq!(
            s.reap_attestations(u64::MAX).unwrap(),
            0,
            "held again: stamp cleared"
        );
        // …and once unheld past the cutoff, the fact dies.
        assert!(s
            .apply_events(
                "y",
                (1, 1),
                (1, 2),
                &[ev(2, 1)],
                &[HoldOp::Drop(h(4))],
                &[],
                400,
                false
            )
            .unwrap());
        assert_eq!(s.reap_attestations(400).unwrap(), 1);
        assert_eq!(s.count_attestations().unwrap(), 0);
        // A fact arriving for an already-unheld hash is stamped at arrival time.
        s.merge_attestations(&[a], 500).unwrap();
        assert_eq!(s.reap_attestations(499).unwrap(), 0);
        assert_eq!(s.reap_attestations(500).unwrap(), 1);
    }

    fn watermarks_and_retain_origins(s: &dyn SyncStore) {
        s.advance_watermark("p", "a", 5).unwrap();
        s.advance_watermark("p", "a", 3).unwrap();
        s.advance_watermark("q", "b", 7).unwrap();
        let mut wm = s.watermarks().unwrap();
        wm.sort();
        assert_eq!(
            wm,
            vec![
                ("p".into(), "a".into(), 5u64),
                ("q".into(), "b".into(), 7u64)
            ],
            "watermarks keep the max"
        );
        // Origin b departs the config: its holdings, journal, clock, and watermark rows go;
        // attestations it alone held get stamped for the reaper.
        assert!(s
            .apply_events(
                "b",
                (0, 0),
                (1, 1),
                &[ev(1, 1)],
                &[HoldOp::Add(h(8))],
                &[att("r", 8, &[])],
                0,
                false
            )
            .unwrap());
        let keep = vec!["p".to_string(), "q".to_string(), "a".to_string()];
        s.retain_origins(&keep, 900).unwrap();
        assert_eq!(s.clock("b").unwrap(), Clock::default());
        assert!(s.holdings("b").unwrap().is_empty());
        assert_eq!(
            s.watermarks().unwrap(),
            vec![("p".into(), "a".into(), 5u64)]
        );
        assert_eq!(
            s.reap_attestations(900).unwrap(),
            1,
            "departed origin's facts age out"
        );
    }

    fn mw_state_roundtrip(s: &dyn SyncStore) {
        assert!(s.mw_load().unwrap().0.is_empty());
        s.mw_save(
            &[("p".into(), 0.5), ("q".into(), 1.5)],
            1000,
            "1e8 0.2 1000",
        )
        .unwrap();
        let (rows, globals) = s.mw_load().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(globals.as_deref(), Some("1e8 0.2 1000"));
        s.mw_shift_updated(100).unwrap();
        let (rows, _) = s.mw_load().unwrap();
        assert!(rows.iter().all(|(_, _, u)| *u == 900));
        s.mw_prune(&["q".to_string()]).unwrap();
        let (rows, _) = s.mw_load().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "q");
    }
}
