//! The embedded index backend: RocksDB, one column family per logical table.
//!
//! Atomicity comes from one WriteBatch per composite op, taken under STRIPED write locks —
//! readers never take them and see either all of a batch or none of it. Every composite op
//! needs read-modify-write over exactly one key (an origin's clock and journal, a fact's
//! identity, a watermark), and those are disjoint, so the lock is per key-space stripe rather
//! than store-wide; multi-key ops take their stripes in a global order, which is what makes
//! them deadlock-free. (It WAS store-wide, justified by retention stamps needing a consistent
//! read of "who else holds this hash" — removing the reaper removed that requirement, and with
//! it the only reason to serialize unrelated writers.)
//!
//! The exception is the BULK ops — snapshot applies and origin retirement — which commit in
//! BATCH_OPS-bounded chunks so their memory is O(chunk) on any table size; per-hash effects
//! are independent across chunks, and each op's clock (where it has one) moves only in the
//! final batch, so interruption means clean re-application, never divergence.
//!
//! Durability: only SELF-origin applies (and the meta writes that name the self generation)
//! are fsynced — a seq a peer has observed must never be reissued with different events, and
//! only the origin can reissue. Everything else commits asynchronously with the WAL enabled:
//! `manual_wal_flush` stays OFF (load-bearing!), so every batch reaches the kernel page cache
//! at write() time — a narshare crash within one boot loses nothing, and a host crash rolls
//! replicas back to an ordered prefix they can only have FORGOTTEN (single writer: another
//! origin's content at a (gen, seq) is immutable mesh-wide), which the next pull re-learns.
//! Maintenance writes (compaction, watermarks, MW state) ride along: losing them only
//! retains extra history or re-learns state, never diverges.
//!
//! Layout versioning is wipe-and-resync like every narshare cache: a `layout` marker mismatch
//! destroys the database and lets the mesh snapshot us back up.

use super::{
    attestation_hash, hash_part_of, leaf_of, merge_into, path_key_of, Clock, HoldOp, SyncStore,
};
use crate::index::proto;
use anyhow::{bail, Context, Result};
use prost::Message as _;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, Direction, IteratorMode, Options,
    ReadOptions, SliceTransform, WriteBatch, WriteOptions, DB,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

/// One scanned row: rocksdb hands back boxed key/value slices.
type Kv = (Box<[u8]>, Box<[u8]>);
/// Streaming-scan visitor: (key, value) → keep going? See each_opt.
type RowVisitor<'a> = dyn FnMut(&[u8], &[u8]) -> Result<bool> + 'a;

const LAYOUT: &str = "narshare-rocks-3";
/// CFs whose keys start with a fixed 32-byte hash — the hot lookup path. They get a prefix
/// extractor, prefix bloom filters (memtable and SST), and a shared block cache: the proxy is
/// consulted for every substitution the machine attempts, so both hits (common: the mesh holds
/// most of what cache.nixos.org served everyone) and misses (fresh nixpkgs bumps) must resolve
/// in memory, not per-seek SST index reads. `att` is NOT among them: it is keyed by
/// attestation hash, and the substituter reaches it through `att_path` (see CFS).
const HASH_PREFIX_CFS: &[&str] = &["att_path", "att_nar", "holdby"];
/// Shared block cache for the hot CFs. 64 MiB comfortably holds the working set of a
/// mesh-wide fact table (~500k rows) plus holder edges.
const BLOCK_CACHE_BYTES: usize = 64 << 20;
/// Flush threshold for the bulk maintenance batches (snapshot applies, origin retirement). One giant WriteBatch over a peer's whole possession set was a ~600 MiB spike
/// at production scale; per-hash effects are independent, so bounded batches change only how
/// much of the pass a reader can observe mid-way — a crash before the final clock write leaves
/// the clock unmoved and the operation re-applies wholesale.
const BATCH_OPS: usize = 32_768;
/// `att` is keyed by ATTESTATION HASH (16 bytes) ‖ hash_part ‖ nar_hash, so key order is
/// Merkle order: a reconciliation leaf is a contiguous range, repair is a range scan, and a
/// full dump is the same scan over the whole range. The two secondary indexes map the
/// lookup identities onto it — and because they hold 16-byte values instead of ~800-byte
/// attestation bodies, the substituter's working set is the INDEX, which stays cache-resident
/// long after the fact table stops fitting (measured: a miss costs 1.2 µs against the index
/// vs 828 µs against the table).
const CFS: &[&str] = &[
    "meta", "clocks", "journal", "hold", "holdby", "att", "att_path", "att_nar", "wm", "mw",
];
/// A 256-ary Merkle tree of FIXED depth two over the attestation hashes: 256 coarse buckets,
/// each with 256 leaves (65536 in all). Depth is a protocol constant, never adaptive — both
/// ends must address the same leaves, so changing it is a flag day (cheap: the index is
/// disposable). At 320k facts a leaf holds ~5 attestations (~4 KiB), at 3M ~50 (~45 KiB), so
/// one differing leaf is always a small range scan.
const MERKLE_FANOUT: usize = 256;

/// The Merkle aggregates, grown LAZILY: a coarse bucket with no attestations under it is a
/// stub, not 4 KiB of zeros. An absent subtree and an all-zero one are the same value — XOR
/// over nothing IS zero — so sparsity costs the protocol nothing and an empty index costs
/// ~6 KiB instead of a megabyte.
///
/// Granularity is the 256-leaf block rather than the individual leaf, deliberately. Because
/// attestation hashes are uniform, leaves fill fast: at 320k facts ~99% of leaves are already
/// occupied, so a per-leaf map would store 65k hash-table entries (~3 MiB) to avoid 1 MiB of
/// array — worse at the scale that matters, better only below a few thousand facts. Block
/// granularity is strictly better than the flat array everywhere and much better when small.
///
/// The root and the coarse level are maintained INCREMENTALLY. They were recomputed per call
/// before, which cost 78 µs and 43 µs on every sync response — while holding this lock, which
/// widened the window a reader could block in. Now both are O(1) to read and one extra XOR to
/// update.
struct Aggregates {
    /// 256 coarse blocks of 256 leaves; None = nothing under it.
    blocks: Vec<Option<Box<[[u8; 16]; MERKLE_FANOUT]>>>,
    coarse: Vec<[u8; 16]>,
    root: [u8; 16],
}

impl Aggregates {
    fn new() -> Self {
        Self {
            blocks: (0..MERKLE_FANOUT).map(|_| None).collect(),
            coarse: vec![[0u8; 16]; MERKLE_FANOUT],
            root: [0u8; 16],
        }
    }

    /// Fold one attestation hash in or out — XOR is its own inverse, so both are this.
    fn xor(&mut self, h: &[u8; 16]) {
        let leaf = leaf_of(h) as usize;
        let (block, slot) = (leaf >> 8, leaf & 0xff);
        let cells = self.blocks[block]
            .get_or_insert_with(|| Box::new([[0u8; 16]; MERKLE_FANOUT]));
        xor_into(&mut cells[slot], h);
        xor_into(&mut self.coarse[block], h);
        xor_into(&mut self.root, h);
    }

    /// One coarse block's 256 leaves; an unmaterialized block reads as all-empty.
    fn leaves(&self, block: usize) -> Vec<[u8; 16]> {
        match &self.blocks[block] {
            Some(cells) => cells.to_vec(),
            None => vec![[0u8; 16]; MERKLE_FANOUT],
        }
    }
}

/// Write-lock stripes. Every composite op needs read-modify-write atomicity over ONE key —
/// an origin's clock and journal, a fact's (hash_part, nar_hash), a (peer, origin) watermark —
/// and those are disjoint, so one lock per key-space stripe is the right granularity.
///
/// This used to be a single store-wide mutex, and that was justified: retention stamps had to
/// decide "did the LAST holder just leave?", which needs a consistent read across every
/// origin's holdings. Removing the reaper removed that requirement — no write path reads
/// cross-key state any more — leaving the global lock as pure over-serialization, which
/// showed up as concurrent peers' merges queueing behind each other.
const LOCK_STRIPES: usize = 64;

fn stripe_of(key: &[u8]) -> usize {
    let h = blake3::hash(key);
    let b = h.as_bytes();
    (u16::from_le_bytes([b[0], b[1]]) as usize) % LOCK_STRIPES
}

pub struct RocksStore {
    db: DB,
    /// Derived state, rebuilt at open from `att_path` (16-byte values = the hashes, so the
    /// rebuild reads the INDEX, not the ~800-byte bodies). Being derived, it cannot drift
    /// across a crash.
    agg: Mutex<Aggregates>,
    /// Per-stripe write locks (see LOCK_STRIPES); reads never take them.
    stripes: Vec<Mutex<()>>,
    /// The shared block cache, kept for resizing under memory pressure (mem.rs). `Cache` is a
    /// handle onto one refcounted rocksdb object, so this clone IS the cache the CFs use.
    cache: Cache,
}

fn okey(origin: &str) -> Result<Vec<u8>> {
    if origin.len() > 255 || origin.is_empty() {
        bail!("origin name length out of range: {origin:?}");
    }
    let mut k = Vec::with_capacity(1 + origin.len());
    k.push(origin.len() as u8);
    k.extend_from_slice(origin.as_bytes());
    Ok(k)
}

fn jkey(origin: &str, seq: u64) -> Result<Vec<u8>> {
    let mut k = okey(origin)?;
    k.extend_from_slice(&seq.to_be_bytes());
    Ok(k)
}

fn clock_bytes(c: Clock) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[..8].copy_from_slice(&c.generation.to_be_bytes());
    b[8..16].copy_from_slice(&c.seq.to_be_bytes());
    b[16..].copy_from_slice(&c.tail_seq.to_be_bytes());
    b
}

fn clock_from(b: &[u8]) -> Result<Clock> {
    if b.len() != 24 {
        bail!("corrupt clock row ({} bytes)", b.len());
    }
    let u = |r: &[u8]| u64::from_be_bytes(<[u8; 8]>::try_from(r).unwrap());
    Ok(Clock {
        generation: u(&b[..8]),
        seq: u(&b[8..16]),
        tail_seq: u(&b[16..24]),
    })
}

/// Attestation row value: the encoded Attestation, nothing else.
fn att_value(att: &proto::Attestation) -> Vec<u8> {
    att.encode_to_vec()
}

fn att_decode(v: &[u8]) -> Result<proto::Attestation> {
    proto::Attestation::decode(v).context("corrupt attestation body")
}

/// The `att` key: attestation hash first, so storage order IS Merkle order.
fn att_key(att_hash: &[u8; 16], path_key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(80);
    k.extend_from_slice(att_hash);
    k.extend_from_slice(path_key);
    k
}

/// The `att_nar` key: (nar_hash, hash_part) — the NAR-hash lookup identity.
fn nar_key(att: &proto::Attestation) -> Vec<u8> {
    let mut k = Vec::with_capacity(64);
    k.extend_from_slice(&att.nar_hash);
    k.extend_from_slice(hash_part_of(&att.store_path).as_bytes());
    k
}

fn xor_into(dst: &mut [u8; 16], src: &[u8; 16]) {
    for (a, b) in dst.iter_mut().zip(src.iter()) {
        *a ^= *b;
    }
}

impl RocksStore {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating index dir {}", dir.display()))?;
        for attempt in 0..2 {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            opts.set_max_open_files(256);
            // Bound WAL accumulation from rarely-flushed CFs.
            opts.set_max_total_wal_size(64 << 20);
            let cache = Cache::new_lru_cache(BLOCK_CACHE_BYTES);
            let cfds: Vec<ColumnFamilyDescriptor> = CFS
                .iter()
                .map(|n| {
                    let mut o = Options::default();
                    // Rows here are tiny; the rocksdb default of 64 MiB memtables PER CF
                    // (x9 CFs) is what made an idle daemon hold ~200 MB. Small buffers cost
                    // slightly more flushes during a resync storm and nothing at idle.
                    o.set_write_buffer_size(16 << 20);
                    o.set_max_write_buffer_number(2);
                    // EVERY CF shares the one block cache: a table factory with no cache set
                    // silently creates its own private default LRU (32 MiB apiece in current
                    // rocksdb), so the six "cold" CFs — journal and hold among them, both
                    // scanned routinely — were quietly entitled to ~200 MiB nobody budgeted.
                    let mut bb = BlockBasedOptions::default();
                    bb.set_block_cache(&cache);
                    // Index/filter blocks count against the shared cache instead of
                    // accumulating unbounded in the heap.
                    bb.set_cache_index_and_filter_blocks(true);
                    bb.set_pin_l0_filter_and_index_blocks_in_cache(true);
                    // PARTITIONED, and with the top level pinned. Without this, a filter is
                    // one monolithic block per SST — ~400 KB once a CF holds a few hundred
                    // thousand rows — so as soon as the CF outgrows the shared cache, EVERY
                    // lookup re-reads and decompresses the whole thing. Measured at 320k
                    // facts with uniformly distributed hash parts: ~830 µs per narinfo
                    // lookup, hit or miss. Partitioning loads only the relevant few KB.
                    bb.set_index_type(rocksdb::BlockBasedIndexType::TwoLevelIndexSearch);
                    bb.set_partition_filters(true);
                    bb.set_pin_top_level_index_and_filter(true);
                    if HASH_PREFIX_CFS.contains(n) {
                        o.set_prefix_extractor(SliceTransform::create_fixed_prefix(32));
                        o.set_memtable_prefix_bloom_ratio(0.2);
                        bb.set_bloom_filter(10.0, false);
                    } else {
                        o.set_write_buffer_size(4 << 20);
                    }
                    o.set_block_based_table_factory(&bb);
                    ColumnFamilyDescriptor::new(*n, o)
                })
                .collect();
            let db = DB::open_cf_descriptors(&opts, dir, cfds)
                .with_context(|| format!("opening rocksdb index at {}", dir.display()))?;
            let store = Self {
                db,
                stripes: (0..LOCK_STRIPES).map(|_| Mutex::new(())).collect(),
                cache,
                agg: Mutex::new(Aggregates::new()),
            };
            match store.meta_get("layout")? {
                Some(l) if l == LAYOUT => {
                    store.rebuild_aggregates()?;
                    return Ok(store);
                }
                None => {
                    store.meta_put("layout", LAYOUT)?;
                    return Ok(store);
                }
                Some(_) if attempt == 0 => {
                    tracing::info!(
                        "mesh index layout changed: wiping the (disposable) cache for resync"
                    );
                    drop(store);
                    DB::destroy(&Options::default(), dir)
                        .with_context(|| format!("destroying old index at {}", dir.display()))?;
                }
                Some(l) => bail!("index layout still {l:?} after a wipe"),
            }
        }
        unreachable!("two attempts always return or bail");
    }

    /// Lock the stripes covering `keys`, in a global order so two ops that need overlapping
    /// sets can never deadlock. Returning the guards keeps them held for the caller's scope.
    fn lock_keys<'a>(
        &'a self,
        keys: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<std::sync::MutexGuard<'a, ()>> {
        let mut idx: Vec<usize> = keys.into_iter().map(stripe_of).collect();
        idx.sort_unstable();
        idx.dedup();
        idx.into_iter()
            .map(|i| self.stripes[i].lock().unwrap())
            .collect()
    }

    /// Lock one key's stripe.
    fn lock_key(&self, key: &[u8]) -> std::sync::MutexGuard<'_, ()> {
        self.stripes[stripe_of(key)].lock().unwrap()
    }

    /// Lock EVERY stripe — for the rare ops whose key set is the whole store.
    fn lock_all(&self) -> Vec<std::sync::MutexGuard<'_, ()>> {
        self.stripes.iter().map(|m| m.lock().unwrap()).collect()
    }

    fn cf(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(name)
            .expect("column families are created at open")
    }

    fn sync_wo() -> WriteOptions {
        let mut wo = WriteOptions::default();
        wo.set_sync(true);
        wo
    }

    /// All (key, value) pairs whose key starts with `prefix`, in key order. Total-order seek:
    /// correct on every CF, including full iterations over the prefix-extractor CFs (where the
    /// default iterator mode would not guarantee cross-prefix order).
    fn scan(&self, cf: &str, prefix: &[u8]) -> Vec<Kv> {
        let mut ro = ReadOptions::default();
        ro.set_total_order_seek(true);
        self.scan_opt(cf, prefix, ro)
    }

    /// The hot-path variant for the HASH_PREFIX_CFS: a full 32-byte prefix seek that the
    /// memtable and SST prefix blooms can answer — a miss costs a couple of in-memory filter
    /// probes instead of index-block reads.
    fn scan_prefix32(&self, cf: &str, prefix: &[u8]) -> Vec<Kv> {
        debug_assert_eq!(prefix.len(), 32);
        let mut ro = ReadOptions::default();
        ro.set_prefix_same_as_start(true);
        self.scan_opt(cf, prefix, ro)
    }

    fn scan_opt(&self, cf: &str, prefix: &[u8], ro: ReadOptions) -> Vec<Kv> {
        let mut out = Vec::new();
        // Iterator errors end the scan early, as they always have here.
        let _ = self.each_opt(cf, prefix, prefix, ro, &mut |k, v| {
            out.push((Box::from(k), Box::from(v)));
            Ok(true)
        });
        out
    }

    /// The streaming core every scan is built on: seek to `from`, then visit rows while their
    /// keys still start with `prefix`, one at a time, WITHOUT materializing the range.
    /// Full-table walks (claims, dump pages) must use this — collecting the att
    /// table was measured at ~400 MiB of transient heap at production scale. The visitor
    /// returns false to stop early.
    fn each_opt(
        &self,
        cf: &str,
        from: &[u8],
        prefix: &[u8],
        ro: ReadOptions,
        f: &mut RowVisitor,
    ) -> Result<()> {
        let it = self.db.iterator_cf_opt(
            self.cf(cf),
            ro,
            IteratorMode::From(from, Direction::Forward),
        );
        for kv in it {
            let (k, v) = kv?;
            if !k.starts_with(prefix) || !f(&k, &v)? {
                break;
            }
        }
        Ok(())
    }

    /// Total-order streaming walk (see `scan` for why total-order matters on prefix CFs).
    fn each(
        &self,
        cf: &str,
        from: &[u8],
        prefix: &[u8],
        f: &mut RowVisitor,
    ) -> Result<()> {
        let mut ro = ReadOptions::default();
        ro.set_total_order_seek(true);
        self.each_opt(cf, from, prefix, ro, f)
    }

    /// Origins currently holding `hash`, minus `exclude`.
    fn holders_of(&self, hash: &[u8; 32], exclude: Option<&str>) -> Vec<String> {
        self.scan_prefix32("holdby", hash)
            .into_iter()
            .filter_map(|(k, _)| String::from_utf8(k[32..].to_vec()).ok())
            .filter(|o| Some(o.as_str()) != exclude)
            .collect()
    }

    /// Fold possession ops into `batch` with their retention side effects. Ops are deduped to
    /// the last op per hash; `origin`'s own row changes are reflected in the holder checks.
    fn apply_holds(&self, batch: &mut WriteBatch, origin: &str, holds: &[HoldOp]) -> Result<()> {
        let mut fin: HashMap<[u8; 32], bool> = HashMap::new(); // true = held after the batch
        for op in holds {
            match op {
                HoldOp::Add(h) => fin.insert(*h, true),
                HoldOp::Drop(h) => fin.insert(*h, false),
            };
        }
        for (h, held) in fin {
            let mut hold_key = okey(origin)?;
            hold_key.extend_from_slice(&h);
            let mut holdby_key = h.to_vec();
            holdby_key.extend_from_slice(origin.as_bytes());
            if held {
                batch.put_cf(self.cf("hold"), hold_key, b"");
                batch.put_cf(self.cf("holdby"), holdby_key, b"");
            } else {
                batch.delete_cf(self.cf("hold"), hold_key);
                batch.delete_cf(self.cf("holdby"), holdby_key);
            }
        }
        Ok(())
    }

    /// Fold attestation merges into `batch`, collecting the attestation hashes that leave
    /// and enter the tree. Facts are grow-only: signatures union, bodies choose their
    /// deterministic maximum, nothing is deleted — but a CHANGED fact moves, because its key
    /// is its hash.
    fn merge_atts(
        &self,
        batch: &mut WriteBatch,
        attests: &[proto::Attestation],
        delta: &mut Vec<[u8; 16]>,
    ) -> Result<usize> {
        // A RocksDB WriteBatch is not visible to `db.get_cf`. Coalesce repeated identities
        // first, so every database row is read and moved exactly once. Without this overlay,
        // two attestations for one new identity both observed "absent": exact duplicates
        // XOR-ed the new hash into the aggregate twice (cancelling it), while differing rows
        // also left an orphaned `att` key behind the final `att_path` entry.
        let mut positions: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut coalesced: Vec<(Vec<u8>, proto::Attestation)> = Vec::new();
        for incoming in attests {
            if <[u8; 32]>::try_from(incoming.nar_hash.as_slice()).is_err() {
                continue; // malformed; the index validates, this is a backstop
            }
            let pk = path_key_of(incoming);
            if let Some(&i) = positions.get(&pk) {
                if let Some(merged) = merge_into(Some(coalesced[i].1.clone()), incoming) {
                    coalesced[i].1 = merged;
                }
            } else if let Some(fresh) = merge_into(None, incoming) {
                positions.insert(pk.clone(), coalesced.len());
                coalesced.push((pk, fresh));
            }
        }

        let mut changed = 0usize;
        for (pk, incoming) in coalesced {
            let old = match self.db.get_cf(self.cf("att_path"), &pk)? {
                Some(raw) => {
                    let oh: [u8; 16] = raw[..].try_into().context("corrupt att_path row")?;
                    Some((oh, self.att_at(&raw, &pk)?))
                }
                None => None,
            };
            let existing = old.as_ref().and_then(|(_, a)| a.clone());
            let Some(merged) = merge_into(existing, &incoming) else {
                continue; // exact duplicate: no row change, no tree movement
            };
            let nh = attestation_hash(&merged);
            if old.as_ref().map(|(oh, _)| *oh) == Some(nh) {
                continue;
            }
            if let Some((oh, _)) = old {
                // The key IS the hash, so a changed fact MOVES.
                batch.delete_cf(self.cf("att"), att_key(&oh, &pk));
                delta.push(oh);
            }
            batch.put_cf(self.cf("att"), att_key(&nh, &pk), att_value(&merged));
            batch.put_cf(self.cf("att_path"), &pk, nh);
            batch.put_cf(self.cf("att_nar"), nar_key(&merged), nh);
            delta.push(nh);
            changed += 1;
        }
        Ok(changed)
    }

    /// Commit a batch, then fold its attestation-hash changes into the aggregates.
    ///
    /// ORDER IS LOAD-BEARING, in one direction only. XOR-ing before the commit would, on a
    /// failed write, leave the tree permanently claiming a fact that does not exist — a
    /// durable lie, until the next restart rebuilds. XOR-ing after can only leave rows
    /// momentarily ahead of the tree, which makes us UNDER-advertise: a peer concludes we are
    /// missing something, sends facts we already have, and the merge is a no-op. A wasted
    /// round trip, self-correcting, and microseconds wide.
    ///
    /// The aggregate lock is deliberately NOT held across the write. It was, which made the
    /// pair atomic to readers — but with striped write locks that single mutex would
    /// re-serialize every concurrent writer and give back exactly what striping buys. It also
    /// cost readers a measured 2.45 ms tail, since a root request could land behind a commit.
    /// Now the critical section is a few XORs.
    ///
    /// Nothing durable can half-complete either way: the rocksdb batch is atomic, and the
    /// aggregates are DERIVED state that a crash discards wholesale (rebuild_aggregates at
    /// open recomputes them from the committed rows).
    fn commit_with_delta(
        &self,
        batch: WriteBatch,
        delta: &[[u8; 16]],
        durable: bool,
    ) -> Result<()> {
        if durable {
            self.db.write_opt(batch, &Self::sync_wo())?;
        } else {
            self.db.write(batch)?;
        }
        if !delta.is_empty() {
            let mut agg = self.agg.lock().unwrap();
            for h in delta {
                agg.xor(h);
            }
        }
        Ok(())
    }

    /// Recompute every leaf aggregate from `att_path` (16-byte values = the hashes).
    fn rebuild_aggregates(&self) -> Result<()> {
        let mut fresh = Aggregates::new();
        self.each("att_path", b"", b"", &mut |_, v| {
            let h: [u8; 16] = v.try_into().context("corrupt att_path row")?;
            fresh.xor(&h);
            Ok(true)
        })?;
        *self.agg.lock().unwrap() = fresh;
        Ok(())
    }

    /// Attach current holders, dropping rows nobody can serve.
    fn lookup_atts(
        &self,
        rows: Vec<proto::Attestation>,
    ) -> Result<Vec<(proto::Attestation, Vec<String>)>> {
        let mut out = Vec::new();
        for att in rows {
            let Ok(hash) = <[u8; 32]>::try_from(att.nar_hash.as_slice()) else {
                continue;
            };
            let holders = self.holders_of(&hash, None);
            if !holders.is_empty() {
                out.push((att, holders));
            }
        }
        Ok(out)
    }

    /// Fetch one attestation by index entry: the index holds its hash, which with the path
    /// key IS its `att` key.
    fn att_at(&self, attestation_hash: &[u8], path_key: &[u8]) -> Result<Option<proto::Attestation>> {
        let h: [u8; 16] = attestation_hash
            .try_into()
            .context("corrupt attestation-hash index entry")?;
        match self.db.get_cf(self.cf("att"), att_key(&h, path_key))? {
            Some(v) => Ok(Some(att_decode(&v)?)),
            None => Ok(None),
        }
    }
}

impl Drop for RocksStore {
    fn drop(&mut self) {
        // One fsync on graceful shutdown: the buffered async tail (peer replicas, facts)
        // survives a later host crash, at zero runtime cost.
        let _ = self.db.flush_wal(true);
    }
}

impl SyncStore for RocksStore {
    fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .db
            .get_cf(self.cf("meta"), key.as_bytes())?
            .map(|v| String::from_utf8_lossy(&v).into_owned()))
    }

    fn meta_put(&self, key: &str, value: &str) -> Result<()> {
        let _g = self.lock_key(key.as_bytes());
        self.db.put_cf_opt(
            self.cf("meta"),
            key.as_bytes(),
            value.as_bytes(),
            &Self::sync_wo(),
        )?;
        Ok(())
    }

    fn clock(&self, origin: &str) -> Result<Clock> {
        match self.db.get_cf(self.cf("clocks"), okey(origin)?)? {
            Some(v) => clock_from(&v),
            None => Ok(Clock::default()),
        }
    }

    fn set_generation(&self, origin: &str, generation: u64) -> Result<()> {
        let _g = self.lock_key(origin.as_bytes());
        let mut c = self.clock(origin)?;
        c.generation = generation;
        self.db.put_cf_opt(
            self.cf("clocks"),
            okey(origin)?,
            clock_bytes(c),
            &Self::sync_wo(),
        )?;
        Ok(())
    }

    fn apply_events(
        &self,
        origin: &str,
        expect: (u64, u64),
        set: (u64, u64),
        journal: &[(u64, Vec<u8>)],
        holds: &[HoldOp],
        attests: &[proto::Attestation],
        durable: bool,
    ) -> Result<bool> {
        // This origin's clock, and every fact this batch merges: disjoint from any other
        // origin's apply, and from merges of other facts.
        let mut keys: Vec<Vec<u8>> = vec![origin.as_bytes().to_vec()];
        keys.extend(attests.iter().map(path_key_of));
        let _g = self.lock_keys(keys.iter().map(|k| k.as_slice()));
        let cur = self.clock(origin)?;
        if (cur.generation, cur.seq) != expect {
            return Ok(false);
        }
        let mut batch = WriteBatch::default();
        for (seq, bytes) in journal {
            batch.put_cf(self.cf("journal"), jkey(origin, *seq)?, bytes);
        }
        self.apply_holds(&mut batch, origin, holds)?;
        let mut delta = Vec::new();
        self.merge_atts(&mut batch, attests, &mut delta)?;
        let c = Clock {
            generation: set.0,
            seq: set.1,
            tail_seq: cur.tail_seq,
        };
        batch.put_cf(self.cf("clocks"), okey(origin)?, clock_bytes(c));
        self.commit_with_delta(batch, &delta, durable)?;
        Ok(true)
    }

    fn replace_holdings(
        &self,
        origin: &str,
        generation: u64,
        seq: u64,
        held: &[[u8; 32]],
    ) -> Result<bool> {
        let _g = self.lock_key(origin.as_bytes());
        let cur = self.clock(origin)?;
        if generation < cur.generation || (generation == cur.generation && seq < cur.seq) {
            return Ok(false);
        }
        let prefix = okey(origin)?;
        let mut old: HashSet<[u8; 32]> = HashSet::new();
        self.each("hold", &prefix, &prefix, &mut |k, _| {
            if let Ok(h) = <[u8; 32]>::try_from(&k[k.len() - 32..]) {
                old.insert(h);
            }
            Ok(true)
        })?;
        let new: HashSet<[u8; 32]> = held.iter().copied().collect();
        let mut ops: Vec<HoldOp> = Vec::new();
        ops.extend(old.difference(&new).map(|h| HoldOp::Drop(*h)));
        ops.extend(new.difference(&old).map(|h| HoldOp::Add(*h)));
        // Bounded batches (see BATCH_OPS): each hash appears in exactly one chunk, so the
        // per-hash retention arithmetic is chunk-independent; the writer lock spans the whole
        // replace, and the clock advances only at the very end, after every chunk landed —
        // an interrupted apply is simply re-offered by the next pull.
        for chunk in ops.chunks(BATCH_OPS) {
            let mut batch = WriteBatch::default();
            self.apply_holds(&mut batch, origin, chunk)?;
            // Snapshot applies are always replicas of OTHER origins: async (see module docs).
            self.db.write(batch)?;
        }
        let mut batch = WriteBatch::default();
        self.each("journal", &prefix, &prefix, &mut |k, _| {
            batch.delete_cf(self.cf("journal"), k);
            if batch.len() >= BATCH_OPS {
                self.db.write(std::mem::take(&mut batch))?;
            }
            Ok(true)
        })?;
        let c = Clock {
            generation,
            seq,
            tail_seq: seq,
        };
        batch.put_cf(self.cf("clocks"), &prefix, clock_bytes(c));
        self.db.write(batch)?;
        Ok(true)
    }

    fn merge_attestations(&self, attests: &[proto::Attestation]) -> Result<usize> {
        let keys: Vec<Vec<u8>> = attests.iter().map(path_key_of).collect();
        let _g = self.lock_keys(keys.iter().map(|k| k.as_slice()));
        let mut batch = WriteBatch::default();
        let mut delta = Vec::new();
        let changed = self.merge_atts(&mut batch, attests, &mut delta)?;
        if changed > 0 {
            // Facts are re-learnable from any snapshot-bearing response: async.
            self.commit_with_delta(batch, &delta, false)?;
        }
        Ok(changed)
    }

    fn journal_suffix(
        &self,
        origin: &str,
        after: u64,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool)> {
        let prefix = okey(origin)?;
        let start = jkey(origin, after.saturating_add(1))?;
        let mut events = Vec::new();
        let mut bytes = 0usize;
        let it = self.db.iterator_cf(
            self.cf("journal"),
            IteratorMode::From(&start, Direction::Forward),
        );
        for kv in it {
            let (k, v) = kv?;
            if !k.starts_with(&prefix) {
                break;
            }
            if bytes + v.len() > max_bytes && !events.is_empty() {
                return Ok((events, true));
            }
            bytes += v.len();
            events.push(v.into_vec());
        }
        Ok((events, false))
    }

    fn holdings(&self, origin: &str) -> Result<Vec<[u8; 32]>> {
        Ok(self
            .scan("hold", &okey(origin)?)
            .into_iter()
            .filter_map(|(k, _)| <[u8; 32]>::try_from(&k[k.len() - 32..]).ok())
            .collect())
    }

    fn attestation_page(
        &self,
        prefix: &[u8],
        cursor: &[u8],
        max_bytes: usize,
    ) -> Result<(Vec<proto::Attestation>, Option<Vec<u8>>)> {
        let mut page: Vec<proto::Attestation> = Vec::new();
        let mut used = 0usize;
        let mut last_key: Vec<u8> = Vec::new();
        let mut more = false;
        // Seek to the cursor when resuming, else to the start of the subtree; either way the
        // walk stops at the first key outside `prefix`.
        let from = if cursor.is_empty() { prefix } else { cursor };
        self.each("att", from, prefix, &mut |k, v| {
            if k == cursor {
                return Ok(true); // the seek is inclusive; resume strictly after
            }
            let att = att_decode(v)?;
            let len = att.encoded_len();
            if used + len > max_bytes && !page.is_empty() {
                more = true;
                return Ok(false);
            }
            used += len;
            last_key = k.to_vec();
            page.push(att);
            Ok(true)
        })?;
        Ok((page, more.then_some(last_key)))
    }

    fn compact_journal(&self, origin: &str, floor: u64) -> Result<()> {
        let _g = self.lock_key(origin.as_bytes());
        let mut c = self.clock(origin)?;
        if floor <= c.tail_seq {
            return Ok(());
        }
        let mut batch = WriteBatch::default();
        let prefix = okey(origin)?;
        let start = jkey(origin, c.tail_seq.saturating_add(1))?;
        let it = self.db.iterator_cf(
            self.cf("journal"),
            IteratorMode::From(&start, Direction::Forward),
        );
        for kv in it {
            let (k, _) = kv?;
            if !k.starts_with(&prefix) {
                break;
            }
            let seq = u64::from_be_bytes(<[u8; 8]>::try_from(&k[k.len() - 8..]).unwrap());
            if seq > floor {
                break;
            }
            batch.delete_cf(self.cf("journal"), k);
        }
        c.tail_seq = floor;
        batch.put_cf(self.cf("clocks"), prefix, clock_bytes(c));
        self.db.write(batch)?;
        Ok(())
    }

    fn retain_origins(&self, keep: &[String]) -> Result<()> {
        let _g = self.lock_all();
        let keep: HashSet<&str> = keep.iter().map(String::as_str).collect();
        let departed: Vec<String> = self
            .scan("clocks", b"")
            .into_iter()
            .filter_map(|(k, _)| String::from_utf8(k[1..].to_vec()).ok())
            .filter(|o| !keep.contains(o.as_str()))
            .collect();
        let mut batch = WriteBatch::default();
        for origin in &departed {
            tracing::info!("dropping departed origin {origin:?} from the index");
            let prefix = okey(origin)?;
            self.each("hold", &prefix, &prefix, &mut |k, _| {
                let h = <[u8; 32]>::try_from(&k[k.len() - 32..]).unwrap();
                let mut by = h.to_vec();
                by.extend_from_slice(origin.as_bytes());
                batch.delete_cf(self.cf("hold"), k);
                batch.delete_cf(self.cf("holdby"), by);
                if batch.len() >= BATCH_OPS {
                    self.db.write(std::mem::take(&mut batch))?;
                }
                Ok(true)
            })?;
            self.each("journal", &prefix, &prefix, &mut |k, _| {
                batch.delete_cf(self.cf("journal"), k);
                if batch.len() >= BATCH_OPS {
                    self.db.write(std::mem::take(&mut batch))?;
                }
                Ok(true)
            })?;
            batch.delete_cf(self.cf("clocks"), &prefix);
        }
        for (k, _) in self.scan("wm", b"") {
            let plen = k[0] as usize;
            let peer = std::str::from_utf8(&k[1..1 + plen]).unwrap_or("");
            let origin = std::str::from_utf8(&k[1 + plen..]).unwrap_or("");
            if !keep.contains(peer) || !keep.contains(origin) {
                batch.delete_cf(self.cf("wm"), k);
            }
        }
        self.db.write(batch)?;
        Ok(())
    }

    fn lookup_hash_part(&self, hash_part: &str) -> Result<Vec<(proto::Attestation, Vec<String>)>> {
        // Through att_path: 16-byte values keep this index cache-resident long after the
        // attestation bodies stop fitting, which is what keeps a MISS in the microseconds.
        let hp = hash_part.as_bytes();
        let entries = if hp.len() == 32 {
            self.scan_prefix32("att_path", hp)
        } else {
            self.scan("att_path", hp)
        };
        let mut rows = Vec::new();
        for (pk, h) in entries {
            if let Some(att) = self.att_at(&h, &pk)? {
                rows.push(att);
            }
        }
        self.lookup_atts(rows)
    }

    fn lookup_nar_hash(
        &self,
        nar_hash: &[u8; 32],
    ) -> Result<Vec<(proto::Attestation, Vec<String>)>> {
        let mut rows = Vec::new();
        // att_nar is keyed (nar_hash, hash_part); the path key is the other order.
        for (k, h) in self.scan_prefix32("att_nar", nar_hash) {
            let mut pk = k[32..].to_vec();
            pk.extend_from_slice(nar_hash);
            if let Some(att) = self.att_at(&h, &pk)? {
                rows.push(att);
            }
        }
        self.lookup_atts(rows)
    }

    fn for_each_claim(
        &self,
        f: &mut dyn FnMut(super::ClaimRow) -> Result<()>,
    ) -> Result<()> {
        /// The differ's slim view of a fact: prost skips unlisted fields without allocating,
        /// so this avoids decoding 200k reference lists once per diff cycle.
        #[derive(prost::Message)]
        struct Slim {
            #[prost(string, tag = "1")]
            store_path: String,
            #[prost(bytes = "vec", tag = "2")]
            nar_hash: Vec<u8>,
            #[prost(string, repeated, tag = "6")]
            sigs: Vec<String>,
        }
        self.each("att", b"", b"", &mut |_, v| {
            let s = Slim::decode(v).context("corrupt attestation body")?;
            f((s.store_path, s.nar_hash, s.sigs))?;
            Ok(true)
        })
    }

    fn attestation_sigs(&self, hash_part: &str, nar_hash: &[u8]) -> Result<Option<Vec<String>>> {
        // The path key addresses att_path, which holds the attestation hash that (with the
        // path key) addresses the fact itself.
        let mut pk = Vec::with_capacity(64);
        pk.extend_from_slice(hash_part.as_bytes());
        pk.extend_from_slice(nar_hash);
        match self.db.get_cf(self.cf("att_path"), &pk)? {
            Some(h) => Ok(self.att_at(&h, &pk)?.map(|a| a.sigs)),
            None => Ok(None),
        }
    }

    fn is_held(&self, origin: &str, nar_hash: &[u8; 32]) -> Result<bool> {
        let mut key = okey(origin)?;
        key.extend_from_slice(nar_hash);
        Ok(self.db.get_cf(self.cf("hold"), &key)?.is_some())
    }

    fn advance_watermark(&self, peer: &str, origin: &str, seq: u64) -> Result<()> {
        let key = format!("{peer}\u{0}{origin}");
        let _g = self.lock_key(key.as_bytes());
        let mut key = okey(peer)?;
        key.extend_from_slice(origin.as_bytes());
        let cur = self
            .db
            .get_cf(self.cf("wm"), &key)?
            .map(|v| u64::from_be_bytes(<[u8; 8]>::try_from(&v[..8]).unwrap()))
            .unwrap_or(0);
        if seq > cur {
            self.db.put_cf(self.cf("wm"), key, seq.to_be_bytes())?;
        }
        Ok(())
    }

    fn watermarks(&self) -> Result<Vec<(String, String, u64)>> {
        Ok(self
            .scan("wm", b"")
            .into_iter()
            .filter_map(|(k, v)| {
                let plen = k[0] as usize;
                let peer = std::str::from_utf8(&k[1..1 + plen]).ok()?.to_owned();
                let origin = std::str::from_utf8(&k[1 + plen..]).ok()?.to_owned();
                let seq = u64::from_be_bytes(<[u8; 8]>::try_from(&v[..8]).ok()?);
                Some((peer, origin, seq))
            })
            .collect())
    }

    fn mw_save(&self, rows: &[(String, f64)], updated: u64, globals: &str) -> Result<()> {
        let _g = self.lock_all();
        let mut batch = WriteBatch::default();
        for (peer, w) in rows {
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&w.to_bits().to_be_bytes());
            v.extend_from_slice(&updated.to_be_bytes());
            batch.put_cf(self.cf("mw"), peer.as_bytes(), v);
        }
        batch.put_cf(self.cf("meta"), b"mw_globals", globals.as_bytes());
        self.db.write(batch)?;
        Ok(())
    }

    fn mw_load(&self) -> Result<(Vec<(String, f64, u64)>, Option<String>)> {
        let rows = self
            .scan("mw", b"")
            .into_iter()
            .filter_map(|(k, v)| {
                let peer = String::from_utf8(k.to_vec()).ok()?;
                let w = f64::from_bits(u64::from_be_bytes(<[u8; 8]>::try_from(&v[..8]).ok()?));
                let u = u64::from_be_bytes(<[u8; 8]>::try_from(&v[8..16]).ok()?);
                Some((peer, w, u))
            })
            .collect();
        Ok((rows, self.meta_get("mw_globals")?))
    }

    fn mw_prune(&self, keep: &[String]) -> Result<()> {
        let _g = self.lock_all();
        let keep: HashSet<&str> = keep.iter().map(String::as_str).collect();
        let mut batch = WriteBatch::default();
        for (k, _) in self.scan("mw", b"") {
            if std::str::from_utf8(&k)
                .map(|p| !keep.contains(p))
                .unwrap_or(true)
            {
                batch.delete_cf(self.cf("mw"), k);
            }
        }
        self.db.write(batch)?;
        Ok(())
    }

    fn mw_shift_updated(&self, secs: i64) -> Result<()> {
        let _g = self.lock_all();
        let mut batch = WriteBatch::default();
        for (k, v) in self.scan("mw", b"") {
            let w = &v[..8];
            let u = u64::from_be_bytes(<[u8; 8]>::try_from(&v[8..16]).unwrap());
            let shifted = (u as i64 - secs).max(0) as u64;
            let mut nv = w.to_vec();
            nv.extend_from_slice(&shifted.to_be_bytes());
            batch.put_cf(self.cf("mw"), k, nv);
        }
        if let Some(g) = self.meta_get("mw_globals")? {
            let mut it = g.split_whitespace();
            if let (Some(br), Some(al), Some(up)) = (it.next(), it.next(), it.next()) {
                if let Ok(up) = up.parse::<i64>() {
                    batch.put_cf(
                        self.cf("meta"),
                        b"mw_globals",
                        format!("{br} {al} {}", up - secs).as_bytes(),
                    );
                }
            }
        }
        self.db.write(batch)?;
        Ok(())
    }

    fn origin_stats(&self, origin: &str) -> Result<(u64, u64)> {
        let journal = self.scan("journal", &okey(origin)?).len() as u64;
        let holdings = self.scan("hold", &okey(origin)?).len() as u64;
        Ok((journal, holdings))
    }

    fn count_attestations(&self) -> Result<u64> {
        let mut n = 0u64;
        // att_path, not att: one 16-byte row per fact instead of an ~800-byte body.
        self.each("att_path", b"", b"", &mut |_, _| {
            n += 1;
            Ok(true)
        })?;
        Ok(n)
    }

    fn merkle_root(&self) -> Result<[u8; 16]> {
        Ok(self.agg.lock().unwrap().root)
    }

    fn merkle_children(&self, prefix: &[u8]) -> Result<Vec<[u8; 16]>> {
        let agg = self.agg.lock().unwrap();
        match prefix.len() {
            0 => Ok(agg.coarse.clone()),
            1 => Ok(agg.leaves(prefix[0] as usize)),
            n => bail!("merkle tree is depth two; cannot expand a {n}-byte prefix"),
        }
    }

    #[cfg(test)]
    fn compact_for_bench(&self) {
        for name in CFS {
            self.db
                .compact_range_cf(self.cf(name), None::<&[u8]>, None::<&[u8]>);
        }
    }

    fn cache_ceiling(&self) -> u64 {
        BLOCK_CACHE_BYTES as u64
    }

    fn set_cache_capacity(&self, bytes: u64) {
        // set_capacity takes &mut, but a Cache is a handle onto one refcounted rocksdb object:
        // the clone resizes the very cache every CF was opened against. Shrinking evicts
        // inside rocksdb immediately.
        self.cache.clone().set_capacity(bytes as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        crate::store::conformance::run_all(&move |name: &str| {
            Box::new(RocksStore::open(&root.join(name)).unwrap()) as Box<dyn SyncStore>
        });
    }

    #[test]
    #[ignore] // measurement bench: cargo test --release -- --ignored --nocapture bench_control
    fn bench_control_plane() {
        let dir = tempfile::tempdir().unwrap();
        let s = RocksStore::open(dir.path()).unwrap();
        crate::store::bench::run("rocksdb", &s);
    }

    #[test]
    #[ignore] // measurement bench: cargo test --release -- --ignored --nocapture bench_merkle
    fn bench_merkle() {
        let dir = tempfile::tempdir().unwrap();
        let s = RocksStore::open(dir.path()).unwrap();
        crate::store::bench::run_merkle("rocksdb", &s);
    }

    #[test]
    fn layout_mismatch_wipes() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = RocksStore::open(dir.path()).unwrap();
            s.meta_put("layout", "something-old").unwrap();
            s.meta_put("self_generation", "42").unwrap();
        }
        let s = RocksStore::open(dir.path()).unwrap();
        assert_eq!(
            s.meta_get("self_generation").unwrap(),
            None,
            "old state wiped"
        );
        assert_eq!(s.meta_get("layout").unwrap(), Some(LAYOUT.into()));
    }
}
