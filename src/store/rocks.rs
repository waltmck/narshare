//! The embedded index backend: RocksDB, one column family per logical table.
//!
//! Atomicity comes from a store-wide writer lock around read-modify-write sections plus a
//! single WriteBatch per composite op — readers never take the lock and see either all of a
//! batch or none of it. That serializes writers, which is exactly the trade accepted when the
//! shared-table layout was chosen: applies are rare and group-committed, and correctness of
//! the holder-count/stamp maintenance requires a consistent read of "who else holds this hash"
//! anyway.
//!
//! Durability: only SELF-origin applies (and the meta writes that name the self generation)
//! are fsynced — a seq a peer has observed must never be reissued with different events, and
//! only the origin can reissue. Everything else commits asynchronously with the WAL enabled:
//! `manual_wal_flush` stays OFF (load-bearing!), so every batch reaches the kernel page cache
//! at write() time — a narshare crash within one boot loses nothing, and a host crash rolls
//! replicas back to an ordered prefix they can only have FORGOTTEN (single writer: another
//! origin's content at a (gen, seq) is immutable mesh-wide), which the next pull re-learns.
//! Maintenance writes (compaction, reaping, watermarks, MW state) ride along: losing them only
//! retains extra history or re-learns state, never diverges.
//!
//! Layout versioning is wipe-and-resync like every narshare cache: a `layout` marker mismatch
//! destroys the database and lets the mesh snapshot us back up.

use super::{hash_part_of, Clock, HoldOp, SyncStore};
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

const LAYOUT: &str = "narshare-rocks-1";
/// CFs whose keys start with a fixed 32-byte hash — the hot lookup path. They get a prefix
/// extractor, prefix bloom filters (memtable and SST), and a shared block cache: the proxy is
/// consulted for every substitution the machine attempts, so both hits (common: the mesh holds
/// most of what cache.nixos.org served everyone) and misses (fresh nixpkgs bumps) must resolve
/// in memory, not per-seek SST index reads.
const HASH_PREFIX_CFS: &[&str] = &["att", "attby", "holdby"];
/// Shared block cache for the hot CFs. 64 MiB comfortably holds the working set of a
/// mesh-wide fact table (~500k rows) plus holder edges.
const BLOCK_CACHE_BYTES: usize = 64 << 20;
const CFS: &[&str] = &[
    "meta", "clocks", "journal", "hold", "holdby", "att", "attby", "wm", "mw",
];

pub struct RocksStore {
    db: DB,
    /// Serializes composite writes; reads are lock-free against atomic batches.
    write: Mutex<()>,
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

/// Attestation row value: 1 flag byte + 8-byte unheld_since + the encoded Attestation.
fn att_value(att: &proto::Attestation, unheld_since: Option<u64>) -> Vec<u8> {
    let mut v = Vec::with_capacity(9 + att.encoded_len());
    v.push(unheld_since.is_some() as u8);
    v.extend_from_slice(&unheld_since.unwrap_or(0).to_be_bytes());
    att.encode(&mut v).expect("vec write is infallible");
    v
}

fn att_decode(v: &[u8]) -> Result<(proto::Attestation, Option<u64>)> {
    if v.len() < 9 {
        bail!("corrupt attestation row ({} bytes)", v.len());
    }
    let stamp = (v[0] == 1).then(|| u64::from_be_bytes(<[u8; 8]>::try_from(&v[1..9]).unwrap()));
    let att = proto::Attestation::decode(&v[9..]).context("corrupt attestation body")?;
    Ok((att, stamp))
}

fn att_key(att: &proto::Attestation) -> Vec<u8> {
    let mut k = Vec::with_capacity(64);
    k.extend_from_slice(hash_part_of(&att.store_path).as_bytes());
    k.extend_from_slice(&att.nar_hash);
    k
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
                    if HASH_PREFIX_CFS.contains(n) {
                        o.set_prefix_extractor(SliceTransform::create_fixed_prefix(32));
                        o.set_memtable_prefix_bloom_ratio(0.2);
                        let mut bb = BlockBasedOptions::default();
                        bb.set_bloom_filter(10.0, false);
                        bb.set_block_cache(&cache);
                        // Index/filter blocks count against the shared cache instead of
                        // accumulating unbounded in the heap.
                        bb.set_cache_index_and_filter_blocks(true);
                        bb.set_pin_l0_filter_and_index_blocks_in_cache(true);
                        o.set_block_based_table_factory(&bb);
                    } else {
                        o.set_write_buffer_size(4 << 20);
                    }
                    ColumnFamilyDescriptor::new(*n, o)
                })
                .collect();
            let db = DB::open_cf_descriptors(&opts, dir, cfds)
                .with_context(|| format!("opening rocksdb index at {}", dir.display()))?;
            let store = Self {
                db,
                write: Mutex::new(()),
            };
            match store.meta_get("layout")? {
                Some(l) if l == LAYOUT => return Ok(store),
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

    /// att-CF rows for one store-path hash part; the bloom-accelerated path requires the
    /// exact 32-byte prefix, anything else (never produced by the proxy, but the trait cannot
    /// promise it) falls back to a total-order scan.
    fn scan_att_by_hash_part(&self, hash_part: &str) -> Vec<Kv> {
        if hash_part.len() == 32 {
            self.scan_prefix32("att", hash_part.as_bytes())
        } else {
            self.scan("att", hash_part.as_bytes())
        }
    }

    fn scan_opt(&self, cf: &str, prefix: &[u8], ro: ReadOptions) -> Vec<Kv> {
        let mut out = Vec::new();
        let it = self.db.iterator_cf_opt(
            self.cf(cf),
            ro,
            IteratorMode::From(prefix, Direction::Forward),
        );
        for kv in it {
            let Ok((k, v)) = kv else { break };
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k, v));
        }
        out
    }

    /// Origins currently holding `hash`, minus `exclude`.
    fn holders_of(&self, hash: &[u8; 32], exclude: Option<&str>) -> Vec<String> {
        self.scan_prefix32("holdby", hash)
            .into_iter()
            .filter_map(|(k, _)| String::from_utf8(k[32..].to_vec()).ok())
            .filter(|o| Some(o.as_str()) != exclude)
            .collect()
    }

    /// Stamp (or clear) unheld_since on every attestation of `hash`, into `batch`.
    fn restamp(&self, batch: &mut WriteBatch, hash: &[u8; 32], stamp: Option<u64>) -> Result<()> {
        for (k, _) in self.scan_prefix32("attby", hash) {
            let hp = &k[32..];
            let mut akey = hp.to_vec();
            akey.extend_from_slice(hash);
            let Some(v) = self.db.get_cf(self.cf("att"), &akey)? else {
                continue;
            };
            let (att, old) = att_decode(&v)?;
            let new = match (old, stamp) {
                (Some(old), Some(_)) => Some(old), // keep the EARLIEST unheld stamp
                (_, s) => s,
            };
            if new != old {
                batch.put_cf(self.cf("att"), akey, att_value(&att, new));
            }
        }
        Ok(())
    }

    /// Fold possession ops into `batch` with their retention side effects. Ops are deduped to
    /// the last op per hash; `origin`'s own row changes are reflected in the holder checks.
    fn apply_holds(
        &self,
        batch: &mut WriteBatch,
        origin: &str,
        holds: &[HoldOp],
        now: u64,
    ) -> Result<()> {
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
                self.restamp(batch, &h, None)?;
            } else {
                batch.delete_cf(self.cf("hold"), hold_key);
                batch.delete_cf(self.cf("holdby"), holdby_key);
                if self.holders_of(&h, Some(origin)).is_empty() {
                    self.restamp(batch, &h, Some(now))?;
                }
            }
        }
        Ok(())
    }

    /// Fold attestation merges into `batch`; returns how many rows were new or changed.
    /// `newly_held`/`newly_dropped` bias the holder check for hashes this same batch changes
    /// for `origin` (the batch is not yet visible to reads).
    #[allow(clippy::too_many_arguments)]
    fn merge_atts(
        &self,
        batch: &mut WriteBatch,
        attests: &[proto::Attestation],
        newly_held: &HashSet<[u8; 32]>,
        newly_dropped: &HashSet<[u8; 32]>,
        origin: Option<&str>,
        now: u64,
    ) -> Result<usize> {
        let mut changed = 0usize;
        for att in attests {
            let key = att_key(att);
            let hash: [u8; 32] = match <[u8; 32]>::try_from(att.nar_hash.as_slice()) {
                Ok(h) => h,
                Err(_) => continue, // malformed; the index validates, this is a backstop
            };
            let exclude = if newly_dropped.contains(&hash) {
                origin
            } else {
                None
            };
            let held = newly_held.contains(&hash) || !self.holders_of(&hash, exclude).is_empty();
            match self.db.get_cf(self.cf("att"), &key)? {
                None => {
                    let stamp = (!held).then_some(now);
                    batch.put_cf(self.cf("att"), &key, att_value(att, stamp));
                    let mut by = hash.to_vec();
                    by.extend_from_slice(hash_part_of(&att.store_path).as_bytes());
                    batch.put_cf(self.cf("attby"), by, b"");
                    changed += 1;
                }
                Some(v) => {
                    let (mut cur, stamp) = att_decode(&v)?;
                    let before_sigs = cur.sigs.len();
                    for s in &att.sigs {
                        if !cur.sigs.contains(s) {
                            cur.sigs.push(s.clone());
                        }
                    }
                    let body_changed = cur.nar_size != att.nar_size
                        || cur.references != att.references
                        || cur.ca != att.ca;
                    if body_changed {
                        // Body LWW: any surviving signature must verify over the CURRENT body
                        // at use time, so a divergent claim can only make itself inert.
                        cur.nar_size = att.nar_size;
                        cur.references = att.references.clone();
                        cur.ca = att.ca.clone();
                    }
                    if body_changed || cur.sigs.len() != before_sigs {
                        let stamp = if held { None } else { stamp };
                        batch.put_cf(self.cf("att"), &key, att_value(&cur, stamp));
                        changed += 1;
                    }
                }
            }
        }
        Ok(changed)
    }

    fn lookup_atts(
        &self,
        rows: Vec<(proto::Attestation, Option<u64>)>,
    ) -> Result<Vec<(proto::Attestation, Vec<String>)>> {
        let mut out = Vec::new();
        for (att, _) in rows {
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
        let _g = self.write.lock().unwrap();
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
        let _g = self.write.lock().unwrap();
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
        now: u64,
        durable: bool,
    ) -> Result<bool> {
        let _g = self.write.lock().unwrap();
        let cur = self.clock(origin)?;
        if (cur.generation, cur.seq) != expect {
            return Ok(false);
        }
        let mut batch = WriteBatch::default();
        for (seq, bytes) in journal {
            batch.put_cf(self.cf("journal"), jkey(origin, *seq)?, bytes);
        }
        let mut newly_held: HashSet<[u8; 32]> = HashSet::new();
        let mut newly_dropped: HashSet<[u8; 32]> = HashSet::new();
        for op in holds {
            match op {
                HoldOp::Add(h) => newly_held.insert(*h),
                HoldOp::Drop(h) => newly_dropped.insert(*h),
            };
        }
        self.apply_holds(&mut batch, origin, holds, now)?;
        self.merge_atts(
            &mut batch,
            attests,
            &newly_held,
            &newly_dropped,
            Some(origin),
            now,
        )?;
        let c = Clock {
            generation: set.0,
            seq: set.1,
            tail_seq: cur.tail_seq,
        };
        batch.put_cf(self.cf("clocks"), okey(origin)?, clock_bytes(c));
        if durable {
            self.db.write_opt(batch, &Self::sync_wo())?;
        } else {
            self.db.write(batch)?;
        }
        Ok(true)
    }

    fn replace_holdings(
        &self,
        origin: &str,
        generation: u64,
        seq: u64,
        held: &[[u8; 32]],
        now: u64,
    ) -> Result<bool> {
        let _g = self.write.lock().unwrap();
        let cur = self.clock(origin)?;
        if generation < cur.generation || (generation == cur.generation && seq < cur.seq) {
            return Ok(false);
        }
        let mut batch = WriteBatch::default();
        let old: HashSet<[u8; 32]> = self
            .scan("hold", &okey(origin)?)
            .into_iter()
            .filter_map(|(k, _)| <[u8; 32]>::try_from(&k[k.len() - 32..]).ok())
            .collect();
        let new: HashSet<[u8; 32]> = held.iter().copied().collect();
        let mut ops: Vec<HoldOp> = Vec::new();
        ops.extend(old.difference(&new).map(|h| HoldOp::Drop(*h)));
        ops.extend(new.difference(&old).map(|h| HoldOp::Add(*h)));
        self.apply_holds(&mut batch, origin, &ops, now)?;
        for (k, _) in self.scan("journal", &okey(origin)?) {
            batch.delete_cf(self.cf("journal"), k);
        }
        let c = Clock {
            generation,
            seq,
            tail_seq: seq,
        };
        batch.put_cf(self.cf("clocks"), okey(origin)?, clock_bytes(c));
        // Snapshot applies are always replicas of OTHER origins: async (see module docs).
        self.db.write(batch)?;
        Ok(true)
    }

    fn merge_attestations(&self, attests: &[proto::Attestation], now: u64) -> Result<usize> {
        let _g = self.write.lock().unwrap();
        let mut batch = WriteBatch::default();
        let changed = self.merge_atts(
            &mut batch,
            attests,
            &HashSet::new(),
            &HashSet::new(),
            None,
            now,
        )?;
        if changed > 0 {
            // Facts are re-learnable from any snapshot-bearing response: async.
            self.db.write(batch)?;
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

    fn all_attestations(&self) -> Result<Vec<proto::Attestation>> {
        self.scan("att", b"")
            .into_iter()
            .map(|(_, v)| Ok(att_decode(&v)?.0))
            .collect()
    }

    fn compact_journal(&self, origin: &str, floor: u64) -> Result<()> {
        let _g = self.write.lock().unwrap();
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

    fn reap_attestations(&self, cutoff: u64) -> Result<usize> {
        let _g = self.write.lock().unwrap();
        let mut batch = WriteBatch::default();
        let mut reaped = 0usize;
        for (k, v) in self.scan("att", b"") {
            let (att, stamp) = att_decode(&v)?;
            if let Some(s) = stamp {
                if s <= cutoff {
                    batch.delete_cf(self.cf("att"), &k);
                    let mut by = att.nar_hash.clone();
                    by.extend_from_slice(hash_part_of(&att.store_path).as_bytes());
                    batch.delete_cf(self.cf("attby"), by);
                    reaped += 1;
                }
            }
        }
        if reaped > 0 {
            self.db.write(batch)?;
        }
        Ok(reaped)
    }

    fn retain_origins(&self, keep: &[String], now: u64) -> Result<()> {
        let _g = self.write.lock().unwrap();
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
            for (k, _) in self.scan("hold", &okey(origin)?) {
                let h = <[u8; 32]>::try_from(&k[k.len() - 32..]).unwrap();
                let mut by = h.to_vec();
                by.extend_from_slice(origin.as_bytes());
                batch.delete_cf(self.cf("hold"), k);
                batch.delete_cf(self.cf("holdby"), by);
                if self.holders_of(&h, Some(origin)).is_empty() {
                    self.restamp(&mut batch, &h, Some(now))?;
                }
            }
            for (k, _) in self.scan("journal", &okey(origin)?) {
                batch.delete_cf(self.cf("journal"), k);
            }
            batch.delete_cf(self.cf("clocks"), okey(origin)?);
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
        let rows = self
            .scan_att_by_hash_part(hash_part)
            .into_iter()
            .map(|(_, v)| att_decode(&v))
            .collect::<Result<Vec<_>>>()?;
        self.lookup_atts(rows)
    }

    fn lookup_nar_hash(
        &self,
        nar_hash: &[u8; 32],
    ) -> Result<Vec<(proto::Attestation, Vec<String>)>> {
        let mut rows = Vec::new();
        for (k, _) in self.scan_prefix32("attby", nar_hash) {
            let mut akey = k[32..].to_vec();
            akey.extend_from_slice(nar_hash);
            if let Some(v) = self.db.get_cf(self.cf("att"), &akey)? {
                rows.push(att_decode(&v)?);
            }
        }
        self.lookup_atts(rows)
    }

    fn attested_claims(&self) -> Result<Vec<(String, Vec<u8>, Vec<String>)>> {
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
        self.scan("att", b"")
            .into_iter()
            .map(|(_, v)| {
                if v.len() < 9 {
                    bail!("corrupt attestation row ({} bytes)", v.len());
                }
                let s = Slim::decode(&v[9..]).context("corrupt attestation body")?;
                Ok((s.store_path, s.nar_hash, s.sigs))
            })
            .collect()
    }

    fn attestation_sigs(&self, hash_part: &str, nar_hash: &[u8]) -> Result<Option<Vec<String>>> {
        let mut key = Vec::with_capacity(64);
        key.extend_from_slice(hash_part.as_bytes());
        key.extend_from_slice(nar_hash);
        match self.db.get_cf(self.cf("att"), &key)? {
            Some(v) => Ok(Some(att_decode(&v)?.0.sigs)),
            None => Ok(None),
        }
    }

    fn is_held(&self, origin: &str, nar_hash: &[u8; 32]) -> Result<bool> {
        let mut key = okey(origin)?;
        key.extend_from_slice(nar_hash);
        Ok(self.db.get_cf(self.cf("hold"), &key)?.is_some())
    }

    fn advance_watermark(&self, peer: &str, origin: &str, seq: u64) -> Result<()> {
        let _g = self.write.lock().unwrap();
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
        let _g = self.write.lock().unwrap();
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
        let _g = self.write.lock().unwrap();
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
        let _g = self.write.lock().unwrap();
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
        Ok(self.scan("att", b"").len() as u64)
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
