//! The replicated mesh index: which origin holds which FEASIBLE narinfo (CA, or signed under
//! the mesh's shared trust anchor), synced by per-origin journals with snapshot fallback.
//!
//! The structural fact the whole protocol leans on: every synced set has exactly ONE writer —
//! its origin. An origin numbers its own add/remove events with a monotonic seq, so "peer P has
//! seen deletion N" collapses to "P's watermark ≥ N", and journal compaction to the minimum
//! watermark across the (fixed) peer set is safe. Everything else is recovery: a receiver whose
//! watermark predates the retained journal tail — or whose stored generation mismatches — falls
//! back to a full per-origin snapshot, the same path that serves first contact, cache loss, and
//! peer addition.
//!
//! STORAGE IS SHARDED BY ORIGIN, because that same single-writer fact makes origins' write
//! streams disjoint: each origin lives in its own SQLite file (`origins/<name>.db`) holding its
//! clock, its journal, and its paths — so applies for DIFFERENT origins run fully in parallel
//! (separate files, separate WALs, separate locks), a per-origin wipe is a table truncation,
//! and there is no cross-origin coupling at write time at all. What the old shared-table layout
//! bought with sig-merging, holder edges, and orphan GC, the shards get for free: lookups fan
//! out over the (≤ config-sized) shard set and merge rows by (store_path, nar_hash) at READ
//! time, unioning signatures and collecting holders. A small `meta.db` carries the node-global
//! oddments: self generation, trust-anchor digest, sync watermarks, persisted MW weights.
//!
//! Persistence lives under `<cache.dir>` — the daemon's only on-disk state, and state it can
//! always afford to lose: rows are re-learnable from the mesh, signatures re-verify, and a
//! lost cache bumps the self GENERATION so regenerated sequence numbers never alias old ones.
//! That disposability is also the schema-migration story: a layout-version mismatch wipes the
//! cache and lets the mesh resync it, rather than migrating in place.
//! Feasibility is verified on apply (an exporter's claim is never trusted) and re-verified at
//! use, which is what makes "remove a trusted key" degrade cleanly: rows go inert, not away.

use crate::db::StoreDb;
use crate::narinfo::RemoteNarinfo;
use crate::sig::TrustedKeys;
use anyhow::{bail, Context, Result};
use prost::Message as _;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/narshare.mesh.v1.rs"));
}

/// On-disk layout version. The cache is disposable by design, so a mismatch (or the pre-shard
/// single-file layout) wipes the directory and lets the mesh resync — no migrations.
const SCHEMA_VERSION: &str = "2";
/// Journal rows retained per origin beyond the min-watermark rule — the backstop that keeps one
/// dead or long-offline peer from pinning the journal forever. Stragglers land on the snapshot
/// path, which must exist anyway.
const JOURNAL_BACKSTOP: u64 = 50_000;
/// Suffix bytes per origin per sync response; more sets `truncated` and the puller loops.
const SUFFIX_BYTES_CAP: usize = 8 << 20;
/// Soft byte budget for one WHOLE sync response (suffix events + snapshot rows, encoded).
/// Origins that would overflow it are deferred with an empty truncated suffix and picked up by
/// the puller's truncated loop next round — without this, a response carrying several origins'
/// full snapshots (first contact with a mature mesh) can exceed the puller's hard caps
/// (SYNC_CAP/SYNC_RAW_CAP in peers.rs) and every retry fails identically: a permanent wedge.
/// A SINGLE origin's snapshot is never split (wipe-and-replace semantics), so one origin's
/// holdings must stay under the puller's 256 MiB raw cap — ~600k paths, far past any real node.
const RESPONSE_BYTES_CAP: usize = 24 << 20;
/// Half-life of persisted MW weights: at load, each weight is pulled toward uniform (1.0) by
/// 2^(-age/half_life) — an hour-old vector keeps ~97% of its shape, a week-old one ~1%
/// (effectively fresh). The best-rate yardstick and mean-loss decay toward 0 the same way.
const MW_HALF_LIFE_SECS: f64 = 86_400.0;

/// One origin's storage: its clock, journal, and paths, in its own SQLite file. The `rw`
/// connection serializes that origin's writes (which the protocol already serializes
/// logically); `ro` gives lookups and sync responses WAL snapshot reads that never queue
/// behind an apply.
struct Shard {
    rw: Mutex<Connection>,
    ro: Mutex<Connection>,
}

pub struct Index {
    /// meta.db: self generation, trust anchor, watermarks, persisted MW state.
    meta: Mutex<Connection>,
    shards: HashMap<String, Shard>,
    pub self_name: String,
    /// Configured origin universe: self + peers. Anything else is rejected and reaped.
    origin_set: HashSet<String>,
    peer_names: Vec<String>,
    trusted: TrustedKeys,
}

/// One lookup result: a feasible narinfo and who currently holds it.
#[derive(Debug)]
pub struct Found {
    pub info: RemoteNarinfo,
    /// Origin names, possibly including self.
    pub holders: Vec<String>,
}

pub enum Apply {
    Applied(usize),
    /// The suffix did not connect to our state (gap or unknown baseline): snapshot required.
    NeedSnapshot,
}

/// Origin names are config-supplied strings; keep the common case readable on disk and make
/// the rest unambiguous (hex never collides with the readable form because of the prefix).
fn shard_file_name(origin: &str) -> String {
    let safe = origin
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if safe && !origin.starts_with('.') && !origin.is_empty() {
        format!("{origin}.db")
    } else {
        format!("x{}.db", hex::encode(origin))
    }
}

fn open_conn(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    // FULL, deliberately: the sync protocol treats every seq a peer has OBSERVED as
    // permanent — with NORMAL, a power loss can revert the WAL past a seq a peer already
    // pulled, and re-issuing those numbers with different events diverges that peer until
    // the paths independently change. Write rate is one transaction per diff/apply, so the
    // fsync is noise. (The pull-side self-clock regression check is the backstop for the
    // same failure arriving via other roads, e.g. a restored disk image.)
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

fn open_conn_ro(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening {} read-only", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

impl Index {
    pub fn open(
        dir: &Path,
        self_name: &str,
        peer_names: &[String],
        trusted: TrustedKeys,
    ) -> Result<Self> {
        let origins_dir = dir.join("origins");
        std::fs::create_dir_all(&origins_dir)
            .with_context(|| format!("creating cache dir {}", origins_dir.display()))?;

        // Layout versioning by wipe-and-resync: the pre-shard single-file layout, or any
        // future schema bump, deletes the disposable cache (self generation reminting is the
        // designed consequence; peers snapshot us back up).
        let meta_path = dir.join("meta.db");
        let stored_schema: Option<String> = if meta_path.exists() {
            let c = open_conn(&meta_path)?;
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            )?;
            c.query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| r.get(0))
                .optional()?
        } else {
            None
        };
        if dir.join("index.db").exists() || stored_schema.as_deref() != Some(SCHEMA_VERSION) {
            if dir.join("index.db").exists() || stored_schema.is_some() {
                info!("mesh index layout changed: wiping the (disposable) cache for resync");
            }
            for entry in std::fs::read_dir(dir)? {
                let p = entry?.path();
                if p.is_dir() {
                    std::fs::remove_dir_all(&p)?;
                } else {
                    std::fs::remove_file(&p)?;
                }
            }
            std::fs::create_dir_all(&origins_dir)?;
        }

        let meta = open_conn(&meta_path)?;
        meta.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS watermarks (
                 peer TEXT NOT NULL,
                 origin TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 PRIMARY KEY (peer, origin));
             CREATE TABLE IF NOT EXISTS mw_state (
                 peer TEXT PRIMARY KEY,
                 weight REAL NOT NULL,
                 updated INTEGER NOT NULL);",
        )?;
        meta.execute(
            "INSERT INTO meta (key, value) VALUES ('schema', ?1)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [SCHEMA_VERSION],
        )?;

        // Self generation: minted once per database lifetime. A lost cache mints a new one, so
        // regenerated (gen, seq) pairs never alias what peers saw before the loss.
        let gen: Option<String> = meta
            .query_row("SELECT value FROM meta WHERE key = 'self_generation'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let self_gen: u64 = match gen {
            Some(g) => g.parse().context("corrupt self_generation")?,
            None => {
                // Nanoseconds: two database lifetimes of the same node must never share a
                // generation, even when created within the same second.
                let g = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(1);
                meta.execute(
                    "INSERT INTO meta (key, value) VALUES ('self_generation', ?1)",
                    [g.to_string()],
                )?;
                g
            }
        };

        let mut origin_set: HashSet<String> = peer_names.iter().cloned().collect();
        origin_set.insert(self_name.to_owned());

        // Reap origins that left the config: their shard files, and — crucially — their
        // watermark contribution, which would otherwise pin journal compaction forever.
        let expected: HashSet<String> = origin_set.iter().map(|o| shard_file_name(o)).collect();
        for entry in std::fs::read_dir(&origins_dir)? {
            let p = entry?.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
            let base = name.trim_end_matches("-wal").trim_end_matches("-shm");
            if !expected.contains(base) {
                info!("dropping departed origin shard {name:?} from the index");
                let _ = std::fs::remove_file(&p);
            }
        }
        {
            let names: Vec<String> = origin_set.iter().cloned().collect();
            let placeholders = vec!["?"; names.len()].join(",");
            meta.execute(
                &format!(
                    "DELETE FROM watermarks WHERE peer NOT IN ({placeholders}) \
                     OR origin NOT IN ({placeholders})"
                ),
                rusqlite::params_from_iter(names.iter().chain(names.iter())),
            )?;
        }

        // Open every origin's shard (self + peers), creating schemas as needed.
        let mut shards = HashMap::new();
        for origin in &origin_set {
            let path = origins_dir.join(shard_file_name(origin));
            let rw = open_conn(&path)?;
            rw.execute_batch(
                "CREATE TABLE IF NOT EXISTS clock (
                     id INTEGER PRIMARY KEY CHECK (id = 1),
                     generation INTEGER NOT NULL,
                     seq INTEGER NOT NULL,
                     tail_seq INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS paths (
                     store_path TEXT PRIMARY KEY,
                     hash_part TEXT NOT NULL,
                     nar_hash BLOB NOT NULL,
                     nar_size INTEGER NOT NULL,
                     refs TEXT NOT NULL,
                     ca TEXT NOT NULL,
                     sigs TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS paths_hash ON paths(hash_part);
                 CREATE INDEX IF NOT EXISTS paths_nar ON paths(nar_hash);
                 CREATE TABLE IF NOT EXISTS journal (
                     seq INTEGER PRIMARY KEY,
                     event BLOB NOT NULL);",
            )?;
            rw.execute(
                "INSERT INTO clock (id, generation, seq, tail_seq) VALUES (1, 0, 0, 0)
                 ON CONFLICT (id) DO NOTHING",
                [],
            )?;
            if origin == self_name {
                // meta's self_generation is authoritative (heals a torn bump too).
                rw.execute(
                    "UPDATE clock SET generation = ?1 WHERE id = 1",
                    params![self_gen as i64],
                )?;
            }
            let ro = open_conn_ro(&path)?;
            shards.insert(origin.clone(), Shard { rw: Mutex::new(rw), ro: Mutex::new(ro) });
        }

        // A changed trust anchor voids every peer origin's clock: events applied under the old
        // anchor may have been skipped as infeasible (they are journaled at their ORIGIN, not
        // here), and a clock that already covers those seqs would answer "up to date" forever —
        // re-adding a key must force full snapshots instead. Paths stay (incoming snapshots
        // wipe-replace them, and use-time feasibility keeps them honest meanwhile); the self
        // origin needs nothing, because the own-db differ re-exports newly-feasible paths on
        // its own.
        let anchor = trusted.anchor_digest();
        let stored_anchor: Option<String> = meta
            .query_row("SELECT value FROM meta WHERE key = 'trust_anchor'", [], |r| r.get(0))
            .optional()?;
        if stored_anchor.as_deref() != Some(anchor.as_str()) {
            if stored_anchor.is_some() {
                info!("trust anchor changed: forcing a full resync of every peer origin");
                for (origin, shard) in &shards {
                    if origin == self_name {
                        continue;
                    }
                    let conn = shard.rw.lock().unwrap();
                    conn.execute_batch(
                        "UPDATE clock SET generation = 0, seq = 0, tail_seq = 0 WHERE id = 1;
                         DELETE FROM journal;",
                    )?;
                }
            }
            meta.execute(
                "INSERT INTO meta (key, value) VALUES ('trust_anchor', ?1)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                [&anchor],
            )?;
        }

        Ok(Self {
            meta: Mutex::new(meta),
            shards,
            self_name: self_name.to_owned(),
            origin_set,
            peer_names: peer_names.to_vec(),
            trusted,
        })
    }

    fn shard(&self, origin: &str) -> Result<&Shard> {
        self.shards
            .get(origin)
            .with_context(|| format!("no shard for origin {origin:?}"))
    }

    pub fn is_known_origin(&self, name: &str) -> bool {
        self.origin_set.contains(name)
    }

    /// Feasibility under the CURRENT anchor: CA, or any signature that verifies. Checked on
    /// apply (never trust the exporter) and again at use (removed keys make rows inert).
    fn feasible(&self, n: &proto::Narinfo) -> bool {
        if n.nar_hash.len() != 32 || n.store_path.len() < 44 || !n.store_path.starts_with('/') {
            return false;
        }
        if !n.ca.is_empty() {
            return true;
        }
        self.trusted.any_sig_valid(&proto_to_remote(n))
    }

    fn clock_of(conn: &Connection) -> Result<(u64, u64, u64)> {
        let (g, s, t): (i64, i64, i64) = conn.query_row(
            "SELECT generation, seq, tail_seq FROM clock WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok((g as u64, s as u64, t as u64))
    }

    /// Our full clock vector, for sync requests (doubles as the ack that drives compaction).
    /// Read-only shard connections: never queues behind an apply, and cross-origin atomicity
    /// is not needed (each clock pairs with its own origin's independent stream).
    pub fn clock_vector(&self) -> Result<Vec<proto::OriginClock>> {
        let mut v = Vec::with_capacity(self.shards.len());
        for (origin, shard) in &self.shards {
            let conn = shard.ro.lock().unwrap();
            let (generation, seq, _) = Self::clock_of(&conn)?;
            v.push(proto::OriginClock { origin: origin.clone(), generation, seq });
        }
        Ok(v)
    }

    /// Record what `peer` proved it has seen (its sync request's clock vector).
    pub fn record_watermarks(&self, peer: &str, clocks: &[proto::OriginClock]) -> Result<()> {
        for c in clocks {
            if !self.origin_set.contains(&c.origin) {
                continue;
            }
            // Only meaningful if the peer is on the same generation we are; a stale-generation
            // watermark must not unblock compaction of a journal it has not actually seen.
            let ours = {
                let conn = self.shard(&c.origin)?.ro.lock().unwrap();
                Self::clock_of(&conn)?.0
            };
            if ours != c.generation {
                continue;
            }
            let meta = self.meta.lock().unwrap();
            meta.execute(
                "INSERT INTO watermarks (peer, origin, seq) VALUES (?1, ?2, ?3)
                 ON CONFLICT (peer, origin) DO UPDATE SET seq = MAX(seq, excluded.seq)",
                params![peer, c.origin, c.seq as i64],
            )?;
        }
        Ok(())
    }

    /// Build the per-origin answer for a sync request: up-to-date, journal suffix, or snapshot.
    /// Each origin is read under its own shard's read-only snapshot — per-origin consistency is
    /// exactly what the protocol needs, and applies to OTHER origins proceed concurrently.
    pub fn respond(&self, req: &proto::SyncRequest) -> Result<Vec<proto::OriginUpdate>> {
        self.respond_budgeted(req, RESPONSE_BYTES_CAP)
    }

    fn respond_budgeted(
        &self,
        req: &proto::SyncRequest,
        budget: usize,
    ) -> Result<Vec<proto::OriginUpdate>> {
        let have: HashMap<&str, &proto::OriginClock> =
            req.have.iter().map(|c| (c.origin.as_str(), c)).collect();
        let mut out = Vec::new();
        let mut used = 0usize;
        // Sorted iteration: deterministic budget allocation across rounds (HashMap order
        // would defer a different suffix each time and confuse debugging).
        let mut names: Vec<&String> = self.shards.keys().collect();
        names.sort();
        for name in names {
            let shard = &self.shards[name];
            let conn = shard.ro.lock().unwrap();
            let tx = conn.unchecked_transaction()?;
            let (gen, seq, tail) = Self::clock_of(&tx)?;
            if gen == 0 {
                continue; // we know nothing about this origin yet
            }
            let theirs = have.get(name.as_str());
            let (their_gen, their_seq) =
                theirs.map(|c| (c.generation, c.seq)).unwrap_or((0, 0));
            if their_gen > gen {
                continue; // they are ahead of us on this origin; nothing useful from us
            }
            if their_gen == gen && their_seq >= seq {
                out.push(proto::OriginUpdate {
                    origin: name.clone(),
                    generation: gen,
                    seq,
                    truncated: false,
                    body: Some(proto::origin_update::Body::UpToDate(true)),
                });
                continue;
            }
            // This origin needs data. If the response is already at budget, defer it whole:
            // an empty truncated suffix makes the puller come straight back for another round.
            if used >= budget {
                out.push(proto::OriginUpdate {
                    origin: name.clone(),
                    generation: gen,
                    seq,
                    truncated: true,
                    body: Some(proto::origin_update::Body::Suffix(proto::Suffix {
                        events: Vec::new(),
                    })),
                });
                continue;
            }
            let body = if their_gen == gen && their_seq >= tail {
                // Journal suffix (their_seq, ...], capped per origin and by the response budget.
                let mut events = Vec::new();
                let mut bytes = 0usize;
                let mut truncated = false;
                let mut stmt = tx.prepare_cached(
                    "SELECT seq, event FROM journal WHERE seq > ?1 ORDER BY seq",
                )?;
                let mut rows = stmt.query(params![their_seq as i64])?;
                while let Some(row) = rows.next()? {
                    let blob: Vec<u8> = row.get(1)?;
                    if bytes + blob.len() > SUFFIX_BYTES_CAP && !events.is_empty() {
                        truncated = true;
                        break;
                    }
                    bytes += blob.len();
                    events.push(
                        proto::Event::decode(&blob[..]).context("corrupt journal event")?,
                    );
                }
                used += bytes;
                out.push(proto::OriginUpdate {
                    origin: name.clone(),
                    generation: gen,
                    seq,
                    truncated,
                    body: Some(proto::origin_update::Body::Suffix(proto::Suffix { events })),
                });
                continue;
            } else {
                // Their watermark predates our tail, or their generation is stale: snapshot.
                let held = snapshot_rows(&tx)?;
                used += held.iter().map(prost::Message::encoded_len).sum::<usize>();
                proto::origin_update::Body::Snapshot(proto::Snapshot { held })
            };
            out.push(proto::OriginUpdate {
                origin: name.clone(),
                generation: gen,
                seq,
                truncated: false,
                body: Some(body),
            });
        }
        Ok(out)
    }

    /// Apply one origin's journal suffix. Idempotent; last-writer-wins per path (a plain
    /// UPSERT — the shard holds only this origin's rows).
    pub fn apply_suffix(
        &self,
        origin: &str,
        generation: u64,
        events: &[proto::Event],
    ) -> Result<Apply> {
        if origin == self.self_name || !self.origin_set.contains(origin) {
            bail!("suffix for unexpected origin {origin:?}");
        }
        // Feasibility (an ed25519 verify per signed add) needs no database: do it BEFORE
        // taking the shard's write lock. (Applies for OTHER origins don't contend at all.)
        let feasible: Vec<bool> = events
            .iter()
            .map(|e| match &e.op {
                Some(proto::event::Op::Add(n)) => self.feasible(n),
                _ => true,
            })
            .collect();
        let shard = self.shard(origin)?;
        let mut conn = shard.rw.lock().unwrap();
        let tx = conn.transaction()?;
        let (our_gen, mut our_seq, _) = Self::clock_of(&tx)?;
        if generation < our_gen {
            return Ok(Apply::Applied(0)); // stale relay; ignore
        }
        if generation > our_gen {
            if our_gen == 0 && our_seq == 0 {
                // We know nothing yet: adopting a generation via a from-zero suffix is
                // identical to snapshotting an empty state and replaying.
                tx.execute(
                    "UPDATE clock SET generation = ?1 WHERE id = 1",
                    params![generation as i64],
                )?;
            } else {
                // The origin regenerated (cache loss): our copy is void. A suffix cannot
                // rebuild it from nothing — only a snapshot can.
                return Ok(Apply::NeedSnapshot);
            }
        }
        let mut applied = 0usize;
        for (e, feas) in events.iter().zip(&feasible) {
            if e.seq <= our_seq {
                continue; // replay
            }
            if e.seq != our_seq + 1 {
                return Ok(Apply::NeedSnapshot); // gap: suffix does not connect
            }
            tx.execute(
                "INSERT OR REPLACE INTO journal (seq, event) VALUES (?1, ?2)",
                params![e.seq as i64, e.encode_to_vec()],
            )?;
            apply_op_tx(&tx, origin, e, *feas)?;
            our_seq = e.seq;
            applied += 1;
        }
        tx.execute("UPDATE clock SET seq = ?1 WHERE id = 1", params![our_seq as i64])?;
        tx.commit()?;
        Ok(Apply::Applied(applied))
    }

    /// Replace our copy of an origin wholesale (the recovery path).
    pub fn apply_snapshot(
        &self,
        origin: &str,
        generation: u64,
        seq: u64,
        held: &[proto::Narinfo],
    ) -> Result<usize> {
        if origin == self.self_name || !self.origin_set.contains(origin) {
            bail!("snapshot for unexpected origin {origin:?}");
        }
        // Verify outside the write lock (see apply_suffix) — this is the path where it matters
        // most: a first-contact snapshot of a large signed origin is thousands of verifies.
        let feasible: Vec<bool> = held.iter().map(|n| self.feasible(n)).collect();
        let shard = self.shard(origin)?;
        let mut conn = shard.rw.lock().unwrap();
        let tx = conn.transaction()?;
        let (our_gen, our_seq, _) = Self::clock_of(&tx)?;
        if generation < our_gen || (generation == our_gen && seq < our_seq) {
            // Stale relay — including the concurrent-pull race where another peer's loop
            // advanced this origin past `seq` while this snapshot was in flight; wiping to the
            // older state would silently drop the newer events.
            return Ok(0);
        }
        tx.execute_batch("DELETE FROM paths; DELETE FROM journal;")?;
        let mut inserted = 0usize;
        for (n, feas) in held.iter().zip(&feasible) {
            if !feas {
                debug!("snapshot of {origin}: skipping infeasible {}", n.store_path);
                continue;
            }
            upsert_path_tx(&tx, n)?;
            inserted += 1;
        }
        // We have state as of `seq` but no journal history: suffixes we can serve start there.
        tx.execute(
            "UPDATE clock SET generation = ?1, seq = ?2, tail_seq = ?2 WHERE id = 1",
            params![generation as i64, seq as i64],
        )?;
        tx.commit()?;
        Ok(inserted)
    }

    /// Remint our self generation strictly above `floor` — the self-clock-regression recovery.
    /// Triggered from the pull side when a peer reports a FUTURE for our own origin (cache loss
    /// with a backwards wall clock; a restored disk image; a WAL reverted by power loss): the
    /// mesh remembers seqs we no longer own, so we must move to a fresh generation and let
    /// snapshots re-teach everyone. Journal and holdings stay — content is still correct, only
    /// the (generation, seq) namespace moves.
    pub fn bump_self_generation(&self, floor: u64) -> Result<u64> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        let g = nanos.max(floor.saturating_add(1));
        // meta first (authoritative), then the shard clock; a crash in between is healed at
        // open, where meta's value is re-stamped onto the shard.
        {
            let meta = self.meta.lock().unwrap();
            meta.execute(
                "UPDATE meta SET value = ?1 WHERE key = 'self_generation'",
                [g.to_string()],
            )?;
        }
        let shard = self.shard(&self.self_name)?;
        let conn = shard.rw.lock().unwrap();
        conn.execute("UPDATE clock SET generation = ?1 WHERE id = 1", params![g as i64])?;
        Ok(g)
    }

    /// The exporting node's half: diff our Nix db against our indexed self-holdings and emit
    /// add/remove events to our own journal. Feasibility is checked HERE, by the exporter, per
    /// the design: only CA or trusted-signed rows leave this node. Returns events emitted.
    ///
    /// Three-phase so the write lock is held only for the actual writes: the self origin has
    /// exactly one writer (the own-db loop; tests call this inline), so the held-snapshot
    /// cannot go stale between phases.
    pub fn sync_own_db(&self, db: &StoreDb) -> Result<usize> {
        let candidates = db.feasible_candidates()?;
        let shard = self.shard(&self.self_name)?;

        // Phase 1: snapshot what we currently export (brief read).
        let held: HashMap<String, (Vec<u8>, String)> = {
            let conn = shard.ro.lock().unwrap();
            let mut stmt =
                conn.prepare_cached("SELECT store_path, nar_hash, sigs FROM paths")?;
            let held = stmt
                .query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?
                .collect::<rusqlite::Result<_>>()?;
            held
        };

        // Phase 2: diff, with the ed25519 verifies for changed rows done lock-free. The self
        // shard contains EXACTLY what we exported (no cross-origin sig merging exists in the
        // sharded layout), so plain equality is the honest change test — it also catches
        // signature removal.
        let mut adds: Vec<proto::Narinfo> = Vec::new();
        let mut kept: HashSet<&str> = HashSet::with_capacity(candidates.len());
        for info in &candidates {
            let changed = match held.get(&info.path) {
                Some((hash, sigs)) => {
                    let stored: HashSet<&str> = sigs.split_whitespace().collect();
                    let ours: HashSet<&str> = info.sigs.iter().map(String::as_str).collect();
                    hash[..] != info.nar_hash[..] || stored != ours
                }
                None => true,
            };
            if !changed {
                kept.insert(info.path.as_str());
                continue;
            }
            // References are fetched HERE, one query per CHANGED row — never for the whole
            // candidate set (a per-row JOIN across a 100k-path store cost ~10 CPU-seconds per
            // diff, measured in production). The signed fingerprint covers them and the
            // exported narinfo carries them, so only exports need them.
            let refs = db.references_of(info.id)?;
            let n = proto::Narinfo {
                store_path: info.path.clone(),
                nar_hash: info.nar_hash.to_vec(),
                nar_size: info.nar_size,
                references: refs
                    .iter()
                    .map(|r| crate::narinfo::basename(r, &db.store_dir).to_owned())
                    .collect(),
                ca: info.ca.clone().unwrap_or_default(),
                sigs: info.sigs.clone(),
            };
            // Feasibility (with its ed25519 verify) only for changed rows: unchanged rows were
            // already vetted when first exported.
            if self.feasible(&n) {
                kept.insert(info.path.as_str());
                adds.push(n);
            }
        }
        // Anything held but no longer exportable gets a Remove: GC'd paths, but also paths
        // whose row REGRESSED — rebuilt in place without a signature, or changed to something
        // the anchor no longer covers. A stale index entry would send peers chasing bytes we
        // cannot serve, and each such fetch burns a failure streak before nix falls back.
        let removes: Vec<String> =
            held.keys().filter(|p| !kept.contains(p.as_str())).cloned().collect();
        if adds.is_empty() && removes.is_empty() {
            return Ok(0);
        }

        // Phase 3: write everything in one transaction on the self shard.
        let mut conn = shard.rw.lock().unwrap();
        let tx = conn.transaction()?;
        let (_, mut seq, _) = Self::clock_of(&tx)?;
        let mut emitted = 0usize;
        let mut emit = |tx: &Connection, e: proto::Event| -> Result<()> {
            tx.execute(
                "INSERT INTO journal (seq, event) VALUES (?1, ?2)",
                params![e.seq as i64, e.encode_to_vec()],
            )?;
            apply_op_tx(tx, &self.self_name, &e, true)?;
            emitted += 1;
            Ok(())
        };
        for n in adds {
            seq += 1;
            emit(&tx, proto::Event { seq, op: Some(proto::event::Op::Add(n)) })?;
        }
        for path in removes {
            seq += 1;
            emit(&tx, proto::Event { seq, op: Some(proto::event::Op::Remove(path)) })?;
        }
        tx.execute("UPDATE clock SET seq = ?1 WHERE id = 1", params![seq as i64])?;
        tx.commit()?;
        Ok(emitted)
    }

    /// Compact journals: to the minimum watermark across all configured peers (the ack rule),
    /// with the size backstop so a straggler cannot pin retention forever. Per-shard
    /// transactions; origins compact independently.
    pub fn compact(&self) -> Result<()> {
        // Watermarks first (brief meta read), then each shard on its own lock.
        let marks: HashMap<(String, String), i64> = {
            let meta = self.meta.lock().unwrap();
            let mut stmt = meta.prepare_cached("SELECT peer, origin, seq FROM watermarks")?;
            let m = stmt
                .query_map([], |r| {
                    Ok(((r.get(0)?, r.get(1)?), r.get(2)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            m
        };
        for (origin, shard) in &self.shards {
            let mut conn = shard.rw.lock().unwrap();
            let tx = conn.transaction()?;
            let (_, seq, tail) = Self::clock_of(&tx)?;
            let (seq, tail) = (seq as i64, tail as i64);
            let mut floor: i64 = seq;
            for peer in &self.peer_names {
                let w = marks.get(&(peer.clone(), origin.clone())).copied().unwrap_or(0);
                floor = floor.min(w);
            }
            // Backstop: never retain more than JOURNAL_BACKSTOP events regardless of acks.
            floor = floor.max(seq - (JOURNAL_BACKSTOP as i64).min(seq));
            if floor > tail {
                tx.execute("DELETE FROM journal WHERE seq <= ?1", params![floor])?;
                tx.execute("UPDATE clock SET tail_seq = ?1 WHERE id = 1", params![floor])?;
            }
            tx.commit()?;
        }
        Ok(())
    }

    /// Lookup by store-path hash part, feasibility re-verified at use.
    pub fn lookup_hash_part(&self, hash_part: &str) -> Result<Vec<Found>> {
        self.lookup_merged(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT store_path, nar_hash, nar_size, refs, ca, sigs FROM paths \
                 WHERE hash_part = ?1",
            )?;
            let v = stmt
                .query_map([hash_part], row_to_narinfo)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })
    }

    /// Lookup by narhash (NAR requests after a proxy restart included — the index persists).
    pub fn lookup_nar_hash(&self, nar_hash: &[u8; 32]) -> Result<Vec<Found>> {
        self.lookup_merged(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT store_path, nar_hash, nar_size, refs, ca, sigs FROM paths \
                 WHERE nar_hash = ?1",
            )?;
            let v = stmt
                .query_map(params![&nar_hash[..]], row_to_narinfo)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })
    }

    /// Fan a per-shard query out over every origin and merge by (store_path, nar_hash):
    /// holders collect, signature sets union — the read-time equivalent of what the shared-
    /// table layout did at write time, minus all of its coupling.
    fn lookup_merged<F>(&self, per_shard: F) -> Result<Vec<Found>>
    where
        F: Fn(&Connection) -> Result<Vec<proto::Narinfo>>,
    {
        let mut merged: Vec<(proto::Narinfo, Vec<String>)> = Vec::new();
        for (origin, shard) in &self.shards {
            let rows = {
                let conn = shard.ro.lock().unwrap();
                per_shard(&conn)?
            };
            for n in rows {
                match merged
                    .iter_mut()
                    .find(|(m, _)| m.store_path == n.store_path && m.nar_hash == n.nar_hash)
                {
                    Some((m, holders)) => {
                        for s in n.sigs {
                            if !m.sigs.contains(&s) {
                                m.sigs.push(s);
                            }
                        }
                        holders.push(origin.clone());
                    }
                    None => merged.push((n, vec![origin.clone()])),
                }
            }
        }
        // Re-verify at use: a key removed from the anchor makes its rows inert, and
        // re-adding it wakes them — nothing is deleted on trust changes.
        Ok(merged
            .into_iter()
            .filter(|(n, _)| self.feasible(n))
            .map(|(n, holders)| Found { info: proto_to_remote(&n), holders })
            .collect())
    }

    /// Persist the MW pool's learned state, stamped now. Keyed by peer NAME — indices are not
    /// stable across config edits.
    pub fn save_mw(
        &self,
        peers: &[String],
        weights: &[f64],
        best_rate: f64,
        avg_loss: f64,
    ) -> Result<()> {
        let now = unix_now() as i64;
        let meta = self.meta.lock().unwrap();
        for (name, w) in peers.iter().zip(weights) {
            meta.execute(
                "INSERT INTO mw_state (peer, weight, updated) VALUES (?1, ?2, ?3)
                 ON CONFLICT (peer) DO UPDATE SET weight = excluded.weight,
                                                  updated = excluded.updated",
                params![name, w, now],
            )?;
        }
        meta.execute(
            "INSERT INTO meta (key, value) VALUES ('mw_globals', ?1)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            [format!("{best_rate} {avg_loss} {now}")],
        )?;
        Ok(())
    }

    /// Load persisted MW state for the given peer order, decayed toward the fresh pool
    /// (uniform weights, zero yardstick) by staleness. None when nothing was ever saved.
    pub fn load_mw(&self, peers: &[String]) -> Result<Option<(Vec<f64>, f64, f64)>> {
        let now = unix_now() as i64;
        let meta = self.meta.lock().unwrap();
        let rows: HashMap<String, (f64, i64)> = meta
            .prepare("SELECT peer, weight, updated FROM mw_state")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?))))?
            .collect::<rusqlite::Result<_>>()?;
        if rows.is_empty() {
            return Ok(None);
        }
        // Reap rows for peers that left the config.
        for name in rows.keys() {
            if !peers.contains(name) {
                meta.execute("DELETE FROM mw_state WHERE peer = ?1", [name])?;
            }
        }
        let decay = |age: i64| 0.5f64.powf((age.max(0) as f64) / MW_HALF_LIFE_SECS);
        let mut any = false;
        let weights: Vec<f64> = peers
            .iter()
            .map(|name| match rows.get(name) {
                Some(&(w, updated)) => {
                    any = true;
                    1.0 + (w - 1.0) * decay(now - updated)
                }
                None => 1.0, // a new peer starts fresh
            })
            .collect();
        if !any {
            return Ok(None);
        }
        let globals: Option<String> = meta
            .query_row("SELECT value FROM meta WHERE key = 'mw_globals'", [], |r| r.get(0))
            .optional()?;
        let (best_rate, avg_loss) = match globals.as_deref().map(|g| {
            let mut it = g.split_whitespace();
            (
                it.next().and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0),
                it.next().and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0),
                it.next().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0),
            )
        }) {
            Some((br, al, updated)) => {
                let f = decay(now - updated);
                (br * f, al * f)
            }
            None => (0.0, 0.0),
        };
        Ok(Some((weights, best_rate, avg_loss)))
    }

    /// Test hook: age every persisted MW stamp backwards.
    #[cfg(test)]
    pub fn age_mw(&self, secs: i64) {
        let meta = self.meta.lock().unwrap();
        meta.execute("UPDATE mw_state SET updated = updated - ?1", [secs]).unwrap();
        if let Ok(g) =
            meta.query_row("SELECT value FROM meta WHERE key = 'mw_globals'", [], |r| {
                r.get::<_, String>(0)
            })
        {
            let mut it = g.split_whitespace();
            let (br, al, up) = (
                it.next().unwrap().to_owned(),
                it.next().unwrap().to_owned(),
                it.next().unwrap().parse::<i64>().unwrap(),
            );
            meta.execute(
                "UPDATE meta SET value = ?1 WHERE key = 'mw_globals'",
                [format!("{br} {al} {}", up - secs)],
            )
            .unwrap();
        }
    }

    /// Full introspection for the status endpoint: per-origin clocks, journal and holding
    /// sizes, narinfo total, watermarks. Read-only connections throughout.
    pub fn status(&self) -> Result<serde_json::Value> {
        let mut origins: Vec<serde_json::Value> = Vec::new();
        let mut names: Vec<&String> = self.shards.keys().collect();
        names.sort();
        let mut distinct: HashSet<(String, Vec<u8>)> = HashSet::new();
        for name in names {
            let shard = &self.shards[name];
            let conn = shard.ro.lock().unwrap();
            let (generation, seq, tail_seq) = Self::clock_of(&conn)?;
            let journal_len: i64 =
                conn.query_row("SELECT COUNT(*) FROM journal", [], |r| r.get(0))?;
            let holdings: i64 =
                conn.query_row("SELECT COUNT(*) FROM paths", [], |r| r.get(0))?;
            let mut stmt = conn.prepare_cached("SELECT store_path, nar_hash FROM paths")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                distinct.insert((row.get(0)?, row.get(1)?));
            }
            origins.push(serde_json::json!({
                "name": name,
                "generation": generation,
                "seq": seq,
                "tail_seq": tail_seq,
                "journal_len": journal_len,
                "holdings": holdings,
            }));
        }
        let watermarks: Vec<serde_json::Value> = {
            let meta = self.meta.lock().unwrap();
            let mut stmt = meta
                .prepare_cached("SELECT peer, origin, seq FROM watermarks ORDER BY peer, origin")?;
            let v = stmt
                .query_map([], |r| {
                    Ok(serde_json::json!({
                        "peer": r.get::<_, String>(0)?,
                        "origin": r.get::<_, String>(1)?,
                        "seq": r.get::<_, i64>(2)? as u64,
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?;
            v
        };
        Ok(serde_json::json!({
            "self": self.self_name,
            "narinfos": distinct.len(),
            "origins": origins,
            "watermarks": watermarks,
        }))
    }

    /// (generation, seq) of an origin as we know it.
    pub fn origin_clock(&self, origin: &str) -> Result<(u64, u64)> {
        let conn = self.shard(origin)?.ro.lock().unwrap();
        let (g, s, _) = Self::clock_of(&conn)?;
        Ok((g, s))
    }

    #[cfg(test)]
    pub fn count_narinfos(&self) -> usize {
        let mut distinct: HashSet<(String, Vec<u8>)> = HashSet::new();
        for shard in self.shards.values() {
            let conn = shard.ro.lock().unwrap();
            let mut stmt = conn.prepare("SELECT store_path, nar_hash FROM paths").unwrap();
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                distinct.insert((row.get(0).unwrap(), row.get(1).unwrap()));
            }
        }
        distinct.len()
    }

    #[cfg(test)]
    pub fn journal_len(&self, origin: &str) -> usize {
        let conn = self.shard(origin).unwrap().ro.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM journal", [], |r| r.get::<_, i64>(0)).unwrap()
            as usize
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fold one journal event into the shard's paths table. `feasible` is the caller's
/// PRE-COMPUTED verdict for add events (the ed25519 verify happens outside the write lock);
/// removes ignore it. LWW per path is a plain UPSERT: the shard holds only its own origin's
/// rows, so there is nothing to merge and nothing to orphan-collect.
fn apply_op_tx(tx: &Connection, origin: &str, e: &proto::Event, feasible: bool) -> Result<()> {
    match &e.op {
        Some(proto::event::Op::Add(n)) => {
            if feasible {
                upsert_path_tx(tx, n)?;
            } else {
                // Journaled verbatim for faithful relay, but never enters our tables.
                debug!("origin {origin}: infeasible add for {} ignored", n.store_path);
                tx.execute("DELETE FROM paths WHERE store_path = ?1", [&n.store_path])?;
            }
        }
        Some(proto::event::Op::Remove(path)) => {
            tx.execute("DELETE FROM paths WHERE store_path = ?1", [path])?;
        }
        None => {}
    }
    Ok(())
}

fn upsert_path_tx(tx: &Connection, n: &proto::Narinfo) -> Result<()> {
    let hash_part = n
        .store_path
        .rsplit('/')
        .next()
        .unwrap_or("")
        .get(..32)
        .unwrap_or("")
        .to_owned();
    tx.execute(
        "INSERT OR REPLACE INTO paths (store_path, hash_part, nar_hash, nar_size, refs, ca, sigs)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            n.store_path,
            hash_part,
            n.nar_hash,
            n.nar_size as i64,
            n.references.join(" "),
            n.ca,
            n.sigs.join(" ")
        ],
    )?;
    Ok(())
}

fn row_to_narinfo(r: &rusqlite::Row) -> rusqlite::Result<proto::Narinfo> {
    Ok(proto::Narinfo {
        store_path: r.get(0)?,
        nar_hash: r.get(1)?,
        nar_size: r.get::<_, i64>(2)? as u64,
        references: r
            .get::<_, String>(3)?
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        ca: r.get(4)?,
        sigs: r.get::<_, String>(5)?.split_whitespace().map(str::to_owned).collect(),
    })
}

fn snapshot_rows(conn: &Connection) -> Result<Vec<proto::Narinfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT store_path, nar_hash, nar_size, refs, ca, sigs FROM paths",
    )?;
    let v = stmt
        .query_map([], row_to_narinfo)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(v)
}

pub fn proto_to_remote(n: &proto::Narinfo) -> RemoteNarinfo {
    RemoteNarinfo {
        store_path: n.store_path.clone(),
        compression: "none".into(),
        nar_hash: <[u8; 32]>::try_from(n.nar_hash.as_slice()).unwrap_or([0u8; 32]),
        nar_size: n.nar_size,
        references: n.references.clone(),
        deriver: None,
        ca: (!n.ca.is_empty()).then(|| n.ca.clone()),
        sigs: n.sigs.clone(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn ni(name: &str, hash_byte: u8) -> proto::Narinfo {
        proto::Narinfo {
            store_path: format!("/nix/store/{}{name}", "x".repeat(32)),
            nar_hash: vec![hash_byte; 32],
            nar_size: 100,
            references: vec![],
            ca: "fixed:r:sha256:dummy".into(),
            sigs: vec![],
        }
    }

    fn add(seq: u64, n: proto::Narinfo) -> proto::Event {
        proto::Event { seq, op: Some(proto::event::Op::Add(n)) }
    }

    fn remove(seq: u64, name: &str) -> proto::Event {
        proto::Event {
            seq,
            op: Some(proto::event::Op::Remove(format!("/nix/store/{}{name}", "x".repeat(32)))),
        }
    }

    fn idx(dir: &std::path::Path, name: &str, peers: &[&str]) -> Index {
        let peers: Vec<String> = peers.iter().map(|s| s.to_string()).collect();
        Index::open(&dir.join(format!("cache-{name}")), name, &peers, TrustedKeys::none())
            .unwrap()
    }

    #[test]
    fn lww_multi_holder_and_orphan_gc() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a", "c"]);
        // Two origins hold the same (path, h1).
        assert!(matches!(
            b.apply_suffix("a", 1, &[add(1, ni("-p", 1))]).unwrap(),
            Apply::Applied(1)
        ));
        assert!(matches!(
            b.apply_suffix("c", 1, &[add(1, ni("-p", 1))]).unwrap(),
            Apply::Applied(1)
        ));
        assert_eq!(b.count_narinfos(), 1);
        // Origin a rebuilds the path with different content: LWW repoints a's holding; the h1
        // row survives because c still holds it.
        b.apply_suffix("a", 1, &[add(2, ni("-p", 2))]).unwrap();
        assert_eq!(b.count_narinfos(), 2);
        // c GCs it: h1 is orphaned and dies with its metadata; h2 remains via a.
        b.apply_suffix("c", 1, &[remove(2, "-p")]).unwrap();
        assert_eq!(b.count_narinfos(), 1);
        let rows = b.lookup_hash_part(&"x".repeat(32)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].holders, vec!["a".to_string()]);
        assert_eq!(rows[0].info.nar_hash, [2u8; 32]);
    }

    #[test]
    fn replay_is_idempotent_and_gaps_need_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        let events = [add(1, ni("-p", 1)), add(2, ni("-q", 2))];
        assert!(matches!(b.apply_suffix("a", 1, &events).unwrap(), Apply::Applied(2)));
        // Exact replay: applied 0, state unchanged.
        assert!(matches!(b.apply_suffix("a", 1, &events).unwrap(), Apply::Applied(0)));
        assert_eq!(b.count_narinfos(), 2);
        // A gap cannot be applied.
        assert!(matches!(
            b.apply_suffix("a", 1, &[add(9, ni("-z", 9))]).unwrap(),
            Apply::NeedSnapshot
        ));
        // A regenerated origin (higher gen over existing state) also needs a snapshot.
        assert!(matches!(
            b.apply_suffix("a", 2, &[add(1, ni("-p", 1))]).unwrap(),
            Apply::NeedSnapshot
        ));
        // And the snapshot replaces wholesale.
        let n = b.apply_snapshot("a", 2, 5, &[ni("-r", 3)]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(b.count_narinfos(), 1);
        assert_eq!(b.origin_clock("a").unwrap(), (2, 5));
    }

    #[test]
    fn first_contact_gets_a_snapshot_then_suffixes_then_compaction() {
        let dir = tempfile::tempdir().unwrap();
        // Node a: exports its own fake store.
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let p1 = format!("{}/{}-one", store.display(), "1".repeat(32));
        let p2 = format!("{}/{}-two", store.display(), "2".repeat(32));
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[
                (&p1, [1u8; 32], 10, Some("fixed:r:sha256:x")),
                (&p2, [2u8; 32], 20, Some("fixed:r:sha256:y")),
            ],
        );
        let db = crate::db::StoreDb::open(&db_path, store.to_str().unwrap()).unwrap();
        let a = idx(dir.path(), "a", &["b", "c"]);
        assert_eq!(a.sync_own_db(&db).unwrap(), 2);
        assert_eq!(a.sync_own_db(&db).unwrap(), 0, "differ must be idempotent");

        // First contact: b's zero clock earns a snapshot.
        let b = idx(dir.path(), "b", &["a", "c"]);
        let req =
            proto::SyncRequest { requester: "b".into(), have: b.clock_vector().unwrap() };
        let ups = a.respond(&req).unwrap();
        let up = ups.iter().find(|u| u.origin == "a").unwrap();
        let proto::origin_update::Body::Snapshot(snap) = up.body.as_ref().unwrap() else {
            panic!("first contact must be a snapshot");
        };
        b.apply_snapshot("a", up.generation, up.seq, &snap.held).unwrap();
        assert_eq!(b.count_narinfos(), 2);

        // Incremental: a GCs one path; b's next pull is a 1-event suffix.
        crate::db::tests::delete_path(&db_path, &p2);
        assert_eq!(a.sync_own_db(&db).unwrap(), 1);
        let req =
            proto::SyncRequest { requester: "b".into(), have: b.clock_vector().unwrap() };
        let ups = a.respond(&req).unwrap();
        let up = ups.iter().find(|u| u.origin == "a").unwrap();
        let proto::origin_update::Body::Suffix(sfx) = up.body.as_ref().unwrap() else {
            panic!("incremental pull must be a suffix");
        };
        assert_eq!(sfx.events.len(), 1);
        b.apply_suffix("a", up.generation, &sfx.events).unwrap();
        assert_eq!(b.count_narinfos(), 1);

        // Compaction: only when EVERY configured peer's watermark covers the journal.
        a.record_watermarks("b", &b.clock_vector().unwrap()).unwrap();
        a.compact().unwrap();
        assert!(a.journal_len("a") > 0, "peer c has not acked; journal must be retained");
        let mut c_clock = b.clock_vector().unwrap();
        for cl in &mut c_clock {
            if cl.origin == "b" {
                cl.origin = "c".into(); // pretend c has seen the same
            }
        }
        a.record_watermarks("c", &b.clock_vector().unwrap()).unwrap();
        a.compact().unwrap();
        assert_eq!(a.journal_len("a"), 0, "all peers acked: the deletion can be dropped");
        // A straggler (or newcomer) whose watermark predates the tail gets a snapshot.
        let fresh = idx(dir.path(), "c", &["a", "b"]);
        let req =
            proto::SyncRequest { requester: "c".into(), have: fresh.clock_vector().unwrap() };
        let ups = a.respond(&req).unwrap();
        let up = ups.iter().find(|u| u.origin == "a").unwrap();
        assert!(matches!(up.body, Some(proto::origin_update::Body::Snapshot(_))));
    }

    #[test]
    fn infeasible_rows_are_relayed_but_never_served() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a", "c"]);
        // No CA, no trusted sig: journaled verbatim (faithful relay), absent from the tables.
        let mut bogus = ni("-p", 1);
        bogus.ca = String::new();
        bogus.sigs = vec!["unknown-1:AAAA".into()];
        b.apply_suffix("a", 1, &[add(1, bogus)]).unwrap();
        assert_eq!(b.count_narinfos(), 0);
        assert_eq!(b.journal_len("a"), 1);
        // …and a downstream peer already on this generation receives the event from our
        // journal unchanged (a zero-clock peer would get a snapshot, which carries feasible
        // state only — resurrection after an anchor change rides the ORIGIN's re-export).
        let c = idx(dir.path(), "c", &["a", "b"]);
        c.apply_suffix("a", 1, &[]).unwrap(); // adopt generation 1 at seq 0
        let req =
            proto::SyncRequest { requester: "c".into(), have: c.clock_vector().unwrap() };
        let ups = b.respond(&req).unwrap();
        let up = ups.iter().find(|u| u.origin == "a").unwrap();
        let proto::origin_update::Body::Suffix(sfx) = up.body.as_ref().unwrap() else {
            panic!("expected the relayed suffix");
        };
        assert_eq!(sfx.events.len(), 1);
    }

    #[test]
    fn mw_weights_persist_and_decay_toward_uniform() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["p", "q"]);
        let names = vec!["p".to_string(), "q".to_string()];
        assert!(b.load_mw(&names).unwrap().is_none(), "nothing saved yet");

        b.save_mw(&names, &[1.0, 0.05], 1e8, 0.2).unwrap();
        // Fresh: essentially unchanged.
        let (w, br, al) = b.load_mw(&names).unwrap().unwrap();
        assert!((w[0] - 1.0).abs() < 1e-6 && (w[1] - 0.05).abs() < 0.01, "{w:?}");
        assert!(br > 9e7 && al > 0.19);

        // A day old: halfway back toward uniform.
        b.age_mw(86_400);
        let (w, _, _) = b.load_mw(&names).unwrap().unwrap();
        assert!((w[1] - 0.525).abs() < 0.02, "one half-life ⇒ midpoint, got {}", w[1]);

        // A week old: effectively fresh again (the yardstick fades with it).
        b.age_mw(6 * 86_400);
        let (w, br, al) = b.load_mw(&names).unwrap().unwrap();
        assert!(w[1] > 0.99, "week-old weights are not worth much: {w:?}");
        assert!(br < 1e6 && al < 0.01);

        // Peers that left the config are reaped; new peers start uniform.
        let renamed = vec!["p".to_string(), "r".to_string()];
        let (w, _, _) = b.load_mw(&renamed).unwrap().unwrap();
        assert_eq!(w.len(), 2);
        assert!((w[1] - 1.0).abs() < 1e-9, "unknown peer must start fresh");
    }

    /// A fake store with one CA path, plus the (db_path, StoreDb, path) handles tests need.
    fn own_store(dir: &std::path::Path) -> (std::path::PathBuf, crate::db::StoreDb, String) {
        let store = dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let p = format!("{}/{}-pkg", store.display(), "7".repeat(32));
        let db_path = crate::db::tests::fake_db(
            dir,
            &[(&p, [7u8; 32], 10, Some("fixed:r:sha256:x"))],
        );
        let db = crate::db::StoreDb::open(&db_path, store.to_str().unwrap()).unwrap();
        (db_path, db, p)
    }

    #[test]
    fn merged_peer_sigs_do_not_reemit_our_own_paths() {
        // hold_tx merges sig sets into the shared (path, narhash) row; the differ must compare
        // by SUBSET or every diff re-exports the path forever — a mesh-wide hint/pull livelock.
        let dir = tempfile::tempdir().unwrap();
        let (_db_path, db, path) = own_store(dir.path());
        let a = idx(dir.path(), "a", &["b"]);
        assert_eq!(a.sync_own_db(&db).unwrap(), 1);
        // Peer b holds the same (path, hash) with an extra signature: merged into the row.
        let n = proto::Narinfo {
            store_path: path.clone(),
            nar_hash: vec![7u8; 32],
            nar_size: 10,
            references: vec![],
            ca: "fixed:r:sha256:x".into(),
            sigs: vec!["some-cache-1:AAAA".into()],
        };
        a.apply_suffix("b", 1, &[add(1, n)]).unwrap();
        // The differ sees a strict superset of its own sigs: NOT a change.
        assert_eq!(a.sync_own_db(&db).unwrap(), 0, "sig merge must not re-emit");
        assert_eq!(a.journal_len("a"), 1);
    }

    #[test]
    fn feasibility_regression_emits_a_remove() {
        // A path rebuilt in place without CA/sigs must leave the mesh index, or peers chase
        // bytes we no longer serve.
        let dir = tempfile::tempdir().unwrap();
        let (db_path, db, path) = own_store(dir.path());
        let a = idx(dir.path(), "a", &["b"]);
        assert_eq!(a.sync_own_db(&db).unwrap(), 1);
        assert_eq!(a.lookup_hash_part(&"7".repeat(32)).unwrap().len(), 1);
        crate::db::tests::clear_feasibility(&db_path, &path);
        assert_eq!(a.sync_own_db(&db).unwrap(), 1, "regression must emit a Remove");
        assert!(a.lookup_hash_part(&"7".repeat(32)).unwrap().is_empty());
        assert_eq!(a.sync_own_db(&db).unwrap(), 0, "…exactly once");
    }

    #[test]
    fn respond_defers_origins_past_the_byte_budget() {
        let dir = tempfile::tempdir().unwrap();
        let x = idx(dir.path(), "x", &["a", "b", "c"]);
        x.apply_suffix("a", 1, &[add(1, ni("-pa", 1))]).unwrap();
        x.apply_suffix("b", 1, &[add(1, ni("-pb", 2))]).unwrap();
        // A zero-clock requester with a 1-byte budget: the first data-bearing origin ships,
        // the second is deferred as an empty truncated suffix.
        let c = idx(dir.path(), "c", &["x", "a", "b"]);
        let req = proto::SyncRequest { requester: "c".into(), have: c.clock_vector().unwrap() };
        let ups = x.respond_budgeted(&req, 1).unwrap();
        // Only a/b matter: x's own origin is an empty snapshot that costs no budget.
        let snapshots = ups
            .iter()
            .filter(|u| u.origin != "x")
            .filter(|u| matches!(u.body, Some(proto::origin_update::Body::Snapshot(_))))
            .count();
        // Only a/b matter here too: the responder's own (empty-state) origin may also be
        // deferred once the budget is spent — a harmless extra round for zero bytes.
        let deferred: Vec<_> = ups
            .iter()
            .filter(|u| u.origin != "x")
            .filter(|u| {
                u.truncated
                    && matches!(&u.body,
                        Some(proto::origin_update::Body::Suffix(s)) if s.events.is_empty())
            })
            .collect();
        assert_eq!(snapshots, 1, "exactly one origin fits the budget: {ups:?}");
        assert_eq!(deferred.len(), 1, "the other must be deferred, not dropped: {ups:?}");
        // The deferral round-trips: applying it changes nothing but flags another round, and
        // an unbudgeted follow-up delivers the rest.
        let d = deferred[0];
        assert!(matches!(
            c.apply_suffix(&d.origin, d.generation, &[]).unwrap(),
            Apply::Applied(0)
        ));
        for u in &ups {
            if let Some(proto::origin_update::Body::Snapshot(s)) = &u.body {
                c.apply_snapshot(&u.origin, u.generation, u.seq, &s.held).unwrap();
            }
        }
        let req = proto::SyncRequest { requester: "c".into(), have: c.clock_vector().unwrap() };
        let ups = x.respond_budgeted(&req, usize::MAX).unwrap();
        for u in &ups {
            match &u.body {
                Some(proto::origin_update::Body::Snapshot(s)) => {
                    c.apply_snapshot(&u.origin, u.generation, u.seq, &s.held).unwrap();
                }
                Some(proto::origin_update::Body::Suffix(s)) => {
                    c.apply_suffix(&u.origin, u.generation, &s.events).unwrap();
                }
                _ => {}
            }
        }
        assert_eq!(c.count_narinfos(), 2, "both origins' rows arrive within two rounds");
    }

    #[test]
    fn a_stale_snapshot_cannot_regress_a_newer_copy() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        b.apply_suffix("a", 1, &[add(1, ni("-p", 1)), add(2, ni("-q", 2))]).unwrap();
        // A lagging relay's snapshot at seq 1 arrives late (concurrent-pull race): ignored.
        assert_eq!(b.apply_snapshot("a", 1, 1, &[ni("-p", 1)]).unwrap(), 0);
        assert_eq!(b.count_narinfos(), 2);
        assert_eq!(b.origin_clock("a").unwrap(), (1, 2));
        // A HIGHER generation still replaces wholesale, whatever its seq.
        assert_eq!(b.apply_snapshot("a", 2, 1, &[ni("-r", 3)]).unwrap(), 1);
        assert_eq!(b.count_narinfos(), 1);
    }

    #[test]
    fn self_generation_remints_strictly_above_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        let (g0, _) = b.origin_clock("b").unwrap();
        // The mesh remembers a future generation for us (e.g. our clock went backwards).
        let new = b.bump_self_generation(u64::MAX - 1).unwrap();
        assert_eq!(new, u64::MAX, "must exceed the floor even past the wall clock");
        assert!(new > g0);
        assert_eq!(b.origin_clock("b").unwrap().0, new);
        // …and it persists: a reopen keeps the reminted generation.
        drop(b);
        let b = idx(dir.path(), "b", &["a"]);
        assert_eq!(b.origin_clock("b").unwrap().0, new);
    }

    #[test]
    fn a_changed_trust_anchor_resets_peer_origin_clocks() {
        let dir = tempfile::tempdir().unwrap();
        {
            let b = idx(dir.path(), "b", &["a"]);
            b.apply_suffix("a", 1, &[add(1, ni("-p", 1))]).unwrap();
            assert_eq!(b.origin_clock("a").unwrap(), (1, 1));
        }
        // Reopen with the same (empty) anchor: nothing moves.
        {
            let b = idx(dir.path(), "b", &["a"]);
            assert_eq!(b.origin_clock("a").unwrap(), (1, 1));
        }
        // Reopen with a DIFFERENT anchor: peer clocks zero so the next pulls resync from
        // snapshots (events skipped as infeasible under the old anchor are unrecoverable
        // from a clock that already covers them). Existing rows stay until then.
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([9u8; 32]));
        let pk = format!(
            "k-1:{}",
            {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(*kp.pk)
            }
        );
        let peers: Vec<String> = vec!["a".into()];
        let b = Index::open(
            &dir.path().join("cache-b"),
            "b",
            &peers,
            crate::sig::TrustedKeys::parse(&[pk]),
        )
        .unwrap();
        assert_eq!(b.origin_clock("a").unwrap(), (0, 0));
        assert_eq!(b.journal_len("a"), 0);
        assert_eq!(b.count_narinfos(), 1, "rows persist; snapshots will wipe-replace them");
        // Our own clock is untouched — the differ re-exports newly-feasible paths itself.
        assert!(b.origin_clock("b").unwrap().0 > 0);
    }

    #[test]
    #[ignore] // measurement bench: cargo test --release shard_apply -- --ignored --nocapture
    fn shard_apply_parallelism() {
        // The sharding claim, measured: snapshot applies for DIFFERENT origins run on
        // separate files/locks, so a full-mesh resync storm costs max(apply) wall time, not
        // sum(apply).
        let rows = |origin: u8| -> Vec<proto::Narinfo> {
            (0..20_000u32)
                .map(|i| proto::Narinfo {
                    store_path: format!(
                        "/nix/store/{:08}o{origin:02}{}-pkg-{i}",
                        i,
                        "z".repeat(22)
                    ),
                    nar_hash: {
                        let mut h = [origin; 32];
                        h[..4].copy_from_slice(&i.to_le_bytes());
                        h.to_vec()
                    },
                    nar_size: 1000,
                    references: vec![],
                    ca: "fixed:r:sha256:dummy".into(),
                    sigs: vec![],
                })
                .collect()
        };
        let snaps: Vec<Vec<proto::Narinfo>> = (1..=4).map(rows).collect();

        let dir = tempfile::tempdir().unwrap();
        let seq_idx = idx(dir.path(), "s", &["a", "b", "c", "d"]);
        let t0 = std::time::Instant::now();
        for (i, name) in ["a", "b", "c", "d"].iter().enumerate() {
            seq_idx.apply_snapshot(name, 1, 1, &snaps[i]).unwrap();
        }
        let sequential = t0.elapsed();

        let par_idx = idx(dir.path(), "p", &["a", "b", "c", "d"]);
        let t0 = std::time::Instant::now();
        std::thread::scope(|s| {
            for (i, name) in ["a", "b", "c", "d"].iter().enumerate() {
                let par_idx = &par_idx;
                let snap = &snaps[i];
                s.spawn(move || par_idx.apply_snapshot(name, 1, 1, snap).unwrap());
            }
        });
        let parallel = t0.elapsed();
        println!(
            "[shard] 4 origins x 20k-row snapshots: sequential {sequential:?}, \
             parallel {parallel:?} ({:.2}x)",
            sequential.as_secs_f64() / parallel.as_secs_f64()
        );
        assert_eq!(par_idx.count_narinfos(), 80_000);
        assert!(
            parallel < sequential,
            "parallel applies must beat sequential: {parallel:?} vs {sequential:?}"
        );
    }

    #[test]
    fn departed_origins_are_reaped_at_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let b = idx(dir.path(), "b", &["a", "c"]);
            b.apply_suffix("a", 1, &[add(1, ni("-p", 1))]).unwrap();
            assert_eq!(b.count_narinfos(), 1);
        }
        // Reopen with "a" removed from the config: its rows, journal, and watermark
        // contribution must all go.
        let peers: Vec<String> = vec!["c".into()];
        let b = Index::open(
            &dir.path().join("cache-b"),
            "b",
            &peers,
            TrustedKeys::none(),
        )
        .unwrap();
        assert_eq!(b.count_narinfos(), 0);
        assert!(!b.is_known_origin("a"));
    }
}
