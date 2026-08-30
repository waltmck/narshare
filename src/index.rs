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
//! Persistence lives at `<cache.dir>/index.db` — the daemon's only on-disk state, and state it
//! can always afford to lose: rows are re-learnable from the mesh, signatures re-verify, and a
//! lost cache bumps the self GENERATION so regenerated sequence numbers never alias old ones.
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

/// Journal rows retained per origin beyond the min-watermark rule — the backstop that keeps one
/// dead or long-offline peer from pinning the journal forever. Stragglers land on the snapshot
/// path, which must exist anyway.
const JOURNAL_BACKSTOP: u64 = 50_000;
/// Suffix bytes per origin per sync response; more sets `truncated` and the puller loops.
const SUFFIX_BYTES_CAP: usize = 8 << 20;
/// Half-life of persisted MW weights: at load, each weight is pulled toward uniform (1.0) by
/// 2^(-age/half_life) — an hour-old vector keeps ~97% of its shape, a week-old one ~1%
/// (effectively fresh). The best-rate yardstick and mean-loss decay toward 0 the same way.
const MW_HALF_LIFE_SECS: f64 = 86_400.0;

pub struct Index {
    conn: Mutex<Connection>,
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

impl Index {
    pub fn open(
        dir: &Path,
        self_name: &str,
        peer_names: &[String],
        trusted: TrustedKeys,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating cache dir {}", dir.display()))?;
        let conn = Connection::open(dir.join("index.db"))
            .with_context(|| format!("opening {}/index.db", dir.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS origins (
                 name TEXT PRIMARY KEY,
                 generation INTEGER NOT NULL,
                 seq INTEGER NOT NULL,
                 tail_seq INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS narinfos (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 hash_part TEXT NOT NULL,
                 store_path TEXT NOT NULL,
                 nar_hash BLOB NOT NULL,
                 nar_size INTEGER NOT NULL,
                 refs TEXT NOT NULL,
                 ca TEXT NOT NULL,
                 sigs TEXT NOT NULL,
                 UNIQUE (store_path, nar_hash));
             CREATE INDEX IF NOT EXISTS narinfos_hash ON narinfos(hash_part);
             CREATE INDEX IF NOT EXISTS narinfos_nar ON narinfos(nar_hash);
             CREATE TABLE IF NOT EXISTS holders (
                 origin TEXT NOT NULL,
                 store_path TEXT NOT NULL,
                 narinfo INTEGER NOT NULL,
                 PRIMARY KEY (origin, store_path));
             CREATE INDEX IF NOT EXISTS holders_narinfo ON holders(narinfo);
             CREATE TABLE IF NOT EXISTS journal (
                 origin TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 event BLOB NOT NULL,
                 PRIMARY KEY (origin, seq));
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

        // Self generation: minted once per database lifetime. A lost cache mints a new one, so
        // regenerated (gen, seq) pairs never alias what peers saw before the loss.
        let gen: Option<String> =
            conn.query_row("SELECT value FROM meta WHERE key = 'self_generation'", [], |r| {
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
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('self_generation', ?1)",
                    [g.to_string()],
                )?;
                g
            }
        };
        conn.execute(
            "INSERT INTO origins (name, generation, seq, tail_seq) VALUES (?1, ?2, 0, 0)
             ON CONFLICT (name) DO NOTHING",
            params![self_name, self_gen],
        )?;
        for p in peer_names {
            conn.execute(
                "INSERT INTO origins (name, generation, seq, tail_seq) VALUES (?1, 0, 0, 0)
                 ON CONFLICT (name) DO NOTHING",
                params![p],
            )?;
        }

        // Reap origins that left the config: their rows, journals, and — crucially — their
        // watermark contribution, which would otherwise pin journal compaction forever.
        let mut origin_set: HashSet<String> = peer_names.iter().cloned().collect();
        origin_set.insert(self_name.to_owned());
        let known: Vec<String> = conn
            .prepare("SELECT name FROM origins")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?;
        for o in known {
            if !origin_set.contains(&o) {
                info!("dropping departed origin {o:?} from the index");
                wipe_origin_tx(&conn, &o)?;
                conn.execute("DELETE FROM origins WHERE name = ?1", [&o])?;
                conn.execute("DELETE FROM watermarks WHERE peer = ?1 OR origin = ?1", [&o])?;
            }
        }

        Ok(Self {
            conn: Mutex::new(conn),
            self_name: self_name.to_owned(),
            origin_set,
            peer_names: peer_names.to_vec(),
            trusted,
        })
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

    /// Our full clock vector, for sync requests (doubles as the ack that drives compaction).
    pub fn clock_vector(&self) -> Result<Vec<proto::OriginClock>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT name, generation, seq FROM origins")?;
        let v = stmt
            .query_map([], |r| {
                Ok(proto::OriginClock {
                    origin: r.get(0)?,
                    generation: r.get::<_, i64>(1)? as u64,
                    seq: r.get::<_, i64>(2)? as u64,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(v)
    }

    /// Record what `peer` proved it has seen (its sync request's clock vector).
    pub fn record_watermarks(&self, peer: &str, clocks: &[proto::OriginClock]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        for c in clocks {
            if !self.origin_set.contains(&c.origin) {
                continue;
            }
            // Only meaningful if the peer is on the same generation we are; a stale-generation
            // watermark must not unblock compaction of a journal it has not actually seen.
            let ours: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT generation, seq FROM origins WHERE name = ?1",
                    [&c.origin],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if ours.map(|(g, _)| g as u64) != Some(c.generation) {
                continue;
            }
            conn.execute(
                "INSERT INTO watermarks (peer, origin, seq) VALUES (?1, ?2, ?3)
                 ON CONFLICT (peer, origin) DO UPDATE SET seq = MAX(seq, excluded.seq)",
                params![peer, c.origin, c.seq as i64],
            )?;
        }
        Ok(())
    }

    /// Build the per-origin answer for a sync request: up-to-date, journal suffix, or snapshot.
    pub fn respond(&self, req: &proto::SyncRequest) -> Result<Vec<proto::OriginUpdate>> {
        let have: HashMap<&str, &proto::OriginClock> =
            req.have.iter().map(|c| (c.origin.as_str(), c)).collect();
        let conn = self.conn.lock().unwrap();
        let origins: Vec<(String, i64, i64, i64)> = conn
            .prepare("SELECT name, generation, seq, tail_seq FROM origins")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut out = Vec::new();
        for (name, gen, seq, tail) in origins {
            let (gen, seq, tail) = (gen as u64, seq as u64, tail as u64);
            if gen == 0 {
                continue; // we know nothing about this origin yet
            }
            let theirs = have.get(name.as_str());
            let (their_gen, their_seq) =
                theirs.map(|c| (c.generation, c.seq)).unwrap_or((0, 0));
            if their_gen > gen {
                continue; // they are ahead of us on this origin; nothing useful from us
            }
            let body = if their_gen == gen && their_seq >= seq {
                proto::origin_update::Body::UpToDate(true)
            } else if their_gen == gen && their_seq >= tail {
                // Journal suffix (their_seq, ...], capped.
                let mut events = Vec::new();
                let mut bytes = 0usize;
                let mut truncated = false;
                let mut stmt = conn.prepare_cached(
                    "SELECT seq, event FROM journal WHERE origin = ?1 AND seq > ?2 ORDER BY seq",
                )?;
                let mut rows = stmt.query(params![name, their_seq as i64])?;
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
                let update = proto::OriginUpdate {
                    origin: name.clone(),
                    generation: gen,
                    seq,
                    truncated,
                    body: Some(proto::origin_update::Body::Suffix(proto::Suffix { events })),
                };
                out.push(update);
                continue;
            } else {
                // Their watermark predates our tail, or their generation is stale: snapshot.
                proto::origin_update::Body::Snapshot(proto::Snapshot {
                    held: snapshot_tx(&conn, &name)?,
                })
            };
            out.push(proto::OriginUpdate {
                origin: name,
                generation: gen,
                seq,
                truncated: false,
                body: Some(body),
            });
        }
        Ok(out)
    }

    /// Apply one origin's journal suffix. Idempotent; last-writer-wins per (origin, path).
    pub fn apply_suffix(
        &self,
        origin: &str,
        generation: u64,
        events: &[proto::Event],
    ) -> Result<Apply> {
        if origin == self.self_name || !self.origin_set.contains(origin) {
            bail!("suffix for unexpected origin {origin:?}");
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let (our_gen, mut our_seq): (u64, u64) = {
            let (g, s): (i64, i64) = tx.query_row(
                "SELECT generation, seq FROM origins WHERE name = ?1",
                [origin],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            (g as u64, s as u64)
        };
        if generation < our_gen {
            return Ok(Apply::Applied(0)); // stale relay; ignore
        }
        if generation > our_gen {
            if our_gen == 0 && our_seq == 0 {
                // We know nothing yet: adopting a generation via a from-zero suffix is
                // identical to snapshotting an empty state and replaying.
                tx.execute(
                    "UPDATE origins SET generation = ?2 WHERE name = ?1",
                    params![origin, generation as i64],
                )?;
            } else {
                // The origin regenerated (cache loss): our copy is void. A suffix cannot
                // rebuild it from nothing — only a snapshot can.
                return Ok(Apply::NeedSnapshot);
            }
        }
        let mut applied = 0usize;
        for e in events {
            if e.seq <= our_seq {
                continue; // replay
            }
            if e.seq != our_seq + 1 {
                return Ok(Apply::NeedSnapshot); // gap: suffix does not connect
            }
            tx.execute(
                "INSERT OR REPLACE INTO journal (origin, seq, event) VALUES (?1, ?2, ?3)",
                params![origin, e.seq as i64, e.encode_to_vec()],
            )?;
            self.apply_op_tx(&tx, origin, e)?;
            our_seq = e.seq;
            applied += 1;
        }
        tx.execute(
            "UPDATE origins SET seq = ?2 WHERE name = ?1",
            params![origin, our_seq as i64],
        )?;
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
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let our_gen: u64 = tx
            .query_row("SELECT generation FROM origins WHERE name = ?1", [origin], |r| {
                r.get::<_, i64>(0).map(|g| g as u64)
            })?;
        if generation < our_gen {
            return Ok(0); // stale relay
        }
        wipe_origin_tx(&tx, origin)?;
        let mut inserted = 0usize;
        for n in held {
            if !self.feasible(n) {
                debug!("snapshot of {origin}: skipping infeasible {}", n.store_path);
                continue;
            }
            self.hold_tx(&tx, origin, n)?;
            inserted += 1;
        }
        // We have state as of `seq` but no journal history: suffixes we can serve start there.
        tx.execute(
            "UPDATE origins SET generation = ?2, seq = ?3, tail_seq = ?3 WHERE name = ?1",
            params![origin, generation as i64, seq as i64],
        )?;
        tx.commit()?;
        Ok(inserted)
    }

    fn apply_op_tx(&self, tx: &Connection, origin: &str, e: &proto::Event) -> Result<()> {
        match &e.op {
            Some(proto::event::Op::Add(n)) => {
                if self.feasible(n) {
                    self.hold_tx(tx, origin, n)?;
                } else {
                    // Journaled verbatim for faithful relay, but never enters our tables.
                    debug!("origin {origin}: infeasible add for {} ignored", n.store_path);
                    unhold_tx(tx, origin, &n.store_path)?;
                }
            }
            Some(proto::event::Op::Remove(path)) => unhold_tx(tx, origin, path)?,
            None => {}
        }
        Ok(())
    }

    /// Upsert the narinfo row (merging signatures) and point `origin`'s holding at it.
    fn hold_tx(&self, tx: &Connection, origin: &str, n: &proto::Narinfo) -> Result<()> {
        let hash_part = n
            .store_path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .get(..32)
            .unwrap_or("")
            .to_owned();
        let refs = n.references.join(" ");
        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, sigs FROM narinfos WHERE store_path = ?1 AND nar_hash = ?2",
                params![n.store_path, n.nar_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let id = match existing {
            Some((id, sigs)) => {
                // Merge signatures: different origins may have retained different sig sets.
                let mut set: Vec<&str> = sigs.split_whitespace().collect();
                for s in &n.sigs {
                    if !set.contains(&s.as_str()) {
                        set.push(s);
                    }
                }
                tx.execute(
                    "UPDATE narinfos SET sigs = ?2 WHERE id = ?1",
                    params![id, set.join(" ")],
                )?;
                id
            }
            None => {
                tx.execute(
                    "INSERT INTO narinfos (hash_part, store_path, nar_hash, nar_size, refs, ca, sigs)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        hash_part,
                        n.store_path,
                        n.nar_hash,
                        n.nar_size as i64,
                        refs,
                        n.ca,
                        n.sigs.join(" ")
                    ],
                )?;
                tx.last_insert_rowid()
            }
        };
        // LWW per (origin, path): displace any prior holding of this path.
        let prior: Option<i64> = tx
            .query_row(
                "SELECT narinfo FROM holders WHERE origin = ?1 AND store_path = ?2",
                params![origin, n.store_path],
                |r| r.get(0),
            )
            .optional()?;
        tx.execute(
            "INSERT OR REPLACE INTO holders (origin, store_path, narinfo) VALUES (?1, ?2, ?3)",
            params![origin, n.store_path, id],
        )?;
        if let Some(old) = prior {
            if old != id {
                gc_if_orphaned_tx(tx, old)?;
            }
        }
        Ok(())
    }

    /// The exporting node's half: diff our Nix db against our indexed self-holdings and emit
    /// add/remove events to our own journal. Feasibility is checked HERE, by the exporter, per
    /// the design: only CA or trusted-signed rows leave this node. Returns events emitted.
    pub fn sync_own_db(&self, db: &StoreDb) -> Result<usize> {
        // Snapshot the Nix db first (its own lock), THEN take ours.
        let live: HashSet<String> = db.all_paths()?.into_iter().collect();
        let candidates = db.feasible_candidates()?;

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let held: HashMap<String, (Vec<u8>, String)> = tx
            .prepare(
                "SELECT h.store_path, n.nar_hash, n.sigs FROM holders h
                 JOIN narinfos n ON n.id = h.narinfo WHERE h.origin = ?1",
            )?
            .query_map([&self.self_name], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?
            .collect::<rusqlite::Result<_>>()?;

        let mut seq: u64 = tx
            .query_row("SELECT seq FROM origins WHERE name = ?1", [&self.self_name], |r| {
                r.get::<_, i64>(0).map(|s| s as u64)
            })?;
        let mut emitted = 0usize;
        let emit = |tx: &Connection, e: proto::Event| -> Result<()> {
            tx.execute(
                "INSERT INTO journal (origin, seq, event) VALUES (?1, ?2, ?3)",
                params![self.self_name, e.seq as i64, e.encode_to_vec()],
            )?;
            self.apply_op_tx(tx, &self.self_name, &e)?;
            Ok(())
        };

        for info in &candidates {
            let n = pathinfo_to_proto(info, &db.store_dir);
            let changed = match held.get(&info.path) {
                Some((hash, sigs)) => {
                    hash != &n.nar_hash.to_vec()
                        || sigs.split_whitespace().collect::<HashSet<_>>()
                            != n.sigs.iter().map(String::as_str).collect::<HashSet<_>>()
                }
                None => true,
            };
            // Feasibility (with its ed25519 verify) only for changed rows: unchanged rows were
            // already vetted when first exported.
            if changed && self.feasible(&n) {
                seq += 1;
                emitted += 1;
                emit(&tx, proto::Event { seq, op: Some(proto::event::Op::Add(n)) })?;
            }
        }
        for path in held.keys() {
            if !live.contains(path) {
                seq += 1;
                emitted += 1;
                emit(
                    &tx,
                    proto::Event { seq, op: Some(proto::event::Op::Remove(path.clone())) },
                )?;
            }
        }
        if emitted > 0 {
            tx.execute(
                "UPDATE origins SET seq = ?2 WHERE name = ?1",
                params![self.self_name, seq as i64],
            )?;
        }
        tx.commit()?;
        Ok(emitted)
    }

    /// Compact journals: to the minimum watermark across all configured peers (the ack rule),
    /// with the size backstop so a straggler cannot pin retention forever.
    pub fn compact(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let origins: Vec<(String, i64, i64)> = conn
            .prepare("SELECT name, seq, tail_seq FROM origins")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (origin, seq, tail) in origins {
            let mut floor: i64 = seq;
            for peer in &self.peer_names {
                let w: Option<i64> = conn
                    .query_row(
                        "SELECT seq FROM watermarks WHERE peer = ?1 AND origin = ?2",
                        params![peer, origin],
                        |r| r.get(0),
                    )
                    .optional()?;
                floor = floor.min(w.unwrap_or(0));
            }
            // Backstop: never retain more than JOURNAL_BACKSTOP events regardless of acks.
            floor = floor.max(seq - (JOURNAL_BACKSTOP as i64).min(seq));
            if floor > tail {
                conn.execute(
                    "DELETE FROM journal WHERE origin = ?1 AND seq <= ?2",
                    params![origin, floor],
                )?;
                conn.execute(
                    "UPDATE origins SET tail_seq = ?2 WHERE name = ?1",
                    params![origin, floor],
                )?;
            }
        }
        Ok(())
    }

    /// Lookup by store-path hash part, feasibility re-verified at use.
    pub fn lookup_hash_part(&self, hash_part: &str) -> Result<Vec<Found>> {
        self.lookup("SELECT id FROM narinfos WHERE hash_part = ?1", hash_part)
    }

    /// Lookup by narhash (NAR requests after a proxy restart included — the index persists).
    pub fn lookup_nar_hash(&self, nar_hash: &[u8; 32]) -> Result<Vec<Found>> {
        let conn = self.conn.lock().unwrap();
        let ids: Vec<i64> = conn
            .prepare_cached("SELECT id FROM narinfos WHERE nar_hash = ?1")?
            .query_map(params![&nar_hash[..]], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        self.found_from_ids(&conn, &ids)
    }

    fn lookup(&self, sql: &str, key: &str) -> Result<Vec<Found>> {
        let conn = self.conn.lock().unwrap();
        let ids: Vec<i64> = conn
            .prepare_cached(sql)?
            .query_map([key], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        self.found_from_ids(&conn, &ids)
    }

    fn found_from_ids(&self, conn: &Connection, ids: &[i64]) -> Result<Vec<Found>> {
        let mut out = Vec::new();
        for &id in ids {
            let n: proto::Narinfo = conn.query_row(
                "SELECT store_path, nar_hash, nar_size, refs, ca, sigs FROM narinfos WHERE id = ?1",
                [id],
                |r| {
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
                        sigs: r
                            .get::<_, String>(5)?
                            .split_whitespace()
                            .map(str::to_owned)
                            .collect(),
                    })
                },
            )?;
            // Re-verify at use: a key removed from the anchor makes its rows inert, and
            // re-adding it wakes them — nothing is deleted on trust changes.
            if !self.feasible(&n) {
                continue;
            }
            let holders: Vec<String> = conn
                .prepare_cached("SELECT origin FROM holders WHERE narinfo = ?1")?
                .query_map([id], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()?;
            if holders.is_empty() {
                continue;
            }
            out.push(Found { info: proto_to_remote(&n), holders });
        }
        Ok(out)
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
        let conn = self.conn.lock().unwrap();
        for (name, w) in peers.iter().zip(weights) {
            conn.execute(
                "INSERT INTO mw_state (peer, weight, updated) VALUES (?1, ?2, ?3)
                 ON CONFLICT (peer) DO UPDATE SET weight = excluded.weight,
                                                  updated = excluded.updated",
                params![name, w, now],
            )?;
        }
        conn.execute(
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
        let conn = self.conn.lock().unwrap();
        let rows: HashMap<String, (f64, i64)> = conn
            .prepare("SELECT peer, weight, updated FROM mw_state")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?))))?
            .collect::<rusqlite::Result<_>>()?;
        if rows.is_empty() {
            return Ok(None);
        }
        // Reap rows for peers that left the config.
        for name in rows.keys() {
            if !peers.contains(name) {
                conn.execute("DELETE FROM mw_state WHERE peer = ?1", [name])?;
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
        let globals: Option<String> = conn
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
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE mw_state SET updated = updated - ?1", [secs]).unwrap();
        if let Ok(g) =
            conn.query_row("SELECT value FROM meta WHERE key = 'mw_globals'", [], |r| {
                r.get::<_, String>(0)
            })
        {
            let mut it = g.split_whitespace();
            let (br, al, up) = (
                it.next().unwrap().to_owned(),
                it.next().unwrap().to_owned(),
                it.next().unwrap().parse::<i64>().unwrap(),
            );
            conn.execute(
                "UPDATE meta SET value = ?1 WHERE key = 'mw_globals'",
                [format!("{br} {al} {}", up - secs)],
            )
            .unwrap();
        }
    }

    /// (generation, seq) of an origin as we know it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn origin_clock(&self, origin: &str) -> Result<(u64, u64)> {
        let conn = self.conn.lock().unwrap();
        let (g, s): (i64, i64) = conn.query_row(
            "SELECT generation, seq FROM origins WHERE name = ?1",
            [origin],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((g as u64, s as u64))
    }

    #[cfg(test)]
    pub fn count_narinfos(&self) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM narinfos", [], |r| r.get::<_, i64>(0)).unwrap()
            as usize
    }

    #[cfg(test)]
    pub fn journal_len(&self, origin: &str) -> usize {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM journal WHERE origin = ?1", [origin], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap() as usize
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Drop a holder edge and orphan-GC the narinfo it pointed at.
fn unhold_tx(tx: &Connection, origin: &str, store_path: &str) -> Result<()> {
    let prior: Option<i64> = tx
        .query_row(
            "SELECT narinfo FROM holders WHERE origin = ?1 AND store_path = ?2",
            params![origin, store_path],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id) = prior {
        tx.execute(
            "DELETE FROM holders WHERE origin = ?1 AND store_path = ?2",
            params![origin, store_path],
        )?;
        gc_if_orphaned_tx(tx, id)?;
    }
    Ok(())
}

/// "When no peer has a derivation corresponding to the narinfo, the narinfo (and its
/// signatures) can be garbage collected."
fn gc_if_orphaned_tx(tx: &Connection, narinfo_id: i64) -> Result<()> {
    let holders: i64 = tx.query_row(
        "SELECT COUNT(*) FROM holders WHERE narinfo = ?1",
        [narinfo_id],
        |r| r.get(0),
    )?;
    if holders == 0 {
        tx.execute("DELETE FROM narinfos WHERE id = ?1", [narinfo_id])?;
    }
    Ok(())
}

fn wipe_origin_tx(tx: &Connection, origin: &str) -> Result<()> {
    let held: Vec<i64> = tx
        .prepare("SELECT narinfo FROM holders WHERE origin = ?1")?
        .query_map([origin], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    tx.execute("DELETE FROM holders WHERE origin = ?1", [origin])?;
    for id in held {
        gc_if_orphaned_tx(tx, id)?;
    }
    tx.execute("DELETE FROM journal WHERE origin = ?1", [origin])?;
    Ok(())
}

fn snapshot_tx(conn: &Connection, origin: &str) -> Result<Vec<proto::Narinfo>> {
    let mut stmt = conn.prepare_cached(
        "SELECT n.store_path, n.nar_hash, n.nar_size, n.refs, n.ca, n.sigs
         FROM holders h JOIN narinfos n ON n.id = h.narinfo WHERE h.origin = ?1",
    )?;
    let v = stmt
        .query_map([origin], |r| {
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
        })?
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

fn pathinfo_to_proto(info: &crate::db::PathInfo, store_dir: &str) -> proto::Narinfo {
    proto::Narinfo {
        store_path: info.path.clone(),
        nar_hash: info.nar_hash.to_vec(),
        nar_size: info.nar_size,
        references: info
            .references
            .iter()
            .map(|r| crate::narinfo::basename(r, store_dir).to_owned())
            .collect(),
        ca: info.ca.clone().unwrap_or_default(),
        sigs: info.sigs.clone(),
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
