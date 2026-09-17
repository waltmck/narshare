//! The postgres index backend: the shared-table design in its native habitat.
//!
//! Atomicity is a SQL transaction per composite op; same-origin apply races are arbitrated by
//! `SELECT … FOR UPDATE` on the clock row. Possession rows are independent per (origin, hash),
//! so they need no cross-row serialization now that facts carry no holder-derived state. Signature union is a plain
//! array append of previously-unseen entries inside the upsert, so concurrent attestation
//! merges compose without any read-modify-write in the client.
//!
//! Durability: connections default to `synchronous_commit = off`; SELF-origin applies (and
//! the meta writes naming the self generation) escalate per transaction with
//! `SET LOCAL synchronous_commit = on` — an observed seq must never be reissued with
//! different events, and only the origin can reissue. Async commits can be lost not just on
//! host crashes but on a postgres crash/OOM-kill too (wal_buffers live in the SERVER's shared
//! memory, unlike an embedded store's page-cache writes), which is exactly why self-origin
//! transactions wait for a real WAL flush. Everything lost asynchronously is a replica or a
//! re-learnable fact: crash recovery yields a transaction-consistent prefix, and the next
//! pull re-teaches it. (UNLOGGED tables are deliberately NOT used: they truncate on crash
//! recovery, which would take the self journal with them.)
//!
//! Everything lives in one schema (default "narshare"); layout versioning is wipe-and-resync
//! via `DROP SCHEMA … CASCADE` on a `layout` marker mismatch.

use super::{
    attestation_hash, hash_part_of, leaf_of, merge_into, Clock, HoldOp, SyncStore,
};
use crate::index::proto;
use anyhow::{bail, Context, Result};
use postgres::types::Type;
use postgres::{Client, NoTls, Statement, Transaction};
use std::collections::HashSet;
use std::sync::Mutex;

const LAYOUT: &str = "narshare-pg-3";
/// Idle connections kept for reuse; excess connects are dropped on return. Lookups and applies
/// already serialize per call site, so a small pool covers the real concurrency.
const POOL_MAX: usize = 4;
/// The reconciliation tree's shape — a protocol constant, identical in every backend.
const MERKLE_LEAVES: i32 = 1 << 16;
const MERKLE_FANOUT: i32 = 256;

pub struct PgStore {
    url: String,
    schema: String,
    pool: Mutex<Vec<PooledConn>>,
}

/// A pooled connection with its lazily-prepared hot-path statements: the two proxy lookups run
/// for every substitution the machine attempts, so they should not re-plan per call. Statements
/// are per-connection state, which is why they live in the pool entry.
struct PooledConn {
    client: Client,
    lookup_hp: Option<Statement>,
    lookup_nh: Option<Statement>,
}

impl PooledConn {
    fn new(client: Client) -> Self {
        Self {
            client,
            lookup_hp: None,
            lookup_nh: None,
        }
    }
}

impl std::ops::Deref for PooledConn {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.client
    }
}

impl std::ops::DerefMut for PooledConn {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.client
    }
}

/// Reassemble an attestation hash from the two bigints the aggregates are computed over.
fn halves_to_hash(hi: i64, lo: i64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&hi.to_be_bytes());
    out[8..].copy_from_slice(&lo.to_be_bytes());
    out
}

fn i2u(v: i64) -> u64 {
    v as u64
}
fn u2i(v: u64) -> i64 {
    v as i64
}

/// Advisory-lock key for a nar hash: the first 8 bytes, sign-cast. Collisions between
/// different hashes only over-serialize, never under-serialize.
fn advisory_key(hash: &[u8]) -> i64 {
    i64::from_be_bytes(<[u8; 8]>::try_from(&hash[..8]).unwrap_or([0; 8]))
}

/// The whole-store advisory lock, hierarchically paired with the per-hash locks: fine-grained
/// transactions take it SHARED plus their per-hash exclusives; bulk transactions (snapshot
/// applies, departures) take it EXCLUSIVE and skip per-hash locking entirely — advisory locks
/// live in the server's lock table (max_locks_per_transaction), and 100k of them in one
/// transaction exhausts it, as the control-plane bench demonstrated.
const GLOBAL_LOCK: i64 = i64::from_be_bytes(*b"narshare");
/// Above this many distinct hashes, a transaction escalates to the exclusive global lock.
const PER_HASH_LOCK_CAP: usize = 1_000;

/// Take retention-stamp locks for the given hashes: global-shared + sorted per-hash exclusives
/// (the global order that makes cross-origin transactions deadlock-free), escalating to
/// global-exclusive for bulk sets.
fn lock_hashes<'a>(tx: &mut Transaction<'_>, hashes: impl Iterator<Item = &'a [u8]>) -> Result<()> {
    let mut keys: Vec<i64> = hashes.map(advisory_key).collect();
    keys.sort_unstable();
    keys.dedup();
    if keys.len() > PER_HASH_LOCK_CAP {
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&GLOBAL_LOCK])?;
        return Ok(());
    }
    tx.execute("SELECT pg_advisory_xact_lock_shared($1)", &[&GLOBAL_LOCK])?;
    for k in keys {
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&k])?;
    }
    Ok(())
}

/// Lock the clock row (creating it at zero first) and return it — the same-origin race gate.
fn lock_clock(tx: &mut Transaction<'_>, origin: &str) -> Result<Clock> {
    tx.execute(
        "INSERT INTO clocks (origin, generation, seq, tail_seq) VALUES ($1, 0, 0, 0)
         ON CONFLICT (origin) DO NOTHING",
        &[&origin],
    )?;
    let row = tx.query_one(
        "SELECT generation, seq, tail_seq FROM clocks WHERE origin = $1 FOR UPDATE",
        &[&origin],
    )?;
    Ok(Clock {
        generation: i2u(row.get(0)),
        seq: i2u(row.get(1)),
        tail_seq: i2u(row.get(2)),
    })
}

/// The possession-change statements, prepared ONCE per transaction — bulk applies run these
/// tens of thousands of times, and re-parsing per row dominated the ingest bench.
struct HoldStmts {
    add: Statement,
    del: Statement,
}

fn hold_stmts(tx: &mut Transaction<'_>) -> Result<HoldStmts> {
    Ok(HoldStmts {
        add: tx.prepare(
            "INSERT INTO holdings (origin, nar_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )?,
        del: tx.prepare("DELETE FROM holdings WHERE origin = $1 AND nar_hash = $2")?,
    })
}

/// Materialize one possession change. The transaction sees its own prior writes, so batched
/// Add/Drop sequences compose naturally.
fn apply_hold(
    tx: &mut Transaction<'_>,
    st: &HoldStmts,
    origin: &str,
    op: &HoldOp,
) -> Result<()> {
    match op {
        HoldOp::Add(h) => {
            tx.execute(&st.add, &[&origin, &&h[..]])?;
        }
        HoldOp::Drop(h) => {
            tx.execute(&st.del, &[&origin, &&h[..]])?;
        }
    }
    Ok(())
}

/// Dump cursor: the (hash_part, nar_hash) primary key of the last row served. Opaque outside
/// this backend — only the responder that issued it ever interprets it — so paging in primary
/// key order here is fine even though rocksdb pages in attestation-hash order. A malformed
/// cursor degrades to a dump from the start, which grow-only dedup absorbs.
fn split_cursor(cursor: &[u8]) -> (String, Vec<u8>) {
    if cursor.len() < 32 {
        return (String::new(), Vec::new());
    }
    match std::str::from_utf8(&cursor[..32]) {
        Ok(hp) => (hp.to_owned(), cursor[32..].to_vec()),
        Err(_) => (String::new(), Vec::new()),
    }
}

fn join_cursor(hash_part: &str, nar_hash: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(hash_part.len() + nar_hash.len());
    c.extend_from_slice(hash_part.as_bytes());
    c.extend_from_slice(nar_hash);
    c
}

fn row_to_att(row: &postgres::Row) -> proto::Attestation {
    proto::Attestation {
        store_path: row.get(0),
        nar_hash: row.get(1),
        nar_size: i2u(row.get(2)),
        references: row.get(3),
        ca: row.get(4),
        sigs: row.get(5),
    }
}

const ATT_COLS: &str = "store_path, nar_hash, nar_size, refs, ca, sigs";

/// Fold one attestation hash into the maintained aggregates. XOR is its own inverse, so this
/// both adds and removes. The ROOT is deliberately not a stored row: it would be one hot row
/// every fact write contends on, and a 256-row aggregate over level 1 costs nothing instead.
fn agg_xor(tx: &mut Transaction<'_>, h: &[u8; 16]) -> Result<()> {
    let leaf = leaf_of(h) as i32;
    let hi = i64::from_be_bytes(<[u8; 8]>::try_from(&h[..8]).unwrap());
    let lo = i64::from_be_bytes(<[u8; 8]>::try_from(&h[8..]).unwrap());
    for (level, node) in [(2i16, leaf), (1i16, leaf >> 8)] {
        tx.execute(
            "INSERT INTO att_agg (level, node, hi, lo) VALUES ($1, $2, $3, $4)
             ON CONFLICT (level, node) DO UPDATE
                 SET hi = att_agg.hi # EXCLUDED.hi, lo = att_agg.lo # EXCLUDED.lo",
            &[&level, &node, &hi, &lo],
        )?;
    }
    Ok(())
}

/// Merge one attestation: read the current row, merge in Rust (shared with every other
/// backend, so the canonical form and its hash are identical mesh-wide), write it back with
/// the attestation hash split into the two bigints the aggregates are computed over.
///
/// Client-side read-modify-write, deliberately: the SQL upsert this replaced could union
/// signature arrays, but not put them in a canonical ORDER, and two nodes that disagree on
/// the encoding of the same logical fact would hash it differently and never converge.
fn merge_att(tx: &mut Transaction<'_>, att: &proto::Attestation) -> Result<bool> {
    let hp = hash_part_of(&att.store_path).to_owned();
    let row = tx.query_opt(
        "SELECT store_path, nar_size, refs, ca, sigs, h_hi, h_lo FROM attestations
         WHERE hash_part = $1 AND nar_hash = $2 FOR UPDATE",
        &[&hp, &&att.nar_hash[..]],
    )?;
    let old_hash = row.as_ref().map(|r| halves_to_hash(r.get(5), r.get(6)));
    let existing = row.as_ref().map(|r| proto::Attestation {
        store_path: r.get(0),
        nar_hash: att.nar_hash.clone(),
        nar_size: i2u(r.get(1)),
        references: r.get(2),
        ca: r.get(3),
        sigs: r.get(4),
    });
    let Some(merged) = merge_into(existing, att) else {
        return Ok(false);
    };
    let h = attestation_hash(&merged);
    if old_hash == Some(h) {
        return Ok(false); // identical content arriving by another route: nothing moves
    }
    let leaf = leaf_of(&h) as i32;
    let hi = i64::from_be_bytes(<[u8; 8]>::try_from(&h[..8]).unwrap());
    let lo = i64::from_be_bytes(<[u8; 8]>::try_from(&h[8..]).unwrap());
    tx.execute(
        "INSERT INTO attestations
             (hash_part, nar_hash, store_path, nar_size, refs, ca, sigs, leaf, h_hi, h_lo)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (hash_part, nar_hash) DO UPDATE SET
             store_path = EXCLUDED.store_path, nar_size = EXCLUDED.nar_size,
             refs = EXCLUDED.refs, ca = EXCLUDED.ca, sigs = EXCLUDED.sigs,
             leaf = EXCLUDED.leaf, h_hi = EXCLUDED.h_hi, h_lo = EXCLUDED.h_lo",
        &[
            &hp,
            &&merged.nar_hash[..],
            &merged.store_path,
            &u2i(merged.nar_size),
            &merged.references,
            &merged.ca,
            &merged.sigs,
            &leaf,
            &hi,
            &lo,
        ],
    )?;
    // Same transaction as the row: the tree cannot describe a set that was not committed,
    // nor miss one that was.
    if let Some(old) = old_hash {
        agg_xor(tx, &old)?;
    }
    agg_xor(tx, &h)?;
    Ok(true)
}

impl PgStore {
    /// `url` is a postgres connection string (URL or key=value form); `schema` isolates one
    /// index per database (the production default is "narshare").
    pub fn connect(url: &str, schema: &str, unlogged: bool) -> Result<Self> {
        if schema.is_empty()
            || !schema
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || schema.as_bytes()[0].is_ascii_digit()
        {
            bail!("index schema name must be a plain identifier, got {schema:?}");
        }
        let store = Self {
            url: url.to_owned(),
            schema: schema.to_owned(),
            pool: Mutex::new(Vec::new()),
        };
        store.migrate(unlogged)?;
        Ok(store)
    }

    fn new_conn(&self) -> Result<Client> {
        let mut c = Client::connect(&self.url, NoTls)
            .with_context(|| format!("connecting to postgres index at {}", self.url))?;
        c.batch_execute(&format!(
            "CREATE SCHEMA IF NOT EXISTS \"{s}\"; SET search_path TO \"{s}\";
             SET synchronous_commit = off",
            s = self.schema
        ))?;
        Ok(c)
    }

    /// Run `f` on a pooled connection; a connection that saw an error and closed is dropped
    /// rather than returned (the next call reconnects).
    fn with_conn<R>(&self, f: impl FnOnce(&mut PooledConn) -> Result<R>) -> Result<R> {
        let mut conn = match self.pool.lock().unwrap().pop() {
            Some(c) => c,
            None => PooledConn::new(self.new_conn()?),
        };
        let out = f(&mut conn);
        if !conn.client.is_closed() {
            let mut pool = self.pool.lock().unwrap();
            if pool.len() < POOL_MAX {
                pool.push(conn);
            }
        }
        out
    }

    fn migrate(&self, unlogged: bool) -> Result<()> {
        let mut c = self.new_conn()?;
        let stored: Option<String> = c
            .query_opt("SELECT value FROM meta WHERE key = 'layout'", &[])
            .ok()
            .flatten()
            .map(|r| r.get(0));
        if let Some(l) = &stored {
            if l == LAYOUT {
                return Ok(());
            }
            tracing::info!("mesh index layout changed: wiping the (disposable) schema for resync");
            c.batch_execute(&format!(
                "DROP SCHEMA \"{s}\" CASCADE; CREATE SCHEMA \"{s}\"; SET search_path TO \"{s}\"",
                s = self.schema
            ))?;
        }
        let t = if unlogged {
            "CREATE UNLOGGED TABLE IF NOT EXISTS"
        } else {
            "CREATE TABLE IF NOT EXISTS"
        };
        c.batch_execute(&format!(
            "{t} meta (key text PRIMARY KEY, value text NOT NULL);
             {t} clocks (origin text PRIMARY KEY,
                         generation int8 NOT NULL, seq int8 NOT NULL, tail_seq int8 NOT NULL);
             {t} journal (origin text NOT NULL, seq int8 NOT NULL, event bytea NOT NULL,
                          PRIMARY KEY (origin, seq));
             {t} holdings (origin text NOT NULL, nar_hash bytea NOT NULL,
                           PRIMARY KEY (origin, nar_hash));
             DROP INDEX IF EXISTS holdings_by_hash;
             CREATE INDEX IF NOT EXISTS holdings_by_hash_origin
                 ON holdings (nar_hash, origin);
             {t} attestations (hash_part text NOT NULL, nar_hash bytea NOT NULL,
                               store_path text NOT NULL, nar_size int8 NOT NULL,
                               refs text[] NOT NULL, ca text NOT NULL, sigs text[] NOT NULL,
                               leaf int NOT NULL, h_hi int8 NOT NULL, h_lo int8 NOT NULL,
                               PRIMARY KEY (hash_part, nar_hash));
             CREATE INDEX IF NOT EXISTS attestations_by_hash ON attestations (nar_hash);
             CREATE INDEX IF NOT EXISTS attestations_by_leaf ON attestations (leaf);
             -- The Merkle aggregates, MAINTAINED rather than recomputed: one row per
             -- non-empty node (level 2 = leaf, level 1 = coarse), XOR-merged in the SAME
             -- transaction as the fact write. Recomputing meant a table aggregate per
             -- response; this makes the root and a descent 256-row reads at any table size.
             -- Sparse by construction: an unwritten node has no row, and absent == zero.
             {t} att_agg (level int2 NOT NULL, node int NOT NULL,
                          hi int8 NOT NULL, lo int8 NOT NULL,
                          PRIMARY KEY (level, node));
             {t} watermarks (peer text NOT NULL, origin text NOT NULL, seq int8 NOT NULL,
                             PRIMARY KEY (peer, origin));
             {t} mw_state (peer text PRIMARY KEY, weight float8 NOT NULL, updated int8 NOT NULL);
             INSERT INTO meta (key, value) VALUES ('layout', '{LAYOUT}')
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;",
        ))?;
        self.pool.lock().unwrap().push(PooledConn::new(c));
        Ok(())
    }
}

impl SyncStore for PgStore {
    fn meta_get(&self, key: &str) -> Result<Option<String>> {
        self.with_conn(|c| {
            Ok(
                c.query_opt("SELECT value FROM meta WHERE key = $1", &[&key])?
                    .map(|r| r.get(0)),
            )
        })
    }

    fn meta_put(&self, key: &str, value: &str) -> Result<()> {
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            // Rare writes, and one of them names the self generation: always durable.
            tx.batch_execute("SET LOCAL synchronous_commit = on")?;
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[&key, &value],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    fn clock(&self, origin: &str) -> Result<Clock> {
        self.with_conn(|c| {
            Ok(c.query_opt(
                "SELECT generation, seq, tail_seq FROM clocks WHERE origin = $1",
                &[&origin],
            )?
            .map(|r| Clock {
                generation: i2u(r.get(0)),
                seq: i2u(r.get(1)),
                tail_seq: i2u(r.get(2)),
            })
            .unwrap_or_default())
        })
    }

    fn set_generation(&self, origin: &str, generation: u64) -> Result<()> {
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            // Only ever called for the self origin: durable.
            tx.batch_execute("SET LOCAL synchronous_commit = on")?;
            tx.execute(
                "INSERT INTO clocks (origin, generation, seq, tail_seq) VALUES ($1, $2, 0, 0)
                 ON CONFLICT (origin) DO UPDATE SET generation = EXCLUDED.generation",
                &[&origin, &u2i(generation)],
            )?;
            tx.commit()?;
            Ok(())
        })
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
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            if durable {
                // Self-origin commits wait for the WAL flush (see module docs).
                tx.batch_execute("SET LOCAL synchronous_commit = on")?;
            }
            let cur = lock_clock(&mut tx, origin)?;
            if (cur.generation, cur.seq) != expect {
                return Ok(false);
            }
            let hold_hashes = holds.iter().map(|op| match op {
                HoldOp::Add(h) | HoldOp::Drop(h) => &h[..],
            });
            let att_hashes = attests.iter().map(|a| &a.nar_hash[..]);
            lock_hashes(&mut tx, hold_hashes.chain(att_hashes))?;
            let ins = tx.prepare_typed(
                "INSERT INTO journal (origin, seq, event) VALUES ($1, $2, $3)
                 ON CONFLICT (origin, seq) DO UPDATE SET event = EXCLUDED.event",
                &[Type::TEXT, Type::INT8, Type::BYTEA],
            )?;
            for (seq, bytes) in journal {
                tx.execute(&ins, &[&origin, &u2i(*seq), bytes])?;
            }
            let hst = hold_stmts(&mut tx)?;
            for op in holds {
                apply_hold(&mut tx, &hst, origin, op)?;
            }
            for att in attests {
                merge_att(&mut tx, att)?;
            }
            tx.execute(
                "UPDATE clocks SET generation = $2, seq = $3 WHERE origin = $1",
                &[&origin, &u2i(set.0), &u2i(set.1)],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }

    fn replace_holdings(
        &self,
        origin: &str,
        generation: u64,
        seq: u64,
        held: &[[u8; 32]],
    ) -> Result<bool> {
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            let cur = lock_clock(&mut tx, origin)?;
            if generation < cur.generation || (generation == cur.generation && seq < cur.seq) {
                return Ok(false);
            }
            let old: HashSet<Vec<u8>> = tx
                .query(
                    "SELECT nar_hash FROM holdings WHERE origin = $1",
                    &[&origin],
                )?
                .into_iter()
                .map(|r| r.get(0))
                .collect();
            let new: HashSet<Vec<u8>> = held.iter().map(|h| h.to_vec()).collect();
            lock_hashes(&mut tx, old.union(&new).map(|h| &h[..]))?;
            let hst = hold_stmts(&mut tx)?;
            for h in old.difference(&new) {
                let h32 = <[u8; 32]>::try_from(&h[..]).context("corrupt holding row")?;
                apply_hold(&mut tx, &hst, origin, &HoldOp::Drop(h32))?;
            }
            for h in new.difference(&old) {
                let h32 = <[u8; 32]>::try_from(&h[..]).unwrap();
                apply_hold(&mut tx, &hst, origin, &HoldOp::Add(h32))?;
            }
            tx.execute("DELETE FROM journal WHERE origin = $1", &[&origin])?;
            tx.execute(
                "UPDATE clocks SET generation = $2, seq = $3, tail_seq = $3 WHERE origin = $1",
                &[&origin, &u2i(generation), &u2i(seq)],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }

    fn merge_attestations(&self, attests: &[proto::Attestation]) -> Result<usize> {
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            lock_hashes(&mut tx, attests.iter().map(|a| &a.nar_hash[..]))?;
            let mut changed = 0usize;
            for att in attests {
                changed += merge_att(&mut tx, att)? as usize;
            }
            tx.commit()?;
            Ok(changed)
        })
    }

    fn journal_suffix(
        &self,
        origin: &str,
        after: u64,
        max_bytes: usize,
    ) -> Result<(Vec<Vec<u8>>, bool)> {
        self.with_conn(|c| {
            let rows = c.query(
                "SELECT event FROM journal WHERE origin = $1 AND seq > $2 ORDER BY seq",
                &[&origin, &u2i(after)],
            )?;
            let mut events = Vec::new();
            let mut bytes = 0usize;
            for row in rows {
                let e: Vec<u8> = row.get(0);
                if bytes + e.len() > max_bytes && !events.is_empty() {
                    return Ok((events, true));
                }
                bytes += e.len();
                events.push(e);
            }
            Ok((events, false))
        })
    }

    fn holdings(&self, origin: &str) -> Result<Vec<[u8; 32]>> {
        self.with_conn(|c| {
            Ok(c.query(
                "SELECT nar_hash FROM holdings WHERE origin = $1",
                &[&origin],
            )?
            .into_iter()
            .filter_map(|r| <[u8; 32]>::try_from(&r.get::<_, Vec<u8>>(0)[..]).ok())
            .collect())
        })
    }

    fn attestation_page(
        &self,
        prefix: &[u8],
        cursor: &[u8],
        max_bytes: usize,
    ) -> Result<(Vec<proto::Attestation>, Option<Vec<u8>>)> {
        use prost::Message as _;
        const FETCH: i64 = 1024;
        // The Merkle node as a leaf range — this backend keys rows by path identity, so the
        // subtree is expressed as a filter rather than a key range, but it selects exactly
        // the same attestations as the rocksdb range scan does.
        let (leaf_lo, leaf_hi): (i32, i32) = match prefix.len() {
            0 => (0, MERKLE_LEAVES),
            1 => {
                let base = prefix[0] as i32 * MERKLE_FANOUT;
                (base, base + MERKLE_FANOUT)
            }
            2 => {
                let leaf = u16::from_be_bytes([prefix[0], prefix[1]]) as i32;
                (leaf, leaf + 1)
            }
            n => bail!("merkle tree is depth two; cannot address a {n}-byte prefix"),
        };
        let (mut hp, mut nh) = split_cursor(cursor);
        self.with_conn(|c| {
            let mut page: Vec<proto::Attestation> = Vec::new();
            let mut used = 0usize;
            loop {
                let rows = c.query(
                    &format!(
                        "SELECT {ATT_COLS}, hash_part FROM attestations
                         WHERE (hash_part, nar_hash) > ($1, $2)
                           AND leaf >= $3 AND leaf < $4
                         ORDER BY hash_part, nar_hash LIMIT $5"
                    ),
                    &[&hp, &nh, &leaf_lo, &leaf_hi, &FETCH],
                )?;
                let exhausted = rows.len() < FETCH as usize;
                for r in &rows {
                    let att = row_to_att(r);
                    let len = att.encoded_len();
                    if used + len > max_bytes && !page.is_empty() {
                        return Ok((page, Some(join_cursor(&hp, &nh))));
                    }
                    used += len;
                    hp = r.get(6);
                    nh = r.get(1);
                    page.push(att);
                }
                if exhausted {
                    return Ok((page, None));
                }
            }
        })
    }

    fn compact_journal(&self, origin: &str, floor: u64) -> Result<()> {
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            let cur = lock_clock(&mut tx, origin)?;
            if floor <= cur.tail_seq {
                return Ok(());
            }
            tx.execute(
                "DELETE FROM journal WHERE origin = $1 AND seq <= $2",
                &[&origin, &u2i(floor)],
            )?;
            tx.execute(
                "UPDATE clocks SET tail_seq = $2 WHERE origin = $1",
                &[&origin, &u2i(floor)],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    fn retain_origins(&self, keep: &[String]) -> Result<()> {
        let keep: Vec<String> = keep.to_vec();
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            let departed: Vec<String> = tx
                .query(
                    "SELECT origin FROM clocks WHERE origin <> ALL ($1)",
                    &[&keep],
                )?
                .into_iter()
                .map(|r| r.get(0))
                .collect();
            for origin in &departed {
                tracing::info!("dropping departed origin {origin:?} from the index");
                let held: Vec<Vec<u8>> = tx
                    .query("SELECT nar_hash FROM holdings WHERE origin = $1", &[origin])?
                    .into_iter()
                    .map(|r| r.get(0))
                    .collect();
                lock_hashes(&mut tx, held.iter().map(|h| &h[..]))?;
                let hst = hold_stmts(&mut tx)?;
                for h in held {
                    let h32 = <[u8; 32]>::try_from(&h[..]).context("corrupt holding row")?;
                    apply_hold(&mut tx, &hst, origin, &HoldOp::Drop(h32))?;
                }
                tx.execute("DELETE FROM journal WHERE origin = $1", &[origin])?;
                tx.execute("DELETE FROM clocks WHERE origin = $1", &[origin])?;
            }
            tx.execute(
                "DELETE FROM watermarks WHERE peer <> ALL ($1) OR origin <> ALL ($1)",
                &[&keep],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    fn lookup_hash_part(&self, hash_part: &str) -> Result<Vec<(proto::Attestation, Vec<String>)>> {
        self.with_conn(|c| {
            if c.lookup_hp.is_none() {
                c.lookup_hp = Some(c.client.prepare(&format!(
                    "SELECT {ATT_COLS},
                            COALESCE((SELECT array_agg(h.origin) FROM holdings h
                                      WHERE h.nar_hash = attestations.nar_hash), '{{}}')
                     FROM attestations WHERE hash_part = $1"
                ))?);
            }
            let stmt = c.lookup_hp.clone().expect("prepared above");
            let rows = c.client.query(&stmt, &[&hash_part])?;
            Ok(rows
                .iter()
                .map(|r| (row_to_att(r), r.get::<_, Vec<String>>(6)))
                .filter(|(_, holders)| !holders.is_empty())
                .collect())
        })
    }

    fn lookup_nar_hash(
        &self,
        nar_hash: &[u8; 32],
    ) -> Result<Vec<(proto::Attestation, Vec<String>)>> {
        self.with_conn(|c| {
            if c.lookup_nh.is_none() {
                c.lookup_nh = Some(c.client.prepare(&format!(
                    "SELECT {ATT_COLS},
                            COALESCE((SELECT array_agg(h.origin) FROM holdings h
                                      WHERE h.nar_hash = attestations.nar_hash), '{{}}')
                     FROM attestations WHERE nar_hash = $1"
                ))?);
            }
            let stmt = c.lookup_nh.clone().expect("prepared above");
            let rows = c.client.query(&stmt, &[&&nar_hash[..]])?;
            Ok(rows
                .iter()
                .map(|r| (row_to_att(r), r.get::<_, Vec<String>>(6)))
                .filter(|(_, holders)| !holders.is_empty())
                .collect())
        })
    }

    fn for_each_claim(
        &self,
        f: &mut dyn FnMut(super::ClaimRow) -> Result<()>,
    ) -> Result<()> {
        const FETCH: i64 = 4096;
        self.with_conn(|c| {
            let (mut hp, mut nh) = split_cursor(b"");
            loop {
                // Keyset pagination (see attestation_page): the claim set is O(mesh) and must
                // never be materialized whole on either end of the wire.
                let rows = c.query(
                    "SELECT store_path, nar_hash, sigs, hash_part FROM attestations
                     WHERE (hash_part, nar_hash) > ($1, $2)
                     ORDER BY hash_part, nar_hash LIMIT $3",
                    &[&hp, &nh, &FETCH],
                )?;
                let exhausted = rows.len() < FETCH as usize;
                for r in rows {
                    hp = r.get(3);
                    let hash: Vec<u8> = r.get(1);
                    nh = hash.clone();
                    f((r.get(0), hash, r.get(2)))?;
                }
                if exhausted {
                    return Ok(());
                }
            }
        })
    }

    fn attestation_sigs(&self, hash_part: &str, nar_hash: &[u8]) -> Result<Option<Vec<String>>> {
        self.with_conn(|c| {
            Ok(c.query_opt(
                "SELECT sigs FROM attestations WHERE hash_part = $1 AND nar_hash = $2",
                &[&hash_part, &nar_hash],
            )?
            .map(|r| r.get(0)))
        })
    }

    fn is_held(&self, origin: &str, nar_hash: &[u8; 32]) -> Result<bool> {
        self.with_conn(|c| {
            Ok(c.query_opt(
                "SELECT 1 FROM holdings WHERE origin = $1 AND nar_hash = $2",
                &[&origin, &&nar_hash[..]],
            )?
            .is_some())
        })
    }

    fn advance_watermark(&self, peer: &str, origin: &str, seq: u64) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO watermarks (peer, origin, seq) VALUES ($1, $2, $3)
                 ON CONFLICT (peer, origin) DO UPDATE
                     SET seq = GREATEST(watermarks.seq, EXCLUDED.seq)",
                &[&peer, &origin, &u2i(seq)],
            )?;
            Ok(())
        })
    }

    fn watermarks(&self) -> Result<Vec<(String, String, u64)>> {
        self.with_conn(|c| {
            Ok(c.query("SELECT peer, origin, seq FROM watermarks", &[])?
                .into_iter()
                .map(|r| (r.get(0), r.get(1), i2u(r.get(2))))
                .collect())
        })
    }

    fn mw_save(&self, rows: &[(String, f64)], updated: u64, globals: &str) -> Result<()> {
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            for (peer, w) in rows {
                tx.execute(
                    "INSERT INTO mw_state (peer, weight, updated) VALUES ($1, $2, $3)
                     ON CONFLICT (peer) DO UPDATE
                         SET weight = EXCLUDED.weight, updated = EXCLUDED.updated",
                    &[peer, w, &u2i(updated)],
                )?;
            }
            tx.execute(
                "INSERT INTO meta (key, value) VALUES ('mw_globals', $1)
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[&globals],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    fn mw_load(&self) -> Result<(Vec<(String, f64, u64)>, Option<String>)> {
        self.with_conn(|c| {
            let rows = c
                .query("SELECT peer, weight, updated FROM mw_state", &[])?
                .into_iter()
                .map(|r| (r.get(0), r.get(1), i2u(r.get(2))))
                .collect();
            let globals = c
                .query_opt("SELECT value FROM meta WHERE key = 'mw_globals'", &[])?
                .map(|r| r.get(0));
            Ok((rows, globals))
        })
    }

    fn mw_prune(&self, keep: &[String]) -> Result<()> {
        let keep = keep.to_vec();
        self.with_conn(|c| {
            c.execute("DELETE FROM mw_state WHERE peer <> ALL ($1)", &[&keep])?;
            Ok(())
        })
    }

    fn mw_shift_updated(&self, secs: i64) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "UPDATE mw_state SET updated = GREATEST(updated - $1, 0)",
                &[&secs],
            )?;
            if let Some(g) = c
                .query_opt("SELECT value FROM meta WHERE key = 'mw_globals'", &[])?
                .map(|r| r.get::<_, String>(0))
            {
                let mut it = g.split_whitespace();
                if let (Some(br), Some(al), Some(Ok(up))) =
                    (it.next(), it.next(), it.next().map(|u| u.parse::<i64>()))
                {
                    c.execute(
                        "UPDATE meta SET value = $1 WHERE key = 'mw_globals'",
                        &[&format!("{br} {al} {}", up - secs)],
                    )?;
                }
            }
            Ok(())
        })
    }

    fn origin_stats(&self, origin: &str) -> Result<(u64, u64)> {
        self.with_conn(|c| {
            let j: i64 = c
                .query_one("SELECT COUNT(*) FROM journal WHERE origin = $1", &[&origin])?
                .get(0);
            let h: i64 = c
                .query_one(
                    "SELECT COUNT(*) FROM holdings WHERE origin = $1",
                    &[&origin],
                )?
                .get(0);
            Ok((j as u64, h as u64))
        })
    }

    fn merkle_root(&self) -> Result<[u8; 16]> {
        // 256 rows at most — never the fact table.
        self.with_conn(|c| {
            let row = c.query_one(
                "SELECT COALESCE(bit_xor(hi), 0), COALESCE(bit_xor(lo), 0)
                 FROM att_agg WHERE level = 1",
                &[],
            )?;
            Ok(halves_to_hash(row.get(0), row.get(1)))
        })
    }

    fn merkle_children(&self, prefix: &[u8]) -> Result<Vec<[u8; 16]>> {
        // Read from the maintained rows: no cache to go stale (this backend is SHARED between
        // processes, and a stale aggregate that happened to match would read as "in sync" —
        // the one failure worse than no reconciliation) and no table aggregate either.
        let (level, lo, hi): (i16, i32, i32) = match prefix.len() {
            0 => (1, 0, MERKLE_FANOUT),
            1 => {
                let base = prefix[0] as i32 * MERKLE_FANOUT;
                (2, base, base + MERKLE_FANOUT)
            }
            n => bail!("merkle tree is depth two; cannot expand a {n}-byte prefix"),
        };
        self.with_conn(|c| {
            let mut out = vec![[0u8; 16]; MERKLE_FANOUT as usize];
            for r in c.query(
                "SELECT node, hi, lo FROM att_agg WHERE level = $1 AND node >= $2 AND node < $3",
                &[&level, &lo, &hi],
            )? {
                let node: i32 = r.get(0);
                out[(node - lo) as usize] = halves_to_hash(r.get(1), r.get(2));
            }
            Ok(out)
        })
    }

    fn count_attestations(&self) -> Result<u64> {
        self.with_conn(|c| {
            let n: i64 = c
                .query_one("SELECT COUNT(*) FROM attestations", &[])?
                .get(0);
            Ok(n as u64)
        })
    }
}

/// Test support: a throwaway single-user postgres cluster on a unix socket, shared by every
/// test in the process, killed with the process (PDEATHSIG). Tests use one schema each, so
/// they never interfere. Skips (returning None) when `initdb` is not on PATH and no
/// NARSHARE_TEST_PG_URL is provided.
#[cfg(test)]
pub mod testpg {
    use std::sync::OnceLock;

    static URL: OnceLock<Option<String>> = OnceLock::new();

    pub fn url() -> Option<String> {
        URL.get_or_init(boot).clone()
    }

    fn boot() -> Option<String> {
        if let Ok(u) = std::env::var("NARSHARE_TEST_PG_URL") {
            return Some(u);
        }
        if std::process::Command::new("initdb")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!(
                "postgres backend tests SKIPPED: initdb not on PATH (nix develop provides it)"
            );
            return None;
        }
        let dir = tempfile::tempdir().ok()?.keep();
        let data = dir.join("data");
        let sock = dir.join("sock");
        std::fs::create_dir_all(&sock).ok()?;
        let ok = std::process::Command::new("initdb")
            .args(["-D"])
            .arg(&data)
            .args(["-A", "trust", "--no-sync", "-U", "narshare"])
            .output()
            .ok()?
            .status
            .success();
        if !ok {
            eprintln!("postgres backend tests SKIPPED: initdb failed");
            return None;
        }
        use std::os::unix::process::CommandExt as _;
        let mut cmd = std::process::Command::new("postgres");
        cmd.args(["-D"])
            .arg(&data)
            .args(["-k"])
            .arg(&sock)
            // fsync=off: a throwaway cluster. The remaining flags mirror the production
            // ZFS tuning (modules/postgres.nix withZfs in the deployer's config): CoW
            // filesystems cannot tear pages, so full-page images, WAL zero-fill, and
            // segment recycling are pure write amplification there — without these the
            // bench measures ZFS pathologies instead of narshare's own write behavior.
            .args(["-c", "listen_addresses=", "-c", "fsync=off"])
            .args(["-c", "full_page_writes=off"])
            .args(["-c", "wal_init_zero=off"])
            .args(["-c", "wal_recycle=off"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        let child = cmd.spawn().ok()?;
        std::mem::forget(child); // dies with us via PDEATHSIG
        let url = format!("host={} user=narshare dbname=postgres", sock.display());
        for _ in 0..100 {
            if postgres::Client::connect(&url, postgres::NoTls).is_ok() {
                return Some(url);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        eprintln!("postgres backend tests SKIPPED: cluster did not come up");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance() {
        let Some(url) = testpg::url() else { return };
        crate::store::conformance::run_all(&move |name: &str| {
            Box::new(PgStore::connect(&url, &format!("conf_{name}"), false).unwrap())
                as Box<dyn SyncStore>
        });
    }

    #[test]
    #[ignore] // measurement bench: cargo test --release -- --ignored --nocapture bench_control
    fn bench_control_plane() {
        let Some(url) = testpg::url() else { return };
        let s = PgStore::connect(&url, "bench_control", false).unwrap();
        crate::store::bench::run("postgres (throwaway cluster, unix socket, fsync=off)", &s);
    }

    #[test]
    fn layout_mismatch_wipes() {
        let Some(url) = testpg::url() else { return };
        {
            let s = PgStore::connect(&url, "layout_test", false).unwrap();
            s.meta_put("layout", "something-old").unwrap();
            s.meta_put("self_generation", "42").unwrap();
        }
        let s = PgStore::connect(&url, "layout_test", false).unwrap();
        assert_eq!(
            s.meta_get("self_generation").unwrap(),
            None,
            "old state wiped"
        );
        assert_eq!(s.meta_get("layout").unwrap(), Some(LAYOUT.into()));
    }
}
