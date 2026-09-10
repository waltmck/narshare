//! The postgres index backend: the shared-table design in its native habitat.
//!
//! Atomicity is a SQL transaction per composite op; same-origin apply races are arbitrated by
//! `SELECT … FOR UPDATE` on the clock row, and cross-origin races on retention stamps (the
//! "did the LAST holder just leave?" check) are serialized per nar-hash with transaction-scoped
//! advisory locks — row locks alone cannot close that phantom. Signature union is a plain
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

use super::{hash_part_of, Clock, HoldOp, SyncStore};
use crate::index::proto;
use anyhow::{bail, Context, Result};
use postgres::types::Type;
use postgres::{Client, NoTls, Statement, Transaction};
use std::collections::HashSet;
use std::sync::Mutex;

const LAYOUT: &str = "narshare-pg-1";
/// Idle connections kept for reuse; excess connects are dropped on return. Lookups and applies
/// already serialize per call site, so a small pool covers the real concurrency.
const POOL_MAX: usize = 4;

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
    clear: Statement,
    del: Statement,
    stamp: Statement,
}

fn hold_stmts(tx: &mut Transaction<'_>) -> Result<HoldStmts> {
    Ok(HoldStmts {
        add: tx.prepare(
            "INSERT INTO holdings (origin, nar_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )?,
        clear: tx.prepare(
            "UPDATE attestations SET unheld_since = NULL
             WHERE nar_hash = $1 AND unheld_since IS NOT NULL",
        )?,
        del: tx.prepare("DELETE FROM holdings WHERE origin = $1 AND nar_hash = $2")?,
        // Keep the EARLIEST unheld stamp; only stamp when the last holder just left.
        stamp: tx.prepare(
            "UPDATE attestations SET unheld_since = $2
             WHERE nar_hash = $1 AND unheld_since IS NULL
               AND NOT EXISTS (SELECT 1 FROM holdings h WHERE h.nar_hash = $1)",
        )?,
    })
}

/// Materialize one possession change with its retention side effects. The transaction sees its
/// own prior writes, so batched Add/Drop sequences compose naturally.
fn apply_hold(
    tx: &mut Transaction<'_>,
    st: &HoldStmts,
    origin: &str,
    op: &HoldOp,
    now: u64,
) -> Result<()> {
    match op {
        HoldOp::Add(h) => {
            let h = &h[..];
            tx.execute(&st.add, &[&origin, &h])?;
            tx.execute(&st.clear, &[&h])?;
        }
        HoldOp::Drop(h) => {
            let h = &h[..];
            tx.execute(&st.del, &[&origin, &h])?;
            tx.execute(&st.stamp, &[&h, &u2i(now)])?;
        }
    }
    Ok(())
}

/// The fact-upsert statement, prepared once per transaction (bulk merges execute it per row).
fn merge_stmt(tx: &mut Transaction<'_>) -> Result<Statement> {
    tx.prepare(
        "INSERT INTO attestations
             (hash_part, nar_hash, store_path, nar_size, refs, ca, sigs, unheld_since)
         VALUES ($1, $2, $3, $4, $5, $6, $7,
                 CASE WHEN EXISTS (SELECT 1 FROM holdings h WHERE h.nar_hash = $2)
                      THEN NULL ELSE $8::int8 END)
         ON CONFLICT (hash_part, nar_hash) DO UPDATE SET
             store_path = EXCLUDED.store_path,
             nar_size   = EXCLUDED.nar_size,
             refs       = EXCLUDED.refs,
             ca         = EXCLUDED.ca,
             sigs       = attestations.sigs ||
                 (SELECT COALESCE(array_agg(s), '{}') FROM unnest(EXCLUDED.sigs) s
                  WHERE s <> ALL (attestations.sigs))
         WHERE attestations.nar_size IS DISTINCT FROM EXCLUDED.nar_size
            OR attestations.refs <> EXCLUDED.refs
            OR attestations.ca <> EXCLUDED.ca
            OR EXISTS (SELECT 1 FROM unnest(EXCLUDED.sigs) s
                       WHERE s <> ALL (attestations.sigs))",
    )
    .map_err(Into::into)
}

/// Upsert one attestation fact: body last-writer-wins, sigs union (existing order kept,
/// unseen entries appended), fresh rows stamped unless their hash is held. Returns whether
/// the row was new or changed.
fn merge_att(
    tx: &mut Transaction<'_>,
    st: &Statement,
    att: &proto::Attestation,
    now: u64,
) -> Result<bool> {
    let hp = hash_part_of(&att.store_path).to_owned();
    let n = tx.execute(
        st,
        &[
            &hp,
            &&att.nar_hash[..],
            &att.store_path,
            &u2i(att.nar_size),
            &att.references,
            &att.ca,
            &att.sigs,
            &u2i(now),
        ],
    )?;
    Ok(n > 0)
}

fn row_to_att(row: &postgres::Row) -> proto::Attestation {
    proto::Attestation {
        store_path: row.get(0),
        nar_hash: row.get::<_, Vec<u8>>(1),
        nar_size: i2u(row.get(2)),
        references: row.get(3),
        ca: row.get(4),
        sigs: row.get(5),
    }
}

const ATT_COLS: &str = "store_path, nar_hash, nar_size, refs, ca, sigs";

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
                               unheld_since int8,
                               PRIMARY KEY (hash_part, nar_hash));
             CREATE INDEX IF NOT EXISTS attestations_by_hash ON attestations (nar_hash);
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
        now: u64,
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
                apply_hold(&mut tx, &hst, origin, op, now)?;
            }
            let mst = merge_stmt(&mut tx)?;
            for att in attests {
                merge_att(&mut tx, &mst, att, now)?;
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
        now: u64,
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
                apply_hold(&mut tx, &hst, origin, &HoldOp::Drop(h32), now)?;
            }
            for h in new.difference(&old) {
                let h32 = <[u8; 32]>::try_from(&h[..]).unwrap();
                apply_hold(&mut tx, &hst, origin, &HoldOp::Add(h32), now)?;
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

    fn merge_attestations(&self, attests: &[proto::Attestation], now: u64) -> Result<usize> {
        self.with_conn(|c| {
            let mut tx = c.transaction()?;
            lock_hashes(&mut tx, attests.iter().map(|a| &a.nar_hash[..]))?;
            let mst = merge_stmt(&mut tx)?;
            let mut changed = 0usize;
            for att in attests {
                changed += merge_att(&mut tx, &mst, att, now)? as usize;
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

    fn all_attestations(&self) -> Result<Vec<proto::Attestation>> {
        self.with_conn(|c| {
            Ok(
                c.query(&format!("SELECT {ATT_COLS} FROM attestations"), &[])?
                    .iter()
                    .map(row_to_att)
                    .collect(),
            )
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

    fn reap_attestations(&self, cutoff: u64) -> Result<usize> {
        self.with_conn(|c| {
            Ok(c.execute(
                "DELETE FROM attestations WHERE unheld_since IS NOT NULL AND unheld_since <= $1",
                &[&u2i(cutoff)],
            )? as usize)
        })
    }

    fn retain_origins(&self, keep: &[String], now: u64) -> Result<()> {
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
                    apply_hold(&mut tx, &hst, origin, &HoldOp::Drop(h32), now)?;
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

    fn attested_claims(&self) -> Result<Vec<(String, Vec<u8>, Vec<String>)>> {
        self.with_conn(|c| {
            Ok(
                c.query("SELECT store_path, nar_hash, sigs FROM attestations", &[])?
                    .into_iter()
                    .map(|r| (r.get(0), r.get(1), r.get(2)))
                    .collect(),
            )
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
