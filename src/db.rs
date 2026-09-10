//! Read-only access to Nix's own database (/nix/var/nix/db/db.sqlite). narshare never writes it —
//! this is Nix's state, not ours. Modern SQLite reads WAL databases read-only by building a private
//! wal-index, so no privileges beyond file read access are needed (verified on the target system).
//!
//! Pinned to the known schema columns; a future Nix that changes them should produce a loud error
//! here, not silent misbehavior.

use crate::nixbase32;
use anyhow::{bail, Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

/// A malformed row in the Nix db (unsupported hash algo, missing narSize) is skipped, not
/// fatal: one odd row must not stop the mesh differ from exporting the other 17k.
fn warn_once(e: &anyhow::Error) {
    tracing::warn!("skipping malformed nix-db row: {e:#}");
}

/// A feasible-candidate row as the differ sees it: everything change detection needs,
/// references deliberately omitted (see candidates).
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: i64,
    pub path: String,
    pub nar_hash: [u8; 32],
    pub nar_size: u64,
    pub sigs: Vec<String>,
    pub ca: Option<String>,
    /// Full store path of the deriver, if recorded — consulted (lazily, per changed row)
    /// for its allowSubstitutes verdict at export time.
    pub deriver: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Full store path.
    pub path: String,
    /// sha256 of the uncompressed NAR.
    pub nar_hash: [u8; 32],
    pub nar_size: u64,
    /// Full store path of the deriver, if recorded.
    pub deriver: Option<String>,
    pub sigs: Vec<String>,
    /// The `ca` column verbatim (e.g. "fixed:r:sha256:<nix32>").
    pub ca: Option<String>,
    /// Full store paths, sorted.
    pub references: Vec<String>,
}

pub struct StoreDb {
    conn: Mutex<Connection>,
    pub store_dir: String,
    /// Lazily built narhash → store-path map (see by_nar_hash): the hash column is unindexed
    /// in Nix's schema and narshare must not write Nix's database, so without this every
    /// first-time NAR request pays a full ValidPaths scan — a nixpkgs rebuild pulling hundreds
    /// of small NARs from this node would serialize hundreds of scans on one connection.
    nar_index: Mutex<Option<NarIndex>>,
}

struct NarIndex {
    /// The nix db's data_version when this map was built. While it stands (the db is the
    /// authoritative cache and data_version moves exactly when another connection commits),
    /// hits are exact AND misses are authoritative — no negative caching, no TTL semantics.
    data_version: i64,
    /// Rebuilds are rate-limited under write churn; a stale-map miss falls back to a single
    /// exact scan instead, so answers are never wrong, only occasionally slower.
    built: std::time::Instant,
    map: std::collections::HashMap<[u8; 32], String>,
}

/// Minimum interval between narhash-map rebuilds: bounds rebuild cost under sustained db
/// write churn combined with miss traffic. Not a correctness knob — a rate-limited stale
/// miss is answered by one exact scan.
const NAR_INDEX_REBUILD_MIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Parse the ValidPaths.hash column: "sha256:" + (base16 | nix32).
fn parse_hash_column(h: &str) -> Result<[u8; 32]> {
    let Some(rest) = h.strip_prefix("sha256:") else {
        bail!("unsupported hash algo in nix db: {h:?}");
    };
    let bytes = match rest.len() {
        64 => hex::decode(rest).with_context(|| format!("bad base16 hash {h:?}"))?,
        52 => nixbase32::decode(rest, 32).with_context(|| format!("bad nix32 hash {h:?}"))?,
        n => bail!("unexpected hash length {n} in nix db: {h:?}"),
    };
    Ok(<[u8; 32]>::try_from(bytes.as_slice()).unwrap())
}

impl StoreDb {
    pub fn open(db_path: &Path, store_dir: &str) -> Result<Self> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening nix db {} read-only", db_path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // Fail loudly now if the schema is not what we expect.
        conn.prepare("SELECT id, path, hash, narSize, deriver, sigs, ca FROM ValidPaths LIMIT 0")
            .context("nix db schema mismatch (ValidPaths columns)")?;
        conn.prepare("SELECT referrer, reference FROM Refs LIMIT 0")
            .context("nix db schema mismatch (Refs columns)")?;
        Ok(Self {
            conn: Mutex::new(conn),
            store_dir: store_dir.trim_end_matches('/').to_owned(),
            nar_index: Mutex::new(None),
        })
    }

    #[allow(clippy::too_many_arguments)] // one row's columns, unpacked positionally
    fn info_from_row(
        conn: &Connection,
        id: i64,
        path: String,
        hash: String,
        nar_size: Option<i64>,
        deriver: Option<String>,
        sigs: Option<String>,
        ca: Option<String>,
    ) -> Result<PathInfo> {
        let Some(nar_size) = nar_size else {
            bail!("path {path} has no narSize in nix db");
        };
        let mut stmt = conn.prepare_cached(
            "SELECT v.path FROM Refs JOIN ValidPaths v ON v.id = Refs.reference \
             WHERE Refs.referrer = ?1 ORDER BY v.path",
        )?;
        let references = stmt
            .query_map([id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(PathInfo {
            path,
            nar_hash: parse_hash_column(&hash)?,
            nar_size: nar_size as u64,
            deriver: deriver.filter(|d| !d.is_empty()),
            sigs: sigs
                .map(|s| s.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_default(),
            ca: ca.filter(|c| !c.is_empty()),
            references,
        })
    }

    /// Look up by the 32-character hash part of a store path (narinfo request).
    pub fn by_hash_part(&self, hash_part: &str) -> Result<Option<PathInfo>> {
        if hash_part.len() != 32 || !hash_part.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Ok(None);
        }
        let lo = format!("{}/{}-", self.store_dir, hash_part);
        let hi = format!("{}/{}.", self.store_dir, hash_part); // '.' = '-' + 1
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT id, path, hash, narSize, deriver, sigs, ca FROM ValidPaths \
             WHERE path >= ?1 AND path < ?2 LIMIT 1",
        )?;
        let row = stmt
            .query_row([&lo, &hi], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })
            .optional()?;
        row.map(|(id, path, hash, sz, drv, sigs, ca)| {
            Self::info_from_row(&conn, id, path, hash, sz, drv, sigs, ca)
        })
        .transpose()
    }

    /// EVERY valid path, as the index differ's candidate set. Deliberately unfiltered:
    /// possession is trust-free (bytes are keyed and verified by NAR hash), so even a local,
    /// unsigned, non-CA rebuild is a legitimate byte source for content some OTHER node holds
    /// a believable fact about — the attestation filter (CA or signatures) is the differ's
    /// job, per row. DELIBERATELY without references: fetching them is one JOIN query per row
    /// (~100k queries on a real store, ~10 CPU-seconds per diff, measured), and change
    /// detection needs only (hash, sigs). Callers fetch references via references_of() for
    /// the handful of rows that actually changed.
    pub fn candidates(&self) -> Result<Vec<Candidate>> {
        Ok(self.additions_since(-1)?.0)
    }

    /// Rows with id strictly above `since`, plus every consistency signal, in ONE read
    /// transaction (a single WAL snapshot — the arithmetic must describe one moment).
    /// ValidPaths.id is AUTOINCREMENT, so additions are monotone and ids are never reused;
    /// deletions and in-place updates are invisible here BY CONSTRUCTION and are detected by
    /// the count / probe signals instead. Commits after this snapshot bump data_version and
    /// earn their own wake — at-least-once, never lost.
    /// Rows with id strictly above `since` plus the table's current max id (the next
    /// watermark — the TABLE max, not the max of returned rows: it must advance past
    /// malformed rows too, or they would be re-fetched forever), in one read transaction.
    /// ValidPaths.id is AUTOINCREMENT (monotone, never reused), so this is the complete
    /// additions stream; deletions and in-place updates are invisible here BY CONSTRUCTION
    /// and are the hourly reconciliation's job.
    pub fn additions_since(&self, since: i64) -> Result<(Vec<Candidate>, i64)> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let max_id: i64 = tx.query_row("SELECT COALESCE(MAX(id), 0) FROM ValidPaths", [], |r| {
            r.get(0)
        })?;
        let mut stmt = tx.prepare_cached(
            "SELECT id, path, hash, narSize, sigs, ca, deriver FROM ValidPaths WHERE id > ?1",
        )?;
        let rows = stmt
            .query_map([since], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut cands = Vec::with_capacity(rows.len());
        for (id, path, hash, sz, sigs, ca, deriver) in rows {
            let Some(nar_size) = sz else {
                warn_once(&anyhow::anyhow!("path {path} has no narSize in nix db"));
                continue;
            };
            match parse_hash_column(&hash) {
                Ok(nar_hash) => cands.push(Candidate {
                    id,
                    path,
                    nar_hash,
                    nar_size: nar_size as u64,
                    sigs: sigs
                        .map(|s| s.split_whitespace().map(str::to_owned).collect())
                        .unwrap_or_default(),
                    ca: ca.filter(|c| !c.is_empty()),
                    deriver: deriver.filter(|d| !d.is_empty()),
                }),
                Err(e) => warn_once(&e),
            }
        }
        drop(stmt);
        tx.commit()?;
        Ok((cands, max_id))
    }

    /// Is ValidPaths.id AUTOINCREMENT (monotone, never reused)? The incremental differ's
    /// count arithmetic is only sound under that guarantee: with a plain rowid PK, SQLite may
    /// reuse a deleted max id, making a delete+reinsert replacement invisible to both the
    /// watermark and the count check. Nix's schema declares it (verified live: sqlite_sequence
    /// is ~12x the row count on a real store); if a future Nix drops it, the differ falls back
    /// to full scans.
    pub fn ids_monotone(&self) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let sql: String = conn.query_row(
            "SELECT COALESCE(sql, '') FROM sqlite_master WHERE name = 'ValidPaths'",
            [],
            |r| r.get(0),
        )?;
        Ok(sql.to_ascii_lowercase().contains("autoincrement"))
    }

    /// Full store paths of one row's references, sorted (the fingerprint needs them) — fetched
    /// per CHANGED row only, never for the whole candidate set.
    pub fn references_of(&self, id: i64) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT v.path FROM Refs JOIN ValidPaths v ON v.id = Refs.reference \
             WHERE Refs.referrer = ?1 ORDER BY v.path",
        )?;
        let refs = stmt
            .query_map([id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(refs)
    }

    /// SQLite's global change counter: increments whenever ANOTHER connection commits to the
    /// database. The differ's cheap gate — an unchanged version means the store is byte-for-
    /// byte as last diffed, so idle rescans and reader-generated inotify chatter cost one
    /// pragma instead of a 100k-row scan.
    pub fn data_version(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("PRAGMA data_version", [], |r| r.get(0))?)
    }

    /// Look up by NAR hash (nar request — the hot path of every fetch a peer makes from us).
    /// The hash column is unindexed in Nix's schema and narshare never writes Nix's database,
    /// so exact-hash queries are full ValidPaths scans; the in-memory map turns the steady
    /// state into one scan per TTL instead of one per distinct NAR. Correctness never depends
    /// on the map: a map miss falls back to the direct scan (a just-registered path must not
    /// 404 behind a stale map), and a map hit is re-verified against the row's actual hash
    /// (the path may have been re-registered with different content since the build).
    pub fn by_nar_hash(&self, nar_hash: &[u8; 32]) -> Result<Option<PathInfo>> {
        // A map hit is usable even from a stale map: by_path re-reads the row and the hash
        // check rejects a since-rewritten path.
        let (hit, fresh) = {
            let guard = self.nar_index.lock().unwrap();
            match guard.as_ref() {
                Some(ix) => (
                    ix.map.get(nar_hash).cloned(),
                    ix.data_version == self.data_version()?,
                ),
                None => (None, false),
            }
        };
        if let Some(path) = hit {
            if let Some(info) = self.by_path(&path)? {
                if &info.nar_hash == nar_hash {
                    return Ok(Some(info));
                }
            }
        }
        if fresh {
            // The map covered every row at this exact data_version: the miss is
            // AUTHORITATIVE. No scan, no negative cache — the db is the cache, and
            // data_version is its invalidation signal.
            return Ok(None);
        }
        if self.rebuild_nar_index()? {
            let path = {
                let guard = self.nar_index.lock().unwrap();
                guard.as_ref().and_then(|ix| ix.map.get(nar_hash).cloned())
            };
            return match path {
                Some(p) => self.by_path(&p),
                None => Ok(None), // authoritative under the just-built version
            };
        }
        // Rebuild rate-limited under churn: answer this one exactly with a single scan.
        self.by_nar_hash_scan(nar_hash)
    }

    /// Rebuild the narhash map, tagged with the data_version read INSIDE the same
    /// transaction as the scan (so the tag and the contents describe one snapshot).
    /// Returns false when rate-limited.
    fn rebuild_nar_index(&self) -> Result<bool> {
        {
            let guard = self.nar_index.lock().unwrap();
            if let Some(ix) = guard.as_ref() {
                if ix.built.elapsed() < NAR_INDEX_REBUILD_MIN {
                    return Ok(false);
                }
            }
        }
        let (map, version) = {
            let conn = self.conn.lock().unwrap();
            let tx = conn.unchecked_transaction()?;
            let version: i64 = tx.query_row("PRAGMA data_version", [], |r| r.get(0))?;
            let mut stmt = tx.prepare_cached("SELECT path, hash FROM ValidPaths")?;
            let mut map = std::collections::HashMap::new();
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let path: String = row.get(0)?;
                let hash: String = row.get(1)?;
                if let Ok(h) = parse_hash_column(&hash) {
                    map.insert(h, path);
                }
            }
            drop(rows);
            drop(stmt);
            tx.commit()?;
            (map, version)
        };
        *self.nar_index.lock().unwrap() = Some(NarIndex {
            data_version: version,
            built: std::time::Instant::now(),
            map,
        });
        Ok(true)
    }

    /// Look up by exact store path (indexed: ValidPaths.path is UNIQUE).
    fn by_path(&self, path: &str) -> Result<Option<PathInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT id, path, hash, narSize, deriver, sigs, ca FROM ValidPaths \
             WHERE path = ?1",
        )?;
        let row = stmt
            .query_row([path], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })
            .optional()?;
        row.map(|(id, path, hash, sz, drv, sigs, ca)| {
            Self::info_from_row(&conn, id, path, hash, sz, drv, sigs, ca)
        })
        .transpose()
    }

    fn by_nar_hash_scan(&self, nar_hash: &[u8; 32]) -> Result<Option<PathInfo>> {
        let b16 = format!("sha256:{}", hex::encode(nar_hash));
        let b32 = format!("sha256:{}", nixbase32::encode(nar_hash));
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT id, path, hash, narSize, deriver, sigs, ca FROM ValidPaths \
             WHERE hash = ?1 OR hash = ?2 LIMIT 1",
        )?;
        let row = stmt
            .query_row([&b16, &b32], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })
            .optional()?;
        row.map(|(id, path, hash, sz, drv, sigs, ca)| {
            Self::info_from_row(&conn, id, path, hash, sz, drv, sigs, ca)
        })
        .transpose()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Minimal replica of the Nix schema, for tests.
    pub fn fake_db(dir: &Path, rows: &[(&str, [u8; 32], u64, Option<&str>)]) -> std::path::PathBuf {
        let db = dir.join("db.sqlite");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF;")
            .unwrap();
        conn.execute_batch(
            "CREATE TABLE ValidPaths (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 path TEXT UNIQUE NOT NULL,
                 hash TEXT NOT NULL,
                 registrationTime INTEGER NOT NULL,
                 deriver TEXT,
                 narSize INTEGER,
                 ultimate INTEGER,
                 sigs TEXT,
                 ca TEXT);
             CREATE TABLE Refs (referrer INTEGER NOT NULL, reference INTEGER NOT NULL,
                 PRIMARY KEY (referrer, reference));",
        )
        .unwrap();
        conn.execute_batch("BEGIN").unwrap();
        for (path, nar_hash, nar_size, ca) in rows {
            conn.execute(
                "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ca) \
                 VALUES (?1, ?2, 0, ?3, ?4)",
                rusqlite::params![
                    path,
                    format!("sha256:{}", hex::encode(nar_hash)),
                    *nar_size as i64,
                    ca
                ],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
        db
    }

    /// Attach a deriver to a fake-db row.
    pub fn set_deriver(db: &Path, path: &str, deriver: &str) {
        let conn = Connection::open(db).unwrap();
        conn.execute(
            "UPDATE ValidPaths SET deriver = ?2 WHERE path = ?1",
            rusqlite::params![path, deriver],
        )
        .unwrap();
    }

    /// Attach signatures to a fake-db row (space-separated, as nix stores them).
    pub fn set_sigs(db: &Path, path: &str, sigs: &str) {
        let conn = Connection::open(db).unwrap();
        conn.execute(
            "UPDATE ValidPaths SET sigs = ?2 WHERE path = ?1",
            rusqlite::params![path, sigs],
        )
        .unwrap();
    }

    /// Register a row into an existing fake db (an in-place rebuild registers anew).
    pub fn insert_path(db: &Path, path: &str, nar_hash: [u8; 32], nar_size: u64, ca: Option<&str>) {
        let conn = Connection::open(db).unwrap();
        conn.execute(
            "INSERT INTO ValidPaths (path, hash, registrationTime, narSize, ca) \
             VALUES (?1, ?2, 0, ?3, ?4)",
            rusqlite::params![
                path,
                format!("sha256:{}", hex::encode(nar_hash)),
                nar_size as i64,
                ca
            ],
        )
        .unwrap();
    }

    /// Simulate a GC: drop a row from the fake db.
    pub fn delete_path(db: &Path, path: &str) {
        let conn = Connection::open(db).unwrap();
        conn.execute("DELETE FROM ValidPaths WHERE path = ?1", [path])
            .unwrap();
    }

    #[test]
    fn lookup_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let hash = [7u8; 32];
        let hp = "0fb2hr6wamcr5f9my5w3slxlv95p4xwn"; // 32-char store-path hash part
        let path = format!("/nix/store/{hp}-foo-1.0");
        let db_path = fake_db(
            dir.path(),
            &[(&path, hash, 1234, Some("fixed:r:sha256:abcd"))],
        );
        let db = StoreDb::open(&db_path, "/nix/store").unwrap();

        let info = db
            .by_hash_part("0fb2hr6wamcr5f9my5w3slxlv95p4xwn8lz8vzbcqmgj9jbb5243")
            .unwrap();
        assert!(
            info.is_none(),
            "52-char narhash is not a 32-char path hash part"
        );

        let info = db.by_hash_part(hp).unwrap().unwrap();
        assert_eq!(info.path, path);
        assert_eq!(info.nar_size, 1234);
        assert_eq!(info.nar_hash, hash);
        assert_eq!(info.ca.as_deref(), Some("fixed:r:sha256:abcd"));

        let info = db.by_nar_hash(&hash).unwrap().unwrap();
        assert_eq!(info.path, path);
        assert!(db.by_nar_hash(&[9u8; 32]).unwrap().is_none());
    }
}
