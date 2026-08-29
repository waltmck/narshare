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
}

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
        Ok(Self { conn: Mutex::new(conn), store_dir: store_dir.trim_end_matches('/').to_owned() })
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
            .query_row(
                [&lo, &hi],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(id, path, hash, sz, drv, sigs, ca)| {
            Self::info_from_row(&conn, id, path, hash, sz, drv, sigs, ca)
        })
        .transpose()
    }

    /// Look up by NAR hash (nar request). The hash column is unindexed, so this scans; callers
    /// cache the result per narhash, and one scan per NAR transfer is noise next to the transfer.
    pub fn by_nar_hash(&self, nar_hash: &[u8; 32]) -> Result<Option<PathInfo>> {
        let b16 = format!("sha256:{}", hex::encode(nar_hash));
        let b32 = format!("sha256:{}", nixbase32::encode(nar_hash));
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT id, path, hash, narSize, deriver, sigs, ca FROM ValidPaths \
             WHERE hash = ?1 OR hash = ?2 LIMIT 1",
        )?;
        let row = stmt
            .query_row(
                [&b16, &b32],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Option<String>>(6)?,
                    ))
                },
            )
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
        db
    }

    #[test]
    fn lookup_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let hash = [7u8; 32];
        let hp = "0fb2hr6wamcr5f9my5w3slxlv95p4xwn"; // 32-char store-path hash part
        let path = format!("/nix/store/{hp}-foo-1.0");
        let db_path =
            fake_db(dir.path(), &[(&path, hash, 1234, Some("fixed:r:sha256:abcd"))]);
        let db = StoreDb::open(&db_path, "/nix/store").unwrap();

        let info = db
            .by_hash_part("0fb2hr6wamcr5f9my5w3slxlv95p4xwn8lz8vzbcqmgj9jbb5243")
            .unwrap();
        assert!(info.is_none(), "52-char narhash is not a 32-char path hash part");

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
