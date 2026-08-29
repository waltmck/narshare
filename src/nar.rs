//! Canonical NAR encoding as a *seek table*: one metadata-only walk (no content reads, O(#files))
//! yields sorted segments `nar_offset → (literal bytes | file + file offset)`. Serving any range of
//! the NAR — including the whole thing — is then binary search + stream: literals from memory, file
//! spans via positioned reads. NARs are never materialized on disk.
//!
//! Format (nix/src/libutil/archive.cc): every token is str(s) = u64-LE length, bytes, zero-padding
//! to 8. A node is "(" "type" (regular|symlink|directory) ... ")"; directory entries are sorted
//! byte-lexicographically by name; a regular's executable flag is the owner-exec bit.
//!
//! Walk adapted from propnix pin/nar.rs (same author), re-shaped to emit segments instead of bytes.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct SeekTable {
    pub nar_size: u64,
    /// All literal (framing) bytes, sliced zero-copy per request.
    lits: Bytes,
    segs: Vec<Seg>,
}

struct Seg {
    nar_off: u64,
    len: u64,
    src: Src,
}

enum Src {
    Lit { lit_off: usize },
    File { path: Arc<PathBuf>, file_off: u64 },
}

/// One resolved piece of a requested range, ready to emit.
pub enum Slice {
    Lit(Bytes),
    File { path: Arc<PathBuf>, off: u64, len: u64 },
}

pub fn build(root: &Path) -> Result<SeekTable> {
    let mut b = Builder { lits: Vec::new(), segs: Vec::new(), off: 0, open_lit: None };
    b.tok(b"nix-archive-1");
    b.node(root)?;
    b.close_lit();
    Ok(SeekTable { nar_size: b.off, lits: Bytes::from(b.lits), segs: b.segs })
}

struct Builder {
    lits: Vec<u8>,
    segs: Vec<Seg>,
    off: u64,
    /// (nar_off, lit_off) of the literal segment currently being appended to, if any.
    open_lit: Option<(u64, usize)>,
}

impl Builder {
    fn raw_lit(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.open_lit.is_none() {
            self.open_lit = Some((self.off, self.lits.len()));
        }
        self.lits.extend_from_slice(bytes);
        self.off += bytes.len() as u64;
    }

    fn close_lit(&mut self) {
        if let Some((nar_off, lit_off)) = self.open_lit.take() {
            self.segs.push(Seg {
                nar_off,
                len: self.off - nar_off,
                src: Src::Lit { lit_off },
            });
        }
    }

    /// A full framed string token as literal bytes.
    fn tok(&mut self, s: &[u8]) {
        self.raw_lit(&(s.len() as u64).to_le_bytes());
        self.raw_lit(s);
        self.raw_lit(&PAD[..pad_len(s.len())]);
    }

    fn file_seg(&mut self, path: &Path, len: u64) {
        self.close_lit();
        self.segs.push(Seg {
            nar_off: self.off,
            len,
            src: Src::File { path: Arc::new(path.to_owned()), file_off: 0 },
        });
        self.off += len;
    }

    fn node(&mut self, path: &Path) -> Result<()> {
        let md = fs::symlink_metadata(path)
            .with_context(|| format!("stat {}", path.display()))?;
        let ft = md.file_type();
        self.tok(b"(");
        self.tok(b"type");
        if ft.is_symlink() {
            let target = fs::read_link(path)
                .with_context(|| format!("readlink {}", path.display()))?;
            self.tok(b"symlink");
            self.tok(b"target");
            self.tok(target.as_os_str().as_bytes());
        } else if ft.is_file() {
            self.tok(b"regular");
            if md.mode() & 0o100 != 0 {
                self.tok(b"executable");
                self.tok(b"");
            }
            self.tok(b"contents");
            // str(contents), framed by hand so the payload is a file segment.
            let len = md.len();
            self.raw_lit(&len.to_le_bytes());
            if len > 0 {
                self.file_seg(path, len);
            }
            self.raw_lit(&PAD[..pad_len(len as usize)]);
        } else if ft.is_dir() {
            self.tok(b"directory");
            let mut names: Vec<_> = fs::read_dir(path)
                .with_context(|| format!("readdir {}", path.display()))?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<_>>()?;
            names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for name in names {
                self.tok(b"entry");
                self.tok(b"(");
                self.tok(b"name");
                self.tok(name.as_bytes());
                self.tok(b"node");
                self.node(&path.join(&name))?;
                self.tok(b")");
            }
        } else {
            bail!("unsupported file type in store path: {}", path.display());
        }
        self.tok(b")");
        Ok(())
    }
}

const PAD: [u8; 8] = [0; 8];

const fn pad_len(n: usize) -> usize {
    (8 - n % 8) % 8
}

impl SeekTable {
    /// Index of the first segment overlapping `start`.
    pub fn first_seg(&self, start: u64) -> usize {
        self.segs.partition_point(|s| s.nar_off + s.len <= start)
    }

    /// Segment `i` clamped to [start, end); None once past the range (or the table).
    /// Literal slices are zero-copy views into the shared framing buffer.
    pub fn seg_slice(&self, i: usize, start: u64, end: u64) -> Option<Slice> {
        let seg = self.segs.get(i)?;
        if seg.nar_off >= end {
            return None;
        }
        let s = start.max(seg.nar_off);
        let e = end.min(seg.nar_off + seg.len);
        let (skip, len) = (s - seg.nar_off, e - s);
        Some(match &seg.src {
            Src::Lit { lit_off } => {
                let lo = lit_off + skip as usize;
                Slice::Lit(self.lits.slice(lo..lo + len as usize))
            }
            Src::File { path, file_off } => {
                Slice::File { path: path.clone(), off: file_off + skip, len }
            }
        })
    }

    /// Resolve [start, end) into a materialized slice list (test helper; streaming callers
    /// iterate first_seg/seg_slice instead).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn slices(&self, start: u64, end: u64) -> Vec<Slice> {
        debug_assert!(start <= end && end <= self.nar_size);
        if start == end {
            return Vec::new();
        }
        (self.first_seg(start)..)
            .map_while(|i| self.seg_slice(i, start, end))
            .collect()
    }

    /// Rough in-memory footprint, for the byte-budgeted cache.
    pub fn approx_bytes(&self) -> u64 {
        (self.lits.len() + self.segs.len() * (std::mem::size_of::<Seg>() + 32)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    /// Materialize the full NAR by resolving slices and reading files with std.
    fn materialize(t: &SeekTable, start: u64, end: u64) -> Vec<u8> {
        let mut out = Vec::new();
        for s in t.slices(start, end) {
            match s {
                Slice::Lit(b) => out.extend_from_slice(&b),
                Slice::File { path, off, len } => {
                    use std::os::unix::fs::FileExt;
                    let f = fs::File::open(path.as_path()).unwrap();
                    let mut buf = vec![0u8; len as usize];
                    f.read_exact_at(&mut buf, off).unwrap();
                    out.extend_from_slice(&buf);
                }
            }
        }
        out
    }

    fn sample_tree(dir: &Path) {
        fs::create_dir_all(dir.join("sub/inner")).unwrap();
        fs::write(dir.join("b-plain.txt"), b"hello world, this is narshare\n").unwrap();
        fs::write(dir.join("a-empty"), b"").unwrap();
        // A file whose length is a multiple of 8 (padding edge case).
        fs::write(dir.join("sub/aligned"), vec![0xabu8; 4096]).unwrap();
        // A larger file with varied content.
        let mut big = fs::File::create(dir.join("sub/inner/big.bin")).unwrap();
        let block: Vec<u8> = (0..=255u8).cycle().take(65537).collect(); // odd length
        big.write_all(&block).unwrap();
        drop(big);
        let exe = dir.join("run.sh");
        fs::write(&exe, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("sub/inner/big.bin", dir.join("link")).unwrap();
    }

    #[test]
    fn matches_nix_nar_dump() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let table = build(dir.path()).unwrap();
        let ours = materialize(&table, 0, table.nar_size);
        assert_eq!(ours.len() as u64, table.nar_size);

        let nix = Command::new("nix")
            .args(["nar", "dump-path", "--"])
            .arg(dir.path())
            .output();
        match nix {
            Ok(out) if out.status.success() => {
                assert_eq!(ours, out.stdout, "NAR bytes differ from `nix nar dump-path`");
            }
            _ => eprintln!("skipping differential test: `nix` unavailable"),
        }
    }

    #[test]
    fn single_file_root() {
        // A store path can be a single regular file, not just a directory.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("just-a-file");
        fs::write(&f, b"0123456789").unwrap();
        let table = build(&f).unwrap();
        let ours = materialize(&table, 0, table.nar_size);
        if let Ok(out) = Command::new("nix").args(["nar", "dump-path", "--"]).arg(&f).output() {
            if out.status.success() {
                assert_eq!(ours, out.stdout);
            }
        }
    }

    /// How much compression ratio do independent per-chunk frames give up versus one
    /// continuous zstd context (and versus continuous + long-distance matching, the upper
    /// bound of what cross-chunk context could buy)? Measured on a real store path; results
    /// recorded in docs/perf.md. Run explicitly:
    ///   NARSHARE_BENCH_STORE_PATH=/nix/store/...-hollow-knight-linux \
    ///   NARSHARE_BENCH_LEVELS=1,3,9 [NARSHARE_BENCH_LIMIT=<bytes>] \
    ///   cargo test --release -- --ignored bench_chunk_ratio --nocapture
    #[test]
    #[ignore]
    fn bench_chunk_ratio() {
        let Ok(root) = std::env::var("NARSHARE_BENCH_STORE_PATH") else {
            eprintln!("set NARSHARE_BENCH_STORE_PATH to a store path");
            return;
        };
        let levels: Vec<i32> = std::env::var("NARSHARE_BENCH_LEVELS")
            .unwrap_or_else(|_| "1,3,9".into())
            .split(',')
            .map(|s| s.trim().parse().unwrap())
            .collect();
        let limit: u64 = std::env::var("NARSHARE_BENCH_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        let table = Arc::new(build(Path::new(&root)).unwrap());
        let total = table.nar_size.min(limit);
        println!("{root}: NAR {} bytes, measuring {} bytes", table.nar_size, total);

        #[derive(Clone, Copy)]
        enum Mode {
            /// One zstd stream, one context — the hypothetical cross-chunk baseline.
            Continuous,
            /// Continuous + 128 MiB long-distance matching: what context could buy at most.
            ContinuousLdm,
            /// Independent frames of this size — exactly what the serve side does per chunk.
            Chunked(u64),
        }
        let modes: [(&str, Mode); 6] = [
            ("continuous", Mode::Continuous),
            ("continuous+ldm", Mode::ContinuousLdm),
            ("chunk-256KiB", Mode::Chunked(256 << 10)),
            ("chunk-1MiB", Mode::Chunked(1 << 20)),
            ("chunk-4MiB", Mode::Chunked(4 << 20)),
            ("chunk-16MiB", Mode::Chunked(16 << 20)),
        ];

        /// Stream the NAR's first `total` bytes into `sink` (reads per thread; cache-hot after
        /// the first pass).
        fn stream(table: &SeekTable, total: u64, mut sink: impl FnMut(&[u8])) {
            use std::os::unix::fs::FileExt;
            let mut i = table.first_seg(0);
            while let Some(s) = table.seg_slice(i, 0, total) {
                i += 1;
                match s {
                    Slice::Lit(b) => sink(&b),
                    Slice::File { path, off, len } => {
                        let f = fs::File::open(path.as_path()).unwrap();
                        let mut buf = vec![0u8; len.min(4 << 20) as usize];
                        let (mut o, mut rem) = (off, len);
                        while rem > 0 {
                            let n = rem.min(4 << 20) as usize;
                            f.read_exact_at(&mut buf[..n], o).unwrap();
                            sink(&buf[..n]);
                            o += n as u64;
                            rem -= n as u64;
                        }
                    }
                }
            }
        }

        struct Counter(u64);
        impl std::io::Write for Counter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0 += b.len() as u64;
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut handles = Vec::new();
        for &level in &levels {
            for &(name, mode) in &modes {
                let table = table.clone();
                handles.push(std::thread::spawn(move || {
                    let t0 = std::time::Instant::now();
                    let out = match mode {
                        Mode::Continuous | Mode::ContinuousLdm => {
                            let mut enc =
                                zstd::stream::write::Encoder::new(Counter(0), level).unwrap();
                            if matches!(mode, Mode::ContinuousLdm) {
                                enc.long_distance_matching(true).unwrap();
                                enc.window_log(27).unwrap();
                            }
                            use std::io::Write;
                            stream(&table, total, |b| enc.write_all(b).unwrap());
                            enc.finish().unwrap().0
                        }
                        Mode::Chunked(sz) => {
                            let mut out = 0u64;
                            let mut buf = Vec::with_capacity(sz as usize);
                            stream(&table, total, |mut b| {
                                while !b.is_empty() {
                                    let room = sz as usize - buf.len();
                                    let take = room.min(b.len());
                                    buf.extend_from_slice(&b[..take]);
                                    b = &b[take..];
                                    if buf.len() == sz as usize {
                                        out += zstd::stream::encode_all(&buf[..], level)
                                            .unwrap()
                                            .len() as u64;
                                        buf.clear();
                                    }
                                }
                            });
                            if !buf.is_empty() {
                                out += zstd::stream::encode_all(&buf[..], level).unwrap().len()
                                    as u64;
                            }
                            out
                        }
                    };
                    (level, name, out, t0.elapsed())
                }));
            }
        }
        let mut rows: Vec<(i32, &str, u64, std::time::Duration)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        rows.sort_by_key(|&(l, n, ..)| (l, n));
        println!(
            "{:>5} {:16} {:>12} {:>8} {:>14} {:>9}",
            "level", "mode", "bytes", "ratio", "vs continuous", "enc MB/s"
        );
        for &(level, name, out, dur) in &rows {
            let baseline = rows
                .iter()
                .find(|&&(l, n, ..)| l == level && n == "continuous")
                .map(|&(_, _, o, _)| o)
                .unwrap();
            println!(
                "{:>5} {:16} {:>12} {:>8.4} {:>+13.2}% {:>9.1}",
                level,
                name,
                out,
                out as f64 / total as f64,
                (out as f64 / baseline as f64 - 1.0) * 100.0,
                total as f64 / dur.as_secs_f64() / 1e6
            );
        }
    }

    #[test]
    fn ranges_agree_with_full() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let table = build(dir.path()).unwrap();
        let full = materialize(&table, 0, table.nar_size);
        let n = table.nar_size;
        // Deterministic awkward boundaries: primes, token edges, file edges.
        let mut cuts = vec![0, 1, 7, 8, 9, 63, 64, 65, n / 3, n / 2, n - 1, n];
        cuts.retain(|&c| c <= n);
        for (i, &a) in cuts.iter().enumerate() {
            for &b in &cuts[i..] {
                let got = materialize(&table, a, b);
                assert_eq!(got, &full[a as usize..b as usize], "range {a}..{b}");
            }
        }
        // Reassemble from fixed-size chunks.
        for chunk in [1u64, 8, 13, 4096] {
            let mut acc = Vec::new();
            let mut off = 0;
            while off < n {
                let end = (off + chunk).min(n);
                acc.extend(materialize(&table, off, end));
                off = end;
            }
            assert_eq!(acc, full, "chunk size {chunk}");
        }
    }
}
