//! The segment manifest: a *tree* description with per-segment blake3 hashes.
//!
//! The manifest deliberately describes the tree, not the NAR: NAR framing is a deterministic
//! function of tree metadata, so consumers synthesize the byte layout themselves
//! (`synth_layout`) and no NAR offset is ever serialized — a manifest cannot disagree with the
//! framing because it does not assert one. Segments are fixed `segment_bytes` splits *within*
//! each regular file, so identical files hash to identical segment lists wherever they sit.
//!
//! Manifests are efficiency metadata, not trust: an incorrect manifest yields a stream that fails the
//! final NarHash check like any other corruption.

use crate::nixbase32;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::Path;

pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// "sha256:<nix32>" — identity; must match the narinfo the consumer resolved.
    pub nar_hash: String,
    pub nar_size: u64,
    pub segment_bytes: u64,
    pub root: Node,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Node {
    Dir { entries: Vec<(String, Node)> },
    Symlink { target: String },
    Regular {
        #[serde(default)]
        executable: bool,
        len: u64,
        /// blake3 (hex) per fixed-size split; empty for an empty file.
        segments: Vec<String>,
    },
}

/// Walk a store path, hashing every file's segments. Blocking (call via spawn_blocking); one
/// sequential read of the tree's content.
pub fn build_tree(root: &Path, segment_bytes: u64) -> Result<Node> {
    use std::os::unix::fs::MetadataExt;
    let md = fs::symlink_metadata(root).with_context(|| format!("stat {}", root.display()))?;
    let ft = md.file_type();
    if ft.is_symlink() {
        let target = fs::read_link(root)?;
        let target = target
            .to_str()
            .with_context(|| format!("non-UTF-8 symlink target in {}", root.display()))?
            .to_owned();
        Ok(Node::Symlink { target })
    } else if ft.is_file() {
        let len = md.len();
        let mut segments = Vec::with_capacity(len.div_ceil(segment_bytes.max(1)) as usize);
        let mut f = fs::File::open(root).with_context(|| format!("open {}", root.display()))?;
        let mut remaining = len;
        let mut buf = vec![0u8; segment_bytes.min(len).max(1) as usize];
        while remaining > 0 {
            let n = remaining.min(segment_bytes) as usize;
            f.read_exact(&mut buf[..n])
                .with_context(|| format!("read {}", root.display()))?;
            segments.push(blake3::hash(&buf[..n]).to_hex().to_string());
            remaining -= n as u64;
        }
        Ok(Node::Regular { executable: md.mode() & 0o100 != 0, len, segments })
    } else if ft.is_dir() {
        let mut names: Vec<_> = fs::read_dir(root)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<_>>()?;
        names.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let name_s = name
                .to_str()
                .with_context(|| format!("non-UTF-8 filename in {}", root.display()))?
                .to_owned();
            entries.push((name_s, build_tree(&root.join(&name), segment_bytes)?));
        }
        Ok(Node::Dir { entries })
    } else {
        bail!("unsupported file type in store path: {}", root.display());
    }
}

/// One contiguous piece of the synthesized NAR byte layout.
pub struct Span {
    pub nar_off: u64,
    pub len: u64,
    pub kind: SpanKind,
}

pub enum SpanKind {
    /// Framing bytes, synthesized locally — never fetched.
    Lit { lit_off: usize },
    /// File content covered by one manifest segment.
    Segment { hash: [u8; 32] },
}

pub struct Layout {
    pub nar_size: u64,
    pub lits: Bytes,
    /// Contiguous, in order, covering [0, nar_size).
    pub spans: Vec<Span>,
}

/// Synthesize the NAR byte layout from a manifest — the same framing walk as nar.rs, driven by
/// manifest metadata instead of the filesystem (kept textually in sync; the differential test
/// pins byte equality).
/// Bound on tree depth when synthesizing a peer-supplied manifest, so a deeply-nested Dir cannot
/// overflow the stack. Real store paths are nowhere near this.
const MAX_DEPTH: u32 = 512;

pub fn synth_layout(m: &Manifest) -> Result<Layout> {
    if m.segment_bytes == 0 {
        bail!("manifest segment_bytes is 0");
    }
    let mut b = Synth { lits: Vec::new(), spans: Vec::new(), off: 0, open_lit: None };
    b.tok(b"nix-archive-1");
    b.node(&m.root, m.segment_bytes, 0)?;
    b.close_lit();
    if b.off != m.nar_size {
        bail!("manifest layout is {} bytes but claims NarSize {}", b.off, m.nar_size);
    }
    Ok(Layout { nar_size: b.off, lits: Bytes::from(b.lits), spans: b.spans })
}

struct Synth {
    lits: Vec<u8>,
    spans: Vec<Span>,
    off: u64,
    open_lit: Option<(u64, usize)>,
}

const PAD: [u8; 8] = [0; 8];
const fn pad_len(n: usize) -> usize {
    (8 - n % 8) % 8
}

impl Synth {
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
            self.spans.push(Span {
                nar_off,
                len: self.off - nar_off,
                kind: SpanKind::Lit { lit_off },
            });
        }
    }

    fn tok(&mut self, s: &[u8]) {
        self.raw_lit(&(s.len() as u64).to_le_bytes());
        self.raw_lit(s);
        self.raw_lit(&PAD[..pad_len(s.len())]);
    }

    fn segment(&mut self, hash: [u8; 32], len: u64) {
        self.close_lit();
        self.spans.push(Span { nar_off: self.off, len, kind: SpanKind::Segment { hash } });
        self.off += len;
    }

    fn node(&mut self, node: &Node, segment_bytes: u64, depth: u32) -> Result<()> {
        if depth > MAX_DEPTH {
            bail!("manifest tree deeper than {MAX_DEPTH}");
        }
        self.tok(b"(");
        self.tok(b"type");
        match node {
            Node::Symlink { target } => {
                self.tok(b"symlink");
                self.tok(b"target");
                self.tok(target.as_bytes());
            }
            Node::Regular { executable, len, segments } => {
                self.tok(b"regular");
                if *executable {
                    self.tok(b"executable");
                    self.tok(b"");
                }
                self.tok(b"contents");
                self.raw_lit(&len.to_le_bytes());
                let expect = len.div_ceil(segment_bytes.max(1));
                if segments.len() as u64 != expect {
                    bail!("file of {len} bytes has {} segments, expected {expect}", segments.len());
                }
                let mut remaining = *len;
                for seg in segments {
                    let slen = remaining.min(segment_bytes);
                    if slen == 0 {
                        bail!("manifest declares a zero-length segment");
                    }
                    let raw = hex::decode(seg).context("bad segment hash hex")?;
                    let hash =
                        <[u8; 32]>::try_from(raw.as_slice()).ok().context("bad segment hash len")?;
                    self.segment(hash, slen);
                    remaining -= slen;
                }
                self.raw_lit(&PAD[..pad_len(*len as usize)]);
            }
            Node::Dir { entries } => {
                self.tok(b"directory");
                let mut prev: Option<&str> = None;
                for (name, child) in entries {
                    if prev.is_some_and(|p| p >= name.as_str()) {
                        bail!("manifest directory entries not strictly sorted");
                    }
                    prev = Some(name);
                    self.tok(b"entry");
                    self.tok(b"(");
                    self.tok(b"name");
                    self.tok(name.as_bytes());
                    self.tok(b"node");
                    self.node(child, segment_bytes, depth + 1)?;
                    self.tok(b")");
                }
            }
        }
        self.tok(b")");
        Ok(())
    }
}

/// Render a manifest for a local path (serve side). Blocking.
pub fn build_manifest(
    root: &Path,
    nar_hash: &[u8; 32],
    nar_size: u64,
    segment_bytes: u64,
) -> Result<Manifest> {
    let m = Manifest {
        version: VERSION,
        nar_hash: format!("sha256:{}", nixbase32::encode(nar_hash)),
        nar_size,
        segment_bytes,
        root: build_tree(root, segment_bytes)?,
    };
    // The layout must reproduce exactly the registered NAR size — refuse to publish a manifest
    // that cannot (mutated store, walk drift).
    let layout = synth_layout(&m)?;
    debug_assert_eq!(layout.nar_size, nar_size);
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nar;
    use std::os::unix::fs::PermissionsExt;

    fn sample_tree(dir: &Path) {
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("small"), b"tiny").unwrap();
        fs::write(dir.join("sub/aligned"), vec![7u8; 8192]).unwrap();
        fs::write(dir.join("sub/odd"), vec![9u8; 5000]).unwrap();
        fs::write(dir.join("empty"), b"").unwrap();
        let exe = dir.join("run");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("sub/odd", dir.join("link")).unwrap();
    }

    /// The load-bearing test: manifest → synth layout must reproduce the filesystem walk's NAR
    /// byte-for-byte (framing from lits, segments from file reads).
    #[test]
    fn synth_layout_matches_real_nar() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let table = nar::build(dir.path()).unwrap();
        let real: Vec<u8> = {
            let mut out = Vec::new();
            for s in table.slices(0, table.nar_size) {
                match s {
                    nar::Slice::Lit(b) => out.extend_from_slice(&b),
                    nar::Slice::File { path, off, len } => {
                        use std::os::unix::fs::FileExt;
                        let f = fs::File::open(path.as_path()).unwrap();
                        let mut buf = vec![0u8; len as usize];
                        f.read_exact_at(&mut buf, off).unwrap();
                        out.extend_from_slice(&buf);
                    }
                }
            }
            out
        };

        for segment_bytes in [1024u64, 4096, 1 << 20] {
            let m = Manifest {
                version: VERSION,
                nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".into(),
                nar_size: table.nar_size,
                segment_bytes,
                root: build_tree(dir.path(), segment_bytes).unwrap(),
            };
            let layout = synth_layout(&m).unwrap();
            assert_eq!(layout.nar_size, real.len() as u64);

            // Reassemble: lits from the layout, segments from the real NAR bytes — and verify
            // each segment's blake3 matches the manifest.
            let mut rebuilt = Vec::new();
            for span in &layout.spans {
                match &span.kind {
                    SpanKind::Lit { lit_off } => rebuilt.extend_from_slice(
                        &layout.lits[*lit_off..*lit_off + span.len as usize],
                    ),
                    SpanKind::Segment { hash } => {
                        let bytes =
                            &real[span.nar_off as usize..(span.nar_off + span.len) as usize];
                        assert_eq!(
                            blake3::hash(bytes).as_bytes(),
                            hash,
                            "segment hash @{} (segment_bytes={segment_bytes})",
                            span.nar_off
                        );
                        rebuilt.extend_from_slice(bytes);
                    }
                }
            }
            assert_eq!(rebuilt, real, "layout must reproduce the NAR (sb={segment_bytes})");
        }
    }

    #[test]
    fn json_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        sample_tree(dir.path());
        let m = Manifest {
            version: VERSION,
            nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".into(),
            nar_size: nar::build(dir.path()).unwrap().nar_size,
            segment_bytes: 4096,
            root: build_tree(dir.path(), 4096).unwrap(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nar_size, m.nar_size);
        assert!(synth_layout(&back).is_ok());
    }
}
