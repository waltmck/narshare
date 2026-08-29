//! narinfo (de)serialization: rendering for the serve side, parsing + client-side rewriting for
//! the proxy side. The format is a tiny line protocol; hand-rolled.

use crate::db::PathInfo;
use crate::nixbase32;
use anyhow::{Context, Result};
use std::fmt::Write as _;

/// Basename of a store path ("<hash>-<name>").
pub fn basename<'a>(store_path: &'a str, store_dir: &str) -> &'a str {
    store_path.strip_prefix(store_dir).and_then(|s| s.strip_prefix('/')).unwrap_or(store_path)
}

/// Render the narinfo we serve: uncompressed NAR, URL keyed by nix32 narhash. Sig/CA pass through
/// from the Nix db verbatim — narshare is a faithful cache, not a signer.
pub fn format_narinfo(info: &PathInfo, store_dir: &str) -> String {
    let nar32 = nixbase32::encode(&info.nar_hash);
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "StorePath: {}", info.path);
    let _ = writeln!(out, "URL: nar/{nar32}.nar");
    let _ = writeln!(out, "Compression: none");
    let _ = writeln!(out, "FileHash: sha256:{nar32}");
    let _ = writeln!(out, "FileSize: {}", info.nar_size);
    let _ = writeln!(out, "NarHash: sha256:{nar32}");
    let _ = writeln!(out, "NarSize: {}", info.nar_size);
    let refs: Vec<&str> = info.references.iter().map(|r| basename(r, store_dir)).collect();
    let _ = writeln!(out, "References: {}", refs.join(" "));
    if let Some(d) = &info.deriver {
        let _ = writeln!(out, "Deriver: {}", basename(d, store_dir));
    }
    for sig in &info.sigs {
        let _ = writeln!(out, "Sig: {sig}");
    }
    if let Some(ca) = &info.ca {
        let _ = writeln!(out, "CA: {ca}");
    }
    out
}

/// A peer's narinfo, as parsed by the proxy. The advertised `URL:` is deliberately NOT retained:
/// narshare always fetches the canonical `nar/<narhash>.nar` relative to the peer base, so a peer
/// cannot redirect the fetch to an arbitrary host (SSRF). FileHash/FileSize are likewise dropped —
/// the proxy reconstructs an uncompressed NAR and the client recomputes them.
#[derive(Debug, Clone)]
pub struct RemoteNarinfo {
    pub store_path: String,
    pub compression: String,
    pub nar_hash: [u8; 32],
    pub nar_size: u64,
    /// Basenames, verbatim.
    pub references: Vec<String>,
    pub deriver: Option<String>,
    pub ca: Option<String>,
}

pub fn parse_narinfo(text: &str) -> Result<RemoteNarinfo> {
    let mut store_path = None;
    let mut url_seen = false;
    // Absent Compression means bzip2 per the historical narinfo default.
    let mut compression = "bzip2".to_owned();
    let mut nar_hash = None;
    let mut nar_size = None;
    let mut references = Vec::new();
    let mut deriver = None;
    let mut ca = None;

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(':').context("narinfo line without ':'")?;
        let value = value.strip_prefix(' ').unwrap_or(value);
        match key {
            "StorePath" => store_path = Some(value.to_owned()),
            "URL" => url_seen = true, // presence validated; value discarded (never trusted)
            "Compression" => compression = value.to_owned(),
            "NarHash" => {
                let h = value
                    .strip_prefix("sha256:")
                    .with_context(|| format!("unsupported NarHash {value:?}"))?;
                let bytes = nixbase32::decode(h, 32)
                    .with_context(|| format!("bad nix32 NarHash {value:?}"))?;
                nar_hash = Some(<[u8; 32]>::try_from(bytes.as_slice()).unwrap());
            }
            "NarSize" => nar_size = Some(value.parse().context("bad NarSize")?),
            "References" => {
                references = value.split_whitespace().map(str::to_owned).collect()
            }
            "Deriver" => deriver = Some(value.to_owned()).filter(|d| !d.is_empty()),
            "CA" => ca = Some(value.to_owned()).filter(|c| !c.is_empty()),
            // URL value, FileHash, FileSize, Sig, unknown keys: ignored.
            _ => {}
        }
    }
    if !url_seen {
        anyhow::bail!("narinfo missing URL");
    }
    Ok(RemoteNarinfo {
        store_path: store_path.context("narinfo missing StorePath")?,
        compression,
        nar_hash: nar_hash.context("narinfo missing NarHash")?,
        nar_size: nar_size.context("narinfo missing NarSize")?,
        references,
        deriver,
        ca,
    })
}

/// Render the narinfo the proxy serves to the local nix: our own /nar URL (keyed by narhash),
/// Sig dropped (CA carries the trust), and Compression: none regardless of what peers serve —
/// the engine reconstructs the uncompressed NAR (wire compression is per-chunk, proxy-internal),
/// and the proxy→nix hop is loopback where recompression is pure waste.
pub fn rewrite_for_client(info: &RemoteNarinfo) -> String {
    let nar32 = nixbase32::encode(&info.nar_hash);
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "StorePath: {}", info.store_path);
    let _ = writeln!(out, "URL: nar/{nar32}.nar");
    let _ = writeln!(out, "Compression: none");
    let _ = writeln!(out, "FileHash: sha256:{nar32}");
    let _ = writeln!(out, "FileSize: {}", info.nar_size);
    let _ = writeln!(out, "NarHash: sha256:{nar32}");
    let _ = writeln!(out, "NarSize: {}", info.nar_size);
    let _ = writeln!(out, "References: {}", info.references.join(" "));
    if let Some(d) = &info.deriver {
        let _ = writeln!(out, "Deriver: {d}");
    }
    if let Some(ca) = &info.ca {
        let _ = writeln!(out, "CA: {ca}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_rewrite_roundtrip() {
        let info = PathInfo {
            path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-foo-1.0".into(),
            nar_hash: [7u8; 32],
            nar_size: 1234,
            deriver: None,
            sigs: vec!["cache.example:xyz".into()],
            ca: Some("fixed:r:sha256:abcd".into()),
            references: vec!["/nix/store/cccccccccccccccccccccccccccccccc-dep".into()],
        };
        let served = format_narinfo(&info, "/nix/store");
        let parsed = parse_narinfo(&served).unwrap();
        assert_eq!(parsed.store_path, info.path);
        assert_eq!(parsed.nar_hash, info.nar_hash);
        assert_eq!(parsed.nar_size, 1234);
        assert_eq!(parsed.compression, "none");
        assert_eq!(parsed.ca.as_deref(), Some("fixed:r:sha256:abcd"));
        assert_eq!(parsed.references, vec!["cccccccccccccccccccccccccccccccc-dep"]);

        let rewritten = rewrite_for_client(&parsed);
        assert!(!rewritten.contains("Sig:"));
        assert!(rewritten.contains("CA: fixed:r:sha256:abcd\n"));
        assert!(rewritten.contains("Compression: none\n"));
        // Idempotent under parse→rewrite.
        let reparsed = parse_narinfo(&rewritten).unwrap();
        assert_eq!(reparsed.nar_hash, info.nar_hash);
        assert_eq!(reparsed.nar_size, parsed.nar_size);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_narinfo("StorePath: /nix/store/x\n").is_err()); // missing fields
        assert!(parse_narinfo("no colon line").is_err());
    }

    #[test]
    fn formats() {
        let info = PathInfo {
            path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-foo-1.0".into(),
            nar_hash: [7u8; 32],
            nar_size: 1234,
            deriver: Some("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-foo.drv".into()),
            sigs: vec!["cache.example:xyz".into()],
            ca: Some("fixed:r:sha256:abcd".into()),
            references: vec!["/nix/store/cccccccccccccccccccccccccccccccc-dep".into()],
        };
        let s = format_narinfo(&info, "/nix/store");
        assert!(s.contains("StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-foo-1.0\n"));
        assert!(s.contains("References: cccccccccccccccccccccccccccccccc-dep\n"));
        assert!(s.contains("Deriver: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-foo.drv\n"));
        assert!(s.contains("Sig: cache.example:xyz\n"));
        assert!(s.contains("CA: fixed:r:sha256:abcd\n"));
        assert!(s.contains("Compression: none\n"));
        let url_line = s.lines().find(|l| l.starts_with("URL: ")).unwrap();
        assert_eq!(url_line.len(), "URL: nar/.nar".len() + 52);
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn advertised_url_is_dropped_not_trusted() {
        // A peer's URL pointing at an internal host must NOT be retained anywhere — the struct
        // has no url field, and the fetch path builds nar/<narhash>.nar from nar_hash only.
        let text = "StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x\n\
                    URL: http://169.254.169.254/latest/meta-data/\n\
                    Compression: none\n\
                    NarHash: sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\n\
                    NarSize: 10\nReferences: \nCA: fixed:r:sha256:x\n";
        let info = parse_narinfo(text).unwrap();
        // The only NAR locator downstream is nar/<narhash>.nar; the SSRF field no longer exists.
        assert_eq!(info.nar_size, 10);
        assert_eq!(nixbase32::encode(&info.nar_hash).len(), 52);
        // Missing URL still rejected (protocol conformance kept).
        let no_url = "StorePath: /nix/store/x\nCompression: none\n\
                      NarHash: sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73\n\
                      NarSize: 10\nReferences: \n";
        assert!(parse_narinfo(no_url).is_err());
    }
}
