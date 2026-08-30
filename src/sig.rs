//! Nix binary-cache signature verification at the proxy gate.
//!
//! A cache signature is ed25519 over the FINGERPRINT — `1;<storePath>;<narHash>;<narSize>;
//! <full-path references, sorted, comma-separated>` — nothing else: not the URL, not the wire
//! representation. That makes it location- and compression-independent, so a signature minted by
//! cache.nixos.org stays valid when the path is re-served by a mesh peer.
//!
//! The proxy verifies against the DOWNLOADER's trust anchor — `trusted-public-keys` from
//! /etc/nix/nix.conf (overridable in narshare's own config) — so a path whose signature the
//! local nix would reject at ingestion is refused at narinfo time, before any bandwidth is
//! spent. The consuming nix still re-verifies everything itself; this gate is purely an
//! efficiency filter, narshare holds no keys and signs nothing.

use crate::narinfo::RemoteNarinfo;
use crate::nixbase32;
use base64::Engine as _;
use std::path::Path;
use tracing::warn;

/// Nix's compiled-in default when nix.conf does not set trusted-public-keys at all.
const NIX_DEFAULT_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

pub struct TrustedKeys {
    /// (key name, public key), from "name:base64" entries.
    keys: Vec<(String, ed25519_compact::PublicKey)>,
}

impl TrustedKeys {
    pub fn none() -> Self {
        Self { keys: Vec::new() }
    }

    /// The mesh trust anchor: explicit config, else the local nix.conf — the same list the
    /// consuming nix will enforce at ingestion. Empty (explicitly, or because nix.conf is
    /// unreadable) means only content-addressed paths are feasible.
    pub fn load(explicit: &Option<Vec<String>>) -> Self {
        match explicit {
            Some(list) => Self::parse(list),
            None => Self::from_nix_conf(Path::new("/etc/nix/nix.conf")).unwrap_or_else(|e| {
                warn!("/etc/nix/nix.conf is unreadable ({e}); CA paths only");
                Self::none()
            }),
        }
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Parse "name:base64pubkey" entries, warning about (and skipping) malformed ones.
    pub fn parse(entries: &[String]) -> Self {
        let mut keys = Vec::new();
        for e in entries {
            let parsed = e.split_once(':').and_then(|(name, b64)| {
                let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
                let pk = ed25519_compact::PublicKey::from_slice(&raw).ok()?;
                Some((name.to_owned(), pk))
            });
            match parsed {
                Some(kv) => keys.push(kv),
                None => warn!("ignoring malformed trusted public key {e:?}"),
            }
        }
        Self { keys }
    }

    /// Trusted keys as the local nix daemon sees them: `trusted-public-keys` (last assignment
    /// wins; nix's compiled-in default when absent) plus every `extra-trusted-public-keys`.
    /// `include` directives are not followed — NixOS renders a flat file; deployments with
    /// exotic layouts can set narshare's own `trusted_public_keys` instead.
    pub fn from_nix_conf(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut base: Option<Vec<String>> = None;
        let mut extra: Vec<String> = Vec::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "trusted-public-keys" | "binary-cache-public-keys" => {
                    base = Some(v.split_whitespace().map(str::to_owned).collect());
                }
                "extra-trusted-public-keys" => {
                    extra.extend(v.split_whitespace().map(str::to_owned));
                }
                _ => {}
            }
        }
        let mut entries = base.unwrap_or_else(|| vec![NIX_DEFAULT_KEY.to_owned()]);
        entries.extend(extra);
        Ok(Self::parse(&entries))
    }

    /// A stable digest of the key set (order-independent). The index stores it so a CHANGED
    /// anchor at startup can force a full peer resync: events applied under the old anchor may
    /// have been skipped as infeasible, and those rows would otherwise stay missing until their
    /// origin happened to re-export them.
    pub fn anchor_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut entries: Vec<String> = self
            .keys
            .iter()
            .map(|(name, pk)| {
                format!("{name}:{}", base64::engine::general_purpose::STANDARD.encode(**pk))
            })
            .collect();
        entries.sort();
        let mut h = Sha256::new();
        for e in &entries {
            h.update(e.as_bytes());
            h.update(b"\n");
        }
        hex::encode(h.finalize())
    }

    /// Does any of this narinfo's signatures verify under any trusted key? Key names must match
    /// AND the ed25519 signature must check out over the fingerprint — a name alone is
    /// spoofable, and a corrupt signature would only be rejected by nix after the whole
    /// transfer.
    pub fn any_sig_valid(&self, info: &RemoteNarinfo) -> bool {
        if self.keys.is_empty() || info.sigs.is_empty() {
            return false;
        }
        let fp = fingerprint(info);
        for sig in &info.sigs {
            let Some((name, b64)) = sig.split_once(':') else { continue };
            let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64) else {
                continue;
            };
            let Ok(sig) = ed25519_compact::Signature::from_slice(&raw) else { continue };
            for (kname, pk) in &self.keys {
                if kname == name && pk.verify(fp.as_bytes(), &sig).is_ok() {
                    return true;
                }
            }
        }
        false
    }
}

/// The signed fingerprint, exactly as nix computes it (path-info.cc): references are FULL store
/// paths, sorted; the store dir is taken from the path itself (the narinfo carries basenames).
pub(crate) fn fingerprint(info: &RemoteNarinfo) -> String {
    let store_dir = info.store_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("/nix/store");
    let mut refs: Vec<String> =
        info.references.iter().map(|b| format!("{store_dir}/{b}")).collect();
    refs.sort();
    format!(
        "1;{};sha256:{};{};{}",
        info.store_path,
        nixbase32::encode(&info.nar_hash),
        info.nar_size,
        refs.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A REAL narinfo tuple and cache.nixos.org-1 signature (captured from a live store), so the
    /// fingerprint format is pinned against nix's actual implementation, not our reading of it.
    fn golden() -> RemoteNarinfo {
        RemoteNarinfo {
            store_path: "/nix/store/cmgcrp6v3ywyq0b5a4faaqi9ffp91bjy-hello-2.12.3".into(),
            compression: "none".into(),
            nar_hash: <[u8; 32]>::try_from(
                nixbase32::decode("1wyl51h7ihyls788agvhb99a8b27fn0pkcgaicg9v3a4d7w9asv5", 32)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap(),
            nar_size: 294440,
            references: vec![
                "cj4jysawj8cc6yv2cwdgzxhdhq7dnf05-glibc-2.42-67".into(),
                "cmgcrp6v3ywyq0b5a4faaqi9ffp91bjy-hello-2.12.3".into(),
            ],
            deriver: None,
            ca: None,
            sigs: vec![
                "cache.nixos.org-1:lAYOHJFn37TtVX6DaqeGo6sxT+Oomoe7dpLptEWSD3elIj78uf9SPZIDpoybA4UmW2HZPkiyl1jsT6MwhT2FBA==".into(),
            ],
        }
    }

    #[test]
    fn verifies_a_real_cache_nixos_org_signature() {
        let keys = TrustedKeys::parse(&[NIX_DEFAULT_KEY.to_owned()]);
        assert_eq!(keys.len(), 1);
        assert!(keys.any_sig_valid(&golden()), "fingerprint must match nix's exactly");
    }

    #[test]
    fn rejects_wrong_key_wrong_sig_and_tampering() {
        let keys = TrustedKeys::parse(&[NIX_DEFAULT_KEY.to_owned()]);
        // Untrusted key name.
        let mut info = golden();
        info.sigs = vec![format!("evil-1:{}", golden().sigs[0].split_once(':').unwrap().1)];
        assert!(!keys.any_sig_valid(&info));
        // Corrupt signature bytes.
        let mut info = golden();
        info.sigs = vec!["cache.nixos.org-1:AAAAHJFn37TtVX6DaqeGo6sxT+Oomoe7dpLptEWSD3elIj78uf9SPZIDpoybA4UmW2HZPkiyl1jsT6MwhT2FBA==".into()];
        assert!(!keys.any_sig_valid(&info));
        // Any signed-field tamper breaks it: size…
        let mut info = golden();
        info.nar_size += 1;
        assert!(!keys.any_sig_valid(&info));
        // …and references.
        let mut info = golden();
        info.references.pop();
        assert!(!keys.any_sig_valid(&info));
        // No trusted keys at all: nothing verifies.
        assert!(!TrustedKeys::none().any_sig_valid(&golden()));
    }

    #[test]
    fn roundtrip_with_a_fresh_keypair() {
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([42u8; 32]));
        let mut info = golden();
        let sig = kp.sk.sign(fingerprint(&info).as_bytes(), None);
        info.sigs = vec![format!(
            "mesh-test-1:{}",
            base64::engine::general_purpose::STANDARD.encode(*sig)
        )];
        let pk = format!(
            "mesh-test-1:{}",
            base64::engine::general_purpose::STANDARD.encode(*kp.pk)
        );
        assert!(TrustedKeys::parse(&[pk]).any_sig_valid(&info));
        // The signature is key-name-scoped: same bytes under a different trusted name fail.
        let other = format!(
            "other:{}",
            base64::engine::general_purpose::STANDARD.encode(*kp.pk)
        );
        let renamed = TrustedKeys::parse(&[other]);
        assert!(!renamed.any_sig_valid(&info));
    }

    #[test]
    fn nix_conf_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("nix.conf");
        // Absent setting: nix's compiled-in default applies.
        std::fs::write(&conf, "experimental-features = nix-command\n").unwrap();
        assert_eq!(TrustedKeys::from_nix_conf(&conf).unwrap().len(), 1);
        // Explicit setting replaces the default (later assignments win), extra- appends.
        std::fs::write(
            &conf,
            format!(
                "trusted-public-keys = bogus\n\
                 trusted-public-keys = {NIX_DEFAULT_KEY}\n\
                 extra-trusted-public-keys = also-bogus {NIX_DEFAULT_KEY}\n"
            ),
        )
        .unwrap();
        let keys = TrustedKeys::from_nix_conf(&conf).unwrap();
        // bogus entries are skipped with a warning; the two well-formed copies remain.
        assert_eq!(keys.len(), 2);
        assert!(keys.any_sig_valid(&golden()));
        // Empty assignment means "trust nothing", not "use the default".
        std::fs::write(&conf, "trusted-public-keys =\n").unwrap();
        assert!(TrustedKeys::from_nix_conf(&conf).unwrap().is_empty());
    }
}
