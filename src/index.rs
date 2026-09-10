//! The replicated mesh index, protocol v2: possession separated from attestation.
//!
//! POSSESSION — which origin holds bytes with which NAR hash — is per-origin state with
//! exactly ONE writer (its origin). An origin numbers its own Have/Drop events with a
//! monotonic seq, so "peer P has seen event N" collapses to "P's watermark >= N", journal
//! compaction to the minimum watermark across the (fixed) peer set, and recovery to a
//! wholesale snapshot of the origin's current hash set — the same path that serves first
//! contact, cache loss, and peer addition.
//!
//! ATTESTATION — "store path P has content H (size, references), believable because of a
//! signature over the narinfo fingerprint or content addressing" — is a FACT: self-verifying,
//! never false, never retracted. Facts ride origin journals when introduced and travel
//! wholesale with snapshot-bearing responses; locally they form a grow-only set, deduped by
//! (store path, NAR hash) with signature sets unioned. Because facts outlive holdings, a
//! signature survives holder churn: a node that GC'd a path re-substitutes it later — from a
//! peer that copied it, or one that rebuilt it bit-identically — under its own old signature.
//! Retention is the held-plus-grace policy: a fact whose hash nobody has held for the grace
//! window is reaped.
//!
//! Trust is enforced at USE, not at ingestion: any well-formed attestation is stored and
//! relayed verbatim (it is journaled at its origin either way), and lookups re-verify — CA, or
//! any signature valid under the CURRENT anchor. Removing a trusted key makes its rows go
//! inert, not away; re-adding it wakes them. No clock surgery on anchor changes, unlike the
//! fused v1 protocol, because nothing feasibility-dependent is ever skipped on apply.
//!
//! A narinfo lookup composes the two layers: attestations for the requested hash part yield
//! NAR hashes, current holders of those hashes are the byte sources.
//!
//! Storage lives behind the SyncStore trait (store/): rocksdb embedded by default, postgres
//! for deployments that want native shared-table concurrency. Both are disposable state —
//! self-verifying, re-learnable; a lost store mints a new GENERATION so regenerated sequence
//! numbers never alias old ones, and peers snapshot us back up.

use crate::db::StoreDb;
use crate::narinfo::RemoteNarinfo;
use crate::sig::TrustedKeys;
use crate::store::{hash_part_of, HoldOp, SyncStore};
use anyhow::{bail, Context, Result};
use prost::Message as _;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::debug;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/narshare.mesh.v2.rs"));
}

/// Journal rows retained per origin beyond the min-watermark rule — the backstop that keeps one
/// dead or long-offline peer from pinning the journal forever. Stragglers land on the snapshot
/// path, which must exist anyway.
const JOURNAL_BACKSTOP: u64 = 50_000;
/// Suffix bytes per origin per sync response; more sets `truncated` and the puller loops.
const SUFFIX_BYTES_CAP: usize = 8 << 20;
/// Soft byte budget for one WHOLE sync response (suffix events + snapshot hashes + the
/// attestation dump, encoded). Origins that would overflow it are deferred with an empty
/// truncated suffix and picked up by the puller's truncated loop next round.
const RESPONSE_BYTES_CAP: usize = 24 << 20;
/// Half-life of persisted MW weights: at load, each weight is pulled toward uniform (1.0) by
/// 2^(-age/half_life) — an hour-old vector keeps ~97% of its shape, a week-old one ~1%
/// (effectively fresh). The best-rate yardstick and mean-loss decay toward 0 the same way.
const MW_HALF_LIFE_SECS: f64 = 86_400.0;

pub struct Index {
    store: Arc<dyn SyncStore>,
    pub self_name: String,
    /// Configured origin universe: self + peers. Anything else is rejected and reaped.
    origin_set: HashSet<String>,
    peer_names: Vec<String>,
    trusted: TrustedKeys,
    /// How long an attestation outlives its last holder.
    grace: Duration,
    /// Pacing for the maintenance pass: sync traffic calls maybe_compact() on every
    /// request/pull, but journal floors move at most once a minute and the attestation
    /// reaper — a full-table scan — at most every ten. Unpaced compact() stays for tests
    /// and for callers that just did something reap-worthy.
    last_compact: Mutex<Option<std::time::Instant>>,
    last_reap: Mutex<Option<std::time::Instant>>,
    /// Deriver drv path -> "may this output be substituted" verdict cache. Reading and
    /// scanning a drv file happens at most once per deriver per process lifetime; without the
    /// cache, paths filtered by allowSubstitutes=false would re-read their drv on every diff
    /// cycle forever (they never produce an attestation, so they stay "new" to the differ).
    nosub: Mutex<HashMap<String, bool>>,
}

/// One lookup result: a feasible attestation and who currently holds its bytes.
#[derive(Debug)]
pub struct Found {
    pub info: RemoteNarinfo,
    /// Origin names, possibly including self. Never empty.
    pub holders: Vec<String>,
}

pub enum Apply {
    Applied(usize),
    /// The suffix did not connect to our state (gap or unknown baseline): snapshot required.
    NeedSnapshot,
}

/// What a sync request gets back: per-origin updates, plus (iff any of them is a snapshot)
/// the full retained attestation dump — the recovery path that re-teaches facts whose journal
/// events were compacted away.
pub struct RespondBundle {
    pub origins: Vec<proto::OriginUpdate>,
    pub attests: Vec<proto::Attestation>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Structurally valid enough to store and serve: a real hash, a real store path, and at least
/// one reason anyone could ever believe it (content addressing or a signature).
pub fn well_formed(a: &proto::Attestation) -> bool {
    a.nar_hash.len() == 32
        && a.store_path.starts_with('/')
        && hash_part_of(&a.store_path).len() == 32
        && (!a.ca.is_empty() || !a.sigs.is_empty())
}

pub fn att_to_remote(a: &proto::Attestation) -> RemoteNarinfo {
    RemoteNarinfo {
        store_path: a.store_path.clone(),
        compression: "none".into(),
        nar_hash: <[u8; 32]>::try_from(a.nar_hash.as_slice()).unwrap_or([0u8; 32]),
        nar_size: a.nar_size,
        references: a.references.clone(),
        deriver: None,
        ca: (!a.ca.is_empty()).then(|| a.ca.clone()),
        sigs: a.sigs.clone(),
    }
}

impl Index {
    pub fn open(
        store: Arc<dyn SyncStore>,
        self_name: &str,
        peer_names: &[String],
        trusted: TrustedKeys,
        grace: Duration,
    ) -> Result<Self> {
        let mut origin_set: HashSet<String> = peer_names.iter().cloned().collect();
        origin_set.insert(self_name.to_owned());

        // Self generation: minted once per store lifetime. A lost store mints a new one, so
        // regenerated (gen, seq) pairs never alias what peers saw before the loss. Nanoseconds:
        // two store lifetimes of the same node must never share a generation, even when created
        // within the same second.
        let self_gen: u64 = match store.meta_get("self_generation")? {
            Some(g) => g.parse().context("corrupt self_generation")?,
            None => {
                let g = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(1);
                store.meta_put("self_generation", &g.to_string())?;
                g
            }
        };
        // The meta value is authoritative (heals a torn bump too).
        store.set_generation(self_name, self_gen)?;

        // Reap origins that left the config: their holdings and journals, and — crucially —
        // their watermark contribution, which would otherwise pin journal compaction forever.
        let keep: Vec<String> = origin_set.iter().cloned().collect();
        store.retain_origins(&keep, unix_now())?;

        Ok(Self {
            store,
            self_name: self_name.to_owned(),
            origin_set,
            peer_names: peer_names.to_vec(),
            trusted,
            grace,
            last_compact: Mutex::new(None),
            last_reap: Mutex::new(None),
            nosub: Mutex::new(HashMap::new()),
        })
    }

    pub fn is_known_origin(&self, name: &str) -> bool {
        self.origin_set.contains(name)
    }

    /// Believable under the CURRENT anchor: CA, or any signature that verifies. Checked at
    /// use — removed keys make rows inert, re-added keys wake them.
    fn feasible(&self, a: &proto::Attestation) -> bool {
        if !well_formed(a) {
            return false;
        }
        if !a.ca.is_empty() {
            return true;
        }
        self.trusted.any_sig_valid(&att_to_remote(a))
    }

    /// Our full clock vector, for sync requests (doubles as the ack that drives compaction).
    pub fn clock_vector(&self) -> Result<Vec<proto::OriginClock>> {
        let mut names: Vec<&String> = self.origin_set.iter().collect();
        names.sort();
        names
            .into_iter()
            .map(|origin| {
                let c = self.store.clock(origin)?;
                Ok(proto::OriginClock {
                    origin: origin.clone(),
                    generation: c.generation,
                    seq: c.seq,
                })
            })
            .collect()
    }

    /// Record what `peer` proved it has seen (its sync request's clock vector).
    pub fn record_watermarks(&self, peer: &str, clocks: &[proto::OriginClock]) -> Result<()> {
        for c in clocks {
            if !self.origin_set.contains(&c.origin) {
                continue;
            }
            // Only meaningful if the peer is on the same generation we are; a stale-generation
            // watermark must not unblock compaction of a journal it has not actually seen.
            if self.store.clock(&c.origin)?.generation != c.generation {
                continue;
            }
            self.store.advance_watermark(peer, &c.origin, c.seq)?;
        }
        Ok(())
    }

    /// Build the answer for a sync request: per origin up-to-date, journal suffix, or
    /// snapshot; plus the attestation dump when any snapshot ships.
    pub fn respond(&self, req: &proto::SyncRequest) -> Result<RespondBundle> {
        self.respond_budgeted(req, RESPONSE_BYTES_CAP)
    }

    fn respond_budgeted(&self, req: &proto::SyncRequest, budget: usize) -> Result<RespondBundle> {
        let have: HashMap<&str, &proto::OriginClock> =
            req.have.iter().map(|c| (c.origin.as_str(), c)).collect();
        let mut origins = Vec::new();
        let mut attests: Vec<proto::Attestation> = Vec::new();
        let mut sent_attests = false;
        let mut used = 0usize;
        // Sorted iteration: deterministic budget allocation across rounds.
        let mut names: Vec<&String> = self.origin_set.iter().collect();
        names.sort();
        for name in names {
            let clock = self.store.clock(name)?;
            let (gen, seq, tail) = (clock.generation, clock.seq, clock.tail_seq);
            if gen == 0 {
                continue; // we know nothing about this origin yet
            }
            let theirs = have.get(name.as_str());
            let (their_gen, their_seq) = theirs.map(|c| (c.generation, c.seq)).unwrap_or((0, 0));
            if their_gen > gen {
                continue; // they are ahead of us on this origin; nothing useful from us
            }
            if their_gen == gen && their_seq >= seq {
                origins.push(proto::OriginUpdate {
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
                origins.push(proto::OriginUpdate {
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
                // Journal suffix (their_seq, ...], capped per origin and by the budget.
                let (raw, truncated) =
                    self.store
                        .journal_suffix(name, their_seq, SUFFIX_BYTES_CAP)?;
                let mut events = Vec::with_capacity(raw.len());
                for blob in raw {
                    used += blob.len();
                    events.push(proto::Event::decode(&blob[..]).context("corrupt journal event")?);
                }
                origins.push(proto::OriginUpdate {
                    origin: name.clone(),
                    generation: gen,
                    seq,
                    truncated,
                    body: Some(proto::origin_update::Body::Suffix(proto::Suffix { events })),
                });
                continue;
            } else {
                // Their watermark predates our tail, or their generation is stale: snapshot,
                // and with the FIRST snapshot of the response, the retained facts (journal
                // history that would have carried them is gone by definition of this path).
                let held: Vec<Vec<u8>> = self
                    .store
                    .holdings(name)?
                    .into_iter()
                    .map(|h| h.to_vec())
                    .collect();
                used += held.len() * 34;
                if !sent_attests {
                    sent_attests = true;
                    attests = self.store.all_attestations()?;
                    used += attests
                        .iter()
                        .map(prost::Message::encoded_len)
                        .sum::<usize>();
                }
                proto::origin_update::Body::Snapshot(proto::Snapshot { held })
            };
            origins.push(proto::OriginUpdate {
                origin: name.clone(),
                generation: gen,
                seq,
                truncated: false,
                body: Some(body),
            });
        }
        Ok(RespondBundle { origins, attests })
    }

    /// Apply one origin's journal suffix. Idempotent; events are journaled verbatim (faithful
    /// relay) while only structurally valid operations materialize.
    pub fn apply_suffix(
        &self,
        origin: &str,
        generation: u64,
        events: &[proto::Event],
    ) -> Result<Apply> {
        if origin == self.self_name || !self.origin_set.contains(origin) {
            bail!("suffix for unexpected origin {origin:?}");
        }
        let cur = self.store.clock(origin)?;
        if generation < cur.generation {
            return Ok(Apply::Applied(0)); // stale relay; ignore
        }
        if generation > cur.generation && !(cur.generation == 0 && cur.seq == 0) {
            // The origin regenerated (cache loss): our copy is void. A suffix cannot rebuild
            // it from nothing — only a snapshot can. (From a zero clock, adopting the
            // generation via a suffix is identical to snapshotting empty state and replaying.)
            return Ok(Apply::NeedSnapshot);
        }
        let mut journal: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut holds: Vec<HoldOp> = Vec::new();
        let mut attests: Vec<proto::Attestation> = Vec::new();
        let mut seq = cur.seq;
        for e in events {
            if e.seq <= seq {
                continue; // replay
            }
            if e.seq != seq + 1 {
                return Ok(Apply::NeedSnapshot); // gap: suffix does not connect
            }
            journal.push((e.seq, e.encode_to_vec()));
            match &e.op {
                Some(proto::event::Op::Have(h)) => match <[u8; 32]>::try_from(h.as_slice()) {
                    Ok(h) => holds.push(HoldOp::Add(h)),
                    Err(_) => debug!("origin {origin}: malformed have ignored"),
                },
                Some(proto::event::Op::Drop(h)) => match <[u8; 32]>::try_from(h.as_slice()) {
                    Ok(h) => holds.push(HoldOp::Drop(h)),
                    Err(_) => debug!("origin {origin}: malformed drop ignored"),
                },
                Some(proto::event::Op::Attest(a)) => {
                    if well_formed(a) {
                        attests.push(a.clone());
                    } else {
                        // Journaled verbatim for faithful relay, but never enters our tables.
                        debug!(
                            "origin {origin}: malformed attestation for {} ignored",
                            a.store_path
                        );
                    }
                }
                None => {}
            }
            seq = e.seq;
        }
        if journal.is_empty() {
            return Ok(Apply::Applied(0));
        }
        let applied = journal.len();
        if !self.store.apply_events(
            origin,
            (cur.generation, cur.seq),
            (generation, seq),
            &journal,
            &holds,
            &attests,
            unix_now(),
            false, // a replica can only forget, never diverge: async is safe
        )? {
            // A concurrent pull applied this suffix first; the next round reconciles.
            return Ok(Apply::Applied(0));
        }
        Ok(Apply::Applied(applied))
    }

    /// Replace our copy of an origin's possession set wholesale (the recovery path). Returns
    /// how many hashes the new copy holds, 0 when the snapshot was stale.
    pub fn apply_snapshot(
        &self,
        origin: &str,
        generation: u64,
        seq: u64,
        held: &[Vec<u8>],
    ) -> Result<usize> {
        if origin == self.self_name || !self.origin_set.contains(origin) {
            bail!("snapshot for unexpected origin {origin:?}");
        }
        let hashes: Vec<[u8; 32]> = held
            .iter()
            .filter_map(|h| <[u8; 32]>::try_from(h.as_slice()).ok())
            .collect();
        if self
            .store
            .replace_holdings(origin, generation, seq, &hashes, unix_now())?
        {
            Ok(hashes.len())
        } else {
            Ok(0) // stale relay (a concurrent pull advanced this origin past `seq`)
        }
    }

    /// Merge attestation facts from a snapshot-bearing response. Returns how many were new.
    pub fn merge_attests(&self, attests: &[proto::Attestation]) -> Result<usize> {
        let valid: Vec<proto::Attestation> =
            attests.iter().filter(|a| well_formed(a)).cloned().collect();
        if valid.is_empty() {
            return Ok(0);
        }
        self.store.merge_attestations(&valid, unix_now())
    }

    /// Remint our self generation strictly above `floor` — the self-clock-regression recovery.
    /// Triggered from the pull side when a peer reports a FUTURE for our own origin (cache loss
    /// with a backwards wall clock; a restored disk image): the mesh remembers seqs we no
    /// longer own, so we must move to a fresh generation and let snapshots re-teach everyone.
    /// Journal and holdings stay — content is still correct, only the (generation, seq)
    /// namespace moves.
    pub fn bump_self_generation(&self, floor: u64) -> Result<u64> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        let g = nanos.max(floor.saturating_add(1));
        // meta first (authoritative), then the clock; a crash in between is healed at open,
        // where meta's value is re-stamped onto the clock.
        self.store.meta_put("self_generation", &g.to_string())?;
        self.store.set_generation(&self.self_name, g)?;
        Ok(g)
    }

    /// Does the deriver permit substitution of its outputs? Missing deriver or unreadable
    /// drv file defaults to yes (the attribute is advisory and absent means true). Detects
    /// both the classic env encoding and the __structuredAttrs JSON encoding.
    fn substitutable(&self, c: &crate::db::Candidate) -> bool {
        let Some(drv) = &c.deriver else { return true };
        if let Some(&v) = self.nosub.lock().unwrap().get(drv) {
            return v;
        }
        let allows = std::fs::read_to_string(drv)
            .map(|s| {
                !s.contains(r#"("allowSubstitutes","")"#)
                    && !s.contains(r#"\"allowSubstitutes\":false"#)
            })
            .unwrap_or(true);
        self.nosub.lock().unwrap().insert(drv.clone(), allows);
        allows
    }

    /// The exporting node's half: diff our Nix db against our indexed state and journal the
    /// difference — possession (Have/Drop of NAR hashes) and new attestations. Facts are never
    /// retracted, so a GC'd or regressed path costs one Drop and nothing else; feasibility is
    /// checked HERE, by the exporter: only CA or trusted-signed rows are attested. Returns
    /// events emitted.
    ///
    /// Three-phase so the store writes happen once: the self origin has exactly one writer
    /// (the own-db loop; tests call this inline), so the read snapshot cannot go stale.
    pub fn sync_own_db(&self, db: &StoreDb) -> Result<usize> {
        let candidates = db.candidates()?;

        // Phase 1: what we already export.
        let held: HashSet<[u8; 32]> = self.store.holdings(&self.self_name)?.into_iter().collect();
        let claims: HashMap<(String, Vec<u8>), Vec<String>> = self
            .store
            .attested_claims()?
            .into_iter()
            .map(|(path, hash, sigs)| ((path, hash), sigs))
            .collect();

        // Phase 2: diff. Possession is the distinct hash set of every candidate; attestations
        // are per-path facts, filtered by the deriver's allowSubstitutes and by feasibility
        // (with its ed25519 verify) — both consulted only for rows that actually changed.
        let local: HashSet<[u8; 32]> = candidates.iter().map(|c| c.nar_hash).collect();
        let mut attests: Vec<proto::Attestation> = Vec::new();
        for c in &candidates {
            // Possession covers every path; a FACT needs a reason anyone could believe it.
            // Unbelievable rows are skipped before any per-row work — they never enter the
            // fact table, so they would otherwise look "changed" and re-derive forever.
            if c.ca.is_none() && c.sigs.is_empty() {
                continue;
            }
            let key = (c.path.clone(), c.nar_hash.to_vec());
            let known = claims
                .get(&key)
                .is_some_and(|sigs| c.sigs.iter().all(|s| sigs.contains(s)));
            if known {
                // A merged sig SUPERSET of ours is not a change — comparing by equality here
                // would re-attest forever: a mesh-wide hint/pull livelock.
                continue;
            }
            if !self.substitutable(c) {
                continue;
            }
            // References are fetched HERE, one query per CHANGED row — never for the whole
            // candidate set (a per-row JOIN across a 100k-path store cost ~10 CPU-seconds per
            // diff, measured in production). The signed fingerprint covers them and the
            // attestation carries them.
            let refs = db.references_of(c.id)?;
            let a = proto::Attestation {
                store_path: c.path.clone(),
                nar_hash: c.nar_hash.to_vec(),
                nar_size: c.nar_size,
                references: refs
                    .iter()
                    .map(|r| crate::narinfo::basename(r, &db.store_dir).to_owned())
                    .collect(),
                ca: c.ca.clone().unwrap_or_default(),
                sigs: c.sigs.clone(),
            };
            if self.feasible(&a) {
                attests.push(a);
            }
        }
        let mut holds: Vec<HoldOp> = Vec::new();
        holds.extend(local.difference(&held).map(|h| HoldOp::Add(*h)));
        holds.extend(held.difference(&local).map(|h| HoldOp::Drop(*h)));
        if attests.is_empty() && holds.is_empty() {
            return Ok(0);
        }

        // Phase 3: journal and materialize. Chunked — a first export of a whole store is
        // hundreds of thousands of events, and encoding them plus the store's write batch all
        // at once was a half-gigabyte memory spike at switch time. Each chunk is atomic and
        // advances the clock; the self origin is single-writer, so a chunk boundary is just
        // a smaller-than-usual export, and a crash between chunks re-diffs the remainder.
        const EXPORT_CHUNK: usize = 10_000;
        enum Op<'a> {
            Att(&'a proto::Attestation),
            Hold(&'a HoldOp),
        }
        let ops: Vec<Op> = attests
            .iter()
            .map(Op::Att)
            .chain(holds.iter().map(Op::Hold))
            .collect();
        let emitted = ops.len();
        let cur = self.store.clock(&self.self_name)?;
        let mut seq = cur.seq;
        for chunk in ops.chunks(EXPORT_CHUNK) {
            let expect = (cur.generation, seq);
            let mut journal: Vec<(u64, Vec<u8>)> = Vec::with_capacity(chunk.len());
            let mut chunk_holds: Vec<HoldOp> = Vec::new();
            let mut chunk_atts: Vec<proto::Attestation> = Vec::new();
            for op in chunk {
                seq += 1;
                let pop = match op {
                    Op::Att(a) => {
                        chunk_atts.push((*a).clone());
                        proto::event::Op::Attest((*a).clone())
                    }
                    Op::Hold(h) => {
                        chunk_holds.push(**h);
                        match h {
                            HoldOp::Add(h) => proto::event::Op::Have(h.to_vec()),
                            HoldOp::Drop(h) => proto::event::Op::Drop(h.to_vec()),
                        }
                    }
                };
                let e = proto::Event { seq, op: Some(pop) };
                journal.push((seq, e.encode_to_vec()));
            }
            if !self.store.apply_events(
                &self.self_name,
                expect,
                (cur.generation, seq),
                &journal,
                &chunk_holds,
                &chunk_atts,
                unix_now(),
                true, // OUR seqs must never be reissued: self-origin commits are durable
            )? {
                bail!("self-origin apply raced: the own-db loop must be the only self writer");
            }
        }
        // The diff's transient maps (candidates, claims) peak at ~100MB on a real store, and
        // glibc retains freed arenas indefinitely — hand them back so a build's worth of diff
        // cycles doesn't read as daemon bloat.
        if emitted > 0 {
            unsafe { libc::malloc_trim(0) };
        }
        Ok(emitted)
    }

    /// The sync-path maintenance entry: full compaction is idempotent housekeeping, so pace
    /// it — at most one journal-floor pass per minute and one attestation reap (a full-table
    /// scan) per ten. This was measured to matter: unpaced, every inbound sync request paid
    /// the reap scan, which alone was most of an idle node's CPU.
    pub fn maybe_compact(&self) -> Result<()> {
        const COMPACT_EVERY: Duration = Duration::from_secs(60);
        const REAP_EVERY: Duration = Duration::from_secs(600);
        let now = std::time::Instant::now();
        {
            let mut last = self.last_compact.lock().unwrap();
            if last.is_some_and(|t| now.duration_since(t) < COMPACT_EVERY) {
                return Ok(());
            }
            *last = Some(now);
        }
        let reap = {
            let mut last = self.last_reap.lock().unwrap();
            if last.is_some_and(|t| now.duration_since(t) < REAP_EVERY) {
                false
            } else {
                *last = Some(now);
                true
            }
        };
        self.compact_inner(reap)
    }

    /// Compact journals — to the minimum watermark across all configured peers (the ack rule),
    /// with the size backstop so a straggler cannot pin retention forever — and reap
    /// attestations whose hash has been unheld past the grace window. Unpaced; production
    /// traffic goes through maybe_compact(), this is for tests and explicit maintenance.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn compact(&self) -> Result<()> {
        self.compact_inner(true)
    }

    fn compact_inner(&self, reap: bool) -> Result<()> {
        let marks: HashMap<(String, String), u64> = self
            .store
            .watermarks()?
            .into_iter()
            .map(|(peer, origin, seq)| ((peer, origin), seq))
            .collect();
        for origin in &self.origin_set {
            let c = self.store.clock(origin)?;
            let mut floor = c.seq;
            for peer in &self.peer_names {
                let w = marks
                    .get(&(peer.clone(), origin.clone()))
                    .copied()
                    .unwrap_or(0);
                floor = floor.min(w);
            }
            // Backstop: never retain more than JOURNAL_BACKSTOP events regardless of acks.
            floor = floor.max(c.seq.saturating_sub(JOURNAL_BACKSTOP));
            if floor > c.tail_seq {
                self.store.compact_journal(origin, floor)?;
            }
        }
        if reap {
            let cutoff = unix_now().saturating_sub(self.grace.as_secs());
            let reaped = self.store.reap_attestations(cutoff)?;
            if reaped > 0 {
                debug!("reaped {reaped} attestation(s) unheld past the grace window");
            }
        }
        Ok(())
    }

    /// Lookup by store-path hash part; feasibility re-verified at use, holderless rows omitted.
    pub fn lookup_hash_part(&self, hash_part: &str) -> Result<Vec<Found>> {
        Ok(self
            .store
            .lookup_hash_part(hash_part)?
            .into_iter()
            .filter(|(a, _)| self.feasible(a))
            .map(|(a, holders)| Found {
                info: att_to_remote(&a),
                holders,
            })
            .collect())
    }

    /// Lookup by NAR hash (NAR requests after a proxy restart included — the index persists).
    pub fn lookup_nar_hash(&self, nar_hash: &[u8; 32]) -> Result<Vec<Found>> {
        Ok(self
            .store
            .lookup_nar_hash(nar_hash)?
            .into_iter()
            .filter(|(a, _)| self.feasible(a))
            .map(|(a, holders)| Found {
                info: att_to_remote(&a),
                holders,
            })
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
        let now = unix_now();
        let rows: Vec<(String, f64)> = peers.iter().cloned().zip(weights.iter().copied()).collect();
        self.store
            .mw_save(&rows, now, &format!("{best_rate} {avg_loss} {now}"))
    }

    /// Load persisted MW state for the given peer order, decayed toward the fresh pool
    /// (uniform weights, zero yardstick) by staleness. None when nothing was ever saved.
    pub fn load_mw(&self, peers: &[String]) -> Result<Option<(Vec<f64>, f64, f64)>> {
        let now = unix_now() as i64;
        let (rows, globals) = self.store.mw_load()?;
        if rows.is_empty() {
            return Ok(None);
        }
        // Reap rows for peers that left the config.
        if rows.iter().any(|(name, _, _)| !peers.contains(name)) {
            self.store.mw_prune(peers)?;
        }
        let by_name: HashMap<&str, (f64, u64)> = rows
            .iter()
            .map(|(n, w, u)| (n.as_str(), (*w, *u)))
            .collect();
        let decay = |age: i64| 0.5f64.powf((age.max(0) as f64) / MW_HALF_LIFE_SECS);
        let mut any = false;
        let weights: Vec<f64> = peers
            .iter()
            .map(|name| match by_name.get(name.as_str()) {
                Some(&(w, updated)) => {
                    any = true;
                    1.0 + (w - 1.0) * decay(now - updated as i64)
                }
                None => 1.0, // a new peer starts fresh
            })
            .collect();
        if !any {
            return Ok(None);
        }
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
        self.store.mw_shift_updated(secs).unwrap();
    }

    /// Full introspection for the status endpoint: per-origin clocks, journal and holding
    /// sizes, attestation total, watermarks.
    pub fn status(&self) -> Result<serde_json::Value> {
        let mut names: Vec<&String> = self.origin_set.iter().collect();
        names.sort();
        let mut origins: Vec<serde_json::Value> = Vec::new();
        for name in names {
            let c = self.store.clock(name)?;
            let (journal_len, holdings) = self.store.origin_stats(name)?;
            origins.push(serde_json::json!({
                "name": name,
                "generation": c.generation,
                "seq": c.seq,
                "tail_seq": c.tail_seq,
                "journal_len": journal_len,
                "holdings": holdings,
            }));
        }
        let mut wm = self.store.watermarks()?;
        wm.sort();
        let watermarks: Vec<serde_json::Value> = wm
            .into_iter()
            .map(|(peer, origin, seq)| {
                serde_json::json!({ "peer": peer, "origin": origin, "seq": seq })
            })
            .collect();
        Ok(serde_json::json!({
            "self": self.self_name,
            "narinfos": self.store.count_attestations()?,
            "origins": origins,
            "watermarks": watermarks,
        }))
    }

    /// (generation, seq) of an origin as we know it.
    pub fn origin_clock(&self, origin: &str) -> Result<(u64, u64)> {
        let c = self.store.clock(origin)?;
        Ok((c.generation, c.seq))
    }

    /// Test seeding: register a fact and make `origin` a holder of its bytes at (gen 1,
    /// seq 1) — the v2 shape of what proxy tests used to do with a one-row v1 snapshot.
    #[cfg(test)]
    pub fn seed_fact(&self, origin: &str, att: proto::Attestation) {
        let h = att.nar_hash.clone();
        self.merge_attests(std::slice::from_ref(&att)).unwrap();
        self.apply_snapshot(origin, 1, 1, &[h]).unwrap();
    }

    #[cfg(test)]
    pub fn count_attestations(&self) -> usize {
        self.store.count_attestations().unwrap() as usize
    }

    #[cfg(test)]
    pub fn journal_len(&self, origin: &str) -> usize {
        self.store.origin_stats(origin).unwrap().0 as usize
    }

    #[cfg(test)]
    pub fn holdings_of(&self, origin: &str) -> Vec<[u8; 32]> {
        self.store.holdings(origin).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::rocks::RocksStore;

    fn att(name: &str, hash_byte: u8) -> proto::Attestation {
        proto::Attestation {
            store_path: format!("/nix/store/{}{name}", "x".repeat(32)),
            nar_hash: vec![hash_byte; 32],
            nar_size: 100,
            references: vec![],
            ca: "fixed:r:sha256:dummy".into(),
            sigs: vec![],
        }
    }

    fn have(seq: u64, hash_byte: u8) -> proto::Event {
        proto::Event {
            seq,
            op: Some(proto::event::Op::Have(vec![hash_byte; 32])),
        }
    }

    fn drop_(seq: u64, hash_byte: u8) -> proto::Event {
        proto::Event {
            seq,
            op: Some(proto::event::Op::Drop(vec![hash_byte; 32])),
        }
    }

    fn attest(seq: u64, a: proto::Attestation) -> proto::Event {
        proto::Event {
            seq,
            op: Some(proto::event::Op::Attest(a)),
        }
    }

    fn idx_grace(dir: &std::path::Path, name: &str, peers: &[&str], grace: Duration) -> Index {
        let peers: Vec<String> = peers.iter().map(|s| s.to_string()).collect();
        let store = Arc::new(RocksStore::open(&dir.join(format!("cache-{name}"))).unwrap());
        Index::open(store, name, &peers, TrustedKeys::none(), grace).unwrap()
    }

    fn idx(dir: &std::path::Path, name: &str, peers: &[&str]) -> Index {
        idx_grace(dir, name, peers, Duration::ZERO)
    }

    fn hp() -> String {
        "x".repeat(32)
    }

    #[test]
    fn possession_and_attestation_compose_into_lookups() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a", "c"]);
        // Origin a introduces the fact and holds the bytes; c holds the same bytes.
        assert!(matches!(
            b.apply_suffix("a", 1, &[attest(1, att("-p", 1)), have(2, 1)])
                .unwrap(),
            Apply::Applied(2)
        ));
        assert!(matches!(
            b.apply_suffix("c", 1, &[have(1, 1)]).unwrap(),
            Apply::Applied(1)
        ));
        let rows = b.lookup_hash_part(&hp()).unwrap();
        assert_eq!(rows.len(), 1);
        let mut holders = rows[0].holders.clone();
        holders.sort();
        assert_eq!(holders, vec!["a".to_string(), "c".to_string()]);
        // a rebuilds the path with different content: new fact, possession moves. The old
        // fact SURVIVES (facts are never retracted) and is still served while c holds h1.
        b.apply_suffix("a", 1, &[attest(3, att("-p", 2)), drop_(4, 1), have(5, 2)])
            .unwrap();
        let rows = b.lookup_hash_part(&hp()).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "both contents resolvable while both are held"
        );
        // c GCs h1: the h1 fact loses its last holder; with zero grace, compaction reaps it.
        b.apply_suffix("c", 1, &[drop_(2, 1)]).unwrap();
        b.compact().unwrap();
        let rows = b.lookup_hash_part(&hp()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].holders, vec!["a".to_string()]);
        assert_eq!(rows[0].info.nar_hash, [2u8; 32]);
        assert_eq!(b.count_attestations(), 1);
    }

    #[test]
    fn signatures_survive_holder_churn_within_grace() {
        // Use case: a host GCs a path, a peer rebuilds it bit-identically later; the fact
        // (with its signatures) must bridge the churn as long as the grace window allows.
        let dir = tempfile::tempdir().unwrap();
        let b = idx_grace(dir.path(), "b", &["a", "c"], Duration::from_secs(3600));
        let mut fact = att("-p", 1);
        fact.sigs = vec!["walt-laptop-1:AAAA".into()];
        b.apply_suffix("a", 1, &[attest(1, fact), have(2, 1)])
            .unwrap();
        // a GCs the path: zero holders, but the fact is stamped, not reaped (grace pending).
        b.apply_suffix("a", 1, &[drop_(3, 1)]).unwrap();
        b.compact().unwrap();
        assert_eq!(
            b.count_attestations(),
            1,
            "fact retained through the grace window"
        );
        assert!(
            b.lookup_hash_part(&hp()).unwrap().is_empty(),
            "but unservable: nobody has bytes"
        );
        // c rebuilds identical bytes: possession returns, the fact wakes with its sig intact.
        b.apply_suffix("c", 1, &[have(1, 1)]).unwrap();
        b.compact().unwrap();
        let rows = b.lookup_hash_part(&hp()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].holders, vec!["c".to_string()]);
        assert_eq!(rows[0].info.sigs, vec!["walt-laptop-1:AAAA".to_string()]);
    }

    #[test]
    fn allow_substitutes_false_is_not_attested() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let p1 = format!("{}/{}-wrapper", store.display(), "1".repeat(32));
        let p2 = format!("{}/{}-real", store.display(), "2".repeat(32));
        let db_path = crate::db::tests::fake_db(
            dir.path(),
            &[
                (&p1, [1u8; 32], 10, Some("fixed:r:sha256:x")),
                (&p2, [2u8; 32], 20, Some("fixed:r:sha256:y")),
            ],
        );
        // p1's deriver forbids substitution (classic env encoding); p2's allows (no attr).
        let drv1 = dir.path().join("wrapper.drv");
        std::fs::write(
            &drv1,
            r#"Derive([...],[("allowSubstitutes",""),("x","y")])"#,
        )
        .unwrap();
        let drv2 = dir.path().join("real.drv");
        std::fs::write(&drv2, r#"Derive([...],[("x","y")])"#).unwrap();
        crate::db::tests::set_deriver(&db_path, &p1, drv1.to_str().unwrap());
        crate::db::tests::set_deriver(&db_path, &p2, drv2.to_str().unwrap());

        let db = crate::db::StoreDb::open(&db_path, store.to_str().unwrap()).unwrap();
        let a = idx(dir.path(), "a", &["b"]);
        // One attestation (p2) plus possession of both hashes: the bytes of a nosub path are
        // still servable content, only its narinfo advertisement is suppressed.
        assert_eq!(a.sync_own_db(&db).unwrap(), 3);
        assert_eq!(a.count_attestations(), 1);
        assert_eq!(a.lookup_hash_part(&"2".repeat(32)).unwrap().len(), 1);
        assert!(a.lookup_hash_part(&"1".repeat(32)).unwrap().is_empty());
        assert_eq!(a.holdings_of("a").len(), 2);
        // Idempotent: the filtered path must not thrash the journal on later diffs.
        assert_eq!(a.sync_own_db(&db).unwrap(), 0);
    }

    #[test]
    fn refs_round_trip_in_order_and_body_lww_on_merge() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        // Deliberately NOT sorted: refs participate in the signature fingerprint, so storage
        // must reproduce the received order byte-exactly, never re-sort.
        let mut a1 = att("-p", 1);
        a1.references = vec!["zzz-late".into(), "aaa-early".into(), "mmm-mid".into()];
        b.apply_suffix("a", 1, &[attest(1, a1), have(2, 1)])
            .unwrap();
        let found = b.lookup_hash_part(&hp()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].info.references,
            ["zzz-late", "aaa-early", "mmm-mid"]
        );
        // The same fact re-introduced with a different body: LWW replaces it whole — a
        // shrunken list must not leave stale tail entries behind.
        let mut a2 = att("-p", 1);
        a2.references = vec!["only-one".into()];
        b.apply_suffix("a", 1, &[attest(3, a2)]).unwrap();
        let found = b.lookup_hash_part(&hp()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].info.references, ["only-one"]);
    }

    #[test]
    fn replay_is_idempotent_and_gaps_need_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        let events = [have(1, 1), have(2, 2)];
        assert!(matches!(
            b.apply_suffix("a", 1, &events).unwrap(),
            Apply::Applied(2)
        ));
        // Exact replay: applied 0, state unchanged.
        assert!(matches!(
            b.apply_suffix("a", 1, &events).unwrap(),
            Apply::Applied(0)
        ));
        assert_eq!(b.holdings_of("a").len(), 2);
        // A gap cannot be applied.
        assert!(matches!(
            b.apply_suffix("a", 1, &[have(9, 9)]).unwrap(),
            Apply::NeedSnapshot
        ));
        // A regenerated origin (higher gen over existing state) also needs a snapshot.
        assert!(matches!(
            b.apply_suffix("a", 2, &[have(1, 1)]).unwrap(),
            Apply::NeedSnapshot
        ));
        // And the snapshot replaces wholesale.
        let n = b.apply_snapshot("a", 2, 5, &[vec![3u8; 32]]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(b.holdings_of("a"), vec![[3u8; 32]]);
        assert_eq!(b.origin_clock("a").unwrap(), (2, 5));
    }

    #[test]
    fn first_contact_gets_snapshot_with_facts_then_suffixes_then_compaction() {
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
        assert_eq!(a.sync_own_db(&db).unwrap(), 4, "two attests + two haves");
        assert_eq!(a.sync_own_db(&db).unwrap(), 0, "differ must be idempotent");

        // First contact: b's zero clock earns a snapshot, and the response carries the facts.
        let b = idx(dir.path(), "b", &["a", "c"]);
        let req = proto::SyncRequest {
            requester: "b".into(),
            have: b.clock_vector().unwrap(),
        };
        let bundle = a.respond(&req).unwrap();
        let up = bundle.origins.iter().find(|u| u.origin == "a").unwrap();
        let proto::origin_update::Body::Snapshot(snap) = up.body.as_ref().unwrap() else {
            panic!("first contact must be a snapshot");
        };
        assert_eq!(
            bundle.attests.len(),
            2,
            "snapshot responses carry the retained facts"
        );
        b.merge_attests(&bundle.attests).unwrap();
        b.apply_snapshot("a", up.generation, up.seq, &snap.held)
            .unwrap();
        assert_eq!(b.holdings_of("a").len(), 2);
        assert_eq!(b.lookup_hash_part(&"1".repeat(32)).unwrap().len(), 1);

        // Incremental: a GCs one path; b's next pull is a 1-event suffix (one Drop — the
        // fact is NOT retracted).
        crate::db::tests::delete_path(&db_path, &p2);
        assert_eq!(a.sync_own_db(&db).unwrap(), 1);
        let req = proto::SyncRequest {
            requester: "b".into(),
            have: b.clock_vector().unwrap(),
        };
        let bundle = a.respond(&req).unwrap();
        assert!(bundle.attests.is_empty(), "no snapshot, no fact dump");
        let up = bundle.origins.iter().find(|u| u.origin == "a").unwrap();
        let proto::origin_update::Body::Suffix(sfx) = up.body.as_ref().unwrap() else {
            panic!("incremental pull must be a suffix");
        };
        assert_eq!(sfx.events.len(), 1);
        b.apply_suffix("a", up.generation, &sfx.events).unwrap();
        assert!(
            b.lookup_hash_part(&"2".repeat(32)).unwrap().is_empty(),
            "no holder anymore"
        );

        // Compaction: only when EVERY configured peer's watermark covers the journal.
        a.record_watermarks("b", &b.clock_vector().unwrap())
            .unwrap();
        a.compact().unwrap();
        assert!(
            a.journal_len("a") > 0,
            "peer c has not acked; journal must be retained"
        );
        a.record_watermarks("c", &b.clock_vector().unwrap())
            .unwrap();
        a.compact().unwrap();
        assert_eq!(
            a.journal_len("a"),
            0,
            "all peers acked: the history can be dropped"
        );
        // A straggler (or newcomer) whose watermark predates the tail gets a snapshot.
        let fresh = idx(dir.path(), "c", &["a", "b"]);
        let req = proto::SyncRequest {
            requester: "c".into(),
            have: fresh.clock_vector().unwrap(),
        };
        let bundle = a.respond(&req).unwrap();
        let up = bundle.origins.iter().find(|u| u.origin == "a").unwrap();
        assert!(matches!(
            up.body,
            Some(proto::origin_update::Body::Snapshot(_))
        ));
        assert!(!bundle.attests.is_empty());
    }

    #[test]
    fn malformed_attestations_are_relayed_but_never_served() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a", "c"]);
        // No CA, no sigs: nothing could ever believe it — journaled verbatim (faithful
        // relay), absent from the tables.
        let mut bogus = att("-p", 1);
        bogus.ca = String::new();
        bogus.sigs = vec![];
        b.apply_suffix("a", 1, &[attest(1, bogus), have(2, 1)])
            .unwrap();
        assert_eq!(b.count_attestations(), 0);
        assert_eq!(b.journal_len("a"), 2);
        // …and a downstream peer already on this generation receives the events from our
        // journal unchanged.
        let c = idx(dir.path(), "c", &["a", "b"]);
        c.apply_suffix("a", 1, &[]).unwrap(); // adopt nothing: still zero clock
        let req = proto::SyncRequest {
            requester: "c".into(),
            have: c.clock_vector().unwrap(),
        };
        let bundle = b.respond(&req).unwrap();
        let up = bundle.origins.iter().find(|u| u.origin == "a").unwrap();
        match up.body.as_ref().unwrap() {
            proto::origin_update::Body::Suffix(sfx) => assert_eq!(sfx.events.len(), 2),
            proto::origin_update::Body::Snapshot(snap) => {
                // A zero clock may also legitimately earn a snapshot; the possession must be
                // there while the malformed fact is not.
                assert_eq!(snap.held.len(), 1);
            }
            _ => panic!("expected data for origin a"),
        }
    }

    #[test]
    fn unsigned_trust_only_rows_are_inert_at_use() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        // Signed-only fact under an anchor (none) that cannot verify it: stored, relayed,
        // never served. Re-adding the key would wake it without any resync.
        let mut signed = att("-p", 1);
        signed.ca = String::new();
        signed.sigs = vec!["unknown-1:AAAA".into()];
        b.apply_suffix("a", 1, &[attest(1, signed), have(2, 1)])
            .unwrap();
        assert_eq!(
            b.count_attestations(),
            1,
            "well-formed: stored for relay and later trust"
        );
        assert!(
            b.lookup_hash_part(&hp()).unwrap().is_empty(),
            "inert under this anchor"
        );
    }

    #[test]
    fn unsigned_local_bytes_serve_under_someone_elses_fact() {
        // A locally built, unsigned, non-CA path exports POSSESSION only (bytes are trust-free;
        // the transfer verifies against the NAR hash) — and when a peer knows a believable fact
        // for the same content, our copy becomes a byte source for it.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let p = format!("{}/{}-local-build", store.display(), "9".repeat(32));
        let db_path = crate::db::tests::fake_db(dir.path(), &[(&p, [9u8; 32], 10, None)]);
        let db = crate::db::StoreDb::open(&db_path, store.to_str().unwrap()).unwrap();
        let a = idx(dir.path(), "a", &["b"]);
        assert_eq!(a.sync_own_db(&db).unwrap(), 1, "one Have, no attestation");
        assert_eq!(a.count_attestations(), 0);
        assert_eq!(a.holdings_of("a"), vec![[9u8; 32]]);
        assert!(a.lookup_hash_part(&"9".repeat(32)).unwrap().is_empty());
        // Peer b introduces a CA fact binding the same content.
        let fact = proto::Attestation {
            store_path: p,
            nar_hash: vec![9u8; 32],
            nar_size: 10,
            references: vec![],
            ca: "fixed:r:sha256:x".into(),
            sigs: vec![],
        };
        a.apply_suffix("b", 1, &[attest(1, fact)]).unwrap();
        let rows = a.lookup_hash_part(&"9".repeat(32)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].holders,
            vec!["a".to_string()],
            "the unsigned local copy is the byte source"
        );
        // And the differ stays quiet: a peer's fact is not ours to re-emit.
        assert_eq!(a.sync_own_db(&db).unwrap(), 0);
    }

    #[test]
    fn merged_peer_sigs_do_not_reemit_our_own_paths() {
        // Sig sets union in the shared fact table; the differ must compare by SUBSET or every
        // diff re-attests forever — a mesh-wide hint/pull livelock.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let p = format!("{}/{}-pkg", store.display(), "7".repeat(32));
        let db_path =
            crate::db::tests::fake_db(dir.path(), &[(&p, [7u8; 32], 10, Some("fixed:r:sha256:x"))]);
        let db = crate::db::StoreDb::open(&db_path, store.to_str().unwrap()).unwrap();
        let a = idx(dir.path(), "a", &["b"]);
        assert_eq!(a.sync_own_db(&db).unwrap(), 2);
        // Peer b holds the same content and knows an extra signature: merged into the fact.
        let fact = proto::Attestation {
            store_path: p.clone(),
            nar_hash: vec![7u8; 32],
            nar_size: 10,
            references: vec![],
            ca: "fixed:r:sha256:x".into(),
            sigs: vec!["some-cache-1:AAAA".into()],
        };
        a.apply_suffix("b", 1, &[attest(1, fact), have(2, 7)])
            .unwrap();
        // The differ sees a strict superset of its own sigs: NOT a change.
        assert_eq!(
            a.sync_own_db(&db).unwrap(),
            0,
            "sig merge must not re-attest"
        );
        assert_eq!(a.journal_len("a"), 2);
    }

    #[test]
    fn content_regression_moves_possession_but_keeps_the_fact() {
        // A path rebuilt in place with different content: possession moves to the new hash;
        // the old fact stays (true forever) but goes unservable, then ages out.
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let p = format!("{}/{}-pkg", store.display(), "7".repeat(32));
        let db_path =
            crate::db::tests::fake_db(dir.path(), &[(&p, [7u8; 32], 10, Some("fixed:r:sha256:x"))]);
        let db = crate::db::StoreDb::open(&db_path, store.to_str().unwrap()).unwrap();
        let a = idx(dir.path(), "a", &["b"]);
        assert_eq!(a.sync_own_db(&db).unwrap(), 2);
        crate::db::tests::delete_path(&db_path, &p);
        crate::db::tests::insert_path(&db_path, &p, [8u8; 32], 10, Some("fixed:r:sha256:y"));
        assert_eq!(
            a.sync_own_db(&db).unwrap(),
            3,
            "attest new + drop old + have new"
        );
        let rows = a.lookup_hash_part(&"7".repeat(32)).unwrap();
        assert_eq!(rows.len(), 1, "only the held content is served");
        assert_eq!(rows[0].info.nar_hash, [8u8; 32]);
        a.compact().unwrap();
        assert_eq!(
            a.count_attestations(),
            1,
            "zero grace: the unheld fact is reaped"
        );
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
        assert!(
            (w[0] - 1.0).abs() < 1e-6 && (w[1] - 0.05).abs() < 0.01,
            "{w:?}"
        );
        assert!(br > 9e7 && al > 0.19);

        // A day old: halfway back toward uniform.
        b.age_mw(86_400);
        let (w, _, _) = b.load_mw(&names).unwrap().unwrap();
        assert!(
            (w[1] - 0.525).abs() < 0.02,
            "one half-life ⇒ midpoint, got {}",
            w[1]
        );

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
    fn respond_defers_origins_past_the_byte_budget() {
        let dir = tempfile::tempdir().unwrap();
        let x = idx(dir.path(), "x", &["a", "b", "c"]);
        x.apply_suffix("a", 1, &[have(1, 1)]).unwrap();
        x.apply_suffix("b", 1, &[have(1, 2)]).unwrap();
        // A zero-clock requester with a 1-byte budget: the first data-bearing origin ships,
        // the second is deferred as an empty truncated suffix.
        let c = idx(dir.path(), "c", &["x", "a", "b"]);
        let req = proto::SyncRequest {
            requester: "c".into(),
            have: c.clock_vector().unwrap(),
        };
        let bundle = x.respond_budgeted(&req, 1).unwrap();
        let ups = &bundle.origins;
        let snapshots = ups
            .iter()
            .filter(|u| u.origin != "x")
            .filter(|u| matches!(u.body, Some(proto::origin_update::Body::Snapshot(_))))
            .count();
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
        assert_eq!(
            deferred.len(),
            1,
            "the other must be deferred, not dropped: {ups:?}"
        );
        // The deferral round-trips: applying it changes nothing but flags another round, and
        // an unbudgeted follow-up delivers the rest.
        let d = deferred[0];
        assert!(matches!(
            c.apply_suffix(&d.origin, d.generation, &[]).unwrap(),
            Apply::Applied(0)
        ));
        for u in ups {
            if let Some(proto::origin_update::Body::Snapshot(s)) = &u.body {
                c.apply_snapshot(&u.origin, u.generation, u.seq, &s.held)
                    .unwrap();
            }
        }
        let req = proto::SyncRequest {
            requester: "c".into(),
            have: c.clock_vector().unwrap(),
        };
        let bundle = x.respond_budgeted(&req, usize::MAX).unwrap();
        for u in &bundle.origins {
            match &u.body {
                Some(proto::origin_update::Body::Snapshot(s)) => {
                    c.apply_snapshot(&u.origin, u.generation, u.seq, &s.held)
                        .unwrap();
                }
                Some(proto::origin_update::Body::Suffix(s)) => {
                    c.apply_suffix(&u.origin, u.generation, &s.events).unwrap();
                }
                _ => {}
            }
        }
        assert_eq!(c.holdings_of("a").len(), 1);
        assert_eq!(c.holdings_of("b").len(), 1);
    }

    #[test]
    fn a_stale_snapshot_cannot_regress_a_newer_copy() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        b.apply_suffix("a", 1, &[have(1, 1), have(2, 2)]).unwrap();
        // A lagging relay's snapshot at seq 1 arrives late (concurrent-pull race): ignored.
        assert_eq!(b.apply_snapshot("a", 1, 1, &[vec![1u8; 32]]).unwrap(), 0);
        assert_eq!(b.holdings_of("a").len(), 2);
        assert_eq!(b.origin_clock("a").unwrap(), (1, 2));
        // A HIGHER generation still replaces wholesale, whatever its seq.
        assert_eq!(b.apply_snapshot("a", 2, 1, &[vec![3u8; 32]]).unwrap(), 1);
        assert_eq!(b.holdings_of("a"), vec![[3u8; 32]]);
    }

    #[test]
    fn self_generation_remints_strictly_above_the_floor() {
        let dir = tempfile::tempdir().unwrap();
        let b = idx(dir.path(), "b", &["a"]);
        let (g0, _) = b.origin_clock("b").unwrap();
        // The mesh remembers a future generation for us (e.g. our clock went backwards).
        let new = b.bump_self_generation(u64::MAX - 1).unwrap();
        assert_eq!(
            new,
            u64::MAX,
            "must exceed the floor even past the wall clock"
        );
        assert!(new > g0);
        assert_eq!(b.origin_clock("b").unwrap().0, new);
        // …and it persists: a reopen keeps the reminted generation.
        drop(b);
        let b = idx(dir.path(), "b", &["a"]);
        assert_eq!(b.origin_clock("b").unwrap().0, new);
    }

    #[test]
    #[ignore] // measurement bench: the per-store-change control-plane cost at 100k paths.
              // True idle is gated to one PRAGMA by the data_version check in sync.rs; this
              // measures the full differ cycle that runs when the store actually changed —
              // the number that must stay battery-safe.
    fn bench_differ_cycle() {
        use std::time::Instant;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let hh = |i: usize| -> [u8; 32] {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&(i as u64).to_le_bytes());
            b[9] = 0x33;
            b
        };
        let paths: Vec<String> = (0..100_000usize)
            .map(|i| format!("{}/{:032x}-pkg-{i}", store.display(), i))
            .collect();
        let rows: Vec<(&str, [u8; 32], u64, Option<&str>)> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_str(), hh(i), 4096u64, Some("fixed:r:sha256:x")))
            .collect();
        let t = Instant::now();
        let db_path = crate::db::tests::fake_db(dir.path(), &rows);
        let db = crate::db::StoreDb::open(&db_path, store.to_str().unwrap()).unwrap();
        println!("[bench] fixture nix db (100k rows): {:?}", t.elapsed());

        let a = idx(dir.path(), "a", &["b"]);
        let t = Instant::now();
        let n = a.sync_own_db(&db).unwrap();
        println!("[bench] initial export ({n} events): {:?}", t.elapsed());
        for round in 0..3 {
            let t = Instant::now();
            assert_eq!(a.sync_own_db(&db).unwrap(), 0);
            println!(
                "[bench] no-change differ cycle #{round} (100k paths): {:?}",
                t.elapsed()
            );
        }
        // One changed path: the common incremental case.
        crate::db::tests::insert_path(
            &db_path,
            &format!("{}/{}-fresh", store.display(), "f".repeat(32)),
            hh(999_999),
            4096,
            Some("fixed:r:sha256:x"),
        );
        let t = Instant::now();
        assert_eq!(a.sync_own_db(&db).unwrap(), 2, "attest + have");
        println!("[bench] one-new-path differ cycle: {:?}", t.elapsed());

        let t = Instant::now();
        for i in 0..10_000usize {
            let _ = a.lookup_hash_part(&format!("{:032x}", i * 10)).unwrap();
        }
        println!(
            "[bench] narinfo lookup through Index (feasibility incl.): {:.1} µs/op",
            t.elapsed().as_secs_f64() * 1e6 / 10_000.0
        );
    }

    #[test]
    fn departed_origins_are_reaped_at_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let b = idx(dir.path(), "b", &["a", "c"]);
            b.apply_suffix("a", 1, &[attest(1, att("-p", 1)), have(2, 1)])
                .unwrap();
            assert_eq!(b.lookup_hash_part(&hp()).unwrap().len(), 1);
        }
        // Reopen with "a" removed from the config: its holdings and journal go; the fact it
        // introduced ages out with zero grace.
        let peers: Vec<String> = vec!["c".into()];
        let store = Arc::new(RocksStore::open(&dir.path().join("cache-b")).unwrap());
        let b = Index::open(store, "b", &peers, TrustedKeys::none(), Duration::ZERO).unwrap();
        assert!(!b.is_known_origin("a"));
        assert!(b.lookup_hash_part(&hp()).unwrap().is_empty());
        b.compact().unwrap();
        assert_eq!(b.count_attestations(), 0);
    }
}
