# narshare — a self-contained mesh substituter: serve + dedup + multi-peer NAR striping

narshare is **both sides** of a mesh binary cache in one daemon, with no harmonia or other cache
server anywhere:

* **Serve**: exposes the local `/nix/store` as a standard Nix binary cache on the mesh interface —
  narinfo from the Nix database, NARs streamed on the fly with HTTP Range support, plus a
  narshare-specific **segment manifest** endpoint that lets peers dedup and verify at sub-file
  granularity.
* **Proxy**: a localhost substituter that `nix` consumes. It fans narinfo lookups out to every peer
  and reconstructs each NAR from two sources, cheapest first: duplicate segments already fetched
  earlier in the same transfer (fetch-once/replay, as in propnix download), and remote ranges
  striped across all holding peers by multiplicative weights over observed throughput —
  zstd-compressed on the wire.

narshare is **completely stateless**: it writes nothing to disk, ever. Its only inputs are
`/nix/store` and Nix's database, both read-only; seek tables and manifests are in-memory,
process-lifetime caches.

Designed for the propnix use case: hundreds-of-GB, highly-compressible, internally-duplicated FOD
game trees, on links spanning **500 kbit/s cellular to 10 GbE** — same binary, same config.

Trust model: none required. Every path the proxy relays is content-addressed (FOD / CA), so the
consuming Nix validates the hash on ingestion. narshare carries no signing keys; by default the proxy
refuses to relay narinfos *without* a `CA:` field (`ca_only`), so it structurally cannot become a
channel for unsigned input-addressed paths even if a client misconfigures `trusted-public-keys`.
Manifests and segment hashes are *efficiency* metadata, not trust: a lying manifest produces a stream
that fails the final NarHash check, same as any corruption. (The serve side passes through whatever
`Sig:`/`CA:` the local db has — it is a faithful cache.)

Scope decisions (settled):

* Serve-side is in the first cut; **no harmonia dependency, ever**.
* **Wire compression is a requirement** — game trees compress very well. Ranges are *addressed* in
  uncompressed NAR offsets but *shipped* as per-chunk zstd frames.
* **Duplicate-segment elimination within a transfer is a requirement** — propnix measured
  significant gains from fetching each distinct chunk once; game trees duplicate assets freely.
  Scope is intra-transfer only (fetch once, replay at later occurrences). Cross-path *local* dedup
  ("the old version is already in my store") needs a persistent index and is **deferred** — the
  settled design is recorded at the end of this document.
* **Adaptive over configurable.** The same device roams between the 10 GbE pair and a 500 kbit/s
  cellular hop; any constant tuned for one extreme is wrong at the other. Chunk size, per-peer
  concurrency, compression level, and hedge deadlines are all *measured into place* at runtime;
  config sets ceilings and policies, not operating points. (This is the propnix philosophy verbatim:
  "a build-time constant … only needs to be comfortably above any plausible knee".)
* Chunk-level sharing of *partial* downloads is out of scope (a peer 60% through a depot can't
  help). The honest fix is snix/castore-style stores; NAR-level is our contract.
* Peer discovery is out of scope — static `[[peers]]`.
* IPv6: no explicit effort; use address-family-agnostic APIs and it should just work.
* Cut for minimality (revisit only with evidence of need): a hashed-mirror endpoint (substitution
  already covers every FOD, fetchurl included; name-skewed flat FODs are a rare case that doesn't
  justify a second protocol), streamed `.nar.zst` for stock clients (every mesh node runs narshare;
  stock nix still substitutes fine over raw NARs), and MW tuning in the config (the constants are
  proven in propnix; they live in code). Fetcher-side integrations (e.g. teaching a downloader to
  race peers against origin) are likewise out of scope: narshare speaks the binary-cache protocol
  and nothing else.

## What exists to steal

* `~/src/propnix/pkgs/propnix-cli/src/pin/hosts.rs` — **the MW pool, already written.** Losses in
  [0,1] against a decaying best-rate yardstick, `exp(-ETA·loss)` update, weight floor `W_MIN` for
  probing collapsed hosts, Herbster–Warmuth fixed-share mixing (`SHARE`) so a recovered peer
  converges back to parity, randomized proportional sampling so concurrent workers don't stampede
  the argmax. Scores candidates by index and owns nothing else — drops in unchanged, constants and
  all.
* `.../pin/concurrency.rs` — **the hill-climbing concurrency governor, now in scope** (previously
  deferred; the cellular end of the requirement is exactly its origin story). Hold the limit for
  `PROBE_EPOCHS`, compare medians, step ×1.3 / back off ×0.7 on error *rate*, hold when blocked by
  the consumer. It is what lets `per_peer_connections` be a *ceiling* rather than a setting: on
  10 GbE it climbs toward the ceiling; on cellular it settles at 1–2 streams instead of drowning the
  link in competing flows.
* `.../pin/dedup.rs` — **the duplicate-occurrence planner, already written.** Static plan over the
  ordered occurrence list: fetch each distinct segment at first occurrence, retain under a bounded
  budget for replay, refetch when over budget — all-or-nothing per segment, peak memory exact.
* `.../pin/engine.rs` — **the chunk scheduler.** Queue-not-retry-ladder (failures requeue at the
  front and re-consult the scorer), liveness-based give-up, bounded read-ahead window driven by an
  ordered consumer. Adaptations: chunk decode is zstd + blake3 only; the liveness signal is **bytes
  received**, not chunks completed (see Adaptivity).
* `.../pin/nar.rs` — **a canonical NAR encoder** (built for hashing during `propnix pin`). The serve
  side needs the same walk three ways: bytes, seek table, manifest. Refactor to one tree-walk
  parameterized over its sink.
* `~/src/wgautomesh` — config shape: flat knobs + `[[peers]]` array of tables, single TOML file.
* nixpkgs `nixos/modules/services/networking/wgautomesh.nix` — module shape: `enable`, `logLevel`,
  freeform `settings` submodule rendered with `pkgs.formats.toml`, typed options for load-bearing
  keys, hardened DynamicUser systemd service.

## Architecture

```
             ┌──────────────────────── one narshare process ───────────────────────┐
nix daemon ──▶ proxy listener (127.0.0.1:5051)      serve listener (mesh:5050) ◀──── peers' proxies,
             │   narinfo fan-out + cache              narinfo ← nix db (sqlite ro)│   plain nix clients
             │   NAR reconstruction:                  NAR walk + seek table       │
             │     replay | remote                    Range (uncompressed offsets)│
             │   MW pool + governor per peer          per-chunk zstd on the wire  │
             │            └────────── in-memory only: seek tables + manifests (LRU) ┘
             └────────────────────────────────────────────────────────────────────┘
                        │ HTTP over wg mesh to each peer's serve listener
```

One process, two listeners. The proxy listener binds loopback (its rewritten narinfos are only
meaningful to the local nix). The serve listener binds the mesh address; reachability policy is the
mesh firewall's job. The proxy never lists itself as a peer — nix checks the local store first
anyway. All derived structures — seek tables, manifests — are **in-memory, process-lifetime LRU
caches**; narshare writes nothing to disk. A path's manifest is computed on first request (one
hashing read of the path through the bounded IO pool) and reused for the life of the process. (The
*Nix* database, `/nix/var/nix/db/db.sqlite`, is read strictly read-only for narinfo metadata —
narshare never writes it; that is Nix's state, not narshare's.)

### Representation vs. addressing (the compression design)

The uncompressed NAR is the *coordinate system*: `NarSize`, the seek table, chunk boundaries, and
manifest segments all refer to uncompressed NAR offsets, so peers are interchangeable byte sources
regardless of what travels on the wire. The wire carries **independent zstd frames per chunk**,
negotiated per request (header carries `zstd:<level>` or `none`; a plain `Range` request without the
header gets raw bytes, so any HTTP client — including stock nix, which substitutes via the raw NAR —
still works). Per-chunk framing keeps chunks independently schedulable across peers and
parallelizes compression across cores.

The **requester picks the encoding** (it knows its link; the server only caps the level it will
spend CPU on). The level itself is adaptive by default — see Adaptivity. MW throughput observations
use **uncompressed goodput** (bytes of NAR delivered per second) — the quantity the consumer
experiences — so weights stay comparable across peers even when encodings differ.

### Adaptivity (one config, both extremes)

The four quantities that no constant can get right at both 500 kbit/s and 10 GbE, and the mechanism
that sets each:

* **Chunk size** — per-peer, targeting a fixed *duration*: `chunk = clamp(goodput_ewma ×
  chunk_target (2s), 256 KiB, chunk_max (16 MiB))`. On 10 GbE chunks pin at the 16 MiB cap; on
  cellular they shrink toward 256 KiB. This keeps MW feedback arriving every ~2 s per stream at any
  link speed (16 MiB chunks on cellular would mean one observation per 4.5 *minutes* — the weights
  would never converge), and bounds retransmission waste when a flaky link drops a transfer
  mid-chunk. (MTU is deliberately NOT an input anywhere: transport is TCP, so the kernel owns
  segmentation and no app-level decision maps onto packet boundaries. The implicit assumption the
  256 KiB floor makes is only that chunks stay orders of magnitude above the path MTU — ~190
  packets even at wireguard's ~1400 — so per-packet overhead never couples to chunking. A static
  MTU knob would become meaningful only if a UDP/QUIC transport ever existed.)
* **Streams per peer** — the concurrency.rs governor, ceiling `per_peer_connections`. 10 GbE needs
  ~8 streams to fill; 8 competing flows on a 500 kbit link is bufferbloat and timeouts. The governor
  finds the knee for *this* link and follows it when it moves (roaming).
* **Compression level** — `encoding = "auto"` (default) is a CLOSED-LOOP per-chunk controller.
  The serving peer reports, in two response headers, where each chunk's service time went —
  disk read, and encode-pool wait + encode — and the requester, which knows total elapsed, wire
  bytes, and its own decode time, classifies the chunk's bottleneck and steps the level:
  encode-dominated (the peer's CPU or its queue) → step down fast; peer-disk-dominated → hold
  (the level can neither help nor hurt); wire-dominated with encode slack → step up, faster
  while the slack is large. The knee settles where encode time is comparable to wire time —
  with chunks pipelined across streams, that is where both stages stay busy. There is
  deliberately NO hysteresis: chunk frames are independent and self-describing, so a level
  switch between chunks is free, and flapping near equilibrium is harmless (hysteresis belongs
  to controls with switching costs, like chunk size). Peers that predate the timing headers get
  the open-loop goodput ladder (`<4 MB/s → 19`, `<40 → 9`, `<400 → 3`, else `1`) as a fallback.
  This is zstd `--adapt`'s idea at chunk granularity with explicit signals; zstd's own `--adapt`
  (and its poor interaction with multithreaded compression) is never involved, because narshare
  never uses zstd's internal multithreading — every chunk is one single-threaded frame, and
  parallelism comes from chunks in flight. On cellular, zstd-19 multiplies effective link
  capacity on game data; on 10 GbE, zstd-1 keeps compression off the critical path. Per-peer
  manual override remains one line of config (it pins the *requested* level; the server's
  `max_zstd_level` cap still applies, and its pool wait still shows up honestly in the headers).
* **Hedge deadline** — narinfo fan-out hedging uses a per-peer deadline derived from observed
  lookup latency (clamped p95 × factor), with `narinfo_timeout` as the *cap*. A fixed 1.5 s deadline
  is generous on LAN and flapping-prone at cellular RTTs. Crucially, **missing the hedge deadline is
  "late", not "failed"**: late positives still widen the holder map; only hard errors (connect
  refused, 5xx, reset) count toward the circuit breaker.

And the one give-up signal that is correct at any speed: **stall = no bytes received across all
streams of a transfer for `stall_timeout`** (byte-progress liveness, engine.rs's rationale — a
chunk-completion-based stall would false-trigger on any link where a chunk takes longer than the
timeout, which is every chunk on cellular with large chunks). A stalled transfer aborts mid-stream;
nix falls back per its own `fallback` setting.

### The give-up floor (`min_bandwidth`)

Roaming far from the mesh, a CDN reachable at local-link speed can beat peers reached through a
long thin path — but narshare cannot measure origin speed (for a credentialed FOD it cannot even
reach origin; only the builder can), so whether to forfeit is **host policy**: `min_bandwidth`,
default off. When set, a transfer whose aggregate network goodput (bytes actually fetched from
peers over elapsed time — locally synthesized framing and replayed duplicates don't count) is
still below the floor after `min_bandwidth_grace` aborts mid-stream; nix records a transfer failure and, per `fallback`, runs
the FOD builder, which fetches from origin. The grace period doubles as a small-transfer
exemption: anything smaller than `min_bandwidth × min_bandwidth_grace` finishes before the rule can
fire, so only transfers big enough for the decision to matter are ever forfeited.

A fired abort establishes a **roaming epoch** (~10 min; a fixed duration — route-change
invalidation was considered and dropped as not worth watching netlink): while
it lasts, the proxy 404s narinfo lookups for paths larger than `min_bandwidth ×
min_bandwidth_grace` — exactly the ones that would abort anyway — so subsequent big FODs go
straight to the builder without repeating the discovery; smaller paths keep substituting.

The knob's honest limitation, documented rather than hidden: it is static per-host policy, so a
device that roams between the 10 GbE LAN and cellular should set a floor meaningful for the roaming
case (or leave it off — a transfer below the floor is *slow*, not wrong, and origin over the same
link may be no faster). Measuring the comparison instead of configuring it (a reference-bandwidth
probe against a public endpoint) was considered and rejected: not worth a third-party dependency.

### I/O architecture (10 GbE: the disk is the bottleneck)

At 10 GbE (~1.2 GB/s raw, more in uncompressed-equivalent goodput once the wire is compressed), a
single synchronous read loop cannot feed the link; NVMe only delivers its bandwidth at queue depth.
The design gets depth from **many independent segment reads in flight**, not from a clever syscall:

* **One abstraction**: `SegmentReader` — `read(path, offset, len) → Bytes` — behind a bounded
  in-flight budget (`[io] concurrency`, default 64), with two backends:
  * **`uring` (default where available)**: an io_uring submission ring on a dedicated thread (or
    per-core rings), servicing reads from a queue. On ext4/XFS with `O_DIRECT` this is genuinely
    completion-driven async at full queue depth. On ZFS today the kernel punts file reads to io-wq
    workers (no NOWAIT path in ZFS), so the win reduces to batched submission and kernel-managed
    workers — modest, but the seam is ready for the day ZFS grows native support, and it benefits
    any non-ZFS deployment now.
  * **`blocking`**: `spawn_blocking` `pread`s under the same semaphore — the fallback for kernels
    with io_uring disabled (seccomp/lockdown). Either way, 64 concurrent reads keep NVMe queues and
    ZFS's I/O pipeline busy and engage per-record decompression across cores.
  * **O_DIRECT always, no knob**: the serving working set (games) exceeds ARC anyway, so cache
    bypass is the sensible default; on compressed/encrypted ZFS the kernel demotes Direct IO to
    buffered transparently (a no-op on these pools), and filesystems that refuse O_DIRECT (tmpfs)
    get an automatic per-call buffered fallback. Reads are 4 KiB-aligned internally; the requested
    sub-slice is returned zero-copy.
* **Every chunk is a natural unit of parallelism.** Serve side: concurrent ranged requests each do
  read-pool → zstd frame → socket, so compression parallelizes across chunks/cores without a
  dedicated compute pool. Proxy side: remote chunks decompress + blake3-verify in parallel on
  arrival.
* **Known serial ceiling, stated honestly**: the final `NarHash` SHA-256 over the ordered stream is
  inherently sequential — ~2 GB/s/core with hardware SHA. It runs pipelined on its own task,
  overlapping everything else, so it caps throughput only above ~2 GB/s goodput. Acceptable.
* **Backpressure is bounded at every stage**: read-pool semaphore, per-response in-flight chunk
  caps, `window_bytes` on ordered emission, governor-set stream counts. No stage buffers
  unboundedly; a slow consumer propagates back to fewer reads in flight, not memory growth.
  (Proxy-side bounds — `window_bytes`, `dedup_budget_bytes` — are per *transfer*; the aggregate
  multiplier is nix's own substitution parallelism, which is the intended cap.)
* Out of scope: TCP tuning (window sizes, BBR) is host configuration; zero-copy `sendfile`/`splice`
  doesn't apply once bytes are transformed.

### Serve side

Backed directly by the local Nix store, read-only:

* **Metadata**: open `/nix/var/nix/db/db.sqlite` read-only (nix-serve-ng prior art; WAL, concurrent
  readers fine). narinfo lookup by hash part = index-friendly range query on `ValidPaths.path`;
  `Refs` join for `References:`; pass through `NarHash`/`NarSize`/`Deriver`/`Sig`/`CA` as-is. Pin to
  the known schema columns and fail loudly on mismatch (schema has been stable for years; a future
  Nix that changes it should produce a clear error, not silent misbehavior).
* **Endpoints**:
  * `GET /nix-cache-info` — `StoreDir`, `WantMassQuery: 1`, `Priority` from config.
  * `GET|HEAD /<hash>.narinfo` — as above; advertises `Compression: none`, `URL: nar/<narhash>.nar`.
  * `GET /nar/<narhash>.nar` — full stream or `Range`; with the chunk-encoding header, ranges come
    back as zstd frames of the requested uncompressed span.
  * `GET /narshare/v1/manifest/<narhash>` — the segment manifest.
* **Seek table (ranges without materializing NARs)**: a NAR is a deterministic function of the tree —
  metadata tokens with stat-known lengths + raw file contents + padding — so a metadata-only walk
  (no content reads, O(#files)) yields sorted segments `nar_offset → (literal bytes | file + file
  offset)`. Serving a range = binary search + stream. Cached per narhash (LRU; kilobytes each),
  built lazily on first NAR request. **Consistency check**: the walk's total must equal the db's
  `NarSize`; on mismatch (corrupt/modified store) answer 500 and log, never serve garbage.
* **Segment manifest**: the seek table's content spans, hashed. Segment = one file, except files
  larger than `segment_bytes` (default 4 MiB) split at fixed boundaries within the file. Each entry:
  `(nar_offset, len, blake3)`; literal (structure) spans carried inline — together they reconstruct
  the byte stream exactly. Building a manifest reads file contents once; results land in the shared
  in-memory manifest LRU. Fixed splitting catches identical files and identical aligned regions (where
  propnix's measured duplication lives — content-addressed depot chunks recur at stable offsets);
  content-defined chunking would also catch shifted duplicates — future upgrade, not first-cut.
* **GC race**: a path can be garbage-collected mid-stream → read fails → response aborts; the
  fetching side treats it like any chunk failure. Correctness comes from the client's hash check.

### Proxy side

* `GET /nix-cache-info` — `Priority:` from config.
* `GET|HEAD /<hash>.narinfo` — fan out to all healthy peers in parallel, hedged per Adaptivity.
  First positive answers the client; every positive (including late arrivals) widens the
  path→holders map used for striping. Rewrites before serving: `URL: nar/<narhash>.nar`,
  `Compression: none` (the proxy⇄nix hop is loopback; recompressing for localhost is waste), drop
  `Sig:`. Negatives cached with `negative_ttl`. **Fan-out is bounded** (semaphore) and identical
  in-flight lookups are coalesced — nix's mass queries against big closures must not become a
  narinfo storm multiplied by peer count (matters at cellular narinfo latencies).
* `GET /nar/<narhash>.nar` — reconstruction + striped fetch (below).

### The reconstruction planner (dedup + striping)

Per NAR fetch:

1. **Get the manifest** from any holder (small; MW-selected). No manifest (older peer, still
   building) → degrade to plain adaptive-chunk striping of the raw range space (M4 behavior).
2. **Partition segments** by source:
   * **Replay**: later occurrences of a distinct remote segment → dedup.rs planning verbatim:
     fetch-once, retain under `dedup_budget_bytes` for in-order replay, over-budget duplicates
     refetch.
   * **Remote**: distinct missing segments, coalesced into per-peer requests of the *current
     adaptive chunk size*, fetched as wire-zstd ranges, striped via the MW pool restricted to
     holders, stream counts set by the governor.
3. **Emit in NAR order** through the `window_bytes` read-ahead bound (the window IS the queue).
   Failures requeue at the front (the block the stream waits on retries first, on whatever peer the
   pool now prefers). Streaming SHA-256 of the emitted body is checked against `NarHash` at the
   end; mismatch aborts the response mid-stream so the client records a clean transfer failure.

Per-segment blake3 gives what flat striping couldn't: **corruption attribution**. A segment that
fails its hash is refetched from a different peer and the origin peer takes a loss-1 observation
(and a log line naming it).

### Failure semantics, consolidated

* Hedge misses are "late", never "failed" (Adaptivity). Hard errors only (refused / reset / 5xx /
  malformed) count toward the per-peer circuit breaker: `breaker_failures` consecutive → down for
  `breaker_cooldown` → half-open probe. Down peers leave fan-out and stripe sets. Breakers handle
  *dead*; MW weights handle *slow*; the two are deliberately separate mechanisms.
* Transfer give-up: byte-progress stall (`stall_timeout`, default 60 s — generous enough to ride
  out cellular radio handoffs), plus the optional `min_bandwidth` floor with its roaming epoch.
  Everything else is nix's own `fallback` behavior.
* All-peers-down: breakers make lookups fail fast; nix proceeds to other substituters or builds.

## Configuration

Single TOML file, `-c`/`--config` (clap derive). `narshare serve` runs both listeners (the only
mode); `narshare check -c foo.toml` validates and prints the parsed config (the NixOS module uses it
as a build-time assertion). Everything except `listen` addresses and `[[peers]]` is defaultable —
the minimal real config is ~6 lines.

```toml
# test.toml

[serve]
listen = "100.64.0.3:5050"         # mesh address; reachability = mesh firewall's job
priority = 30                      # advertised in /nix-cache-info
max_zstd_level = 19                # CPU cap on what requesters may ask for
segment_bytes = "4MiB"             # manifest granularity within large files

[io]
concurrency = 64                   # bounded in-flight reads: keeps NVMe queue depth full
# backend = "auto"                 # auto (uring if available) | uring | blocking

[proxy]
listen = "127.0.0.1:5051"
priority = 30                      # strictly ahead of cache.nixos.org (40): loopback, fast negatives
ca_only = true                     # refuse narinfos without a CA: field (FOD/CA sharing only)

chunk_max = "16MiB"                # ceiling; actual chunk size adapts to ~2s per chunk
window_bytes = "256MiB"            # ordered read-ahead bound
dedup_budget_bytes = "512MiB"      # retention budget for replayed duplicate segments
per_peer_connections = 8           # ceiling; the governor finds the operating point

narinfo_timeout = "5s"             # hedge deadline CAP (actual deadline adapts to observed RTT)
negative_ttl = "30s"
stall_timeout = "60s"              # give up when NO bytes arrive for this long

min_bandwidth = "0"                # give-up floor, off by default; e.g. "1MiB" to forfeit hopeless
min_bandwidth_grace = "60s"        #   transfers to the builder; also sets the small-transfer exemption

breaker_failures = 3
breaker_cooldown = "15s"

[[peers]]
name = "server"
url = "http://100.64.0.2:5050"     # encoding defaults to "auto" (goodput-tiered zstd level)

[[peers]]
name = "cloud"
url = "http://100.64.0.9:5050"
tier = 2                           # only consulted when no tier-1 peer holds the path
encoding = "zstd:9"                # manual override when you know better than auto
```

MW constants are **not** configurable — the propnix-proven values live in code. Sizes/durations
parse human units (`byte-unit`, `humantime-serde`). `[serve]` or `[proxy]` is omittable: serve-only
(always-on host) and proxy-only (Steam Frame) deployments are both legitimate.

## Crate layout

Single bin crate, `narshare`:

```
src/
  main.rs        clap: serve (default) | check; tracing init; spawns both listeners
  config.rs      serde structs + validation + unit parsing
  db.rs          read-only rusqlite over /nix/var/nix/db/db.sqlite (ValidPaths, Refs)
  io.rs          SegmentReader: uring backend (dedicated ring thread) + blocking fallback,
                 bounded in-flight budget, always-O_DIRECT with aligned reads + buffered fallback
  nar.rs         canonical NAR walk — adapted from propnix pin/nar.rs, one walk, three sinks:
                 bytes | seek table | manifest; segment model + range resolution
  manifest.rs    manifest (de)serialization; segment coalescing for remote requests
  serve.rs       serve listener: nix-cache-info, narinfo-from-db, ranged/zstd NAR, manifest
  narinfo.rs     parse/serialize/rewrite narinfo (tiny line format, hand-rolled)
  peers.rs       reqwest client pool, circuit breakers, hedge-deadline tracking, health state
  pool.rs        MW pool — lifted from propnix hosts.rs (same author; add provenance note)
  governor.rs    per-peer stream-count hill climber — adapted from propnix pin/concurrency.rs
  dedup.rs       occurrence planner — lifted from propnix pin/dedup.rs (budgeted retention)
  engine.rs      chunk queue + ordered emitter — adapted from propnix engine.rs (byte-based stall)
  fetch.rs       one NAR reconstruction: planner (local/replay/remote), adaptive chunking, window,
                 hashing, give-up
  proxy.rs       proxy listener: bounded/coalesced fan-out, negative cache, handoff to fetch.rs
```

Deps: `tokio`, `axum` (or bare `hyper`), `reqwest` (plain HTTP only — no TLS is compiled in;
peers live inside the mesh, whose transport is the mesh's own encryption, and integrity comes
from content addressing; https peer URLs are rejected at config validation), `rusqlite`, `zstd`,
`blake3`, `sha2`,
`clap` (derive), `serde`, `toml`, `tracing`/`tracing-subscriber`, `anyhow`, `humantime-serde`,
`byte-unit`. narshare owns no database: `rusqlite` exists solely to read Nix's own db read-only,
and narshare has no on-disk artifacts at all. (snix's
`nix-compat` crate is the fallback for narinfo/NAR/store-path formats if hand-rolling grates, but
the seek table and manifest want their own walk anyway and the formats are small.)

## Flake

* `packages.{narshare,default}` via `rustPlatform.buildRustPackage` (`cargoLock.lockFile`), so
  `nix run .#narshare -- -c test.toml` works.
* `devShells.default` — rustc/cargo/clippy/rust-analyzer.
* `nixosModules.{narshare,default}` — the module below.
* `checks.<system>` — `cargo test` + the NixOS VM test.

## NixOS module (modeled on wgautomesh's)

```nix
services.narshare = {
  enable = mkEnableOption ...;
  package = mkPackageOption ...;
  logLevel = enum ["trace" "debug" "info" "warn" "error"]; # → RUST_LOG
  config = mkOption {
    type = types.submodule {
      freeformType = (pkgs.formats.toml {}).type;
      options.serve = ...;         # typed options for the load-bearing keys,
      options.proxy = ...;         # freeform for the rest — wgautomesh-style
      options.peers = ...;
    };
  };
  addToSubstituters = mkOption {   # convenience: nix.settings.substituters + fallback
    type = types.bool; default = true;
  };
};
```

Implementation notes, cribbed from the wgautomesh module: render with `pkgs.formats.toml`,
`filterAttrs (_: v: v != null)` at top level *and* per-peer (TOML can't encode null), hardened unit
(`DynamicUser`, `ProtectSystem=strict` with no writable paths at all — the daemon is stateless, `PrivateTmp`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`), `Restart=on-failure`,
`after = [ "network-online.target" ]`. Serve side needs only world-readable access to `/nix/store`
and the db, so DynamicUser suffices. No secrets → no runtime config templating. When
`addToSubstituters`: `nix.settings.substituters = [ "http://127.0.0.1:<port>" ]` plus
`nix.settings.fallback = true` — and NO key additions, preserving the CA-only guarantee end to end.
Firewall/mesh-allowlist wiring for the serve port stays in host config (the mesh-fw pattern), not
the module.

## Milestones

* **M0 — skeleton.** Crate, clap, config parse + `check`, flake package. `nix run` works.
* **M1 — serve side, standard protocol.** db.rs + nar.rs + serve.rs: narinfo from the db, full-NAR
  streaming, then the seek table + Range. Acceptance: a *plain* nix client on another host
  substitutes a real FOD with `--substituters http://host:5050` and no trusted keys; `curl -r`
  returns correct bytes for arbitrary ranges (differential-test the seek table against full NAR
  dumps across the whole store). This alone replaces harmonia for the mesh.
* **M1.5 — io_uring read backend.** Dedicated-ring implementation behind the SegmentReader seam,
  auto-detection with blocking fallback. Acceptance: byte-identical serving under
  both backends (reuse the M1 differential tests), and a microbenchmark comparing backends on this
  hardware recorded in `docs/perf.md`.
* **M2 — proxy passthrough.** One peer, no striping: fan-out of one, URL rewrite, negative cache.
  End-to-end `nix build` through the proxy.
* **M3 — fan-out + resilience.** Bounded/coalesced parallel narinfo hedging with adaptive deadlines,
  circuit breakers, byte-progress stall give-up on single-source streams. Kill-a-peer-mid-lookup
  works.
* **M4 — striping + MW + governor + wire compression.** Adaptive chunk sizing, per-chunk zstd with
  auto level, ordered window, pool.rs wired to chunk completions (uncompressed goodput), governor
  on stream counts, requeue-on-failure, streaming NarHash check, `min_bandwidth` floor + roaming
  epoch. Kill-a-peer mid-transfer works. Unit tests drive both extremes with simulated clocks/peers:
  a 500 kbit/s peer set converges to small chunks / 1–2 streams / high zstd and never false-stalls;
  a 10 GbE set pins the ceilings; a slow peer's share decays and recovers; with the floor set, a
  below-floor transfer aborts after the grace and oversized lookups 404 for the epoch; with the
  floor unset (default), nothing ever aborts for slowness.
* **M5 — manifests + intra-transfer dedup.** Manifest sink on the NAR walk, in-memory manifest LRU,
  reconstruction planner (replay-under-budget / remote), per-segment blake3 verification +
  attribution, manifest endpoint + graceful degradation to M4 striping. Acceptance: a synthetic
  tree of repeated blobs transfers each distinct blob once; the serve side's first-request manifest
  hashing overlaps sanely with concurrent plain serving.
* **M5.5 — the two-extremes run.** Perf validation on the real pair (server ⇄ desktop, 10 GbE):
  ARC-warm NAR fetch sustains ≥ 1 GB/s goodput end-to-end; NVMe-cold tracks the disks, not the code
  (compare against `nix nar dump-path >/dev/null` and `fio` at matching queue depth). Slow-link
  validation via `tc netem` on a veth pair (500 kbit / 300 ms RTT): transfer completes, stall never
  false-fires, auto-encoding lands at high zstd. `[io] concurrency`, chunk targets, and encoding
  tiers swept and recorded in `docs/perf.md` so the defaults are measured, not guessed.
* **M6 — observability.** `tracing` spans per fetch; `/metrics` (per-peer weight, goodput, governor
  operating point, breaker state, replay/remote byte split — the fun dashboard).
* **M7 — NixOS module + VM test.** Three-node `nixosTest`, every node running only narshare: A and B
  hold a synthetic 100 MiB FOD and serve; C proxies both, `nix build`s the FOD via the proxy with no
  trusted keys; assert substitution, then stop A mid-second-build and assert completion via B.
  (Adaptive-behavior assertions stay in unit tests — netem in VM tests is flaky; M5.5 covers it on
  real hardware.)

## Deferred: persistent local dedup (the design, so it isn't relitigated)

Cross-path local dedup — "v2's unchanged segments are already in my store inside v1; transfer only
the delta" — was designed, then deliberately deferred to keep narshare stateless. What was settled,
recorded for when measured need arrives:

* **Manifests as flat files** under a cache dir (one per narhash, atomic-rename, zstd JSON —
  hashes and locations only, never content; ~0.001% of content size). The dedup map
  `blake3 → (store path, file, offset, len)` is in-memory, rebuilt at startup by scanning the cache
  dir and resolving each manifest's narhash to a live store path **via the Nix db** — store paths
  are never serialized, which kills the stale-location failure class. Validate-on-read (blake3 the
  bytes before emitting); GC needs no hooks: staleness costs a lookup, never correctness.
* **Full-store coverage** via a background indexer (CA/`fixed:` paths first), incremental via
  cheap `max(id)` polling of ValidPaths.
* **Coarse granularity is enough** (whole-file + 4 MiB segments for candidate discovery); shifted
  content is a manifest-version upgrade doing zsync-style client-side rolling checksums against
  discovered candidates — a fine-grained every-block global index is never needed.
* **The general-fetcher angle**: a `GET /narshare/v1/segment/<blake3>` localhost oracle would let
  any FOD builder (propnix, a manifest-aware fetchurl) dedup against the local store with no code
  linkage — FOD builders have loopback network. Flat FODs can even Range the *origin* for the
  delta, zsync-style, since the manifest travels through the mesh even when the data doesn't.
* If snix's lower-overlay store matures to trustworthy-under-games, that layer supersedes this one;
  the versioned manifest format keeps the exit cheap.
* **Replay retention without RAM** (idea recorded, not adopted): because NAR ingestion is strictly
  sequential and nix writes files at their final path during substitution, a duplicate segment's
  earlier occurrence is already on local disk by the time the later occurrence must be emitted —
  the proxy could read it back from the in-progress store path instead of retaining bytes under
  `dedup_budget_bytes`. Rejected for now: it couples to nix internals (progressive write to the
  final path, mid-ingest permissions, same-host daemon) and adds abort races, while the current
  fallback (over-budget duplicates simply refetch) is nearly free on a fast mesh. FICLONE-based
  dedup-on-write belongs to whoever owns the writes (nix's ingestion, or propnix download's file
  sink via FICLONERANGE — with the caveat that clone ranges must be fs-block/recordsize-aligned,
  which arbitrary chunk boundaries usually violate).
