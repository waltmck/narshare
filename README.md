# narshare

A self-contained mesh Nix substituter: every host **serves** its `/nix/store` as a standard binary
cache, **proxies** its local nix daemon's substitution through every peer — striping each NAR
across all peers that hold it, deduplicating repeated segments within a transfer, compressing
per-chunk on the wire, and adapting chunk sizes, stream counts, and compression levels to links
from 500 kbit/s cellular to 10 GbE — and **replicates the mesh's catalog** so lookups are
answered locally at zero RTT and misses are free. The catalog (sync protocol v2) keeps two
separate kinds of state: *possession* — which peer currently holds bytes with which NAR hash,
announced for EVERY valid path (possession is trust-free; even an unsigned local rebuild is a
byte source for content someone else holds a believable fact about) — and *attestations* —
verifiable store-path → content associations (a trusted signature over the
narinfo fingerprint, or content addressing). Attestations are grow-only facts with unioned
signature sets that outlive holdings by a configurable grace window, so a host that GC'd a path
can re-substitute it later — from a peer that copied it, or one that rebuilt it bit-identically —
under its own old signature.

Correct by construction: narshare carries **no signing keys** and signs nothing. Peers substitute
content-addressed paths (FODs — fetched sources, game data), which the consuming nix verifies on
ingestion — plus input-addressed paths whose upstream cache signature (e.g. cache.nixos.org's,
retained in each peer's Nix db from the original substitution) verifies against the local
`trusted-public-keys` from /etc/nix/nix.conf; the proxy checks the signature before spending any
bandwidth, and nix re-verifies at ingestion. The daemon reads `/nix/store` and Nix's database
(both read-only) and writes only the replicated mesh index — embedded rocksdb under
`/var/cache/narshare` by default, or postgres via `cache.postgres` — state it can always afford
to lose (self-verifying, re-learnable; losing it costs one snapshot resync).

See [PLAN.md](PLAN.md) for the full design; `docs/perf.md` for measured numbers.

## Run

```console
$ nix run .#narshare -- -c test.toml          # serve + proxy per the config
$ nix run .#narshare -- check -c test.toml    # validate a config
```

Minimal real config (see `test.toml` and PLAN.md for all knobs — most things adapt at runtime and
have no knob at all):

```toml
name = "desktop"                # this node's mesh-wide identity

[serve]
listen = "100.64.0.3:5050"      # mesh address; firewalling is the mesh's job

[proxy]
listen = "127.0.0.1:5051"       # what the local nix uses as a substituter

[[peers]]
name = "server"                 # must equal that node's own `name`
url = "http://100.64.0.2:5050"

# optional — default is embedded rocksdb under /var/cache/narshare:
# [cache]
# postgres = "host=/run/postgresql dbname=narshare"
# attestation_grace = "90d"     # how long facts outlive their last holder
```

Every node runs both roles and lists every other node; lookups are answered from the locally
replicated mesh index (kept fresh by inotify-triggered export and hint-driven pulls), so a hit
costs zero RTT and a miss is a local database read.

Point nix at the proxy with no keys:

```nix
nix.settings.substituters = [ "http://127.0.0.1:5051" ];
nix.settings.fallback = true;
```

or use the bundled NixOS module (`nixosModules.narshare`), which wires that up via
`services.narshare.addToSubstituters`.

## Status

Milestones M0–M5 and M8 of PLAN.md are implemented and tested: serve side (seek-table NARs,
ranges, io_uring + always-O_DIRECT reads, chunk-encoding, manifests), proxy side (striped
multi-peer fetch under multiplicative weights and a per-peer concurrency governor, circuit
breakers, intra-transfer dedup keyed by manifest segment hashes — completed transfers are
verified solely by the streaming NarHash gate — byte-progress stall + `min_bandwidth` roaming),
and the replicated mesh index (per-origin journals with watermark-ack compaction, snapshot
recovery, generations, transitive hint+pull propagation, inotify-triggered export, persistent
under /var/cache/narshare) that answers every lookup locally. Remaining: observability (M6),
the two-extremes perf run (M5.5), and the reshaped M7 VM suite for the sync protocol's
edge cases.

## Testing

```console
$ nix develop -c cargo test              # unit + differential tests (~2 s)
$ nix build .#checks.x86_64-linux.mesh   # the mesh VM suite (needs KVM; aarch64-linux too)
```

The mesh suite boots four VMs — three holders behind heterogeneous links (unshaped virtio,
20 Mbit/40 ms, 150 Mbit/25±10 ms with 1 % loss, via `tc netem`) and one proxying client — and
asserts the whole story end to end: a real `nix-store -r` of a CA path through the proxy with no
trusted keys, striped across all three links at once; the `ca_only` gate; NAR-by-hash discovery
after a proxy restart; dedup + wire compression beating the raw rate of the thin link; a
CPU-bound holder (live `CPUQuota=20%`) where the closed-loop encoding controller must beat a
pinned-zstd:19 control proxy with margin; an IO-bound holder (live `IOReadBandwidthMax` on the
store's backing disk — reads are O_DIRECT, so the throttle genuinely bites); and a holder killed
mid-transfer with byte-exact completion via the survivors. Per-link goodput numbers are printed
in the test log (VM-relative; absolute 10 GbE targets are M5.5's, on real hardware).
Interactive: `nix build .#checks.<system>.mesh.driverInteractive && ./result/bin/nixos-test-driver`.
