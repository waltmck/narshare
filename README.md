# narshare

A self-contained mesh Nix substituter: every host **serves** its `/nix/store` as a standard binary
cache and **proxies** its local nix daemon's substitution through every peer — striping each NAR
across all peers that hold it, deduplicating repeated segments within a transfer, compressing
per-chunk on the wire, and adapting chunk sizes, stream counts, and compression levels to links
from 500 kbit/s cellular to 10 GbE.

Correct by construction: peers are configured with **no signing keys**, so only
content-addressed paths (FODs — fetched sources, game data) can be substituted from them, and the
consuming nix verifies every hash on ingestion. The daemon is stateless: it reads `/nix/store` and
Nix's database (both read-only) and writes nothing, ever.

See [PLAN.md](PLAN.md) for the full design; `docs/perf.md` for measured numbers.

## Run

```console
$ nix run .#narshare -- -c test.toml          # serve + proxy per the config
$ nix run .#narshare -- check -c test.toml    # validate a config
```

Minimal real config (see `test.toml` and PLAN.md for all knobs — most things adapt at runtime and
have no knob at all):

```toml
[serve]
listen = "100.64.0.3:5050"      # mesh address; firewalling is the mesh's job

[proxy]
listen = "127.0.0.1:5051"       # what the local nix uses as a substituter

[[peers]]
name = "server"
url = "http://100.64.0.2:5050"
```

Point nix at the proxy with no keys:

```nix
nix.settings.substituters = [ "http://127.0.0.1:5051" ];
nix.settings.fallback = true;
```

or use the bundled NixOS module (`nixosModules.narshare`), which wires that up via
`services.narshare.addToSubstituters`.

## Status

Milestones M0–M5 of PLAN.md are implemented and tested: serve side (seek-table NARs, ranges,
io_uring + always-O_DIRECT reads, chunk-encoding, manifests), proxy side (hedged/coalesced/tiered
lookup fan-out, circuit breakers, striped multi-peer fetch under multiplicative weights and a
per-peer concurrency governor, per-segment blake3 verification with peer attribution,
intra-transfer dedup, byte-progress stall + `min_bandwidth` roaming), restart recovery, and the
M7 mesh VM suite (below). Remaining: observability (M6) and the two-extremes perf run (M5.5).

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
