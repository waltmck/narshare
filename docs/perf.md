# Performance notes

Measured results only — defaults in the config are justified here, not guessed.

## M1.5 — SegmentReader backend microbenchmark

**Setup**: walt-laptop (Apple Silicon, aarch64, NVMe, ZFS rpool: zstd + encryption),
kernel 7.1, warm ARC. 512 × 1 MiB reads at deterministic pseudo-random 4 KiB-aligned
offsets across a single 4.0 GB file
(`no-mans-sky-…/GAMEDATA/PCBANKS/NMSARC.TexPlayer.pak`), concurrency 64.

```
NARSHARE_BENCH_PATH=<big file> cargo test --release -- --ignored bench_backends --nocapture
```

| backend  | run 1     | run 2     | run 3     |
|----------|-----------|-----------|-----------|
| blocking | 1811 MB/s | 1865 MB/s | 2316 MB/s |
| uring    | 2328 MB/s | 2151 MB/s | 2136 MB/s |

**Interpretation**: statistical parity on ZFS (~2.1–2.3 GB/s both), exactly as the plan
predicted — ZFS has no native io_uring read path, so uring ops are punted to io-wq kernel
workers, the same execution shape as the blocking pool; and because zstd/encrypted datasets
demote O_DIRECT to buffered, both backends serve from ARC here. The uring backend's thesis
is native-async filesystems (ext4/XFS) and any future ZFS NOWAIT support; on ZFS it is
simply not worse. Both backends clear the M5.5 10 GbE target (≥ 1 GB/s goodput) with 2×
headroom from a single file at queue depth 64, before any striping.

`backend = "auto"` (uring when available) stands as the default. Cold-NVMe and end-to-end
numbers land here at M5.5.

## M5.5, fast half: 10 GbE-class goodput over loopback

**Setup**: walt-laptop serving its real store; serve + proxy in one process, peered over
127.0.0.1 (test.toml shape). Loopback is far faster than 10 GbE, so this measures the SOFTWARE
ceiling; it is also conservative — one machine runs both ends plus the client, where a real
10 GbE pair splits that CPU. Fetches of the Hollow Knight NAR (5.24 GB, ZFS zstd ~5:1 on disk),
`curl -o /dev/null`, warm runs. (The VM mesh suite cannot measure this: its QEMU fabric tops out
at single-digit Gbit/s — it now prints its own iperf3 baseline so its numbers are read against
that ceiling.)

| path | goodput |
|---|---|
| direct serve, full NAR (stock-client path) | **1.18–1.29 GB/s** |
| proxy, ranged (no NarHash gate) | **1.30–1.31 GB/s** |
| proxy, full — the real substitution path (manifest dedup + NarHash) | **1.12 GB/s** |

Three ceilings were found and removed to get here (each was measured, not guessed):

1. **Serial reads per response** (~143 MB/s): `emit`/`encode_span` issued their 256 KiB reads
   one at a time — queue depth 1 per response against a >3 GB/s disk path with ~ms per-op
   latency. Fixed: READ_AHEAD-deep pipelining within every response (8.5× on direct serving).
2. **Soft SHA-256** (~260 MB/s): the `sha2` crate does not use the ARMv8 SHA-2 crypto
   extensions without the `asm` feature; the NarHash gate is serial on the emit path, so its
   speed is a whole-transfer ceiling. Fixed: `sha2/asm` (~2.4 GB/s, matching `openssl speed`).
3. **Fetch-range fragmentation** (~410 MB/s): the manifest plan's fetchable ranges broke at
   every file's framing lits — 1754 ranges on Hollow Knight's ~1750-file tree, degenerating
   16 MiB chunks into per-file requests. Fixed: ranges merge across ≤64 KiB non-fetch gaps
   (RANGE_MERGE_GAP): 4 ranges, ≤0.01% wire overhead, replay holes (≥ segment size) unmerged
   so dedup is untouched.

A fourth ceiling was removed on trust-model grounds rather than measurement: per-segment blake3
verification (which cost the emitter a second serial hash pass, capping the full path at
~0.75 GB/s) was dropped entirely — segment hashes cannot adjudicate disagreeing sources, so
they are dedup keys only and the contract is "a completed transfer is correct" (see PLAN.md's
reconstruction section). The full path's remaining ~14% gap to the ranged path is the NarHash
SHA-256 gate, the design's acknowledged serial ceiling (~2.4 GB/s hardware). These numbers put
the real substitution path at 10 GbE line rate with ONE machine running both ends plus the
client; the real pair splits that CPU. The hardware pair run and the slow-link half of M5.5
(tc netem, 500 kbit / 300 ms) remain.

## Per-chunk framing: compression ratio given up vs one continuous context

**Setup**: walt-laptop, Hollow Knight (`hollow-knight-linux`, 5.24 GB NAR — Unity assets: mixed
compressible/incompressible, the propnix-representative case). Levels 1/3/9 over the full NAR;
level 19 over the first 2 GiB (level-19 encode of the full NAR costs ~30 CPU-minutes per config).
`continuous` = one zstd stream, one context (the hypothetical cross-chunk baseline);
`continuous+ldm` = that plus 128 MiB long-distance matching (the upper bound of what cross-chunk
context could ever buy); `chunk-N` = independent frames, exactly what the serve side emits.

```
NARSHARE_BENCH_STORE_PATH=<path> cargo test --release -- --ignored bench_chunk_ratio --nocapture
```

| level | continuous ratio | +ldm | chunk 16 MiB | chunk 4 MiB | chunk 1 MiB | chunk 256 KiB |
|------:|-----------------:|-----:|-------------:|------------:|------------:|--------------:|
| 1     | 0.2295 | −4.80% | +0.03% | +0.13% | +0.53% | +2.15% |
| 3     | 0.2185 | −3.62% | +0.09% | +0.41% | +1.70% | +4.33% |
| 9     | 0.2036 | −1.96% | +0.38% | +1.56% | +4.24% | +7.87% |
| 19    | 0.1513 | −2.45% | +1.36% | +4.65% | +9.45% | +15.69% |

(chunk columns: wire bytes relative to `continuous` at the same level; +X% = chunking costs X%
more wire bytes.)

**Interpretation.** The penalty grows as chunks shrink and levels rise — higher levels have
bigger match windows, so cutting the stream discards more. At the operating points the adaptive
chunk sizing actually produces, the cost is where you'd want it: on fast links (levels 1–3,
chunks pinned at the 16 MiB cap) chunking is free (≤0.1%); on a ~4 MB/s link (level 19, ~8 MiB
chunks) it costs a few percent. The bad corner is the ultra-thin link where chunks hit the
256 KiB floor at level 19: **+16% wire bytes** — exactly where bytes are most precious. Effective
ratio there is still 5.7× (vs 6.6× continuous). This is the price of the load-bearing property
that chunks are independently schedulable across peers (striping, failover, per-segment retry all
depend on it); chaining contexts across chunks would couple every chunk to one peer's stream.
LDM shows cross-chunk context tops out at another 2–5% on this data — most redundancy is local.
If the thin-link corner ever matters in practice, the lever is the chunk floor (bigger chunks on
very slow links trade MW feedback cadence for ratio), not stream-context coupling.
