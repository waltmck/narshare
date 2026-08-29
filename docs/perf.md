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
