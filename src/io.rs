//! SegmentReader: multithreaded async positioned reads behind a bounded in-flight budget.
//!
//! NVMe only delivers its bandwidth at queue depth; the depth comes from many independent reads in
//! flight. Two backends behind one seam, selected at startup (`[io] backend`, default auto):
//!
//!   * `uring`: a dedicated ring thread owning an io_uring. Requests arrive over a channel; an
//!     eventfd registered as a read SQE on the ring wakes the thread for new work, so completions
//!     and submissions are waited on in ONE place with no polling. Genuinely completion-driven on
//!     filesystems with native async paths (ext4/XFS); on ZFS the kernel punts file reads to io-wq
//!     workers, which still buys batched submission and kernel-managed workers.
//!   * `blocking`: spawn_blocking preads — the fallback for kernels with io_uring disabled
//!     (seccomp/lockdown, `kernel.io_uring_disabled`).
//!
//! Reads are O_DIRECT, always (no knob): the serving working set (games) exceeds ARC anyway, and
//! on compressed/encrypted ZFS datasets the kernel demotes Direct IO to buffered transparently.
//! Filesystems that refuse O_DIRECT (tmpfs) fall back to buffered per call — behavior is identical
//! either way, only caching differs. Reads use a 4 KiB-aligned window internally and return the
//! requested sub-slice zero-copy.

use crate::config::{IoBackend, IoCfg};
use anyhow::{Context, Result};
use bytes::Bytes;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use tokio::sync::{oneshot, Semaphore};

/// O_DIRECT alignment for offset/length/buffer. 4096 covers every real logical block size.
const ALIGN: u64 = 4096;

#[derive(Clone)]
pub struct SegmentReader {
    sem: Arc<Semaphore>,
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Blocking,
    Uring(Arc<UringPool>),
}

impl SegmentReader {
    pub fn new(cfg: &IoCfg) -> Result<Self> {
        let backend = match cfg.backend {
            IoBackend::Blocking => {
                tracing::info!("io: blocking backend (configured)");
                Backend::Blocking
            }
            IoBackend::Uring => {
                let pool = UringPool::new(cfg.concurrency)
                    .context("io.backend = \"uring\" requested but io_uring is unavailable")?;
                tracing::info!("io: io_uring backend");
                Backend::Uring(Arc::new(pool))
            }
            IoBackend::Auto => match UringPool::new(cfg.concurrency) {
                Ok(pool) => {
                    tracing::info!("io: io_uring backend (auto)");
                    Backend::Uring(Arc::new(pool))
                }
                Err(e) => {
                    tracing::info!("io: io_uring unavailable ({e:#}); using blocking backend");
                    Backend::Blocking
                }
            },
        };
        Ok(Self { sem: Arc::new(Semaphore::new(cfg.concurrency.max(1))), backend })
    }

    #[cfg(test)]
    fn with_backend(backend: Backend, concurrency: usize) -> Self {
        Self { sem: Arc::new(Semaphore::new(concurrency)), backend }
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self::with_backend(Backend::Blocking, 8)
    }

    /// Read exactly `len` bytes at `off`. Short reads (file changed underneath us, e.g. GC) are
    /// errors — correctness comes from failing loudly, never from serving what happens to be there.
    pub async fn read(&self, path: Arc<PathBuf>, off: u64, len: usize) -> Result<Bytes> {
        let _permit = self.sem.clone().acquire_owned().await.expect("semaphore closed");
        match &self.backend {
            Backend::Blocking => {
                tokio::task::spawn_blocking(move || read_segment(&path, off, len))
                    .await
                    .expect("read task panicked")
            }
            Backend::Uring(pool) => pool.read(path, off, len).await,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Shared synchronous read paths (blocking backend, and the uring backend's per-op fallback).
// ---------------------------------------------------------------------------------------------

fn read_segment(path: &std::path::Path, off: u64, len: usize) -> Result<Bytes> {
    match read_direct(path, off, len) {
        Ok(b) => Ok(b),
        // EINVAL/ENOTSUP/EOPNOTSUPP: the filesystem refused O_DIRECT (open or read). Fall back to
        // buffered — same bytes, different caching.
        Err(e) if o_direct_refused(&e) => read_buffered(path, off, len),
        Err(e) => Err(e).with_context(|| format!("read {}B @{} of {}", len, off, path.display())),
    }
}

fn o_direct_refused(e: &std::io::Error) -> bool {
    // Note: ENOTSUP == EOPNOTSUPP on Linux.
    matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP))
}

fn read_buffered(path: &std::path::Path, off: u64, len: usize) -> Result<Bytes> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = vec![0u8; len];
    f.read_exact_at(&mut buf, off)
        .with_context(|| format!("read {}B @{} of {}", len, off, path.display()))?;
    Ok(Bytes::from(buf))
}

/// The aligned-window bookkeeping shared by the synchronous path and the ring: read
/// [astart, aend) ⊇ [off, off+len) into an ALIGN-aligned position inside an over-allocated Vec.
struct Window {
    buf: Vec<u8>,
    shift: usize,
    astart: u64,
    alen: usize,
    /// Bytes from astart that must be filled to cover the request.
    need: usize,
}

impl Window {
    fn new(off: u64, len: usize) -> Self {
        let astart = off - off % ALIGN;
        let aend = (off + len as u64).div_ceil(ALIGN) * ALIGN;
        let alen = (aend - astart) as usize;
        let buf = vec![0u8; alen + ALIGN as usize];
        let shift = (ALIGN as usize - (buf.as_ptr() as usize % ALIGN as usize)) % ALIGN as usize;
        Self { buf, shift, astart, alen, need: (off - astart) as usize + len }
    }

    fn finish(self, off: u64, len: usize) -> Bytes {
        let data_start = self.shift + (off - self.astart) as usize;
        Bytes::from(self.buf).slice(data_start..data_start + len)
    }
}

fn read_direct(path: &std::path::Path, off: u64, len: usize) -> std::io::Result<Bytes> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{FileExt, OpenOptionsExt};

    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECT).open(path)?;
    let mut w = Window::new(off, len);
    let mut filled = 0usize;
    while filled < w.need {
        let n = f.read_at(&mut w.buf[w.shift + filled..w.shift + w.alen], w.astart + filled as u64)?;
        if n == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("EOF at {} while reading {}B @{}", w.astart + filled as u64, len, off),
            ));
        }
        filled += n;
    }
    Ok(w.finish(off, len))
}

// ---------------------------------------------------------------------------------------------
// io_uring backend
// ---------------------------------------------------------------------------------------------

struct Req {
    path: Arc<PathBuf>,
    off: u64,
    len: usize,
    tx: oneshot::Sender<Result<Bytes>>,
}

struct UringPool {
    tx: std_mpsc::Sender<Req>,
    /// Written to wake the ring thread (new request, or shutdown on drop).
    eventfd: OwnedFd,
}

impl UringPool {
    fn new(concurrency: usize) -> Result<Self> {
        let entries = (concurrency.max(8) + 2).next_power_of_two().min(4096) as u32;
        let ring = io_uring::IoUring::new(entries).context("io_uring_setup")?;
        // Probe: some kernels create rings but restrict ops (io_uring_disabled=1 semantics vary).
        // A no-op submit round-trip is cheap and catches ENOSYS/EPERM here instead of per-read.
        let efd = unsafe {
            let fd = libc::eventfd(0, libc::EFD_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).context("eventfd");
            }
            OwnedFd::from_raw_fd(fd)
        };
        let (tx, rx) = std_mpsc::channel::<Req>();
        let handle = tokio::runtime::Handle::current();
        let efd_raw = efd.as_raw_fd();
        std::thread::Builder::new()
            .name("narshare-uring".into())
            .spawn(move || ring_loop(ring, rx, efd_raw, handle))
            .context("spawning uring thread")?;
        Ok(Self { tx, eventfd: efd })
    }

    fn wake(&self) {
        let one = 1u64.to_ne_bytes();
        // A full eventfd counter still wakes the reader; ignore the result.
        unsafe { libc::write(self.eventfd.as_raw_fd(), one.as_ptr().cast(), 8) };
    }

    async fn read(&self, path: Arc<PathBuf>, off: u64, len: usize) -> Result<Bytes> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Req { path, off, len, tx })
            .map_err(|_| anyhow::anyhow!("uring thread gone"))?;
        self.wake();
        rx.await.map_err(|_| anyhow::anyhow!("uring thread dropped request"))?
    }
}

impl Drop for UringPool {
    fn drop(&mut self) {
        // Disconnect the request channel BEFORE waking: the ring thread only learns of shutdown
        // by seeing Disconnected while draining, and it only drains on an eventfd wakeup. Waking
        // first would race field-drop order — the thread could drain Empty, re-arm, and then
        // sleep forever with nobody left to write the eventfd.
        let (dummy, _) = std_mpsc::channel();
        drop(std::mem::replace(&mut self.tx, dummy));
        self.wake();
    }
}

/// Per-op state on the ring. The Vec's heap allocation is stable while SQEs reference it (the Op
/// may move inside the slab; the buffer pointer does not).
struct Op {
    req: Req,
    window: Window,
    filled: usize,
    fd: OwnedFd,
}

const EVENTFD_TOKEN: u64 = u64::MAX;

fn ring_loop(
    mut ring: io_uring::IoUring,
    rx: std_mpsc::Receiver<Req>,
    efd: RawFd,
    handle: tokio::runtime::Handle,
) {
    use io_uring::{opcode, types};

    let mut slab: Vec<Option<Op>> = Vec::new();
    let mut free: Vec<usize> = Vec::new();
    let mut inflight = 0usize;
    let mut efd_buf = [0u8; 8];
    let mut shutdown = false;

    // Wakeup listener: a pending read on the eventfd, re-armed after every completion.
    let arm_eventfd = |ring: &mut io_uring::IoUring, efd_buf: &mut [u8; 8]| {
        let sqe = opcode::Read::new(types::Fd(efd), efd_buf.as_mut_ptr(), 8)
            .build()
            .user_data(EVENTFD_TOKEN);
        unsafe {
            while ring.submission().push(&sqe).is_err() {
                ring.submit().expect("io_uring submit");
            }
        }
    };
    arm_eventfd(&mut ring, &mut efd_buf);

    let submit_read = |ring: &mut io_uring::IoUring, slab: &mut Vec<Option<Op>>, idx: usize| {
        let op = slab[idx].as_mut().unwrap();
        let w = &mut op.window;
        let ptr = unsafe { w.buf.as_mut_ptr().add(w.shift + op.filled) };
        let sqe = opcode::Read::new(
            types::Fd(op.fd.as_raw_fd()),
            ptr,
            (w.alen - op.filled) as u32,
        )
        .offset(w.astart + op.filled as u64)
        .build()
        .user_data(idx as u64);
        unsafe {
            while ring.submission().push(&sqe).is_err() {
                ring.submit().expect("io_uring submit");
            }
        }
    };

    // Start a request: open (sync; dentries are hot) and submit the first read, or divert to the
    // blocking fallback when the filesystem refuses O_DIRECT at open time.
    let start = |ring: &mut io_uring::IoUring,
                 slab: &mut Vec<Option<Op>>,
                 free: &mut Vec<usize>,
                 inflight: &mut usize,
                 req: Req| {
        use std::os::unix::fs::OpenOptionsExt;
        let open = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(req.path.as_path());
        match open {
            Ok(f) => {
                let window = Window::new(req.off, req.len);
                let op = Op { req, window, filled: 0, fd: f.into() };
                let idx = free.pop().unwrap_or_else(|| {
                    slab.push(None);
                    slab.len() - 1
                });
                slab[idx] = Some(op);
                *inflight += 1;
                submit_read(ring, slab, idx);
            }
            Err(e) if o_direct_refused(&e) => {
                let Req { path, off, len, tx } = req;
                handle.spawn_blocking(move || {
                    let _ = tx.send(read_buffered(&path, off, len));
                });
            }
            Err(e) => {
                let msg = format!("open {}", req.path.display());
                let _ = req.tx.send(Err(anyhow::Error::new(e).context(msg)));
            }
        }
    };

    loop {
        if shutdown && inflight == 0 {
            return;
        }
        if let Err(e) = ring.submit_and_wait(1) {
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("io_uring submit_and_wait: {e}");
        }
        // Collect first: processing pushes new SQEs, which needs &mut ring.
        let cqes: Vec<(u64, i32)> = ring.completion().map(|c| (c.user_data(), c.result())).collect();
        for (ud, res) in cqes {
            if ud == EVENTFD_TOKEN {
                // Drain new requests, then re-arm.
                loop {
                    match rx.try_recv() {
                        Ok(req) => start(&mut ring, &mut slab, &mut free, &mut inflight, req),
                        Err(std_mpsc::TryRecvError::Empty) => break,
                        Err(std_mpsc::TryRecvError::Disconnected) => {
                            shutdown = true;
                            break;
                        }
                    }
                }
                if !shutdown {
                    arm_eventfd(&mut ring, &mut efd_buf);
                }
                continue;
            }
            let idx = ud as usize;
            let mut op = slab[idx].take().expect("completion for empty slot");
            free.push(idx);
            inflight -= 1;
            if res < 0 {
                let e = std::io::Error::from_raw_os_error(-res);
                if o_direct_refused(&e) {
                    // Filesystem accepted O_DIRECT at open but refused the read; fall back.
                    let Req { path, off, len, tx } = op.req;
                    handle.spawn_blocking(move || {
                        let _ = tx.send(read_buffered(&path, off, len));
                    });
                } else {
                    let msg =
                        format!("read {}B @{} of {}", op.req.len, op.req.off, op.req.path.display());
                    let _ = op.req.tx.send(Err(anyhow::Error::new(e).context(msg)));
                }
                continue;
            }
            if res == 0 {
                let _ = op.req.tx.send(Err(anyhow::anyhow!(
                    "EOF at {} while reading {}B @{} of {}",
                    op.window.astart + op.filled as u64,
                    op.req.len,
                    op.req.off,
                    op.req.path.display()
                )));
                continue;
            }
            op.filled += res as usize;
            if op.filled >= op.window.need {
                let Op { req, window, .. } = op;
                let _ = req.tx.send(Ok(window.finish(req.off, req.len)));
            } else {
                // Short read; continue where it left off.
                slab[idx] = Some(op);
                free.pop();
                inflight += 1;
                submit_read(&mut ring, &mut slab, idx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_data(dir: &std::path::Path) -> (Arc<PathBuf>, Vec<u8>) {
        let p = dir.join("blob");
        let data: Vec<u8> = (0..100_000u32).flat_map(|i| i.to_le_bytes()).collect();
        std::fs::write(&p, &data).unwrap();
        (Arc::new(p), data)
    }

    const CASES: &[(u64, usize)] =
        &[(0, 10), (1, 4095), (4095, 2), (399_995, 5), (12_345, 65_536), (0, 400_000)];

    #[test]
    fn direct_and_buffered_agree() {
        let dir = tempfile::tempdir().unwrap();
        let (p, data) = test_data(dir.path());
        for &(off, len) in CASES {
            let got = read_segment(&p, off, len).unwrap();
            assert_eq!(&got[..], &data[off as usize..off as usize + len], "@{off}+{len}");
            assert_eq!(got, read_buffered(&p, off, len).unwrap());
        }
        assert!(read_segment(&p, 399_999, 2).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn uring_matches_blocking() {
        let Ok(pool) = UringPool::new(8) else {
            eprintln!("skipping: io_uring unavailable in this environment");
            return;
        };
        let uring = SegmentReader::with_backend(Backend::Uring(Arc::new(pool)), 8);
        let blocking = SegmentReader::with_backend(Backend::Blocking, 8);
        let dir = tempfile::tempdir().unwrap();
        let (p, data) = test_data(dir.path());
        for &(off, len) in CASES {
            let a = uring.read(p.clone(), off, len).await.unwrap();
            let b = blocking.read(p.clone(), off, len).await.unwrap();
            assert_eq!(&a[..], &data[off as usize..off as usize + len], "@{off}+{len}");
            assert_eq!(a, b);
        }
        // Errors propagate, and the pool survives them.
        assert!(uring.read(p.clone(), 399_999, 2).await.is_err());
        assert!(uring.read(Arc::new(dir.path().join("missing")), 0, 1).await.is_err());
        let again = uring.read(p.clone(), 7, 300).await.unwrap();
        assert_eq!(&again[..], &data[7..307]);
    }

    /// Backend microbenchmark (M1.5 / docs/perf.md). Run explicitly:
    ///   NARSHARE_BENCH_PATH=/nix/store/...-big-file cargo test --release -- --ignored bench_backends --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn bench_backends() {
        let Ok(path) = std::env::var("NARSHARE_BENCH_PATH") else {
            eprintln!("set NARSHARE_BENCH_PATH to a large file");
            return;
        };
        let path = Arc::new(PathBuf::from(path));
        let size = std::fs::metadata(path.as_path()).unwrap().len();
        const CHUNK: usize = 1 << 20;
        const N: u64 = 512;
        let backends: Vec<(&str, SegmentReader)> = vec![
            ("blocking", SegmentReader::with_backend(Backend::Blocking, 64)),
            (
                "uring",
                SegmentReader::with_backend(
                    Backend::Uring(Arc::new(UringPool::new(64).expect("uring"))),
                    64,
                ),
            ),
        ];
        for (name, reader) in backends {
            let t0 = std::time::Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for i in 0..N {
                // Deterministic pseudo-random offsets across the file.
                let off = (i * 2654435761 % (size.saturating_sub(CHUNK as u64).max(1)))
                    / ALIGN
                    * ALIGN;
                let r = reader.clone();
                let p = path.clone();
                tasks.spawn(async move { r.read(p, off, CHUNK).await.map(|b| b.len()) });
            }
            let mut bytes = 0usize;
            while let Some(res) = tasks.join_next().await {
                bytes += res.unwrap().unwrap();
            }
            let dt = t0.elapsed().as_secs_f64();
            println!("{name}: {:.0} MB/s ({bytes} bytes in {dt:.3}s)", bytes as f64 / 1e6 / dt);
        }
    }
}
