## The mesh VM suite: four QEMU nodes substituting from each other over a heterogeneous
## virtual topology, exercising exactly the adaptive machinery no unit test can — real TCP,
## real kernels, real narshare daemons under the hardened NixOS module.
##
## Topology (one point-to-point vlan per holder, shaped with tc netem on the data path and a
## matching return-path delay on the client side):
##
##   client eth1 ── vlan 1 ──  alpha   unshaped ("fast": whatever virtio gives)
##   client eth2 ── vlan 2 ──  beta    20 Mbit, 40 ms          (thin, clean)
##   client eth3 ── vlan 3 ──  noisy   150 Mbit, 25±10 ms, 1 % correlated loss
##
## All three holders register an identical, deliberately-shaped fixture (~32 MiB NAR:
## two identical 12 MiB compressible blobs + 8 MiB incompressible) via `nix-store --add`,
## which makes it a CA path — so the client's nix substitutes it through the proxy with NO
## trusted keys, the trust model end to end.
##
## Scenarios: striped substitution across all three links at once; the ca_only gate; proxy
## restart recovery (NAR-by-hash discovery); per-link benchmarks (recorded in the test log);
## the dedup+compression wire-savings assertion on the thin link; a CPU-bound holder
## (CPUQuota=20% set live on the unit) where the closed-loop encoding controller must beat a
## pinned-high-level control proxy; an IO-bound holder (IOReadBandwidthMax on the store's
## backing disk — the store overlay is on-disk, not tmpfs, and content reads are O_DIRECT, so
## the throttle genuinely bites); and a mid-transfer holder kill with completion via the
## survivors.
##
## Absolute numbers from this suite are VM-relative (QEMU vlans top out well below 10 GbE);
## the M5.5 hardware run owns the absolute targets. min_bandwidth/roaming and the adaptive
## convergence details stay in unit tests, per PLAN.md.
##
## Run:  nix build .#checks.<system>.mesh
## Poke: nix build .#checks.<system>.mesh.driverInteractive && ./result/bin/nixos-test-driver
{ self }:
{ pkgs, lib, ... }:
let
  # Deterministic fixture tree — byte-identical on every holder, so `nix-store --add`
  # yields the same store path everywhere. Duplication and compressibility are the point:
  # the wire-savings assertions depend on them.
  fixtureGen = pkgs.writeShellApplication {
    name = "make-fixture";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      out="$1"
      rm -rf "$out"
      mkdir -p "$out/data"
      python3 - "$out" <<'PYEOF'
      import hashlib, os, sys

      out = sys.argv[1]
      # Compressible, duplicated: two identical 12 MiB blobs (dedup must fetch once).
      pat = bytes((i * 7 + (i >> 8)) % 251 for i in range(4096))
      blob = pat * (12 * 1024 * 1024 // 4096)
      for name in ("blob-a", "blob-b"):
          with open(os.path.join(out, "data", name), "wb") as f:
              f.write(blob)
      # Incompressible: a sha256 chain, deterministic without being compressible.
      h = b"narshare-mesh-fixture"
      with open(os.path.join(out, "rand.bin"), "wb") as f:
          for _ in range(8 * 1024 * 1024 // 32):
              h = hashlib.sha256(h).digest()
              f.write(h)
      with open(os.path.join(out, "hello.txt"), "w") as f:
          f.write("narshare mesh fixture\n")
      run = os.path.join(out, "run.sh")
      with open(run, "w") as f:
          f.write("#!/bin/sh\necho narshare\n")
      os.chmod(run, 0o755)
      os.symlink("data/blob-a", os.path.join(out, "link"))
      PYEOF
    '';
  };

  # An input-addressed (non-CA) path present in every VM's store, for the ca_only gate test.
  hello = pkgs.hello;

  narsharePkg = self.packages.${pkgs.stdenv.hostPlatform.system}.narshare;

  common = {
    imports = [ self.nixosModules.narshare ];
    # Holders `nix-store --add` the fixture; the client realises it.
    virtualisation.writableStore = true;
    # On the root disk, NOT tmpfs: the IO-bound scenario throttles /dev/vda, which only means
    # anything if store reads actually reach the block layer (they do: content reads are
    # O_DIRECT, so the page cache never hides them).
    virtualisation.writableStoreUseTmpfs = false;
    virtualisation.cores = 2;
    virtualisation.memorySize = 1536;
    networking.firewall.enable = false;
    boot.kernelModules = [ "sch_netem" ];
    # hello must be IN the system closure: paths referenced only by the test script are
    # readable over 9p but not registered in the VM's Nix db, and the ca_only-gate test
    # needs the holders to actually serve its narinfo.
    environment.systemPackages = [ pkgs.curl pkgs.ethtool pkgs.iperf3 pkgs.jq fixtureGen hello ];
  };

  holder = vlan: ip: {
    imports = [ common ];
    virtualisation.vlans = [ vlan ];
    networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
      { address = ip; prefixLength = 24; }
    ];
    services.narshare = {
      enable = true;
      config.serve = {
        listen = "${ip}:5050";
        # Bounds serve-side zstd encoder memory on these small VMs; auto-encoding requests
        # for higher levels clamp to this. The 500 kbit → zstd-19 tier is a unit-test and
        # M5.5 concern, not a VM-RAM one.
        max_zstd_level = 12;
      };
    };
  };
in
{
  name = "narshare-mesh";

  nodes = {
    alpha = holder 1 "192.168.1.10";
    beta = holder 2 "192.168.2.10";
    noisy = holder 3 "192.168.3.10";

    client = {
      imports = [ common ];
      virtualisation.vlans = [ 1 2 3 ];
      networking.interfaces = {
        eth1.ipv4.addresses = lib.mkForce [ { address = "192.168.1.2"; prefixLength = 24; } ];
        eth2.ipv4.addresses = lib.mkForce [ { address = "192.168.2.2"; prefixLength = 24; } ];
        eth3.ipv4.addresses = lib.mkForce [ { address = "192.168.3.2"; prefixLength = 24; } ];
      };
      services.narshare = {
        enable = true;
        config = {
          proxy.listen = "127.0.0.1:5051";
          peers = [
            { name = "alpha"; url = "http://192.168.1.10:5050"; }
            { name = "beta"; url = "http://192.168.2.10:5050"; }
            { name = "noisy"; url = "http://192.168.3.10:5050"; }
          ];
        };
      };
      # Only the proxy — a cache.nixos.org entry would stall every miss on a network-less VM.
      nix.settings.substituters = lib.mkForce [ "http://127.0.0.1:5051" ];
      # The CPU/IO-bound scenarios run scratch proxies with per-scenario configs by hand.
      environment.systemPackages = [ narsharePkg ];
    };
  };

  testScript = ''
    import time

    results = []

    def rx_bytes(iface):
        return int(client.succeed(f"cat /sys/class/net/{iface}/statistics/rx_bytes").strip())

    def proxy_reset():
        """Fresh proxy state (holders, MW weights, breakers) — narshare is stateless, so a
        restart is the cheap way to isolate scenarios."""
        client.succeed("systemctl restart narshare.service")
        client.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")

    holders = {"alpha": (alpha, "192.168.1.10"), "beta": (beta, "192.168.2.10"), "noisy": (noisy, "192.168.3.10")}

    def peers_up(*names):
        for name, (m, ip) in holders.items():
            if name in names:
                m.succeed("systemctl start narshare.service")
                client.wait_until_succeeds(f"curl -sf http://{ip}:5050/nix-cache-info >/dev/null")
            else:
                m.succeed("systemctl stop narshare.service")

    start_all()

    for m in (alpha, beta, noisy, client):
        m.wait_for_unit("narshare.service")
    client.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")

    # --- topology: shape each holder's egress (the data path), mirror the delay on the
    # client side for a symmetric RTT. Offloads off so netem sees real packet sizes. ---
    for m, dev in ((beta, "eth1"), (noisy, "eth1"), (client, "eth2"), (client, "eth3")):
        m.succeed(f"ethtool -K {dev} tso off gso off gro off || true")
    beta.succeed("tc qdisc replace dev eth1 root netem rate 20mbit delay 40ms limit 4000")
    client.succeed("tc qdisc replace dev eth2 root netem delay 40ms")
    noisy.succeed("tc qdisc replace dev eth1 root netem rate 150mbit delay 25ms 10ms loss 1% 25% limit 8000")
    client.succeed("tc qdisc replace dev eth3 root netem delay 25ms 5ms loss 0.5% 25%")
    for ip in ("192.168.1.10", "192.168.2.10", "192.168.3.10"):
        client.succeed(f"ping -c1 -W5 {ip}")

    # Raw fabric baseline: what the "fast" vlan actually provides. QEMU socket networking is
    # nowhere near 10 GbE, so every absolute number this suite prints must be read against THIS
    # ceiling — 10 GbE-class software validation lives in the loopback bench (docs/perf.md).
    alpha.succeed("iperf3 -s >/dev/null 2>&1 & echo $! > /tmp/iperf.pid")
    client.wait_until_succeeds("iperf3 -c 192.168.1.10 -t 3 -J > /tmp/iperf.json", timeout=30)
    bps = float(client.succeed("jq .end.sum_received.bits_per_second /tmp/iperf.json").strip())
    print(f"[bench] raw fast-link TCP (iperf3): {bps / 1e9:.2f} Gbit/s")
    alpha.succeed("kill $(cat /tmp/iperf.pid)")

    # --- fixture: identical content on every holder => identical CA store path ---
    paths = set()
    for m, _ip in holders.values():
        m.succeed("make-fixture /tmp/fixture")
        paths.add(m.succeed("nix-store --add /tmp/fixture").strip())
    assert len(paths) == 1, f"fixture path differs across holders: {paths}"
    path = paths.pop()
    hash_part = path.removeprefix("/nix/store/")[:32]
    nar_hash = alpha.succeed(f"nix-store -q --hash {path}").strip()
    nar32 = nar_hash.split(":", 1)[1]
    nar_sha_hex = alpha.succeed(f"nix-hash --type sha256 --to-base16 {nar32}").strip()
    nar_size = int(alpha.succeed(f"nix-store -q --size {path}").strip())
    print(f"fixture: {path}  narSize={nar_size}  {nar_hash}")
    nar_url = f"http://127.0.0.1:5051/nar/{nar32}.nar"

    def prime():
        """Resolve the narinfo and give the drainer a beat so every live holder lands in
        the stripe set."""
        client.succeed(f"curl -sf http://127.0.0.1:5051/{hash_part}.narinfo >/dev/null")
        time.sleep(0.75)

    def timed_fetch(tag, url):
        out = client.succeed(
            "curl -sS --fail -o /tmp/out.nar "
            f"-w '%{{time_total}} %{{speed_download}} %{{size_download}}' {url}"
        )
        secs, speed, size = (float(x) for x in out.split())
        size = int(size)
        assert size == nar_size, f"{tag}: got {size} bytes, want {nar_size}"
        sha = client.succeed("sha256sum /tmp/out.nar").split()[0]
        assert sha == nar_sha_hex, f"{tag}: NAR hash mismatch"
        results.append((tag, size, secs, speed / 1e6))
        print(f"[bench] {tag}: {size} bytes in {secs:.2f}s = {speed / 1e6:.2f} MB/s")
        return secs, speed

    # --- live db visibility: paths added AFTER the daemons started must be served ---
    for _name, (_m, ip) in holders.items():
        client.wait_until_succeeds(
            f"curl -sf http://{ip}:5050/{hash_part}.narinfo >/dev/null", timeout=60
        )

    # --- trust model on the wire: CA passes through, Sig does not, URL is canonical ---
    ni = client.succeed(f"curl -sf http://127.0.0.1:5051/{hash_part}.narinfo")
    assert "CA: fixed:" in ni, ni
    assert "Sig:" not in ni, ni
    assert f"URL: nar/{nar32}.nar" in ni, ni

    # --- the flagship: real nix substitutes the CA path through the proxy, striped across
    # fast+thin+noisy simultaneously, with NO trusted keys configured ---
    client.fail(f"nix-store -q --hash {path}")  # precondition: not yet in the client store
    t0 = time.monotonic()
    client.succeed(f"nix-store -r {path}")
    took = time.monotonic() - t0
    client.succeed(f"nix-store --verify-path {path}")
    results.append(("nix-store -r via proxy (striped, no keys)", nar_size, took, nar_size / took / 1e6))
    print(f"[bench] substitution: {nar_size} bytes in {took:.2f}s")

    # --- ca_only gate: an input-addressed path is refused by the proxy, served raw by peers ---
    hello_hp = "${hello}".removeprefix("/nix/store/")[:32]
    gate = client.succeed(
        f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:5051/{hello_hp}.narinfo"
    ).strip()
    assert gate == "404", f"ca_only gate must refuse a non-CA path, got {gate}"
    direct = client.succeed(
        f"curl -s -o /dev/null -w '%{{http_code}}' http://192.168.1.10:5050/{hello_hp}.narinfo"
    ).strip()
    assert direct == "200", f"the serve side is a faithful cache, got {direct}"

    # --- restart recovery: a fresh proxy must serve a NAR by hash with no narinfo first ---
    proxy_reset()
    timed_fetch("proxy, nar-by-hash after restart (discovery)", nar_url)

    # --- benchmarks ---
    timed_fetch("direct alpha (fast link)", f"http://192.168.1.10:5050/nar/{nar32}.nar")

    proxy_reset()
    prime()
    rx0 = [rx_bytes(i) for i in ("eth1", "eth2", "eth3")]
    timed_fetch("proxy striped (fast + thin + noisy)", nar_url)
    shares = [b - a for a, b in zip(rx0, (rx_bytes(i) for i in ("eth1", "eth2", "eth3")))]
    print(f"[bench] striped wire shares fast/thin/noisy: {shares}")

    # Thin link only: dedup + wire compression must beat the raw link, and the wire must
    # carry much less than the NAR (12 MiB duplicated + ~12 MiB compressible of ~33 MiB).
    peers_up("beta")
    proxy_reset()
    prime()
    rx0_thin = rx_bytes("eth2")
    _, speed = timed_fetch("proxy via beta only (20 Mbit, 40 ms)", nar_url)
    wire = rx_bytes("eth2") - rx0_thin
    print(f"[bench] thin-link wire bytes: {wire} of {nar_size} NAR bytes")
    link_bps = 20e6 / 8
    assert speed > 1.2 * link_bps, (
        f"dedup+zstd should push goodput past the raw link rate: {speed:.0f} <= {1.2 * link_bps:.0f} B/s"
    )
    assert wire < nar_size * 0.6, f"wire bytes {wire} should be well under the NAR size {nar_size}"

    peers_up("noisy")
    proxy_reset()
    prime()
    timed_fetch("proxy via noisy only (150 Mbit, 25±10 ms, 1 % loss)", nar_url)

    # --- bounded CPU / bounded IO on a holder: the adaptive machinery must respond ---
    # Single-variable setup: scratch proxies on the client, each pinned to alpha ALONE, with
    # small chunks so the level controller gets enough per-chunk observations. "pinned" requests
    # zstd:19 unconditionally (alpha's max_zstd_level caps it at 12) — the control; "auto" is
    # the closed-loop controller, started FRESH under throttle so it must adapt from its seed.
    peers_up("alpha", "beta", "noisy")

    def scratch_proxy(name, port, extra_peer_line):
        lines = [
            "[proxy]",
            f'listen = "127.0.0.1:{port}"',
            'chunk_max = "1MiB"',
            "[[peers]]",
            'name = "alpha"',
            'url = "http://192.168.1.10:5050"',
        ]
        if extra_peer_line:
            lines.append(extra_peer_line)
        body = "\n".join(lines)
        client.succeed(f"cat > /tmp/{name}.toml <<'NSHEOF'\n{body}\nNSHEOF")
        # Pidfile, not pkill-by-pattern: a pattern like "narshare -c /tmp" also matches the
        # invoking shell's own command line, and pkill would kill it (exit 143).
        client.succeed(
            f"narshare -c /tmp/{name}.toml >/tmp/{name}.log 2>&1 & echo $! > /tmp/{name}.pid"
        )
        client.wait_until_succeeds(f"curl -sf http://127.0.0.1:{port}/nix-cache-info >/dev/null")

    def prime_on(port):
        client.succeed(f"curl -sf http://127.0.0.1:{port}/{hash_part}.narinfo >/dev/null")
        time.sleep(0.3)

    # Warm alpha's seek-table and manifest caches (and take an unthrottled baseline) through
    # the pinned proxy, so the throttled runs measure the throttle, not cold caches.
    scratch_proxy("pinned", 5052, 'encoding = "zstd:19"')
    prime_on(5052)
    timed_fetch("alpha-only, unthrottled (baseline)", f"http://127.0.0.1:5052/nar/{nar32}.nar")

    # CPU-bound holder: 20% of one core, applied LIVE to the running unit (its caches stay
    # warm). The pinned control pays full price for high-level zstd; the closed loop must
    # classify chunks as encode-bound, shed the level, and win with a clear margin.
    alpha.succeed("systemctl set-property --runtime narshare.service CPUQuota=20%")
    prime_on(5052)
    _, pinned_speed = timed_fetch(
        "alpha CPU-bound (20%), pinned zstd:19", f"http://127.0.0.1:5052/nar/{nar32}.nar"
    )
    scratch_proxy("auto", 5053, "")
    prime_on(5053)
    _, auto_speed = timed_fetch(
        "alpha CPU-bound (20%), auto level", f"http://127.0.0.1:5053/nar/{nar32}.nar"
    )
    alpha.succeed("systemctl set-property --runtime narshare.service CPUQuota=")
    assert auto_speed > pinned_speed * 1.3, (
        f"the closed loop must shed the level on a CPU-bound holder: "
        f"auto {auto_speed:.0f} B/s vs pinned {pinned_speed:.0f} B/s"
    )

    # IO-bound holder: 4 MB/s disk reads, applied live. Content reads are O_DIRECT — and the
    # page cache is dropped besides, so even a buffered fallback (if overlayfs refused
    # O_DIRECT) must cross the throttled block layer. The lower duration bound proves the
    # throttle actually bit (dedup means only the ~20 MiB of distinct content is read; goodput
    # may exceed the disk rate). The level controller should classify these read-bound and hold.
    alpha.succeed(
        "systemctl set-property --runtime narshare.service 'IOReadBandwidthMax=/dev/vda 4M'"
    )
    alpha.succeed("sync && echo 3 > /proc/sys/vm/drop_caches")
    prime_on(5053)
    io_secs, _ = timed_fetch(
        "alpha IO-bound (4 MB/s disk), auto", f"http://127.0.0.1:5053/nar/{nar32}.nar"
    )
    alpha.succeed("systemctl set-property --runtime narshare.service 'IOReadBandwidthMax='")
    assert io_secs > 3.0, (
        f"disk throttle did not bite ({io_secs:.1f}s) — is the store overlay on tmpfs, "
        f"or did O_DIRECT fall back to buffered?"
    )
    assert io_secs < 60, f"IO-bound transfer took {io_secs:.1f}s"

    client.succeed("kill $(cat /tmp/pinned.pid /tmp/auto.pid) 2>/dev/null || true")

    # --- kill a holder mid-transfer: the stripe must finish via the survivors ---
    peers_up("alpha", "beta", "noisy")
    alpha.succeed("tc qdisc replace dev eth1 root netem rate 60mbit delay 5ms")
    proxy_reset()
    prime()
    client.succeed("rm -f /tmp/rc /tmp/failover.nar")
    client.succeed(f"( curl -s -o /tmp/failover.nar {nar_url}; echo $? > /tmp/rc ) >/dev/null 2>&1 &")
    time.sleep(1.5)
    alpha.succeed("systemctl stop narshare.service")
    client.wait_until_succeeds("test -f /tmp/rc", timeout=180)
    rc = client.succeed("cat /tmp/rc").strip()
    assert rc == "0", f"failover transfer exited {rc}"
    sha = client.succeed("sha256sum /tmp/failover.nar").split()[0]
    assert sha == nar_sha_hex, "failover transfer must be byte-exact"
    alpha.succeed("tc qdisc del dev eth1 root")
    print("[bench] failover: completed via beta+noisy after alpha died mid-transfer")

    # --- results ---
    print("")
    print("=== narshare mesh benchmarks (VM-relative; absolute 10GbE targets are M5.5) ===")
    for tag, size, secs, mbs in results:
        print(f"  {tag:48} {size / 1e6:8.1f} MB {secs:8.2f} s {mbs:9.2f} MB/s")
  '';
}
