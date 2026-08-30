## The mesh VM suite: four full nodes (every node serves, proxies, and syncs the replicated
## index) over a heterogeneous virtual topology — plus the distributed-systems battery the sync
## protocol demands: partitions, divergent writes with post-heal convergence, node restarts,
## cache loss (generation bump → snapshot resync), GC propagation, transitive relay past an
## unreachable origin, and index persistence across proxy restarts.
##
## Topology: point-to-point shaped links between the client and each holder, plus an unshaped
## holder backbone for holder↔holder sync.
##
##   client eth1 ── vlan 1 ──  alpha   unshaped ("fast": whatever virtio gives)
##   client eth2 ── vlan 2 ──  beta    20 Mbit, 40 ms          (thin, clean)
##   client eth3 ── vlan 3 ──  noisy   150 Mbit, 25±10 ms, 1 % correlated loss
##   alpha/beta/noisy ── vlan 9 ──     unshaped holder backbone
##
## All fixtures are registered at RUNTIME with nix-store --add (content-addressed), and reach
## other nodes only through the real reactive pipeline: inotify on the Nix db → differ → journal
## → hint → pull. Data-plane scenarios (striping, dedup wire savings, failover, CPU/IO-bounded
## holders) ride on top of the converged index.
##
## Absolute numbers are VM-relative (the suite prints its own iperf3 fabric baseline); the
## 10 GbE-class software validation lives in the loopback bench (docs/perf.md).
##
## Run:  nix build .#checks.<system>.mesh
## Poke: nix build .#checks.<system>.mesh.driverInteractive && ./result/bin/nixos-test-driver
{ self }:
{ pkgs, lib, ... }:
let
  # Deterministic fixture trees, parameterized by seed: the same seed yields the same store
  # path on every node; distinct seeds yield distinct paths (for single-holder scenarios).
  fixtureGen = pkgs.writeShellApplication {
    name = "make-fixture";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      out="$1"
      seed="$2"
      rm -rf "$out"
      mkdir -p "$out/data"
      python3 - "$out" "$seed" <<'PYEOF'
      import hashlib, os, sys

      out, seed = sys.argv[1], sys.argv[2].encode()
      # Compressible, duplicated: two identical 12 MiB blobs (dedup must fetch once).
      pat = bytes((i * 7 + (i >> 8) + seed[0]) % 251 for i in range(4096))
      blob = pat * (12 * 1024 * 1024 // 4096)
      for name in ("blob-a", "blob-b"):
          with open(os.path.join(out, "data", name), "wb") as f:
              f.write(blob)
      # Incompressible: a seeded sha256 chain.
      h = b"narshare-mesh-fixture" + seed
      with open(os.path.join(out, "rand.bin"), "wb") as f:
          for _ in range(8 * 1024 * 1024 // 32):
              h = hashlib.sha256(h).digest()
              f.write(h)
      with open(os.path.join(out, "hello.txt"), "w") as f:
          f.write("narshare mesh fixture %s\n" % sys.argv[2])
      run = os.path.join(out, "run.sh")
      with open(run, "w") as f:
          f.write("#!/bin/sh\necho narshare\n")
      os.chmod(run, 0o755)
      os.symlink("data/blob-a", os.path.join(out, "link"))
      PYEOF
    '';
  };

  narsharePkg = self.packages.${pkgs.stdenv.hostPlatform.system}.narshare;

  # The full-mesh peer map: every node lists every other node under its mesh-wide name. The
  # client reaches holders over the SHAPED links; holders reach each other over the backbone
  # and the client over their shaped link (addresses select the route).
  peerUrl = {
    alpha = { beta = "http://192.168.9.11:5050"; noisy = "http://192.168.9.12:5050"; client = "http://192.168.1.2:5050"; };
    beta = { alpha = "http://192.168.9.10:5050"; noisy = "http://192.168.9.12:5050"; client = "http://192.168.2.2:5050"; };
    noisy = { alpha = "http://192.168.9.10:5050"; beta = "http://192.168.9.11:5050"; client = "http://192.168.3.2:5050"; };
    client = { alpha = "http://192.168.1.10:5050"; beta = "http://192.168.2.10:5050"; noisy = "http://192.168.3.10:5050"; };
  };

  peersFor = me: extra:
    (lib.mapAttrsToList (n: url: { name = n; inherit url; }) peerUrl.${me}) ++ extra;

  common = {
    imports = [ self.nixosModules.narshare ];
    virtualisation.writableStore = true;
    # On the root disk, NOT tmpfs: the IO-bound scenario throttles /dev/vda, which only means
    # anything if store reads actually reach the block layer (content reads are O_DIRECT).
    virtualisation.writableStoreUseTmpfs = false;
    virtualisation.cores = 2;
    virtualisation.memorySize = 1536;
    networking.firewall.enable = false;
    boot.kernelModules = [ "sch_netem" ];
    environment.systemPackages =
      [ pkgs.curl pkgs.ethtool pkgs.iperf3 pkgs.jq fixtureGen narsharePkg pkgs.hello ];
    # nix's trust configuration is deliberately UNTOUCHED: narshare adds no keys, ever.
    nix.settings.substituters = lib.mkForce [ "http://127.0.0.1:5051" ];
  };

  holder = name: vlan: ip: {
    imports = [ common ];
    virtualisation.vlans = [ vlan 9 ];
    networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
      { address = ip; prefixLength = 24; }
    ];
    networking.interfaces.eth2.ipv4.addresses = lib.mkForce [
      { address = peerUrlIp name; prefixLength = 24; }
    ];
    services.narshare = {
      enable = true;
      config = {
        inherit name;
        serve = {
          listen = "0.0.0.0:5050";
          # Bounds serve-side zstd encoder memory on these small VMs.
          max_zstd_level = 12;
        };
        proxy.listen = "127.0.0.1:5051";
        peers = peersFor name (
          # alpha additionally accepts the client-side scratch proxies (CPU/IO scenarios) as
          # origins; their URLs are unreachable from alpha, which only costs breaker noise.
          lib.optionals (name == "alpha") [
            { name = "xauto"; url = "http://127.0.0.1:1"; }
            { name = "xpinned"; url = "http://127.0.0.1:1"; }
          ]
        );
      };
    };
  };

  peerUrlIp = name:
    { alpha = "192.168.9.10"; beta = "192.168.9.11"; noisy = "192.168.9.12"; }.${name};
in
{
  name = "narshare-mesh";

  nodes = {
    alpha = holder "alpha" 1 "192.168.1.10";
    beta = holder "beta" 2 "192.168.2.10";
    noisy = holder "noisy" 3 "192.168.3.10";

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
          name = "client";
          serve.listen = "0.0.0.0:5050";
          proxy.listen = "127.0.0.1:5051";
          peers = peersFor "client" [ ];
        };
      };
    };
  };

  testScript = ''
    import json
    import time

    results = []

    # ---- observability helpers (the /narshare/v1/status endpoint) ----------------------
    def status(machine):
        return json.loads(
            machine.succeed("curl -sf http://127.0.0.1:5051/narshare/v1/status")
        )

    CORE = ("alpha", "beta", "noisy", "client")

    def identity(machine):
        """The convergence identity: per-origin (generation, seq) plus the narinfo count.
        Two fully synced nodes must agree EXACTLY."""
        st = status(machine)
        clocks = {
            o["name"]: (o["generation"], o["seq"])
            for o in st["index"]["origins"]
            if o["name"] in CORE
        }
        return clocks, st["index"]["narinfos"]

    def wait_converged(machines, timeout=120, tag=""):
        deadline = time.time() + timeout
        while True:
            ids = [identity(m) for m in machines]
            if all(i == ids[0] for i in ids[1:]):
                print(f"[status] {tag}: mesh convergent — {ids[0][1]} narinfos, "
                      f"clocks {ids[0][0]}")
                return
            if time.time() > deadline:
                raise AssertionError(f"{tag}: mesh did not converge: {ids}")
            time.sleep(3)

    def tsnap(machine):
        """(transfer counters, per-peer breaker opens) for before/after delta assertions."""
        p = status(machine)["proxy"]
        return p["transfers"], {q["name"]: q["breaker"]["opens_total"] for q in p["peers"]}

    def wait_no_active_transfers(machines, timeout=150):
        deadline = time.time() + timeout
        while True:
            active = {m.name: status(m)["proxy"]["transfers"]["active"] for m in machines}
            if all(v == 0 for v in active.values()):
                print("[status] no leaked transfers anywhere")
                return
            if time.time() > deadline:
                raise AssertionError(f"leaked transfers: {active}")
            time.sleep(3)

    def rx_bytes(iface):
        return int(client.succeed(f"cat /sys/class/net/{iface}/statistics/rx_bytes").strip())

    def narinfo_code(machine, hp):
        return machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:5051/{hp}.narinfo"
        ).strip()

    def wait_narinfo(machine, hp, code, timeout=45):
        machine.wait_until_succeeds(
            f"[ \"$(curl -s -o /dev/null -w '%{{http_code}}' "
            f"http://127.0.0.1:5051/{hp}.narinfo)\" = \"{code}\" ]",
            timeout=timeout,
        )

    def add_fixture(machine, seed):
        machine.succeed(f"make-fixture /tmp/fixture-{seed} {seed}")
        path = machine.succeed(f"nix-store --add /tmp/fixture-{seed}").strip()
        return path, path.removeprefix("/nix/store/")[:32]

    def nar_meta(machine, path):
        nar_hash = machine.succeed(f"nix-store -q --hash {path}").strip().split(":", 1)[1]
        size = int(machine.succeed(f"nix-store -q --size {path}").strip())
        sha_hex = machine.succeed(f"nix-hash --type sha256 --to-base16 {nar_hash}").strip()
        return nar_hash, size, sha_hex

    def timed_fetch(tag, url, nar_size, sha_hex):
        out = client.succeed(
            "curl -sS --fail -o /tmp/out.nar "
            f"-w '%{{time_total}} %{{speed_download}} %{{size_download}}' {url}"
        )
        secs, speed, size = (float(x) for x in out.split())
        size = int(size)
        assert size == nar_size, f"{tag}: got {size} bytes, want {nar_size}"
        sha = client.succeed("sha256sum /tmp/out.nar").split()[0]
        assert sha == sha_hex, f"{tag}: NAR hash mismatch"
        results.append((tag, size, secs, speed / 1e6))
        print(f"[bench] {tag}: {size} bytes in {secs:.2f}s = {speed / 1e6:.2f} MB/s")
        return secs, speed

    start_all()
    for m in (alpha, beta, noisy, client):
        m.wait_for_unit("narshare.service")
        m.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")

    # --- topology shaping (holder egress = the data path; client side mirrors the delay) ---
    for m, dev in ((beta, "eth1"), (noisy, "eth1"), (client, "eth2"), (client, "eth3")):
        m.succeed(f"ethtool -K {dev} tso off gso off gro off || true")
    beta.succeed("tc qdisc replace dev eth1 root netem rate 20mbit delay 40ms limit 4000")
    client.succeed("tc qdisc replace dev eth2 root netem delay 40ms")
    noisy.succeed(
        "tc qdisc replace dev eth1 root netem rate 150mbit delay 25ms 10ms loss 1% 25% limit 8000"
    )
    client.succeed("tc qdisc replace dev eth3 root netem delay 25ms 5ms loss 0.5% 25%")
    for ip in ("192.168.1.10", "192.168.2.10", "192.168.3.10"):
        client.succeed(f"ping -c1 -W5 {ip}")
    alpha.succeed("ping -c1 -W5 192.168.9.11 && ping -c1 -W5 192.168.9.12")

    # Raw fabric baseline: what the "fast" vlan actually provides.
    alpha.succeed("iperf3 -s >/dev/null 2>&1 & echo $! > /tmp/iperf.pid")
    client.wait_until_succeeds("iperf3 -c 192.168.1.10 -t 3 -J > /tmp/iperf.json", timeout=30)
    bps = float(client.succeed("jq .end.sum_received.bits_per_second /tmp/iperf.json").strip())
    print(f"[bench] raw fast-link TCP (iperf3): {bps / 1e9:.2f} Gbit/s")
    alpha.succeed("kill $(cat /tmp/iperf.pid)")

    # =====================================================================================
    # Reactive convergence: a path registered on every holder reaches the client's local
    # index through inotify → differ → hint → pull, with no lookup traffic at all.
    # =====================================================================================
    for m in (alpha, beta, noisy):
        add_fixture(m, "shared")
    path, hp = add_fixture(alpha, "shared")  # same content, same path (already added: no-op)
    nar32, nar_size, sha_hex = nar_meta(alpha, path)
    wait_narinfo(client, hp, 200)
    # Measure the add→visible latency precisely with a FRESH single-holder path: poll INSIDE
    # the client at 50 ms granularity (the test driver's own polling is 1 s-quantized).
    _, lat_hp = add_fixture(alpha, "latency-probe")
    elapsed = float(
        client.succeed(
            "t0=$(date +%s.%N); for i in $(seq 1 600); do "
            f"[ \"$(curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:5051/{lat_hp}.narinfo)\" = 200 ] && break; "
            "sleep 0.05; done; t1=$(date +%s.%N); echo \"$t1 $t0\" | awk '{print $1-$2}'"
        ).strip()
    )
    assert elapsed < 30, f"convergence took {elapsed}s"
    print(f"[conv] add on alpha -> visible on client in {elapsed:.2f}s")
    # …and holder-to-holder over the backbone.
    wait_narinfo(beta, hp, 200)
    # The narinfo itself: CA passthrough, canonical URL.
    ni = client.succeed(f"curl -sf http://127.0.0.1:5051/{hp}.narinfo")
    assert "CA: fixed:" in ni, ni
    assert f"URL: nar/{nar32}.nar" in ni, ni
    # A miss is a free local 404 — no peer sees it.
    assert narinfo_code(client, "c" * 32) == "404"
    # The strong form of convergence: every node's per-origin clocks and narinfo counts agree
    # exactly (via the status endpoint), not just one sampled narinfo.
    wait_converged([alpha, beta, noisy, client], tag="initial")

    # =====================================================================================
    # Data plane over the converged index.
    # =====================================================================================
    nar_url = f"http://127.0.0.1:5051/nar/{nar32}.nar"
    direct = client.succeed(
        f"curl -sS --fail -o /tmp/direct.nar -w '%{{size_download}}' "
        f"http://192.168.1.10:5050/nar/{nar32}.nar"
    )
    assert int(float(direct)) == nar_size
    timed_fetch("proxy striped (fast + thin + noisy)", nar_url, nar_size, sha_hex)

    # A path held ONLY by beta: thin-link dedup + compression must beat the raw link.
    bpath, bhp = add_fixture(beta, "beta-only")
    bnar32, bsize, bsha = nar_meta(beta, bpath)
    wait_narinfo(client, bhp, 200)
    rx0 = rx_bytes("eth2")
    _, speed = timed_fetch(
        "beta-only (20 Mbit, 40 ms)", f"http://127.0.0.1:5051/nar/{bnar32}.nar", bsize, bsha
    )
    wire = rx_bytes("eth2") - rx0
    print(f"[bench] thin-link wire bytes: {wire} of {bsize} NAR bytes")
    assert speed > 1.2 * (20e6 / 8), "dedup+zstd should beat the raw link rate"
    assert wire < bsize * 0.6, f"wire bytes {wire} should be well under the NAR size {bsize}"

    # A path held ONLY by noisy: completes byte-exact through loss.
    npath, nhp = add_fixture(noisy, "noisy-only")
    nnar32, nsize, nsha = nar_meta(noisy, npath)
    wait_narinfo(client, nhp, 200)
    timed_fetch(
        "noisy-only (150 Mbit, 25±10 ms, 1 % loss)",
        f"http://127.0.0.1:5051/nar/{nnar32}.nar",
        nsize,
        nsha,
    )

    # Real nix substitution end to end, no keys.
    client.fail(f"nix-store -q --hash {path}")
    client.succeed(f"nix-store -r {path}")
    client.succeed(f"nix-store --verify-path {path}")

    # An unsigned input-addressed path never enters the mesh (feasibility at the exporter);
    # its CA sibling registered at the same time does — evidence the pipeline ran.
    expr = (
        'derivation { name = "unsigned-tool"; system = builtins.currentSystem; '
        'builder = "/bin/sh"; args = [ "-c" "echo hi > $out" ]; }'
    )
    unsigned = (
        alpha.succeed(f"nix-build --option sandbox false --no-out-link -E '{expr}'")
        .strip()
        .splitlines()[-1]
    )
    upath, uhp = add_fixture(alpha, "with-unsigned")
    wait_narinfo(client, uhp, 200)
    assert narinfo_code(client, unsigned.removeprefix("/nix/store/")[:32]) == "404"

    # =====================================================================================
    # GC propagation: deleting the path on its only holder must 404 mesh-wide.
    # =====================================================================================
    noisy.succeed(f"nix-store --delete {npath}")
    wait_narinfo(client, nhp, 404)
    print("[conv] GC on the holder propagated to a client 404")

    # =====================================================================================
    # Index persistence: a restarted proxy answers narinfo AND nar with no resync.
    # =====================================================================================
    client.succeed("systemctl restart narshare.service")
    client.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")
    assert narinfo_code(client, hp) == "200", "the index must persist across restarts"
    timed_fetch("striped again after proxy restart", nar_url, nar_size, sha_hex)

    # =====================================================================================
    # Partition: beta drops off entirely. The mesh keeps moving; divergent writes on both
    # sides of the cut converge after the heal.
    # =====================================================================================
    beta.succeed("ip link set eth1 down; ip link set eth2 down")
    part_a, part_a_hp = add_fixture(alpha, "during-partition-alpha")
    part_b, part_b_hp = add_fixture(beta, "during-partition-beta")
    wait_narinfo(client, part_a_hp, 200)  # alpha's write converges without beta
    assert narinfo_code(client, part_b_hp) == "404", "beta is cut off; its write cannot arrive"
    # Transfers of the shared fixture still complete without beta.
    timed_fetch("striped during beta's partition", nar_url, nar_size, sha_hex)

    beta.succeed("ip link set eth1 up; ip link set eth2 up")
    beta.wait_until_succeeds("ping -c1 -W2 192.168.9.10")
    # Convergence in BOTH directions after the heal (beta's own boot/hints or the 60 s sync
    # timer; a fresh write also re-hints the mesh).
    wait_narinfo(client, part_b_hp, 200, timeout=90)
    wait_narinfo(beta, part_a_hp, 200, timeout=90)
    print("[conv] divergent writes converged after partition heal")

    # =====================================================================================
    # Transitive relay: alpha loses its client link but keeps the backbone. Its new write
    # reaches the client THROUGH beta/noisy; the bytes are unreachable until the heal.
    # =====================================================================================
    alpha.succeed("ip link set eth1 down")
    tpath, thp = add_fixture(alpha, "transitive")
    tnar32, tsize, tsha = nar_meta(alpha, tpath)
    wait_narinfo(client, thp, 200, timeout=90)
    print("[conv] alpha's write reached the client via relay while alpha was unreachable")
    # The proxy 200s the headers (the index says available) but the BODY must fail: the only
    # holder is unreachable, so chunks error and the transfer aborts cleanly.
    client.fail(f"curl -sf --max-time 20 -o /dev/null http://127.0.0.1:5051/nar/{tnar32}.nar")
    alpha.succeed("ip link set eth1 up")
    client.wait_until_succeeds("ping -c1 -W2 192.168.1.10")
    client.wait_until_succeeds(
        f"curl -sf -o /tmp/t.nar http://127.0.0.1:5051/nar/{tnar32}.nar", timeout=60
    )
    assert client.succeed("sha256sum /tmp/t.nar").split()[0] == tsha

    # =====================================================================================
    # Cache loss: beta loses /var/cache. Its generation bumps; peers snapshot-resync; its
    # own holdings re-export and stay visible.
    # =====================================================================================
    beta.succeed("systemctl stop narshare.service")
    beta.succeed("rm -rf /var/cache/narshare/*")
    beta.succeed("systemctl start narshare.service")
    beta.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")
    wait_narinfo(beta, hp, 200, timeout=90)      # beta relearns the mesh
    wait_narinfo(client, bhp, 200, timeout=90)   # the mesh relearns beta (new generation)
    print("[conv] cache loss healed via generation bump + snapshots")

    # =====================================================================================
    # Kill a holder mid-transfer: the stripe finishes via the survivors.
    # =====================================================================================
    alpha.succeed("tc qdisc replace dev eth1 root netem rate 60mbit delay 5ms")
    client.succeed("rm -f /tmp/rc /tmp/failover.nar")
    client.succeed(
        f"( curl -s -o /tmp/failover.nar {nar_url}; echo $? > /tmp/rc ) >/dev/null 2>&1 &"
    )
    time.sleep(1.5)
    alpha.succeed("systemctl stop narshare.service")
    client.wait_until_succeeds("test -f /tmp/rc", timeout=180)
    assert client.succeed("cat /tmp/rc").strip() == "0"
    assert client.succeed("sha256sum /tmp/failover.nar").split()[0] == sha_hex
    alpha.succeed("tc qdisc del dev eth1 root")
    alpha.succeed("systemctl start narshare.service")
    alpha.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")
    print("[bench] failover: completed via beta+noisy after alpha died mid-transfer")

    # =====================================================================================
    # Resilience battery.
    # =====================================================================================

    # --- (a) Many small concurrent fetches alongside a big transfer -----------------------
    # The nixpkgs-rebuild shape: a burst of small NARs must stay low-latency while one big
    # transfer occupies stream slots (slot wake-ups + the serve-side small-encode lane).
    small_hashes = []
    for i in range(24):
        for m in (alpha, beta):
            m.succeed(f"seq -f 'narshare-small-{i}-%.0f' 1 4000 > /tmp/small-{i}")
        p = alpha.succeed(f"nix-store --add /tmp/small-{i}").strip()
        assert beta.succeed(f"nix-store --add /tmp/small-{i}").strip() == p
        small_hashes.append(
            alpha.succeed(f"nix-store -q --hash {p}").strip().split(":", 1)[1]
        )
        if i == 23:
            last_hp = p.removeprefix("/nix/store/")[:32]
    wait_narinfo(client, last_hp, 200)
    pre_t, _ = tsnap(client)
    client.succeed("rm -f /tmp/big-rc")
    client.succeed(
        f"( curl -sf -o /tmp/big.nar {nar_url}; echo $? > /tmp/big-rc ) >/dev/null 2>&1 &"
    )
    urls = " ".join(f"http://127.0.0.1:5051/nar/{h}.nar" for h in small_hashes)
    t_small = float(client.succeed(
        "t0=$(date +%s.%N); "
        f"printf '%s\\n' {urls} | xargs -P 12 -I@ curl -sf -o /dev/null @ && "
        "t1=$(date +%s.%N) && echo \"$t1 $t0\" | awk '{print $1-$2}'"
    ).strip())
    client.wait_until_succeeds("test -f /tmp/big-rc", timeout=120)
    assert client.succeed("cat /tmp/big-rc").strip() == "0"
    assert client.succeed("sha256sum /tmp/big.nar").split()[0] == sha_hex
    assert t_small < 30, f"24 small NARs took {t_small:.1f}s under a concurrent big transfer"
    print(f"[bench] 24 small NARs (x12 parallel, big transfer running): {t_small:.2f}s")
    # Attribution: exactly 25 clean completions (24 small + 1 big), zero aborts of any kind.
    post_t, _ = tsnap(client)
    assert post_t["completed"] - pre_t["completed"] == 25, (pre_t, post_t)
    for k, v in post_t["aborted"].items():
        assert v == pre_t["aborted"][k], f"unexpected {k} abort during parallel smalls"

    # --- (b) SIGSTOP black hole: accepts TCP, never answers ------------------------------
    # The nastiest failure mode: alpha's kernel completes handshakes while the daemon is
    # frozen. Chunk deadlines must strike it out of the transfer; the survivors finish.
    # (alpha is shaped down so the fetch is guaranteed to still be running at the freeze.)
    alpha.succeed("tc qdisc replace dev eth1 root netem rate 60mbit delay 5ms")
    pre_t, pre_b = tsnap(client)
    client.succeed("rm -f /tmp/bh-rc /tmp/bh.nar")
    client.succeed(
        f"( curl -sf -o /tmp/bh.nar {nar_url}; echo $? > /tmp/bh-rc ) >/dev/null 2>&1 &"
    )
    time.sleep(1.0)
    t0 = time.time()
    alpha.succeed("kill -STOP $(systemctl show -p MainPID --value narshare.service)")
    client.wait_until_succeeds("test -f /tmp/bh-rc", timeout=90)
    bh_secs = time.time() - t0
    assert client.succeed("cat /tmp/bh-rc").strip() == "0"
    assert client.succeed("sha256sum /tmp/bh.nar").split()[0] == sha_hex
    print(f"[bench] black-holed holder mid-transfer: finished via survivors in {bh_secs:.1f}s")
    # A FRESH transfer while alpha is still frozen must also complete, time-bounded.
    t0 = time.time()
    client.succeed(f"curl -sf --max-time 90 -o /tmp/bh2.nar {nar_url}")
    assert client.succeed("sha256sum /tmp/bh2.nar").split()[0] == sha_hex
    print(f"[bench] fresh transfer, holder still frozen: {time.time() - t0:.1f}s")
    # Attribution: both fetches completed cleanly — no stall or streak fired; the black hole
    # was ridden out by the survivors. (The breaker may or may not have opened: hung chunks
    # strike only if they REACH their deadlines, and a transfer that finishes first reaps them
    # without a verdict — a black hole that never blocked anyone needs no striking. The
    # deterministic breaker-opens coverage is the hard-dead-holder scenario below.)
    post_t, post_b = tsnap(client)
    assert post_t["completed"] - pre_t["completed"] == 2, (pre_t, post_t)
    assert post_t["aborted"]["stall"] == pre_t["aborted"]["stall"], "no stall abort"
    assert post_t["aborted"]["streak"] == pre_t["aborted"]["streak"], "no streak abort"
    print(f"[status] frozen-holder breaker opens delta: {post_b['alpha'] - pre_b['alpha']}")
    alpha.succeed("kill -CONT $(systemctl show -p MainPID --value narshare.service)")
    alpha.succeed("tc qdisc del dev eth1 root")
    alpha.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")

    # --- (c) All holders dead: the narinfo must 404 FAST (do no harm) --------------------
    # bhp/bnar32 is held only by beta. Kill beta, burn its breaker with one failed body,
    # then the metadata itself must go 404 — nix falls straight through to its other
    # substituters instead of stalling out per path.
    beta.succeed("systemctl stop narshare.service")
    _, pre_b = tsnap(client)
    # --max-time 3: the breaker opens within ~0.5s of the first refused chunks, and the 404
    # must be probed while it is still open (15s cooldown), not after the half-open point.
    client.fail(f"curl -sf --max-time 3 -o /dev/null http://127.0.0.1:5051/nar/{bnar32}.nar")
    _, post_b = tsnap(client)
    assert post_b["beta"] > pre_b["beta"], "the dead holder's breaker must have opened"
    t404 = float(client.succeed(
        f"t0=$(date +%s.%N); code=$(curl -s -o /dev/null -w '%{{http_code}}' "
        f"http://127.0.0.1:5051/{bhp}.narinfo); t1=$(date +%s.%N); "
        f"[ \"$code\" = 404 ] && echo \"$t1 $t0\" | awk '{{print $1-$2}}'"
    ).strip())
    assert t404 < 1.0, f"all-holders-dead narinfo took {t404:.2f}s (want instant 404)"
    print(f"[conv] all-holders-dead narinfo: 404 in {t404 * 1000:.0f}ms")
    beta.succeed("systemctl start narshare.service")
    beta.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")
    wait_narinfo(client, bhp, 200, timeout=45)  # breaker cooldown + ambient sync probe
    client.succeed(f"curl -sf --max-time 60 -o /dev/null http://127.0.0.1:5051/nar/{bnar32}.nar")
    print("[conv] holder recovery: breaker closed, path serves again")

    # --- (d) Link degrades mid-transfer ---------------------------------------------------
    # alpha's fast link collapses to 1 Mbit while a striped transfer runs: MW re-weights the
    # stripe onto beta+noisy and the transfer still completes in bounded time.
    # (pre-shaped for the same reason as (b): the collapse must land mid-transfer.)
    alpha.succeed("tc qdisc replace dev eth1 root netem rate 60mbit delay 5ms")
    client.succeed("rm -f /tmp/dg-rc /tmp/dg.nar")
    client.succeed(
        f"( curl -sf -o /tmp/dg.nar {nar_url}; echo $? > /tmp/dg-rc ) >/dev/null 2>&1 &"
    )
    time.sleep(1.0)
    t0 = time.time()
    alpha.succeed("tc qdisc replace dev eth1 root netem rate 1mbit delay 100ms limit 1000")
    client.wait_until_succeeds("test -f /tmp/dg-rc", timeout=120)
    assert client.succeed("cat /tmp/dg-rc").strip() == "0"
    assert client.succeed("sha256sum /tmp/dg.nar").split()[0] == sha_hex
    print(f"[bench] link collapsed to 1 Mbit mid-transfer: finished in {time.time() - t0:.1f}s")
    alpha.succeed("tc qdisc del dev eth1 root")

    # --- (e) Flapping holder under sequential fetch load ----------------------------------
    # noisy restarts three times while the client pulls the shared NAR back to back: every
    # fetch must succeed (multi-holder paths ride out a flapping peer).
    client.succeed("rm -f /tmp/flap-rc")
    client.succeed(
        f"( for i in 1 2 3 4 5 6; do curl -sf -o /tmp/flap.nar {nar_url} || "
        "{ echo fail > /tmp/flap-rc; exit 1; }; done; echo ok > /tmp/flap-rc ) "
        ">/dev/null 2>&1 &"
    )
    for _ in range(3):
        noisy.succeed("systemctl restart narshare.service")
        time.sleep(2)
    client.wait_until_succeeds("test -f /tmp/flap-rc", timeout=240)
    assert client.succeed("cat /tmp/flap-rc").strip() == "ok"
    assert client.succeed("sha256sum /tmp/flap.nar").split()[0] == sha_hex
    print("[conv] six back-to-back fetches survived three holder restarts")
    # The mesh still converges after the chaos: one more write on each holder lands.
    for m, seed in ((alpha, "post-chaos-a"), (beta, "post-chaos-b"), (noisy, "post-chaos-n")):
        _, chp = add_fixture(m, seed)
        wait_narinfo(client, chp, 200, timeout=90)
    wait_converged([alpha, beta, noisy, client], tag="post-chaos")

    # --- (f) SIGKILL a holder mid-transfer: unclean death + sqlite WAL recovery -----------
    # No graceful shutdown, no final flush: the survivors finish the stripe, and the killed
    # node must come back with the SAME generation (an unclean death is not cache loss).
    pre_gen = {o["name"]: o["generation"] for o in status(beta)["index"]["origins"]}["beta"]
    client.succeed("rm -f /tmp/sk-rc /tmp/sk.nar")
    client.succeed(
        f"( curl -sf -o /tmp/sk.nar {nar_url}; echo $? > /tmp/sk-rc ) >/dev/null 2>&1 &"
    )
    time.sleep(0.7)
    beta.succeed("systemctl kill -s KILL narshare.service")
    client.wait_until_succeeds("test -f /tmp/sk-rc", timeout=120)
    assert client.succeed("cat /tmp/sk-rc").strip() == "0"
    assert client.succeed("sha256sum /tmp/sk.nar").split()[0] == sha_hex
    beta.succeed("systemctl start narshare.service")
    beta.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")
    post_gen = {o["name"]: o["generation"] for o in status(beta)["index"]["origins"]}["beta"]
    assert post_gen == pre_gen, "unclean death is not cache loss: the WAL must recover"
    print("[conv] SIGKILL'd holder recovered its index intact (same generation)")

    # --- (g) Total isolation: the client loses every link; the mesh moves on; rejoin heals
    for dev in ("eth1", "eth2", "eth3"):
        client.succeed(f"ip link set {dev} down")
    _, iso_hp = add_fixture(alpha, "iso-while-client-dark")
    time.sleep(3)  # let the hints for it fail against the dark client
    assert narinfo_code(client, iso_hp) == "404", "an isolated client cannot know new paths"
    for dev in ("eth1", "eth2", "eth3"):
        client.succeed(f"ip link set {dev} up")
    client.wait_until_succeeds("ping -c1 -W2 192.168.1.10")
    # The hints were lost while dark, so this bounds RECONVERGENCE BY TIMER (60s) + breaker
    # recovery on both sides.
    wait_narinfo(client, iso_hp, 200, timeout=120)
    wait_converged([alpha, beta, noisy, client], tag="post-isolation")
    print("[conv] fully isolated client rejoined and caught up on the sync timer")

    # --- (h) Cache restored from a backup: the self-clock regression must be detected -----
    # beta's /var/cache is snapshotted, TWO more paths are exported (mesh sees seq+2), then
    # the old cache is restored and one of the two is deleted from the store. However the
    # restart interleaves, beta's clock ends up numerically BEHIND what the mesh remembers
    # for its origin — the next pull must detect that future, remint beta's generation, and
    # snapshots must reteach everyone (the deleted path vanishes mesh-wide, the kept one
    # stays served).
    beta.succeed("systemctl stop narshare.service")
    # DynamicUser makes /var/cache/narshare a symlink into /var/cache/private — back up the
    # REAL directory, or the "restore" silently round-trips a symlink and tests nothing.
    beta.succeed(
        "rm -rf /tmp/cache-bk && cp -a \"$(readlink -f /var/cache/narshare)\" /tmp/cache-bk"
    )
    beta.succeed("systemctl start narshare.service")
    beta.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")
    p1_path, p1_hp = add_fixture(beta, "restore-p1")
    p2_path, p2_hp = add_fixture(beta, "restore-p2")
    wait_narinfo(client, p2_hp, 200)
    wait_narinfo(client, p1_hp, 200)
    gen_recorded = {o["name"]: o["generation"] for o in status(beta)["index"]["origins"]}["beta"]
    beta.succeed("systemctl stop narshare.service")
    beta.succeed(
        "D=\"$(readlink -f /var/cache/narshare)\" && rm -rf \"$D\" && cp -a /tmp/cache-bk \"$D\""
    )
    beta.succeed(f"nix-store --delete {p1_path}")
    beta.succeed("systemctl start narshare.service")
    beta.wait_until_succeeds("curl -sf http://127.0.0.1:5051/nix-cache-info >/dev/null")
    beta.wait_until_succeeds(
        "curl -sf http://127.0.0.1:5051/narshare/v1/status | "
        "jq -e '.sync.self_generation_bumps >= 1' >/dev/null",
        timeout=90,
    )
    gen_after = {o["name"]: o["generation"] for o in status(beta)["index"]["origins"]}["beta"]
    assert gen_after > gen_recorded, "the reminted generation must move forward"
    wait_narinfo(client, p2_hp, 200, timeout=120)   # survives under the new generation
    wait_narinfo(client, p1_hp, 404, timeout=120)   # wiped by the snapshot resync
    wait_converged([alpha, beta, noisy, client], tag="post-restore")
    print("[conv] restored cache detected its clock regression and reminted its generation")

    # --- (i) add/GC churn: rapid flip-flop converges to the final state -------------------
    for _ in range(4):
        ch_path, ch_hp = add_fixture(noisy, "churn")
        noisy.succeed(f"nix-store --delete {ch_path}")
    wait_narinfo(client, ch_hp, 404, timeout=90)
    wait_converged([alpha, beta, noisy, client], tag="post-churn")
    print("[conv] rapid add/GC churn converged to the final (deleted) state")

    # =====================================================================================
    # Bounded CPU / bounded IO on a holder, judged with scratch proxies pinned to alpha:
    # "xauto" (closed-loop encoding, fresh under throttle) vs "xpinned" (zstd:19 control).
    # =====================================================================================
    def scratch_proxy(name, port, peer_line=""):
        lines = [
            f'name = "{name}"',
            "[cache]",
            f'dir = "/tmp/{name}-cache"',
            "[proxy]",
            f'listen = "127.0.0.1:{port}"',
            'chunk_max = "1MiB"',
            "[[peers]]",
            'name = "alpha"',
            'url = "http://192.168.1.10:5050"',
        ]
        if peer_line:
            lines.append(peer_line)
        body = "\n".join(lines)
        client.succeed(f"cat > /tmp/{name}.toml <<'NSHEOF'\n{body}\nNSHEOF")
        client.succeed(
            f"narshare -c /tmp/{name}.toml >/tmp/{name}.log 2>&1 & echo $! > /tmp/{name}.pid"
        )
        client.wait_until_succeeds(f"curl -sf http://127.0.0.1:{port}/nix-cache-info >/dev/null")
        # Its startup pull already ran; wait for the fixture to be visible.
        client.wait_until_succeeds(
            f"[ \"$(curl -s -o /dev/null -w '%{{http_code}}' "
            f"http://127.0.0.1:{port}/{hp}.narinfo)\" = \"200\" ]",
            timeout=60,
        )

    def scratch_fetch(tag, port):
        out = client.succeed(
            "curl -sS --fail -o /tmp/out.nar "
            f"-w '%{{time_total}} %{{speed_download}}' http://127.0.0.1:{port}/nar/{nar32}.nar"
        )
        secs, speed = (float(x) for x in out.split())
        sha = client.succeed("sha256sum /tmp/out.nar").split()[0]
        assert sha == sha_hex, f"{tag}: NAR hash mismatch"
        results.append((tag, nar_size, secs, speed / 1e6))
        print(f"[bench] {tag}: {secs:.2f}s = {speed / 1e6:.2f} MB/s")
        return secs, speed

    scratch_proxy("xpinned", 5052, peer_line='encoding = "zstd:19"')
    scratch_fetch("alpha-only, unthrottled (baseline)", 5052)

    alpha.succeed("systemctl set-property --runtime narshare.service CPUQuota=20%")
    _, pinned_speed = scratch_fetch("alpha CPU-bound (20%), pinned zstd:19", 5052)
    scratch_proxy("xauto", 5053)
    _, auto_speed = scratch_fetch("alpha CPU-bound (20%), auto level", 5053)
    alpha.succeed("systemctl set-property --runtime narshare.service CPUQuota=")
    assert auto_speed > pinned_speed * 1.3, (
        f"the closed loop must shed the level on a CPU-bound holder: "
        f"auto {auto_speed:.0f} B/s vs pinned {pinned_speed:.0f} B/s"
    )

    alpha.succeed(
        "systemctl set-property --runtime narshare.service 'IOReadBandwidthMax=/dev/vda 4M'"
    )
    alpha.succeed("sync && echo 3 > /proc/sys/vm/drop_caches")
    io_secs, _ = scratch_fetch("alpha IO-bound (4 MB/s disk), auto", 5053)
    alpha.succeed("systemctl set-property --runtime narshare.service 'IOReadBandwidthMax='")
    assert io_secs > 3.0, f"disk throttle did not bite ({io_secs:.1f}s)"
    assert io_secs < 60, f"IO-bound transfer took {io_secs:.1f}s"
    client.succeed("kill $(cat /tmp/xpinned.pid /tmp/xauto.pid) 2>/dev/null || true")

    # =====================================================================================
    # Final invariants, via the status endpoint: nothing leaked, nothing insane.
    # =====================================================================================
    wait_no_active_transfers([alpha, beta, noisy, client])
    for m in (alpha, beta, noisy, client):
        st = status(m)
        for p in st["proxy"]["peers"]:
            w = p["mw_weight"]
            assert 0.0 < w <= 1.0, f"{m.name}: MW weight out of range: {p}"
        for o in st["index"]["origins"]:
            assert o["journal_len"] <= max(o["seq"], 1), f"{m.name}: journal exceeds history: {o}"
        assert st["proxy"]["transfers"]["aborted"]["other"] == 0, (
            f"{m.name}: plan-integrity aborts must never fire: {st['proxy']['transfers']}"
        )
        journals = ", ".join(
            o["name"] + ":" + str(o["journal_len"]) for o in st["index"]["origins"]
        )
        print(
            f"[status] {m.name}: narinfos={st['index']['narinfos']} "
            f"transfers={st['proxy']['transfers']} journals=[{journals}]"
        )

    # --- results ---
    print("")
    print("=== narshare mesh benchmarks (VM-relative; absolute 10GbE targets are M5.5) ===")
    for tag, size, secs, mbs in results:
        print(f"  {tag:48} {size / 1e6:8.1f} MB {secs:8.2f} s {mbs:9.2f} MB/s")
  '';
}
