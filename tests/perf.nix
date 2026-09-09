## The saturation bench: does a narshare transfer approach what the link itself can carry?
##
## The mesh suite validates correctness and *relative* scheduling quality; every number in it
## is a startup transient on a near-zero-latency fabric, which is exactly why a 45% utilization
## gap on a real WiFi + wireguard + cold-NVMe path (BG3, 2026-08-31) never showed up there.
## This bench recreates the regime that gap lives in:
##
##   * real RTT (netem delay, with jitter — request-response bubbles scale with latency),
##   * a rate-capped sub-gigabit link (the production path is WiFi under a gigabit),
##   * cold page cache on the holder (every production byte of a 130 GB NAR is a cold read),
##   * a GB-scale incompressible fixture (long enough for the stream governor to reach its
##     steady state, incompressible so encoding neither helps nor distorts).
##
## The measure is a RATIO against ground truth on the very same shaped path: a single-stream
## curl of the same NAR from the same serve endpoint. That baseline carries the same read,
## seek-table, and HTTP cost — everything except narshare's chunk scheduling — so the ratio
## isolates the transfer pipeline's own efficiency.
##
## Run:  nix build .#checks.<system>.perf -L
{ self }:
{ pkgs, lib, ... }:
let
  # ~1.25 GiB of incompressible bytes. Perf fixtures don't need determinism (nothing asserts
  # on the content hash across runs), so urandom's ~hundreds of MB/s beats a hash chain.
  fixtureGen = pkgs.writeShellApplication {
    name = "make-perf-fixture";
    runtimeInputs = [ pkgs.python3 ];
    text = ''
      out="$1"
      rm -rf "$out"
      mkdir -p "$out"
      python3 - "$out" <<'PYEOF'
      import os, sys
      with open(os.path.join(sys.argv[1], "bulk.bin"), "wb") as f:
          for _ in range(160):
              f.write(os.urandom(8 * 1024 * 1024))
      PYEOF
    '';
  };

  narsharePkg = self.packages.${pkgs.stdenv.hostPlatform.system}.narshare;

  common = {
    imports = [ self.nixosModules.narshare ];
    virtualisation.writableStore = true;
    # Reads must reach the block layer for drop_caches to mean anything.
    virtualisation.writableStoreUseTmpfs = false;
    virtualisation.cores = 4;
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 8192;
    networking.firewall.enable = false;
    boot.kernelModules = [ "sch_netem" ];
    environment.systemPackages = [ pkgs.curl pkgs.ethtool pkgs.iperf3 pkgs.jq fixtureGen narsharePkg ];
  };
in
{
  name = "narshare-perf";

  nodes = {
    alpha = {
      imports = [ common ];
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        { address = "192.168.1.10"; prefixLength = 24; }
      ];
      services.narshare = {
        enable = true;
        config = {
          name = "alpha";
          serve.listen = "0.0.0.0:5050";
          proxy.listen = "127.0.0.1:5051";
          # The scratch proxy on the client syncs from alpha; alpha must recognize it as an
          # origin or its pulls are 403'd. The URL is never dialed (client serves nothing).
          peers = [ { name = "xclient"; url = "http://127.0.0.1:1"; } ];
        };
      };
    };
    client = {
      imports = [ common ];
      virtualisation.vlans = [ 1 ];
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        { address = "192.168.1.2"; prefixLength = 24; }
      ];
    };
  };

  testScript = ''
    import json

    start_all()
    alpha.wait_for_unit("narshare.service")
    client.wait_for_unit("multi-user.target")

    # GSO/TSO would let virtio hand netem 64K superpackets and wreck the rate model.
    for m, dev in [(alpha, "eth1"), (client, "eth1")]:
        m.succeed(f"ethtool -K {dev} tso off gso off gro off || true")

    with subtest("register the bulk fixture"):
        alpha.succeed("make-perf-fixture /tmp/bulk")
        path = alpha.succeed("nix-store --add /tmp/bulk").strip()
        alpha.succeed("rm -rf /tmp/bulk")
        nar32 = alpha.succeed(f"nix-store -q --hash {path}").strip().split(":", 1)[1]
        nar_size = int(alpha.succeed(f"nix-store -q --size {path}").strip())
        print(f"[perf] fixture {path}: {nar_size / 1e6:.0f} MB NAR")

    hp = path.removeprefix("/nix/store/")[:32]

    def scratch_proxy(port, extra=""):
        client.succeed(
            f"cat > /tmp/x{port}.toml <<'EOF'\n"
            'name = "xclient"\n'
            # Own index dir per proxy: the rocksdb store is process-exclusive (unlike the
            # old sqlite layout, which silently tolerated two proxies sharing one index).
            "[cache]\n"
            f'dir = "/tmp/x{port}-cache"\n'
            "[proxy]\n"
            f'listen = "127.0.0.1:{port}"\n'
            f"{extra}\n"
            "[[peers]]\n"
            'name = "alpha"\n'
            'url = "http://192.168.1.10:5050"\n'
            "EOF"
        )
        client.succeed(f"narshare -c /tmp/x{port}.toml >/tmp/x{port}.log 2>&1 &")
        client.wait_until_succeeds(
            "[ \"$(curl -s -o /dev/null -w '%{http_code}' "
            f"http://127.0.0.1:{port}/{hp}.narinfo)\" = \"200\" ]",
            timeout=60,
        )

    with subtest("client proxy sees the fixture"):
        scratch_proxy(5051)

    def cold():
        alpha.succeed("sync && echo 3 > /proc/sys/vm/drop_caches")

    def fetch(tag, url):
        cold()
        out = client.succeed(
            f"curl -sS --fail -o /dev/null -w '%{{time_total}} %{{speed_download}}' {url}"
        )
        secs, speed = (float(x) for x in out.split())
        print(f"[perf] {tag}: {secs:.1f}s = {speed / 1e6:.1f} MB/s")
        return speed

    raw_url = f"http://192.168.1.10:5050/nar/{nar32}.nar"
    proxy_url = f"http://127.0.0.1:5051/nar/{nar32}.nar"

    with subtest("unshaped sanity"):
        fetch("raw single-stream, unshaped", raw_url)

    with subtest("shaped: 900 mbit, 6 ms RTT"):
        # 3 ms +-1 ms each way approximates the production WiFi hop; the rate cap sits just
        # under a gigabit like the real medium. limit sized far above the BDP (~450 pkts).
        # Deterministic delay: netem jitter reorders packets, which collapses TCP throughput
        # by a random amount per boot and makes the BASELINE unstable across runs.
        alpha.succeed("tc qdisc replace dev eth1 root netem delay 3ms rate 900mbit limit 20000")
        client.succeed("tc qdisc replace dev eth1 root netem delay 3ms rate 900mbit limit 20000")
        print("[perf] shaped ping: " + client.succeed("ping -c3 -q 192.168.1.10 | tail -1").strip())

        raw = fetch("raw single-stream, shaped", raw_url)

        def proxied(tag, port):
            cold_speed = fetch(f"proxied [{tag}], cold governor", f"http://127.0.0.1:{port}/nar/{nar32}.nar")
            warm_speed = fetch(f"proxied [{tag}], warm governor", f"http://127.0.0.1:{port}/nar/{nar32}.nar")
            st = json.loads(client.succeed(f"curl -s http://127.0.0.1:{port}/narshare/v1/status"))
            peer = st["proxy"]["peers"][0]
            print(
                f"[perf] [{tag}] governor: limit={peer['streams']['limit']}, "
                f"chunks_ok={peer['chunks_ok']}, chunks_err={peer['chunks_err']}, "
                f"rate_est={peer['rate_bps'] / 1e6:.1f} MB/s; "
                f"utilization: cold {cold_speed / raw:.2f}x, warm {warm_speed / raw:.2f}x"
            )
            return warm_speed

        # A/B the two pipeline knobs against the default before touching the algorithm:
        # bigger chunks amortize per-chunk dead time; more streams hide it with parallelism.
        default_warm = proxied("default", 5051)
        scratch_proxy(5052, 'chunk_max = "16MiB"')
        proxied("chunk_max=16MiB (old default)", 5052)
        scratch_proxy(5053, "per_peer_connections = 16")
        proxied("streams<=16", 5053)

        # A multi-stream transfer that cannot beat ONE raw stream over the same path has
        # re-serialized somewhere (streaming encode landed at 1.33x; the buffered-encode
        # predecessor sat at 0.64x). Same-run ratio, so host load cancels out.
        assert default_warm > raw, (
            f"proxied transfer at {default_warm / 1e6:.1f} MB/s does not beat the "
            f"single-stream baseline {raw / 1e6:.1f} MB/s on the same shaped path"
        )

    with subtest("proxied bytes are exact"):
        cold()
        client.succeed(f"curl -sS --fail -o /tmp/out.nar {proxy_url}")
        got = client.succeed("stat -c %s /tmp/out.nar").strip()
        assert int(got) == nar_size, f"NAR size mismatch: {got} vs {nar_size}"
        client.succeed("rm /tmp/out.nar")
  '';
}
