# NixOS module, modeled on nixpkgs' wgautomesh module: enable/package/logLevel plus a freeform
# TOML `config` rendered verbatim. The daemon reads /nix/store and the Nix db (both read-only)
# and writes only the disposable mesh index under /var/cache/narshare, so the unit gets strict
# hardening with a single CacheDirectory.
self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.narshare;
  settingsFormat = pkgs.formats.toml { };
  filterNulls = lib.filterAttrs (_: v: v != null);
  # TOML cannot encode null: drop null keys at the top level, inside sections, and per-peer.
  cleaned = filterNulls (lib.mapAttrs (
    k: v:
    if k == "peers" then map filterNulls v
    else if builtins.isAttrs v then filterNulls v
    else v
  ) cfg.config);
  configFile = settingsFormat.generate "narshare.toml" cleaned;
in
{
  options.services.narshare = {
    enable = lib.mkEnableOption "narshare, the mesh Nix substituter";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.narshare;
      defaultText = lib.literalExpression "narshare.packages.\${system}.narshare";
      description = "The narshare package to run.";
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [ "trace" "debug" "info" "warn" "error" ];
      default = "info";
      description = "narshare log level.";
    };

    config = lib.mkOption {
      type = lib.types.submodule { freeformType = settingsFormat.type; };
      default = { };
      description = ''
        narshare configuration, rendered to its TOML config verbatim.
        See PLAN.md / test.toml in the narshare repository for the schema
        ([serve], [proxy], [io], [[peers]]).
      '';
    };

    addToSubstituters = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Add the proxy listener to nix.settings.substituters and enable fallback.
        Deliberately adds NO trusted keys, ever: content-addressed (FOD/CA) paths
        verify by hash, and signed input-addressed paths relay only when their
        upstream signature already verifies against keys this machine trusts anyway
        (trusted-public-keys in /etc/nix/nix.conf).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.narshare = {
      description = "narshare mesh Nix substituter";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment.RUST_LOG = "narshare=${cfg.logLevel}";
      serviceConfig = {
        ExecStartPre = "${lib.getExe cfg.package} check -c ${configFile}";
        ExecStart = "${lib.getExe cfg.package} serve -c ${configFile}";
        Restart = "on-failure";
        RestartSec = 2;

        # The one writable path: the mesh index at /var/cache/narshare — state the daemon can
        # always afford to lose (self-verifying, re-learnable; loss bumps the node's sync
        # generation so peers snapshot it back up).
        CacheDirectory = "narshare";
        # A ~40MB disposable-state daemon has no business in swap: parked cold pages get
        # churned back through zswap on every allocation cycle (measured: 99% of the daemon's
        # CPU as kernel time). Keep it resident; under real pressure the kernel/oomd may kill
        # it instead, which costs one journal-tail resync.
        MemorySwapMax = 0;
        DynamicUser = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
      };
    };

    nix.settings = lib.mkIf (cfg.addToSubstituters && cfg.config ? proxy) {
      substituters = [ "http://${cfg.config.proxy.listen}" ];
      fallback = true;
      # Nix caches narinfo 404s for an hour by default. Mesh holdings change
      # minute-to-minute (a peer wakes, resyncs, or indexes a fresh build), so a
      # cached miss turns "retry now that the peer is up" into a silent hour-long
      # outage for that path. Re-querying the local proxy is nearly free.
      narinfo-cache-negative-ttl = lib.mkDefault 30;
    };
  };
}
