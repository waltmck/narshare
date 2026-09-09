{
  description = "narshare — self-contained mesh Nix substituter: serve + dedup + striped NAR fetch";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = eachSystem (pkgs: rec {
        narshare = pkgs.rustPlatform.buildRustPackage {
          pname = "narshare";
          version = "0.1.0";
          # Only the crate inputs: doc edits must not rebuild the package.
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ./proto ./build.rs ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          # prost-build compiles proto/mesh.proto at build time; bindgenHook serves
          # librocksdb-sys' bindgen. ROCKSDB_LIB_DIR links the cached nixpkgs rocksdb
          # instead of compiling the crate's bundled C++ (same major version, and the C API
          # is append-only across minors); drop the env var to fall back to the bundled build.
          nativeBuildInputs = [ pkgs.protobuf pkgs.rustPlatform.bindgenHook ];
          buildInputs = [ pkgs.rocksdb ];
          env.ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib";
          env.ROCKSDB_INCLUDE_DIR = "${pkgs.rocksdb}/include";
          # Differential tests exec `nix`/compare against the real store; they skip themselves
          # when `nix` is absent, so the sandboxed check phase runs the pure tests only.
          meta = {
            description = "Self-contained mesh Nix substituter";
            mainProgram = "narshare";
          };
        };
        default = narshare;
      });

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer protobuf
            # postgres index-backend tests boot a throwaway cluster when initdb is available
            postgresql ];
          # librocksdb-sys runs bindgen at build time; the LIB/INCLUDE dirs make it link
          # the cached nixpkgs rocksdb instead of compiling its bundled C++.
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          ROCKSDB_LIB_DIR = "${pkgs.rocksdb}/lib";
          ROCKSDB_INCLUDE_DIR = "${pkgs.rocksdb}/include";
        };
      });

      nixosModules = rec {
        narshare = import ./module.nix self;
        default = narshare;
      };

      checks = eachSystem (pkgs: {
        # Unit + differential tests run in the package's checkPhase; this is the mesh VM
        # suite: four nodes over shaped links (fast / 20 Mbit / lossy), substituting from
        # each other through the proxy with no trusted keys. Needs KVM.
        mesh = pkgs.testers.runNixOSTest (import ./tests/mesh.nix { inherit self; });
        # The saturation bench: GB-scale transfer over a shaped (sub-gigabit, real-RTT,
        # cold-cache) link, measured as a ratio against a single-stream fetch of the same
        # NAR over the same path. Kept separate from `mesh` so perf iteration is fast.
        perf = pkgs.testers.runNixOSTest (import ./tests/perf.nix { inherit self; });
      });
    };
}
