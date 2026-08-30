fn main() {
    println!("cargo:rerun-if-changed=proto/mesh.proto");
    prost_build::compile_protos(&["proto/mesh.proto"], &["proto/"])
        .expect("compiling proto/mesh.proto (is protoc on PATH? `nix develop` provides it)");
}
