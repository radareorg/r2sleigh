use std::path::Path;

fn main() {
    // The one copy of Ghidra's sources is libsla-sys's: the compiler links its libsla, so it
    // must see the same class layouts.
    let source_path = Path::new("../libsla-sys/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp");
    cxx_build::bridge("src/ffi/sys.rs")
        .define("LOCAL_ZLIB", "1")
        .define("NO_GZIP", "1")
        .flag_if_supported("-std=c++14")
        .file("src/ffi/cpp/bridge.cc")
        .file("src/ffi/cpp/slgh_compile.cc")
        .include(source_path) // Header files coexist with cpp files
        .warnings(false) // Not interested in the warnings for Ghidra code
        .compile("slacomp");

    println!("cargo:rustc-link-lib=sla");

    println!("cargo:rerun-if-changed=src/ffi/sys.rs");

    println!("cargo:rerun-if-changed=src/ffi/cpp");

    println!("cargo:rerun-if-changed={}", source_path.display());
}
