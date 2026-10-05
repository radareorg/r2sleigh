use std::path::Path;

fn main() {
    let source_path = Path::new("ghidra/Ghidra/Features/Decompiler/src/decompile/cpp");

    // The following sources were pulled from the Makefile
    const LIBSLA_SOURCE_FILES: &[&str] = &[
        // CORE=	xml marshal space float address pcoderaw translate opcodes globalcontext
        "xml.cc",
        "marshal.cc",
        "space.cc",
        "float.cc",
        "address.cc",
        "pcoderaw.cc",
        "translate.cc",
        "opcodes.cc",
        "globalcontext.cc",
        // SLEIGH=	sleigh pcodeparse pcodecompile sleighbase slghsymbol \
        // slghpatexpress slghpattern semantics context slaformat compression filemanage
        "sleigh.cc",
        "pcodeparse.cc",
        "pcodecompile.cc",
        "sleighbase.cc",
        "slghsymbol.cc",
        "slghpatexpress.cc",
        "slghpattern.cc",
        "semantics.cc",
        "context.cc",
        "slaformat.cc",
        "compression.cc",
        "filemanage.cc",
        // LIBSLA_NAMES
        "loadimage.cc",
        "memstate.cc",
        "emulate.cc",
        "opbehavior.cc",
        // SLACOMP=slgh_compile slghparse slghscan
        // Omitting slgh_compile since it defines main function
        "slghparse.cc",
        "slghscan.cc",
    ];

    let zlib_path = Path::new("ghidra/Ghidra/Features/Decompiler/src/decompile/zlib");
    const ZLIB_SOURCE_FILES: &[&str] = &[
        "adler32.c",
        "deflate.c",
        "inffast.c",
        "inflate.c",
        "inftrees.c",
        "trees.c",
        "zutil.c",
    ];

    let mut build = cxx_build::bridge("src/sys.rs");

    if std::env::var("CARGO_FEATURE_CLANG").is_ok() {
        build.compiler(std::env::var("RUSTC_LINKER").expect("clang should be the rustc linker"));
    }

    build
        .define("LOCAL_ZLIB", "1")
        .define("NO_GZIP", "1")
        .flag_if_supported("-std=c++11");

    if std::env::var("CARGO_FEATURE_SANCOV").is_ok() {
        build.flag("-fsanitize-coverage=inline-8bit-counters");
    }

    if std::env::var("CARGO_FEATURE_ASAN").is_ok() {
        build.flag("-fsanitize=address");
    }

    if std::env::var("CARGO_FEATURE_UBSAN").is_ok() {
        build.flag("-fsanitize=undefined");
    }

    if std::env::var("CARGO_FEATURE_FUZZING").is_ok() {
        build.flag("-fno-omit-frame-pointer");
    }

    build
        .files(LIBSLA_SOURCE_FILES.iter().map(|s| source_path.join(s)))
        .files(ZLIB_SOURCE_FILES.iter().map(|s| zlib_path.join(s)))
        .file("src/cpp/bridge.cc")
        .include(source_path) // Header files coexist with cpp files
        .warnings(false) // Not interested in the warnings for Ghidra code
        .compile("sla");

    // Rerun if any of the C++ to Rust bindings have changed
    println!("cargo:rerun-if-changed=src/sys.rs");

    // Rerun if any of the C++ bridge code has changed
    println!("cargo:rerun-if-changed=src/cpp");

    // Rerun if any Ghidra code has changed (for testing)
    println!("cargo:rerun-if-changed=ghidra/Ghidra/Features/Decompiler/src/decompile/cpp");
}
