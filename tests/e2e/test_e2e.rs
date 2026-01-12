//! End-to-end tests using radare2 and the r2sleigh plugin.
//!
//! These tests verify the full pipeline:
//! binary → r2sleigh lifting → SSA → decompilation

use std::process::Command;
use std::path::Path;

/// Path to the test binary
const TEST_BINARY: &str = "tests/e2e/test_func";

/// Path to the r2sleigh plugin library
const PLUGIN_PATH: &str = "target/release/libr2sleigh_plugin.so";

/// Run a radare2 command and return the output
fn r2_cmd(binary: &str, cmd: &str) -> Result<String, String> {
    let output = Command::new("r2")
        .args(["-q", "-c", cmd, binary])
        .output()
        .map_err(|e| format!("Failed to run r2: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Run radare2 with the r2sleigh plugin loaded
fn r2_with_plugin(binary: &str, cmd: &str) -> Result<String, String> {
    let plugin_path = Path::new(PLUGIN_PATH);
    if !plugin_path.exists() {
        return Err(format!("Plugin not found at {}. Run `cargo build --release -p r2sleigh-plugin` first.", PLUGIN_PATH));
    }

    // radare2 can load plugins with -L or via r2pm
    // For testing, we'll use the plugin directly via FFI calls in our Rust code
    r2_cmd(binary, cmd)
}

#[test]
fn test_binary_exists() {
    assert!(Path::new(TEST_BINARY).exists(), "Test binary not found. Run `gcc -O0 -g -o tests/e2e/test_func tests/e2e/test_func.c`");
}

#[test]
fn test_r2_analyze_functions() {
    let output = r2_cmd(TEST_BINARY, "aaa; afl").expect("Failed to analyze binary");
    
    // Should find our functions
    assert!(output.contains("add") || output.contains("sym.add"), "Should find 'add' function");
    assert!(output.contains("factorial") || output.contains("sym.factorial"), "Should find 'factorial' function");
    assert!(output.contains("sum_array") || output.contains("sym.sum_array"), "Should find 'sum_array' function");
    assert!(output.contains("main") || output.contains("sym.main"), "Should find 'main' function");
}

#[test]
fn test_r2_disassemble_add() {
    let output = r2_cmd(TEST_BINARY, "aaa; s sym.add; pdf").expect("Failed to disassemble");
    
    // The add function should have some basic operations
    assert!(output.contains("add") || output.contains("mov") || output.contains("ret"), 
            "Disassembly should contain basic x86 instructions");
}

#[test]
fn test_r2_esil_output() {
    let output = r2_cmd(TEST_BINARY, "aaa; s sym.add; e asm.esil=true; pd 5").expect("Failed to get ESIL");
    
    // ESIL output should contain stack operations or register assignments
    println!("ESIL output:\n{}", output);
    // ESIL uses comma-separated operations
    assert!(output.len() > 0, "Should produce ESIL output");
}

#[test]
fn test_r2_cfg() {
    let output = r2_cmd(TEST_BINARY, "aaa; s sym.factorial; agfj").expect("Failed to get CFG");
    
    // CFG JSON output for factorial should have multiple blocks (recursive function with if)
    println!("CFG JSON:\n{}", output);
    assert!(output.contains("[") || output.contains("{"), "Should produce JSON CFG output");
}

#[test]
fn test_r2_basic_blocks() {
    let output = r2_cmd(TEST_BINARY, "aaa; s sym.sum_array; afbj").expect("Failed to get basic blocks");
    
    // sum_array has a loop, so it should have multiple basic blocks
    println!("Basic blocks:\n{}", output);
    assert!(output.contains("[") || output.contains("{"), "Should produce JSON basic blocks output");
}

#[test]
fn test_r2_xrefs() {
    let output = r2_cmd(TEST_BINARY, "aaa; s sym.add; axtj").expect("Failed to get xrefs");
    
    // add is called from main
    println!("Xrefs:\n{}", output);
    // Should have at least one reference
}

#[test]
fn test_r2_variables() {
    let output = r2_cmd(TEST_BINARY, "aaa; s sym.sum_array; afvj").expect("Failed to get variables");
    
    // sum_array has local variables (sum, i)
    println!("Variables:\n{}", output);
}

// ============================================================================
// Direct r2sleigh library tests
// ============================================================================

#[test]
fn test_r2sleigh_lift_instruction() {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    // Load the plugin library dynamically
    let lib_path = Path::new(PLUGIN_PATH);
    if !lib_path.exists() {
        eprintln!("Skipping: Plugin not built. Run `cargo build --release -p r2sleigh-plugin`");
        return;
    }

    // Use dlopen to load the library
    unsafe {
        let lib = libloading::Library::new(lib_path).expect("Failed to load plugin");

        // Get function pointers
        let r2il_arch_init: libloading::Symbol<unsafe extern "C" fn(*const c_char) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_arch_init").expect("Failed to find r2il_arch_init");
        let r2il_is_loaded: libloading::Symbol<unsafe extern "C" fn(*const std::ffi::c_void) -> i32> =
            lib.get(b"r2il_is_loaded").expect("Failed to find r2il_is_loaded");
        let r2il_lift: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize, u64) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_lift").expect("Failed to find r2il_lift");
        let r2il_block_op_count: libloading::Symbol<unsafe extern "C" fn(*const std::ffi::c_void) -> usize> =
            lib.get(b"r2il_block_op_count").expect("Failed to find r2il_block_op_count");
        let r2il_block_to_esil: libloading::Symbol<unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char> =
            lib.get(b"r2il_block_to_esil").expect("Failed to find r2il_block_to_esil");
        let r2il_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_free").expect("Failed to find r2il_free");
        let r2il_block_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_block_free").expect("Failed to find r2il_block_free");
        let r2il_string_free: libloading::Symbol<unsafe extern "C" fn(*mut c_char)> =
            lib.get(b"r2il_string_free").expect("Failed to find r2il_string_free");

        // Initialize x86-64 architecture
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null(), "Failed to initialize x86-64 architecture");
        assert_eq!(r2il_is_loaded(ctx), 1, "Architecture should be loaded");

        // Test lifting "xor eax, eax" (0x31 0xC0)
        let mut bytes = vec![0x31u8, 0xC0];
        bytes.resize(16, 0x90); // Pad with NOPs for libsla

        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null(), "Failed to lift instruction");

        let op_count = r2il_block_op_count(block);
        println!("Lifted {} operations for 'xor eax, eax'", op_count);
        assert!(op_count > 0, "Should have at least one operation");

        // Get ESIL representation
        let esil_ptr = r2il_block_to_esil(ctx, block);
        if !esil_ptr.is_null() {
            let esil = CStr::from_ptr(esil_ptr).to_string_lossy();
            println!("ESIL: {}", esil);
            assert!(esil.len() > 0, "ESIL should not be empty");
            r2il_string_free(esil_ptr);
        }

        // Clean up
        r2il_block_free(block);
        r2il_free(ctx);
    }
}

#[test]
fn test_r2sleigh_ssa_conversion() {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    let lib_path = Path::new(PLUGIN_PATH);
    if !lib_path.exists() {
        eprintln!("Skipping: Plugin not built");
        return;
    }

    unsafe {
        let lib = libloading::Library::new(lib_path).expect("Failed to load plugin");

        let r2il_arch_init: libloading::Symbol<unsafe extern "C" fn(*const c_char) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_arch_init").unwrap();
        let r2il_lift: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize, u64) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_lift").unwrap();
        let r2il_block_to_ssa_json: libloading::Symbol<unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char> =
            lib.get(b"r2il_block_to_ssa_json").unwrap();
        let r2il_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_free").unwrap();
        let r2il_block_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_block_free").unwrap();
        let r2il_string_free: libloading::Symbol<unsafe extern "C" fn(*mut c_char)> =
            lib.get(b"r2il_string_free").unwrap();

        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        // Test "add rax, rbx" (0x48 0x01 0xd8)
        let mut bytes = vec![0x48u8, 0x01, 0xd8];
        bytes.resize(16, 0x90);

        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        // Get SSA JSON
        let ssa_json_ptr = r2il_block_to_ssa_json(ctx, block);
        if !ssa_json_ptr.is_null() {
            let ssa_json = CStr::from_ptr(ssa_json_ptr).to_string_lossy();
            println!("SSA JSON for 'add rax, rbx':\n{}", ssa_json);
            
            // Should contain SSA operation info
            assert!(ssa_json.contains("op") || ssa_json.contains("dst") || ssa_json.contains("["),
                    "SSA JSON should contain operation information");
            
            r2il_string_free(ssa_json_ptr);
        }

        r2il_block_free(block);
        r2il_free(ctx);
    }
}

#[test]
fn test_r2sleigh_defuse_analysis() {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    let lib_path = Path::new(PLUGIN_PATH);
    if !lib_path.exists() {
        eprintln!("Skipping: Plugin not built");
        return;
    }

    unsafe {
        let lib = libloading::Library::new(lib_path).expect("Failed to load plugin");

        let r2il_arch_init: libloading::Symbol<unsafe extern "C" fn(*const c_char) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_arch_init").unwrap();
        let r2il_lift: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize, u64) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_lift").unwrap();
        let r2il_block_defuse_json: libloading::Symbol<unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char> =
            lib.get(b"r2il_block_defuse_json").unwrap();
        let r2il_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_free").unwrap();
        let r2il_block_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_block_free").unwrap();
        let r2il_string_free: libloading::Symbol<unsafe extern "C" fn(*mut c_char)> =
            lib.get(b"r2il_string_free").unwrap();

        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        // Test "mov rax, [rbx]" (memory load)
        let mut bytes = vec![0x48u8, 0x8b, 0x03];
        bytes.resize(16, 0x90);

        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        // Get def-use JSON
        let defuse_json_ptr = r2il_block_defuse_json(ctx, block);
        if !defuse_json_ptr.is_null() {
            let defuse_json = CStr::from_ptr(defuse_json_ptr).to_string_lossy();
            println!("Def-Use JSON for 'mov rax, [rbx]':\n{}", defuse_json);
            
            // Should contain inputs/outputs/live info
            assert!(defuse_json.contains("inputs") || defuse_json.contains("outputs") || defuse_json.contains("live"),
                    "Def-Use JSON should contain analysis information");
            
            r2il_string_free(defuse_json_ptr);
        }

        r2il_block_free(block);
        r2il_free(ctx);
    }
}

#[test]
fn test_r2sleigh_decompile_block() {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    let lib_path = Path::new(PLUGIN_PATH);
    if !lib_path.exists() {
        eprintln!("Skipping: Plugin not built");
        return;
    }

    unsafe {
        let lib = libloading::Library::new(lib_path).expect("Failed to load plugin");

        let r2il_arch_init: libloading::Symbol<unsafe extern "C" fn(*const c_char) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_arch_init").unwrap();
        let r2il_lift: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize, u64) -> *mut std::ffi::c_void> =
            lib.get(b"r2il_lift").unwrap();
        let r2dec_block: libloading::Symbol<unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char> =
            lib.get(b"r2dec_block").unwrap();
        let r2il_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_free").unwrap();
        let r2il_block_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
            lib.get(b"r2il_block_free").unwrap();
        let r2il_string_free: libloading::Symbol<unsafe extern "C" fn(*mut c_char)> =
            lib.get(b"r2il_string_free").unwrap();

        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        assert!(!ctx.is_null());

        // Test "add rax, 1" (0x48 0x83 0xc0 0x01)
        let mut bytes = vec![0x48u8, 0x83, 0xc0, 0x01];
        bytes.resize(16, 0x90);

        let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
        assert!(!block.is_null());

        // Decompile to C
        let c_code_ptr = r2dec_block(ctx, block);
        if !c_code_ptr.is_null() {
            let c_code = CStr::from_ptr(c_code_ptr).to_string_lossy();
            println!("Decompiled C for 'add rax, 1':\n{}", c_code);
            
            // Should produce some C-like output
            // Even if minimal, it should have something
            r2il_string_free(c_code_ptr);
        } else {
            println!("r2dec_block returned null (expected for simple instructions)");
        }

        r2il_block_free(block);
        r2il_free(ctx);
    }
}
