//! End-to-end tests for r2sleigh plugin
//!
//! This test binary loads the r2sleigh plugin and tests the full pipeline:
//! - Instruction lifting (r2il)
//! - SSA conversion
//! - Def-use analysis
//! - Decompilation

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

const PLUGIN_PATH: &str = "../../target/release/libr2sleigh_plugin.so";

fn main() {
    println!("=== r2sleigh End-to-End Plugin Tests ===\n");

    let lib_path = Path::new(PLUGIN_PATH);
    if !lib_path.exists() {
        eprintln!("ERROR: Plugin not found at {}", PLUGIN_PATH);
        eprintln!("Run: cargo build --release -p r2sleigh-plugin");
        std::process::exit(1);
    }

    unsafe {
        let lib = match libloading::Library::new(lib_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("ERROR: Failed to load plugin: {}", e);
                std::process::exit(1);
            }
        };

        // Get function pointers
        type ArchInitFn = unsafe extern "C" fn(*const c_char) -> *mut std::ffi::c_void;
        type IsLoadedFn = unsafe extern "C" fn(*const std::ffi::c_void) -> i32;
        type LiftFn = unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize, u64) -> *mut std::ffi::c_void;
        type OpCountFn = unsafe extern "C" fn(*const std::ffi::c_void) -> usize;
        type ToEsilFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char;
        type ToSsaJsonFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char;
        type DefuseJsonFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char;
        type DecBlockFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char;
        type FreeFn = unsafe extern "C" fn(*mut std::ffi::c_void);
        type StringFreeFn = unsafe extern "C" fn(*mut c_char);
        type BlockTypeFn = unsafe extern "C" fn(*const std::ffi::c_void) -> u32;
        type RegsReadFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char;
        type RegsWriteFn = unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char;

        let r2il_arch_init: libloading::Symbol<ArchInitFn> = lib.get(b"r2il_arch_init").unwrap();
        let r2il_is_loaded: libloading::Symbol<IsLoadedFn> = lib.get(b"r2il_is_loaded").unwrap();
        let r2il_lift: libloading::Symbol<LiftFn> = lib.get(b"r2il_lift").unwrap();
        let r2il_block_op_count: libloading::Symbol<OpCountFn> = lib.get(b"r2il_block_op_count").unwrap();
        let r2il_block_to_esil: libloading::Symbol<ToEsilFn> = lib.get(b"r2il_block_to_esil").unwrap();
        let r2il_block_to_ssa_json: libloading::Symbol<ToSsaJsonFn> = lib.get(b"r2il_block_to_ssa_json").unwrap();
        let r2il_block_defuse_json: libloading::Symbol<DefuseJsonFn> = lib.get(b"r2il_block_defuse_json").unwrap();
        let r2dec_block: libloading::Symbol<DecBlockFn> = lib.get(b"r2dec_block").unwrap();
        let r2il_free: libloading::Symbol<FreeFn> = lib.get(b"r2il_free").unwrap();
        let r2il_block_free: libloading::Symbol<FreeFn> = lib.get(b"r2il_block_free").unwrap();
        let r2il_string_free: libloading::Symbol<StringFreeFn> = lib.get(b"r2il_string_free").unwrap();
        let r2il_block_type: libloading::Symbol<BlockTypeFn> = lib.get(b"r2il_block_type").unwrap();
        let r2il_block_regs_read: libloading::Symbol<RegsReadFn> = lib.get(b"r2il_block_regs_read").unwrap();
        let r2il_block_regs_write: libloading::Symbol<RegsWriteFn> = lib.get(b"r2il_block_regs_write").unwrap();

        // Initialize x86-64 architecture
        println!("--- Test 1: Initialize x86-64 architecture ---");
        let arch = CString::new("x86-64").unwrap();
        let ctx = r2il_arch_init(arch.as_ptr());
        if ctx.is_null() {
            eprintln!("FAIL: Could not initialize x86-64 architecture");
            std::process::exit(1);
        }
        assert_eq!(r2il_is_loaded(ctx), 1);
        println!("PASS: x86-64 architecture initialized\n");

        // Test instructions
        let test_cases = [
            ("xor eax, eax", vec![0x31u8, 0xC0]),
            ("add rax, rbx", vec![0x48, 0x01, 0xD8]),
            ("mov rax, [rbx]", vec![0x48, 0x8B, 0x03]),
            ("mov [rax], rbx", vec![0x48, 0x89, 0x18]),
            ("add rax, 1", vec![0x48, 0x83, 0xC0, 0x01]),
            ("sub rax, rbx", vec![0x48, 0x29, 0xD8]),
            ("push rax", vec![0x50]),
            ("pop rbx", vec![0x5B]),
            ("ret", vec![0xC3]),
            ("call [rip+0]", vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]),
            ("jmp 0x10", vec![0xEB, 0x0E]),
            ("je 0x10", vec![0x74, 0x0E]),
            ("cmp rax, rbx", vec![0x48, 0x39, 0xD8]),
            ("test eax, eax", vec![0x85, 0xC0]),
            ("nop", vec![0x90]),
        ];

        for (name, bytes) in &test_cases {
            println!("--- Test: {} ---", name);
            
            let mut padded = bytes.clone();
            padded.resize(16, 0x90); // Pad with NOPs

            let block = r2il_lift(ctx, padded.as_ptr(), padded.len(), 0x1000);
            if block.is_null() {
                println!("  SKIP: Could not lift instruction\n");
                continue;
            }

            // Operation count
            let op_count = r2il_block_op_count(block);
            println!("  Operations: {}", op_count);

            // Block type
            let block_type = r2il_block_type(block);
            let type_name = match block_type {
                0 => "NULL",
                1 => "JMP",
                2 => "UJMP",
                3 => "CALL",
                4 => "UCALL",
                5 => "RET",
                8 => "NOP",
                9 => "MOV",
                15 => "CMP",
                17 => "ADD",
                18 => "SUB",
                27 => "AND",
                28 => "XOR",
                31 => "STORE",
                32 => "LOAD",
                _ if block_type & 0x80000000 != 0 => "CJMP",
                _ => "OTHER",
            };
            println!("  Type: {} ({})", type_name, block_type);

            // ESIL
            let esil_ptr = r2il_block_to_esil(ctx, block);
            if !esil_ptr.is_null() {
                let esil = CStr::from_ptr(esil_ptr).to_string_lossy();
                println!("  ESIL: {}", esil);
                r2il_string_free(esil_ptr);
            }

            // Registers read/written
            let regs_read_ptr = r2il_block_regs_read(ctx, block);
            if !regs_read_ptr.is_null() {
                let regs_read = CStr::from_ptr(regs_read_ptr).to_string_lossy();
                println!("  Regs Read: {}", regs_read);
                r2il_string_free(regs_read_ptr);
            }

            let regs_write_ptr = r2il_block_regs_write(ctx, block);
            if !regs_write_ptr.is_null() {
                let regs_write = CStr::from_ptr(regs_write_ptr).to_string_lossy();
                println!("  Regs Write: {}", regs_write);
                r2il_string_free(regs_write_ptr);
            }

            // SSA JSON
            let ssa_ptr = r2il_block_to_ssa_json(ctx, block);
            if !ssa_ptr.is_null() {
                let ssa = CStr::from_ptr(ssa_ptr).to_string_lossy();
                // Just show first 200 chars
                let preview: String = ssa.chars().take(200).collect();
                println!("  SSA: {}...", preview.replace('\n', " "));
                r2il_string_free(ssa_ptr);
            }

            // Def-use analysis
            let defuse_ptr = r2il_block_defuse_json(ctx, block);
            if !defuse_ptr.is_null() {
                let defuse = CStr::from_ptr(defuse_ptr).to_string_lossy();
                println!("  Def-Use: {}", defuse.replace('\n', " "));
                r2il_string_free(defuse_ptr);
            }

            // Decompiled C
            let c_ptr = r2dec_block(ctx, block);
            if !c_ptr.is_null() {
                let c_code = CStr::from_ptr(c_ptr).to_string_lossy();
                if !c_code.is_empty() {
                    println!("  C: {}", c_code.replace('\n', " "));
                }
                r2il_string_free(c_ptr);
            }

            r2il_block_free(block);
            println!();
        }

        // Clean up
        r2il_free(ctx);

        println!("=== All tests completed successfully ===");
    }
}
