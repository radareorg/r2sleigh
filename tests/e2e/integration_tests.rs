//! Integration tests for r2sleigh plugin.
//!
//! These tests invoke radare2 with the r2sleigh plugin and validate output.
//! Run with: `cargo test -p r2sleigh-e2e-tests`

use e2e::{r2_at_addr, r2_at_func, require_binary, vuln_test_binary};
use rstest::rstest;

// ============================================================================
// Test fixtures
// ============================================================================

fn setup() {
    require_binary(vuln_test_binary());
}

// ============================================================================
// 1. Basic Plugin Status
// ============================================================================

mod plugin_status {
    use super::*;

    #[test]
    fn plugin_loads_and_shows_arch() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla");
        result.assert_ok();
        assert!(result.contains("x86"), "Should show x86 architecture");
    }

    #[test]
    fn plugin_info_shows_details() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.info");
        result.assert_ok();
        assert!(result.contains_any(&["x86", "64"]), "Should show arch info");
    }

    #[test]
    fn plugin_arch_command() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.arch");
        result.assert_ok();
        assert!(
            result.contains_any(&["x86-64", "x86_64"]),
            "Should show x86-64 arch"
        );
    }
}

// ============================================================================
// 2. Instruction-Level Analysis
// ============================================================================

mod instruction_analysis {
    use super::*;

    /// Test addresses in vuln_test binary (check_secret function)
    const CMP_INSTRUCTION_ADDR: u64 = 0x401221;
    const MOV_INSTRUCTION_ADDR: u64 = 0x40121e;

    #[rstest]
    #[case("a:sla.json", &["IntSub", "IntEqual", "Load"])]
    #[case("a:sla.regs", &["read", "write", "RBP"])]
    #[case("a:sla.vars", &["name", "space", "offset"])]
    #[case("a:sla.ssa", &["SSA", "dst", "src"])]
    #[case("a:sla.defuse", &["inputs", "outputs"])]
    fn instruction_commands_at_cmp(#[case] cmd: &str, #[case] expected: &[&str]) {
        setup();
        let result = r2_at_addr(vuln_test_binary(), CMP_INSTRUCTION_ADDR, cmd);
        result.assert_ok();
        assert!(
            result.contains_any(expected),
            "{} should contain one of {:?}, got: {}",
            cmd,
            expected,
            result.stdout
        );
    }

    #[test]
    fn memory_analysis_at_mov() {
        setup();
        let result = r2_at_addr(vuln_test_binary(), MOV_INSTRUCTION_ADDR, "a:sla.mem");
        result.assert_ok();
        assert!(
            result.contains_any(&["addr", "size", "write"]),
            "Memory analysis should show addr/size/write"
        );
    }

    #[test]
    fn instruction_ssa_uses_named_registers() {
        setup();
        let result = r2_at_addr(vuln_test_binary(), CMP_INSTRUCTION_ADDR, "a:sla.ssa");
        result.assert_ok();
        assert!(
            result.contains_any(&["RBP_", "RSP_"]),
            "SSA output should use named registers"
        );
    }
}

// ============================================================================
// 3. Function-Level SSA
// ============================================================================

mod function_ssa {
    use super::*;

    const CHECK_SECRET_FUNC: &str = "dbg.check_secret";

    #[rstest]
    #[case("a:sla.ssa.func", "blocks")]
    #[case("a:sla.ssa.func", "ops")]
    #[case("a:sla.defuse.func", "def")]
    fn ssa_func_commands(#[case] cmd: &str, #[case] expected: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, cmd);
        result.assert_ok();
        assert!(
            result.contains(expected),
            "{} should contain '{}', got: {}",
            cmd,
            expected,
            result.stdout
        );
    }

    #[test]
    fn ssa_func_contains_phis() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.ssa.func");
        result.assert_ok();
        // May contain "phis" or "phi" depending on output format
        assert!(
            result.contains_any(&["phis", "phi"]),
            "SSA should show phi nodes"
        );
    }
}

// ============================================================================
// 3.1 Optimized SSA
// ============================================================================

mod ssa_opt {
    use super::*;

    const CHECK_SECRET_FUNC: &str = "dbg.check_secret";

    #[test]
    fn ssa_func_opt_includes_stats() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.ssa.func.opt");
        result.assert_ok();
        assert!(
            result.contains_any(&["\"optimized\"", "optimized"]),
            "Optimized SSA should include optimized flag"
        );
        assert!(
            result.contains_any(&["\"stats\"", "stats"]),
            "Optimized SSA should include stats"
        );
    }
}

// ============================================================================
// 4. Control Flow Graph
// ============================================================================

mod cfg {
    use super::*;

    const CHECK_SECRET_FUNC: &str = "dbg.check_secret";

    #[test]
    fn cfg_shows_addresses() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.cfg");
        result.assert_ok();
        assert!(result.contains("0x40"), "CFG should show addresses");
    }

    #[rstest]
    #[case("blocks")]
    #[case("edges")]
    #[case("successors")]
    fn cfg_json_structure(#[case] field: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.cfg.json");
        result.assert_ok();
        assert!(
            result.contains(field),
            "CFG JSON should contain '{}' field",
            field
        );
    }

    #[test]
    fn dominator_tree() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.dom");
        result.assert_ok();
        assert!(
            result.contains_any(&["dominator", "0x40"]),
            "Dominator tree should show structure"
        );
    }
}

// ============================================================================
// 5. Backward Slicing
// ============================================================================

mod slicing {
    use super::*;

    const CHECK_SECRET_FUNC: &str = "dbg.check_secret";

    #[rstest]
    #[case("a:sla.slice ZF_1", "sink_var")]
    #[case("a:sla.slice ZF_1", "ops")]
    #[case("a:sla.slice ZF_1", "blocks")]
    fn slice_output(#[case] cmd: &str, #[case] expected: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, cmd);
        result.assert_ok();
        assert!(
            result.contains(expected),
            "Slice should contain '{}'",
            expected
        );
    }

    #[test]
    fn slice_usage_message() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.slice");
        result.assert_ok();
        assert!(result.contains("Usage"), "Should show usage without args");
    }

    #[test]
    fn slice_nonexistent_var() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            CHECK_SECRET_FUNC,
            "a:sla.slice NONEXISTENT_999",
        );
        result.assert_ok();
        assert!(
            result.contains("not found"),
            "Should report var not found"
        );
    }
}

// ============================================================================
// 6. Taint Analysis
// ============================================================================

mod taint {
    use super::*;

    #[rstest]
    #[case("dbg.check_secret", &["sources", "tainted", "input:reg"])]
    #[case("dbg.vuln_memcpy", &["tainted"])]
    fn taint_analysis(#[case] func: &str, #[case] expected: &[&str]) {
        setup();
        let result = r2_at_func(vuln_test_binary(), func, "a:sla.taint");
        result.assert_ok();
        assert!(
            result.contains_any(expected),
            "Taint should contain one of {:?}",
            expected
        );
    }
}

// ============================================================================
// 7. Symbolic Execution
// ============================================================================

mod symbolic {
    use super::*;

    #[rstest]
    #[case("dbg.check_secret")]
    #[case("dbg.unlock")]
    #[case("dbg.solve_equation")]
    fn sym_explores_paths(#[case] func: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), func, "a:sla.sym");
        result.assert_ok();
        assert!(
            result.contains("paths_explored"),
            "Should report paths explored"
        );
    }

    #[rstest]
    #[case("paths_feasible")]
    #[case("states_explored")]
    fn sym_reports_stats(#[case] stat: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.sym");
        result.assert_ok();
        assert!(result.contains(stat), "Should report {}", stat);
    }
}

// ============================================================================
// 8. Path Exploration
// ============================================================================

mod paths {
    use super::*;

    #[rstest]
    #[case("path_id")]
    #[case("feasible")]
    #[case("solution")]
    #[case("exit_status")]
    fn paths_structure(#[case] field: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.sym.paths");
        result.assert_ok();
        assert!(
            result.contains(field),
            "Paths output should contain '{}'",
            field
        );
    }

    #[test]
    fn finds_magic_value() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.sym.paths");
        result.assert_ok();
        assert!(
            result.contains("0xdead"),
            "Should find magic value 0xdead"
        );
    }

    #[test]
    fn solves_equation() {
        setup();
        // x*2+5=25 -> x=10 (0xa)
        let result = r2_at_func(vuln_test_binary(), "dbg.solve_equation", "a:sla.sym.paths");
        result.assert_ok();
        assert!(result.contains("0xa"), "Should solve x=10");
    }

    #[test]
    fn solves_bitwise() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.bitwise_check", "a:sla.sym.paths");
        result.assert_ok();
        assert!(result.contains("0x5a"), "Should solve bitwise to 0x5a");
    }
}

// ============================================================================
// 9. State Merging
// ============================================================================

mod merging {
    use super::*;

    #[test]
    fn merge_on() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.sym.merge on");
        result.assert_ok();
        assert!(result.contains("on"), "Should confirm merge on");
    }

    #[test]
    fn merge_off() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.sym.merge off");
        result.assert_ok();
        assert!(result.contains("off"), "Should confirm merge off");
    }

    #[test]
    fn merge_status() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.sym.merge");
        result.assert_ok();
        assert!(result.contains("merge"), "Should show merge status");
    }
}

// ============================================================================
// 10. Decompilation
// ============================================================================

mod decompilation {
    use super::*;

    #[test]
    fn decompiles_to_c_types() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.dec");
        result.assert_ok();
        assert!(
            result.contains_any(&["int", "void"]),
            "Should produce C types"
        );
    }

    #[test]
    fn decompiles_control_flow() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.dec");
        result.assert_ok();
        assert!(
            result.contains_any(&["if", "return"]),
            "Should show control flow"
        );
    }

    #[test]
    fn decompiles_braces() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.solve_equation", "a:sla.dec");
        result.assert_ok();
        assert!(result.contains("{"), "Should have function braces");
    }
}

// ============================================================================
// Direct FFI Tests (plugin library)
// ============================================================================

mod ffi {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::path::Path;

    const PLUGIN_PATH: &str = "target/release/libr2sleigh_plugin.so";

    fn require_plugin() -> bool {
        Path::new(PLUGIN_PATH).exists()
    }

    #[test]
    fn lift_xor_instruction() {
        if !require_plugin() {
            eprintln!("Skipping: plugin not built");
            return;
        }

        unsafe {
            let lib = libloading::Library::new(PLUGIN_PATH).expect("load plugin");

            let r2il_arch_init: libloading::Symbol<
                unsafe extern "C" fn(*const c_char) -> *mut std::ffi::c_void,
            > = lib.get(b"r2il_arch_init").unwrap();
            let r2il_is_loaded: libloading::Symbol<
                unsafe extern "C" fn(*const std::ffi::c_void) -> i32,
            > = lib.get(b"r2il_is_loaded").unwrap();
            let r2il_lift: libloading::Symbol<
                unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize, u64) -> *mut std::ffi::c_void,
            > = lib.get(b"r2il_lift").unwrap();
            let r2il_block_op_count: libloading::Symbol<
                unsafe extern "C" fn(*const std::ffi::c_void) -> usize,
            > = lib.get(b"r2il_block_op_count").unwrap();
            let r2il_block_to_esil: libloading::Symbol<
                unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char,
            > = lib.get(b"r2il_block_to_esil").unwrap();
            let r2il_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
                lib.get(b"r2il_free").unwrap();
            let r2il_block_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
                lib.get(b"r2il_block_free").unwrap();
            let r2il_string_free: libloading::Symbol<unsafe extern "C" fn(*mut c_char)> =
                lib.get(b"r2il_string_free").unwrap();

            // Init x86-64
            let arch = CString::new("x86-64").unwrap();
            let ctx = r2il_arch_init(arch.as_ptr());
            assert!(!ctx.is_null(), "Failed to init arch");
            assert_eq!(r2il_is_loaded(ctx), 1);

            // Lift "xor eax, eax" (0x31 0xC0)
            let mut bytes = vec![0x31u8, 0xC0];
            bytes.resize(16, 0x90);

            let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
            assert!(!block.is_null(), "Failed to lift");

            let op_count = r2il_block_op_count(block);
            assert!(op_count > 0, "Should have ops");

            let esil_ptr = r2il_block_to_esil(ctx, block);
            if !esil_ptr.is_null() {
                let esil = CStr::from_ptr(esil_ptr).to_string_lossy();
                assert!(!esil.is_empty(), "ESIL not empty");
                r2il_string_free(esil_ptr);
            }

            r2il_block_free(block);
            r2il_free(ctx);
        }
    }

    #[test]
    fn lift_add_instruction_to_ssa() {
        if !require_plugin() {
            eprintln!("Skipping: plugin not built");
            return;
        }

        unsafe {
            let lib = libloading::Library::new(PLUGIN_PATH).expect("load plugin");

            let r2il_arch_init: libloading::Symbol<
                unsafe extern "C" fn(*const c_char) -> *mut std::ffi::c_void,
            > = lib.get(b"r2il_arch_init").unwrap();
            let r2il_lift: libloading::Symbol<
                unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize, u64) -> *mut std::ffi::c_void,
            > = lib.get(b"r2il_lift").unwrap();
            let r2il_block_to_ssa_json: libloading::Symbol<
                unsafe extern "C" fn(*const std::ffi::c_void, *const std::ffi::c_void) -> *mut c_char,
            > = lib.get(b"r2il_block_to_ssa_json").unwrap();
            let r2il_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
                lib.get(b"r2il_free").unwrap();
            let r2il_block_free: libloading::Symbol<unsafe extern "C" fn(*mut std::ffi::c_void)> =
                lib.get(b"r2il_block_free").unwrap();
            let r2il_string_free: libloading::Symbol<unsafe extern "C" fn(*mut c_char)> =
                lib.get(b"r2il_string_free").unwrap();

            let arch = CString::new("x86-64").unwrap();
            let ctx = r2il_arch_init(arch.as_ptr());
            assert!(!ctx.is_null());

            // "add rax, rbx" (0x48 0x01 0xd8)
            let mut bytes = vec![0x48u8, 0x01, 0xd8];
            bytes.resize(16, 0x90);

            let block = r2il_lift(ctx, bytes.as_ptr(), bytes.len(), 0x1000);
            assert!(!block.is_null());

            let ssa_ptr = r2il_block_to_ssa_json(ctx, block);
            if !ssa_ptr.is_null() {
                let ssa = CStr::from_ptr(ssa_ptr).to_string_lossy();
                assert!(
                    ssa.contains("op") || ssa.contains("dst") || ssa.contains("["),
                    "SSA should have structure"
                );
                r2il_string_free(ssa_ptr);
            }

            r2il_block_free(block);
            r2il_free(ctx);
        }
    }
}
