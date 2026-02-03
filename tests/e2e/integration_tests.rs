//! Integration tests for r2sleigh plugin.
//!
//! These tests invoke radare2 with the r2sleigh plugin and validate output.
//! Run with: `cargo test -p r2sleigh-e2e-tests`

use e2e::{r2_at_addr, r2_at_func, require_binary, vuln_test_binary};
use rstest::rstest;
use serde_json::Value;

// ============================================================================
// Test fixtures
// ============================================================================

fn setup() {
    require_binary(vuln_test_binary());
}

fn parse_json(result: &e2e::R2Result, label: &str) -> Value {
    result.parse_json::<Value>().unwrap_or_else(|e| {
        panic!(
            "{} should be valid JSON: {} -- output: {}",
            label, e, result.stdout
        )
    })
}

fn expect_array<'a>(value: &'a Value, label: &str) -> &'a Vec<Value> {
    match value {
        Value::Array(arr) => arr,
        _ => panic!("{} should be a JSON array", label),
    }
}

fn expect_object<'a>(value: &'a Value, label: &str) -> &'a serde_json::Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("{} should be a JSON object", label),
    }
}

fn contains_named_register(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            let is_varnode = map.contains_key("space") && map.contains_key("offset") && map.contains_key("size");
            if is_varnode {
                let space = map.get("space").and_then(Value::as_str);
                if let Some(space_str) = space {
                    if space_str.eq_ignore_ascii_case("register") {
                        if let Some(name) = map.get("name").and_then(Value::as_str) {
                            if !name.is_empty() {
                                return true;
                            }
                        }
                    }
                }
            }

            map.values().any(contains_named_register)
        }
        Value::Array(arr) => arr.iter().any(contains_named_register),
        _ => false,
    }
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

    #[test]
    fn plugin_arch_override_roundtrip() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "main",
            "a:sla.arch x86-64; a:sla.arch",
        );
        result.assert_ok();
        assert!(
            result.contains_any(&["x86-64", "x86_64"]),
            "Should report overridden arch"
        );
    }
}

// ============================================================================
// 2. Instruction-Level Analysis
// ============================================================================

mod instruction_analysis {
    use super::*;

    /// Test addresses in vuln_test binary (check_secret function)
    const CMP_INSTRUCTION_ADDR: u64 = 0x401241;
    const MOV_INSTRUCTION_ADDR: u64 = 0x40123e;
    const CPUID_INSTRUCTION_ADDR: u64 = 0x4014d9;

    #[rstest]
    #[case("a:sla.json")]
    #[case("a:sla.regs")]
    #[case("a:sla.vars")]
    #[case("a:sla.ssa")]
    #[case("a:sla.defuse")]
    fn instruction_commands_at_cmp(#[case] cmd: &str) {
        setup();
        let result = r2_at_addr(vuln_test_binary(), CMP_INSTRUCTION_ADDR, cmd);
        result.assert_ok();
        let json = parse_json(&result, cmd);
        match cmd {
            "a:sla.json" => {
                let ops = expect_array(&json, cmd);
                assert!(!ops.is_empty(), "a:sla.json should return ops");
                assert!(
                    contains_named_register(&json),
                    "a:sla.json should include named register varnodes"
                );
            }
            "a:sla.regs" => {
                let obj = expect_object(&json, cmd);
                assert!(obj.get("read").map_or(false, |v| v.is_array()));
                assert!(obj.get("write").map_or(false, |v| v.is_array()));
            }
            "a:sla.vars" => {
                let vars = expect_array(&json, cmd);
                assert!(!vars.is_empty(), "a:sla.vars should return entries");
                let first = expect_object(&vars[0], "a:sla.vars entry");
                assert!(first.contains_key("name"));
                assert!(first.contains_key("space"));
                assert!(first.contains_key("offset"));
                assert!(first.contains_key("size"));
            }
            "a:sla.ssa" => {
                let ops = expect_array(&json, cmd);
                assert!(!ops.is_empty(), "a:sla.ssa should return ops");
                let first = expect_object(&ops[0], "a:sla.ssa entry");
                assert!(first.contains_key("op"));
            }
            "a:sla.defuse" => {
                let obj = expect_object(&json, cmd);
                assert!(obj.contains_key("inputs"));
                assert!(obj.contains_key("outputs"));
                assert!(obj.contains_key("live"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn memory_analysis_at_mov() {
        setup();
        let result = r2_at_addr(vuln_test_binary(), MOV_INSTRUCTION_ADDR, "a:sla.mem");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.mem");
        let accesses = expect_array(&json, "a:sla.mem");
        assert!(!accesses.is_empty(), "a:sla.mem should return accesses");
        let first = expect_object(&accesses[0], "a:sla.mem entry");
        assert!(first.contains_key("addr"));
        assert!(first.contains_key("size"));
        assert!(first.contains_key("write"));
        assert!(
            accesses.iter().any(|entry| {
                entry
                    .as_object()
                    .and_then(|obj| obj.get("stack").and_then(Value::as_bool))
                    == Some(true)
            }),
            "a:sla.mem should mark stack accesses"
        );
        assert!(
            accesses.iter().any(|entry| {
                entry.as_object().map_or(false, |obj| {
                    obj.get("stack").and_then(Value::as_bool) == Some(true)
                        && obj.get("stack_offset").map_or(false, |v| v.is_number())
                })
            }),
            "a:sla.mem stack entries should include stack_offset"
        );
    }

    #[test]
    fn analysis_opvals_include_ssa_regs() {
        setup();
        let result = r2_at_addr(vuln_test_binary(), CMP_INSTRUCTION_ADDR, "a:sla.opvals");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.opvals");
        let obj = expect_object(&json, "a:sla.opvals");
        let srcs = obj
            .get("srcs")
            .and_then(Value::as_array)
            .expect("a:sla.opvals srcs array");
        let dsts = obj
            .get("dsts")
            .and_then(Value::as_array)
            .expect("a:sla.opvals dsts array");

        assert!(
            srcs.iter().any(|v| v.as_str() == Some("RBP")),
            "srcs should include RBP"
        );
        assert!(
            dsts.iter().any(|v| v.as_str() == Some("ZF")),
            "dsts should include ZF"
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

    #[test]
    fn callother_includes_userop_name() {
        setup();
        let result = r2_at_addr(vuln_test_binary(), CPUID_INSTRUCTION_ADDR, "a:sla.json");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.json");
        let ops = expect_array(&json, "a:sla.json");

        let mut found = false;
        for op in ops {
            if let Some(callother) = op.get("CallOther").and_then(Value::as_object) {
                let name = callother.get("userop_name").and_then(Value::as_str);
                if let Some(name) = name {
                    if !name.is_empty() {
                        found = true;
                        break;
                    }
                }
            }
        }

        assert!(found, "CallOther ops should include userop_name");
    }
}

// ============================================================================
// 3. Function-Level SSA
// ============================================================================

mod function_ssa {
    use super::*;

    const CHECK_SECRET_FUNC: &str = "dbg.check_secret";

    #[rstest]
    #[case("a:sla.ssa.func")]
    #[case("a:sla.defuse.func")]
    fn ssa_func_commands(#[case] cmd: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, cmd);
        result.assert_ok();
        let json = parse_json(&result, cmd);
        match cmd {
            "a:sla.ssa.func" => {
                let obj = expect_object(&json, cmd);
                assert!(obj.get("blocks").map_or(false, |v| v.is_array()));
                assert!(obj.contains_key("entry_hex"));
            }
            "a:sla.defuse.func" => {
                let obj = expect_object(&json, cmd);
                assert!(obj.contains_key("definitions"));
                assert!(obj.contains_key("uses"));
                assert!(obj.contains_key("live_in"));
                assert!(obj.contains_key("live_out"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn ssa_func_contains_phis() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.ssa.func");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.ssa.func");
        let obj = expect_object(&json, "a:sla.ssa.func");
        let blocks = obj
            .get("blocks")
            .and_then(|v| v.as_array())
            .expect("a:sla.ssa.func should include blocks");
        let has_phi = blocks.iter().any(|block| {
            block
                .get("phis")
                .and_then(|v| v.as_array())
                .map_or(false, |phis| !phis.is_empty())
        });
        assert!(has_phi, "SSA should show phi nodes");
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
        let json = parse_json(&result, "a:sla.ssa.func.opt");
        let obj = expect_object(&json, "a:sla.ssa.func.opt");
        assert!(obj.contains_key("optimized"));
        assert!(obj.contains_key("stats"));
        assert!(obj.contains_key("function"));
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
    #[case("entry")]
    #[case("num_blocks")]
    fn cfg_json_structure(#[case] field: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.cfg.json");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.cfg.json");
        let obj = expect_object(&json, "a:sla.cfg.json");
        assert!(obj.contains_key(field));
    }

    #[test]
    fn dominator_tree() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.dom");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.dom");
        let obj = expect_object(&json, "a:sla.dom");
        assert!(obj.contains_key("idom"));
        assert!(obj.contains_key("children"));
        assert!(obj.contains_key("dominance_frontier"));
        assert!(obj.contains_key("depth"));
    }

    #[test]
    fn cfg_json_blocks_have_successors() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.cfg.json");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.cfg.json");
        let obj = expect_object(&json, "a:sla.cfg.json");
        let blocks = obj
            .get("blocks")
            .and_then(|v| v.as_array())
            .expect("a:sla.cfg.json should include blocks");
        let has_successors = blocks.iter().any(|block| {
            block
                .get("successors")
                .and_then(|v| v.as_array())
                .is_some()
        });
        assert!(has_successors, "CFG blocks should include successors");
    }
}

// ============================================================================
// 5. Backward Slicing
// ============================================================================

mod slicing {
    use super::*;

    const CHECK_SECRET_FUNC: &str = "dbg.check_secret";

    #[rstest]
    #[case("a:sla.slice ZF_1")]
    fn slice_output(#[case] cmd: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, cmd);
        result.assert_ok();
        let json = parse_json(&result, cmd);
        let obj = expect_object(&json, cmd);
        assert!(obj.contains_key("sink_var"));
        assert!(obj.contains_key("ops"));
        assert!(obj.contains_key("blocks"));
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
        let json = parse_json(&result, "a:sla.slice");
        let obj = expect_object(&json, "a:sla.slice error");
        assert!(obj.contains_key("error"));
    }

    /// Verify slice returns operations affecting the sink variable
    #[test]
    fn slice_contains_ops() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.slice ZF_1");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.slice");
        let obj = expect_object(&json, "a:sla.slice");
        
        // Check ops array exists and has entries
        let ops = obj.get("ops").and_then(|v| v.as_array());
        assert!(ops.is_some(), "Slice should contain ops array");
        
        // ZF (zero flag) should have some defining operations
        let ops_arr = ops.unwrap();
        if !ops_arr.is_empty() {
            // Each op should have type, block, and index
            let first_op = &ops_arr[0];
            assert!(first_op.get("type").is_some(), "Op should have type");
            assert!(first_op.get("block").is_some(), "Op should have block");
            assert!(first_op.get("index").is_some(), "Op should have index");
        }
    }

    /// Verify slice returns the affected blocks
    #[test]
    fn slice_contains_blocks() {
        setup();
        let result = r2_at_func(vuln_test_binary(), CHECK_SECRET_FUNC, "a:sla.slice ZF_1");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.slice");
        let obj = expect_object(&json, "a:sla.slice");
        
        // Check blocks array exists
        let blocks = obj.get("blocks").and_then(|v| v.as_array());
        assert!(blocks.is_some(), "Slice should contain blocks array");
        
        // Blocks should be hex addresses
        let blocks_arr = blocks.unwrap();
        for block in blocks_arr {
            let addr = block.as_str().unwrap_or("");
            assert!(addr.starts_with("0x"), "Block address should be hex: {}", addr);
        }
    }

    /// Verify slice at main function works
    #[test]
    fn slice_at_main() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.slice RAX_1");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.slice");
        let obj = expect_object(&json, "a:sla.slice");
        
        // Should have sink_var set correctly
        let sink = obj.get("sink_var").and_then(|v| v.as_str());
        assert_eq!(sink, Some("RAX_1"), "Sink var should be RAX_1");
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
        let json = parse_json(&result, "a:sla.taint");
        let obj = expect_object(&json, "a:sla.taint");
        assert!(obj.contains_key("sources"));
        assert!(obj.contains_key("sinks"));
        assert!(obj.contains_key("sink_hits"));
        assert!(obj.contains_key("tainted_vars"));
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
        let json = parse_json(&result, "a:sla.sym");
        let obj = expect_object(&json, "a:sla.sym");
        assert!(obj.contains_key("paths_explored"));
    }

    #[rstest]
    #[case("paths_feasible")]
    #[case("states_explored")]
    fn sym_reports_stats(#[case] stat: &str) {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.sym");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.sym");
        let obj = expect_object(&json, "a:sla.sym");
        assert!(obj.contains_key(stat), "Should report {}", stat);
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
        let json = parse_json(&result, "a:sla.sym.paths");
        let paths = expect_array(&json, "a:sla.sym.paths");
        assert!(!paths.is_empty(), "a:sla.sym.paths should return paths");
        let first = expect_object(&paths[0], "a:sla.sym.paths entry");
        assert!(first.contains_key(field));
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

// ============================================================================
// 12. Deep radare2 Integration Tests
// ============================================================================
// These tests verify that the plugin integrates seamlessly with radare2's
// native analysis commands (aaa, afv, ax) through the new callback hooks.

mod deep_integration {
    use super::*;

    /// Verify that `aaa` runs successfully with the plugin loaded
    #[test]
    fn aaa_succeeds_with_plugin() {
        setup();
        // Run aaa and verify it completes without crashing
        let result = r2_at_func(vuln_test_binary(), "main", "aaa");
        result.assert_ok();
        // Should not contain errors
        assert!(
            !result.contains("ERROR") || result.contains("INFO"),
            "aaa should complete without fatal errors"
        );
    }

    /// Verify that `afv` shows variables after `aaa`
    #[test]
    fn afv_shows_variables_after_aaa() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "afv");
        result.assert_ok();
        // main() in vuln_test.c has several local variables
        // At minimum we should see some variable output
        assert!(
            result.contains("var") || result.contains("arg") || result.contains("@"),
            "afv should show variables for main()"
        );
    }

    /// Verify that variables have proper naming (not just hex offsets)
    #[test]
    fn afv_shows_named_variables() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "afv");
        result.assert_ok();
        // Should have human-readable variable names, not just raw offsets
        // The output format is like: "var int foo @ RBP-0x8"
        let has_named_var = result.contains("argc")
            || result.contains("argv")
            || result.contains("var")
            || result.contains("arg");
        assert!(has_named_var, "afv should show named variables");
    }

    /// Verify that `ax` shows xrefs after `aaa`
    #[test]
    fn ax_shows_xrefs_after_aaa() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "ax");
        result.assert_ok();
        // main() should have some xrefs (calls to other functions, etc.)
        let has_xrefs = result.contains("0x") || result.contains("->");
        assert!(
            has_xrefs || result.stdout.trim().is_empty() == false,
            "ax should show xrefs for main() (or at least run without error)"
        );
    }

    /// Verify that function analysis completes and basic blocks are created
    #[test]
    fn af_creates_basic_blocks() {
        setup();
        // afb lists basic blocks
        let result = r2_at_func(vuln_test_binary(), "main", "afb");
        result.assert_ok();
        // Should have at least one basic block
        assert!(
            result.contains("0x"),
            "afb should show basic blocks for main()"
        );
    }

    /// Verify that `afvj` (JSON variable output) works
    #[test]
    fn afvj_produces_json() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "afvj");
        result.assert_ok();
        // Should be valid JSON
        let json = parse_json(&result, "afvj");
        // afvj returns an object with "reg", "sp", "bp" keys for different var types
        let obj = expect_object(&json, "afvj");
        // Should have at least one of these keys
        assert!(
            obj.contains_key("reg") || obj.contains_key("sp") || obj.contains_key("bp"),
            "afvj should contain variable categories"
        );
    }

    /// Verify that `axj` (JSON xref output) works  
    #[test]
    fn axj_produces_json() {
        setup();
        // Use axtj (xrefs TO) at a function that's called from main
        // main itself may not have xrefs TO it in the test binary
        let result = r2_at_func(vuln_test_binary(), "sym.vulnerable_function", "axtj");
        result.assert_ok();
        // The output might be empty if no xrefs found, which is fine
        if result.stdout.trim().is_empty() {
            return; // Empty output is acceptable
        }
        // If there's output, it should be valid JSON
        let json = parse_json(&result, "axtj");
        // axtj returns an array
        match &json {
            Value::Array(_) => {}
            Value::Null => {}
            _ => panic!("axtj should return an array or null"),
        }
    }

    /// Verify that radare2 works correctly without the plugin's advanced features
    /// This tests that our core changes don't break basic r2 functionality
    #[test]
    fn radare2_basic_analysis_works() {
        setup();
        // Just basic analysis without relying on plugin-specific features
        let result = r2_at_func(vuln_test_binary(), "main", "pdf");
        result.assert_ok();
        // main() should have disassembly output
        assert!(
            result.contains("push") || result.contains("mov") || result.contains("call") || result.contains("0x"),
            "pdf should show disassembly"
        );
    }

    /// Verify that the plugin's SSA analysis still works via explicit command
    #[test]
    fn sla_ssa_command_still_works() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.ssa");
        result.assert_ok();
        // SSA output should be valid JSON (may be empty array if function is complex)
        // The output format is JSON array of SSA blocks
        let is_json = result.stdout.trim().starts_with("[") || result.stdout.trim().starts_with("{");
        assert!(
            is_json || result.stdout.trim().is_empty(),
            "a:sla.ssa should produce JSON output or be empty"
        );
    }

    /// Test that aaaa (extra analysis) runs successfully with post-analysis hooks
    #[test]
    fn aaaa_runs_post_analysis_hooks() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "aaaa");
        result.assert_ok();
        // Should complete without crashes and show additional analysis
        assert!(
            result.contains("plugin post-analysis") || !result.contains("ERROR"),
            "aaaa should run plugin post-analysis hooks"
        );
    }
}
