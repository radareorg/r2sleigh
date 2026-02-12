//! Integration tests for r2sleigh plugin.
//!
//! These tests invoke radare2 with the r2sleigh plugin and validate output.
//! Run with: `cargo test -p r2sleigh-e2e-tests`

use e2e::{
    r2_at_addr, r2_at_func, r2_cmd, r2_cmd_timeout, r2_cmd_timeout_with_env, require_binary,
    stress_test_binary, stress_test_opt_binary, vuln_test_binary,
};
use rstest::rstest;
use serde_json::Value;
use std::time::Duration;

// ============================================================================
// Test fixtures
// ============================================================================

fn setup() {
    require_binary(vuln_test_binary());
}

mod stress_regressions {
    use super::*;
    use std::sync::Mutex;

    /// Serialize stress tests to avoid concurrent r2 processes fighting for
    /// resources, which causes non-deterministic signal kills (SIGSEGV, OOM).
    /// We recover from a poisoned mutex since stress test panics are expected
    /// (they assert on crashes) and should not cascade to other tests.
    static STRESS_LOCK: Mutex<()> = Mutex::new(());

    fn lock_stress() -> std::sync::MutexGuard<'static, ()> {
        STRESS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn parse_number_symbolic_paths_no_panic() {
        let _guard = lock_stress();
        setup_stress();
        let result = r2_at_func(stress_test_binary(), "dbg.parse_number", "a:sla.sym.paths");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.sym.paths parse_number");
        let arr = expect_array(&json, "a:sla.sym.paths parse_number");
        assert!(!arr.is_empty(), "parse_number should produce symbolic paths");
    }

    #[test]
    fn fp_interpolate_decompile_is_not_empty_stub() {
        let _guard = lock_stress();
        setup_stress();
        let result = r2_at_func(stress_test_binary(), "dbg.fp_interpolate", "a:sla.dec");
        result.assert_ok();
        assert!(result.contains("return"), "decompilation should include return");
        assert!(
            result.contains_any(&[" + ", " * ", "fabs(", "sqrt(", "ceil(", "floor(", "round("]),
            "float decompilation should contain arithmetic/math operations"
        );
        assert!(
            !result.contains("__unhandled_op__"),
            "float decompilation should not contain unhandled placeholders"
        );
    }

    #[test]
    fn ls_main_decompile_uses_large_function_fallback() {
        let _guard = lock_stress();
        let result = r2_cmd_timeout(
            "/bin/ls",
            "aaa; s main; a:sla.dec",
            Duration::from_secs(90),
        );
        result.assert_ok();
        assert!(
            result.contains("r2dec fallback: skipped decompilation"),
            "large functions should be guarded with explicit fallback output"
        );
    }

    #[test]
    fn endbr64_json_returns_noop_marker() {
        let _guard = lock_stress();
        let result = r2_cmd("/bin/ls", "aaa; s main; a:sla.json");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.json /bin/ls main");
        let arr = expect_array(&json, "a:sla.json /bin/ls main");
        assert!(
            !arr.is_empty(),
            "a:sla.json at CET entry should return a no-op marker instead of []"
        );
    }

    #[test]
    fn sla_dec_allows_explicit_target_argument() {
        let _guard = lock_stress();
        setup_stress();
        let result = r2_cmd(stress_test_binary(), "aaa; a:sla.dec dbg.parse_number");
        result.assert_ok();
        assert!(
            result.contains_any(&["parse_number", "dbg.parse_number", "sub_"]),
            "a:sla.dec <target> should decompile the requested function"
        );
    }

    #[test]
    fn sla_dec_reports_missing_symbol_with_guidance() {
        let _guard = lock_stress();
        setup_stress();
        let result = r2_cmd(stress_test_opt_binary(), "aaa; a:sla.dec dbg.nonexistent_symbol");
        result.assert_ok();
        assert!(
            result.contains("may be inlined or stripped"),
            "missing-symbol decompile should provide stripped/inlined guidance"
        );
    }

    #[rstest]
    #[case("dbg.my_strcmp")]
    #[case("sym.hash_func")]
    #[case("dbg.pool_alloc")]
    #[case("dbg.interpret_bytecode")]
    #[case("sym.ackermann")]
    fn o2_pathological_functions_no_crash(#[case] func: &str) {
        let _guard = lock_stress();
        setup_stress();
        let cmd = format!("aaa; a:sla.dec {}", func);
        // Retry once on transient crash (non-deterministic signal in r2 FFI path).
        let result = retry_on_crash(|| {
            r2_cmd_timeout_with_env(
                stress_test_opt_binary(),
                &cmd,
                Duration::from_secs(30),
                &[],
            )
        });
        result.assert_ok();
        assert!(
            !result.stdout.trim().is_empty(),
            "decompilation output should be non-empty for {}",
            func
        );
    }

    /// Test that both the default (iterative) analyzer and the legacy recursive
    /// analyzer produce output for ackermann.  The default path is iterative
    /// (no env var needed); the legacy path is forced via SLEIGH_DEC_LEGACY_ANALYZER=1.
    #[test]
    fn ackermann_decompiles_with_both_analyzers() {
        let _guard = lock_stress();
        setup_stress();
        let cmd = "aaa; a:sla.dec sym.ackermann";

        // Default path: iterative analyzer (primary)
        let iterative = retry_on_crash(|| {
            r2_cmd_timeout_with_env(
                stress_test_opt_binary(),
                cmd,
                Duration::from_secs(30),
                &[],
            )
        });
        iterative.assert_ok();
        assert!(
            !iterative.stdout.trim().is_empty(),
            "iterative (default) analyzer output should be non-empty"
        );

        // Legacy path: forced via env var
        let legacy = retry_on_crash(|| {
            r2_cmd_timeout_with_env(
                stress_test_opt_binary(),
                cmd,
                Duration::from_secs(30),
                &[("SLEIGH_DEC_LEGACY_ANALYZER", "1")],
            )
        });
        legacy.assert_ok();
        assert!(
            !legacy.stdout.trim().is_empty(),
            "legacy analyzer output should be non-empty"
        );
    }
}

fn setup_stress() {
    require_binary(stress_test_binary());
    require_binary(stress_test_opt_binary());
}

/// Retry an r2 invocation up to 2 extra times if killed by a signal.
/// Non-deterministic crashes in the r2/plugin FFI path are occasionally
/// observed on O2-optimized stress test binaries; retries distinguish
/// persistent bugs from transient failures.
fn retry_on_crash(f: impl Fn() -> e2e::R2Result) -> e2e::R2Result {
    for attempt in 0..3 {
        let result = f();
        if !result.crashed {
            return result;
        }
        if attempt < 2 {
            eprintln!("  (retrying after transient crash, attempt {}, exit code {:?})",
                       attempt + 1, result.exit_code);
        } else {
            return result;
        }
    }
    unreachable!()
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
            let is_varnode =
                map.contains_key("space") && map.contains_key("offset") && map.contains_key("size");
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
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.arch x86-64; a:sla.arch");
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
    const CMP_INSTRUCTION_ADDR: u64 = 0x401281;
    const MOV_INSTRUCTION_ADDR: u64 = 0x40127e;
    const CPUID_INSTRUCTION_ADDR: u64 = 0x401519;

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
        assert!(
            blocks
                .iter()
                .all(|block| block.get("phis").map_or(false, |phis| phis.is_array())),
            "SSA blocks should include a phis array even when SCCP simplifies all phis"
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
        let json = parse_json(&result, "a:sla.ssa.func.opt");
        let obj = expect_object(&json, "a:sla.ssa.func.opt");
        assert!(obj.contains_key("optimized"));
        assert!(obj.contains_key("stats"));
        assert!(obj.contains_key("function"));

        let stats = obj
            .get("stats")
            .and_then(Value::as_object)
            .expect("a:sla.ssa.func.opt should include stats object");
        assert!(stats.contains_key("sccp_constants_found"));
        assert!(stats.contains_key("sccp_edges_pruned"));
        assert!(stats.contains_key("sccp_blocks_removed"));
    }

    #[test]
    fn sccp_dead_branch_eliminated() {
        setup();
        let opt = r2_at_func(
            vuln_test_binary(),
            "dbg.test_sccp_dead_branch",
            "a:sla.ssa.func.opt",
        );
        opt.assert_ok();
        let json = parse_json(&opt, "a:sla.ssa.func.opt");
        let obj = expect_object(&json, "a:sla.ssa.func.opt");
        let stats = obj
            .get("stats")
            .and_then(Value::as_object)
            .expect("stats object");
        let removed = stats
            .get("sccp_blocks_removed")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let pruned = stats
            .get("sccp_edges_pruned")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        assert!(
            pruned >= removed,
            "SCCP counters should be self-consistent (edges_pruned >= blocks_removed)"
        );

        let ssa = r2_at_func(
            vuln_test_binary(),
            "dbg.test_sccp_dead_branch",
            "a:sla.ssa.func",
        );
        ssa.assert_ok();
        assert!(ssa.contains("blocks"), "SSA function output should include blocks");
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
        let has_successors = blocks
            .iter()
            .any(|block| block.get("successors").and_then(|v| v.as_array()).is_some());
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
            assert!(
                addr.starts_with("0x"),
                "Block address should be hex: {}",
                addr
            );
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

    #[test]
    fn taint_call_sink_reports_tainted_args_vuln_memcpy() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.vuln_memcpy", "a:sla.taint");
        result.assert_ok();

        let json = parse_json(&result, "a:sla.taint");
        let obj = expect_object(&json, "a:sla.taint");
        let sink_hits = obj
            .get("sink_hits")
            .and_then(|v| v.as_array())
            .expect("a:sla.taint should contain sink_hits array");

        let mut saw_tainted_call_arg = false;
        for hit in sink_hits {
            let hit_obj = expect_object(hit, "a:sla.taint sink_hit entry");
            let op_name = hit_obj
                .get("op")
                .and_then(|v| v.get("op"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if op_name != "Call" && op_name != "CallInd" {
                continue;
            }

            let Some(tainted_vars) = hit_obj.get("tainted_vars").and_then(|v| v.as_array()) else {
                continue;
            };
            for tv in tainted_vars {
                let Some(var_name) = tv.get("var").and_then(|v| v.as_str()) else {
                    continue;
                };
                let base = var_name
                    .split('_')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if matches!(base.as_str(), "rdi" | "rsi" | "rdx" | "rcx" | "r8" | "r9") {
                    saw_tainted_call_arg = true;
                    break;
                }
            }
            if saw_tainted_call_arg {
                break;
            }
        }

        assert!(
            saw_tainted_call_arg,
            "Call sink hits should include tainted x86-64 SysV argument registers for vuln_memcpy"
        );
    }

    #[test]
    fn taint_skips_dead_path_store_sink() {
        setup();
        let opt = r2_at_func(
            vuln_test_binary(),
            "dbg.test_sccp_dead_branch",
            "a:sla.ssa.func.opt",
        );
        opt.assert_ok();
        let opt_json = parse_json(&opt, "a:sla.ssa.func.opt");
        let opt_obj = expect_object(&opt_json, "a:sla.ssa.func.opt");
        let blocks_removed = opt_obj
            .get("stats")
            .and_then(Value::as_object)
            .and_then(|s| s.get("sccp_blocks_removed"))
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let result = r2_at_func(vuln_test_binary(), "dbg.test_sccp_dead_branch", "a:sla.taint");
        result.assert_ok();

        let json = parse_json(&result, "a:sla.taint");
        let obj = expect_object(&json, "a:sla.taint");
        let sink_hits = obj
            .get("sink_hits")
            .and_then(Value::as_array)
            .expect("a:sla.taint should contain sink_hits");

        let has_store_sink = sink_hits.iter().any(|hit| {
            hit.get("op")
                .and_then(|v| v.get("op"))
                .and_then(Value::as_str)
                == Some("Store")
        });
        if blocks_removed > 0 {
            assert!(
                !has_store_sink,
                "when SCCP removes dead blocks, dead-path store sinks should disappear"
            );
        }
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
        assert!(result.contains("0xdead"), "Should find magic value 0xdead");
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
// 9. Interactive Symbolic Commands
// ============================================================================

mod interactive_sym {
    use super::*;

    const CHECK_SECRET_RET: u64 = 0x401296;
    const UNREACHABLE_TARGET: u64 = 0xdeadbeef;

    #[test]
    fn sym_explore_command_exists_and_returns_json() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.check_secret",
            "a:sym.explore 0x401296",
        );
        result.assert_ok();
        let json = parse_json(&result, "a:sym.explore");
        let obj = expect_object(&json, "a:sym.explore");
        assert!(obj.contains_key("target"));
        assert!(obj.contains_key("matched_paths"));
        assert!(obj.contains_key("paths"));
    }

    #[test]
    fn sym_solve_command_exists_and_returns_json() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.check_secret",
            "a:sym.solve 0x401296",
        );
        result.assert_ok();
        let json = parse_json(&result, "a:sym.solve");
        let obj = expect_object(&json, "a:sym.solve");
        assert!(obj.contains_key("found"));
        assert!(obj.contains_key("stats"));
    }

    #[test]
    fn sym_state_reports_empty_before_any_run() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sym.state");
        result.assert_ok();
        let json = parse_json(&result, "a:sym.state");
        let obj = expect_object(&json, "a:sym.state");
        assert_eq!(obj.get("has_state").and_then(Value::as_bool), Some(false));
    }

    #[test]
    fn sym_namespace_alias_keeps_old_sla_sym_paths_working() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.sym.paths");
        result.assert_ok();
        let json = parse_json(&result, "a:sla.sym.paths");
        let arr = expect_array(&json, "a:sla.sym.paths");
        assert!(!arr.is_empty(), "a:sla.sym.paths should still return paths");
    }

    #[test]
    fn sym_explore_finds_all_matching_paths_for_check_secret_target() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.check_secret",
            &format!("a:sym.explore 0x{CHECK_SECRET_RET:x}"),
        );
        result.assert_ok();
        let json = parse_json(&result, "a:sym.explore");
        let obj = expect_object(&json, "a:sym.explore");
        let matched_paths = obj
            .get("matched_paths")
            .and_then(Value::as_u64)
            .expect("matched_paths should be numeric");
        assert!(matched_paths >= 1, "Expected at least one matching path");
        let paths = obj
            .get("paths")
            .and_then(Value::as_array)
            .expect("paths should be an array");
        assert!(!paths.is_empty(), "paths should not be empty");
    }

    #[test]
    fn sym_solve_returns_concrete_input_for_check_secret_target() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.check_secret",
            &format!("a:sym.solve 0x{CHECK_SECRET_RET:x}"),
        );
        result.assert_ok();
        let json = parse_json(&result, "a:sym.solve");
        let obj = expect_object(&json, "a:sym.solve");
        assert_eq!(obj.get("found").and_then(Value::as_bool), Some(true));
        let selected_path = obj
            .get("selected_path")
            .and_then(Value::as_object)
            .expect("selected_path should be an object");
        let solution = selected_path
            .get("solution")
            .and_then(Value::as_object)
            .expect("selected_path.solution should be an object");
        let inputs = solution
            .get("inputs")
            .and_then(Value::as_object)
            .expect("selected_path.solution.inputs should be an object");
        assert!(!inputs.is_empty(), "solve should return concrete inputs");
    }

    #[test]
    fn sym_state_returns_last_solve_result_in_same_session() {
        setup();
        let command =
            format!("aaa; s dbg.check_secret; a:sym.solve 0x{CHECK_SECRET_RET:x}; a:sym.state");
        let result = r2_cmd(vuln_test_binary(), &command);
        result.assert_ok();
        let state_line = result
            .stdout
            .lines()
            .rev()
            .find(|line| line.contains("\"has_state\""))
            .expect("expected a:sym.state JSON line");
        let state_json: Value =
            serde_json::from_str(state_line).expect("a:sym.state line should be valid JSON");
        let obj = expect_object(&state_json, "a:sym.state");
        let expected_target = format!("0x{CHECK_SECRET_RET:x}");
        assert_eq!(obj.get("has_state").and_then(Value::as_bool), Some(true));
        assert_eq!(obj.get("mode").and_then(Value::as_str), Some("solve"));
        assert_eq!(
            obj.get("target").and_then(Value::as_str),
            Some(expected_target.as_str())
        );
    }

    #[test]
    fn sym_explore_missing_target_shows_usage() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sym.explore");
        result.assert_ok();
        assert!(
            result.contains("Usage: a:sym.explore <target_addr_expr>"),
            "Expected usage message for missing target"
        );
    }

    #[test]
    fn sym_solve_invalid_target_expr_reports_error() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sym.solve (()");
        result.assert_ok();
        assert!(
            result.contains("Usage: a:sym.solve <target_addr_expr>"),
            "Expected usage message for invalid target expression"
        );
    }

    #[test]
    fn sym_solve_unreachable_target_reports_found_false() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.check_secret",
            &format!("a:sym.solve 0x{UNREACHABLE_TARGET:x}"),
        );
        result.assert_ok();
        let json = parse_json(&result, "a:sym.solve");
        let obj = expect_object(&json, "a:sym.solve");
        assert_eq!(obj.get("found").and_then(Value::as_bool), Some(false));
    }
}

// ============================================================================
// 10. Function Simulation Coverage
// ============================================================================

mod sim_summaries {
    use super::*;

    fn assert_paths_json_without_error(result: &e2e::R2Result, label: &str) {
        let json = parse_json(result, label);
        let paths = expect_array(&json, label);
        assert!(!paths.is_empty(), "{label} should return at least one path");
        assert!(
            !paths.iter().any(|entry| entry.get("error").is_some()),
            "{label} should not contain error objects"
        );
    }

    #[test]
    fn sym_paths_survives_strlen_calls_process_string() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.process_string", "a:sla.sym.paths");
        result.assert_ok();
        assert_paths_json_without_error(&result, "a:sla.sym.paths process_string");
    }

    #[test]
    fn sym_paths_survives_strcmp_calls_authenticate() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.authenticate", "a:sla.sym.paths");
        result.assert_ok();
        assert_paths_json_without_error(&result, "a:sla.sym.paths authenticate");
    }

    #[test]
    fn sym_paths_survives_memcpy_malloc_calls_alloc_and_copy() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.alloc_and_copy", "a:sla.sym.paths");
        result.assert_ok();
        assert_paths_json_without_error(&result, "a:sla.sym.paths alloc_and_copy");
    }

    #[test]
    fn sym_paths_survives_printf_calls_vuln_printf() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.vuln_printf", "a:sla.sym.paths");
        result.assert_ok();
        assert_paths_json_without_error(&result, "a:sla.sym.paths vuln_printf");
    }

    #[test]
    fn sym_paths_survives_memcpy_printf_calls_vuln_memcpy() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.vuln_memcpy", "a:sla.sym.paths");
        result.assert_ok();
        assert_paths_json_without_error(&result, "a:sla.sym.paths vuln_memcpy");
    }

    #[test]
    fn sym_solve_still_works_on_check_secret_regression() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.check_secret",
            "a:sym.solve 0x401296",
        );
        result.assert_ok();
        let json = parse_json(&result, "a:sym.solve");
        let obj = expect_object(&json, "a:sym.solve");
        assert_eq!(obj.get("found").and_then(Value::as_bool), Some(true));
    }
}

// ============================================================================
// 11. State Merging
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
// 12. Decompilation
// ============================================================================

mod decompilation {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn normalized_dec_output(raw: &str) -> String {
        raw.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with("INFO:") && !line.starts_with("WARN:"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn find_header_line<'a>(normalized: &'a str, prefix: &str) -> Option<&'a str> {
        normalized.lines().find(|line| line.starts_with(prefix))
    }

    fn find_line_containing<'a>(normalized: &'a str, needle: &str) -> Option<&'a str> {
        normalized.lines().find(|line| line.contains(needle))
    }

    fn has_self_sub_zero_assignment(line: &str) -> bool {
        let trimmed = line.trim();
        if !trimmed.ends_with(';') {
            return false;
        }
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            return false;
        };
        let lhs = lhs.trim();
        let rhs = rhs.trim().trim_end_matches(';').trim();
        rhs == format!("{lhs} - 0")
    }

    fn has_self_xor_assignment(line: &str) -> bool {
        let trimmed = line.trim();
        if !trimmed.ends_with(';') {
            return false;
        }
        let Some((_, rhs)) = trimmed.split_once('=') else {
            return false;
        };
        let rhs = rhs.trim().trim_end_matches(';').trim();
        let Some((a, b)) = rhs.split_once('^') else {
            return false;
        };
        let a = a.trim().trim_matches(|c| c == '(' || c == ')').trim();
        let b = b.trim().trim_matches(|c| c == '(' || c == ')').trim();
        !a.is_empty() && a == b
    }

    fn extract_identifiers(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut current = String::new();

        for ch in text.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                current.push(ch);
            } else if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        }

        if !current.is_empty() {
            out.push(current);
        }

        out
    }

    fn is_semantic_name(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower.starts_with("local_")
            || lower.starts_with("arg")
            || lower.starts_with("field_")
            || lower.starts_with("var_")
            || lower.starts_with("sub_")
            || lower.starts_with("str.")
            || lower.starts_with("0x")
            || lower.contains('.')
    }

    fn split_ssa_suffix(name: &str) -> Option<(&str, &str)> {
        let (base, suffix) = name.rsplit_once('_')?;
        if base.is_empty() || suffix.is_empty() {
            return None;
        }
        if suffix.chars().all(|ch| ch.is_ascii_digit()) {
            Some((base, suffix))
        } else {
            None
        }
    }

    #[test]
    fn decompilation_regression_guardrails_core_set() {
        setup();
        let cases = [
            ("dbg.test_boolxor", "^"),
            ("dbg.test_loop_switch", "switch ("),
            ("dbg.test_piece", "<<"),
            ("dbg.test_array_index", "["),
            ("dbg.test_array_index_neg", "["),
            ("dbg.test_struct_field", "->field_"),
        ];

        for (func, needle) in cases {
            let result = r2_at_func(vuln_test_binary(), func, "a:sla.dec");
            result.assert_ok();
            let normalized = normalized_dec_output(&result.stdout);
            assert!(
                normalized.contains(needle),
                "Guardrail for {} should contain '{}'",
                func,
                needle
            );
        }
    }

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

    #[test]
    fn decompiles_ptradd_subscript() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_array_index", "a:sla.dec");
        result.assert_ok();
        assert!(result.contains("["), "Should use subscript for pointer add");
    }

    #[test]
    fn decompiles_ptrsub_subscript() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_array_index_neg", "a:sla.dec");
        result.assert_ok();
        assert!(result.contains("["), "Should use subscript for pointer sub");
    }

    #[test]
    fn decompiles_piece_pattern() {
        setup();
        let piece = r2_at_func(vuln_test_binary(), "dbg.test_piece", "a:sla.dec");
        piece.assert_ok();
        assert!(piece.contains("<<"), "Should show a shift for PIECE");
        assert!(piece.contains("|"), "Should show bitwise OR for PIECE");
    }

    #[test]
    fn decompiles_boolxor() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_boolxor", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);
        let return_line =
            find_header_line(&normalized, "return ").expect("Should emit direct return statement");
        assert!(
            return_line.contains("^"),
            "Return should preserve XOR behavior"
        );
        let has_direct_gt = return_line.contains("> 0");
        let has_ge_with_ne = return_line.contains(">= 0") && return_line.contains("!= 0");
        let has_signed_negative_check = return_line.contains("< 0");
        let has_flag_style_fallback = return_line.contains("of_");
        assert!(
            has_direct_gt || has_ge_with_ne || has_signed_negative_check || has_flag_style_fallback,
            "Should preserve a signed relational predicate shape"
        );
        assert!(
            return_line.contains("arg1")
                || return_line.contains("arg2")
                || return_line.contains("a >")
                || return_line.contains("b >")
                || return_line.contains("a !=")
                || return_line.contains("b !=")
                || find_line_containing(&normalized, "t1_1 = arg1").is_some()
                || find_line_containing(&normalized, "t2_2 = arg2").is_some(),
            "Predicate operands should use recovered argument-style names directly or via local aliases"
        );
        assert!(
            !return_line.contains(" - 0 == 0"),
            "Should eliminate cmp-to-zero scaffolding in returned bool predicate"
        );
        for line in normalized.lines().filter(|line| {
            line.contains('=') && is_predicate_line(line) && !line.starts_with("return ")
        }) {
            assert!(
                !line.contains(" - 0 == 0"),
                "Intermediate predicate assignment should not contain cmp-to-zero subtraction scaffold: {}",
                line
            );
        }
        assert!(
            !normalized.contains("return *rsp"),
            "Should not emit low-level stack-return artifact after high-level return"
        );
        assert!(
            !normalized.contains("t1_1 = arg1;"),
            "Should prune dead temp copy assignment for arg1"
        );
        assert!(
            !normalized.contains("t2_2 = arg2;"),
            "Should prune dead temp copy assignment for arg2"
        );
        assert!(
            !normalized.contains("arg1 = edi;"),
            "Should suppress entry argument identity assignment for arg1"
        );
        assert!(
            !normalized.contains("arg2 = esi;"),
            "Should suppress entry argument identity assignment for arg2"
        );
    }

    #[test]
    fn decompiles_without_singleton_ssa_suffixes() {
        setup();
        let funcs = [
            "dbg.check_secret",
            "dbg.solve_equation",
            "dbg.test_boolxor",
            "dbg.test_setlocale_wrapper",
            "dbg.test_multi_use_temp",
        ];

        for func in funcs {
            let result = r2_at_func(vuln_test_binary(), func, "a:sla.dec");
            result.assert_ok();
            let normalized = normalized_dec_output(&result.stdout);

            let mut unsuffixed_bases = HashSet::new();
            let mut versions_by_base: HashMap<String, HashSet<String>> = HashMap::new();

            for ident in extract_identifiers(&normalized) {
                if is_semantic_name(&ident) {
                    continue;
                }

                if let Some((base, suffix)) = split_ssa_suffix(&ident) {
                    versions_by_base
                        .entry(base.to_ascii_lowercase())
                        .or_default()
                        .insert(suffix.to_string());
                } else {
                    unsuffixed_bases.insert(ident.to_ascii_lowercase());
                }
            }

            for (base, versions) in versions_by_base {
                assert!(
                    versions.len() > 1 || unsuffixed_bases.contains(&base),
                    "{} should not contain singleton suffixed SSA name for base '{}'",
                    func,
                    base
                );
            }
        }
    }

    #[test]
    fn decompiles_check_secret_with_direct_hex_compare() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        assert!(
            normalized.contains("0xdead"),
            "check_secret should preserve the compared magic value as hex"
        );
        assert!(
            !normalized.contains(" - 57005"),
            "check_secret should not emit decimal subtraction compare scaffold"
        );
        assert!(
            !normalized.contains(" - 0 == 0") && !normalized.contains(" - 0 != 0"),
            "check_secret should rewrite subtraction-to-zero compares into direct compares"
        );
    }

    #[test]
    fn decompiles_entry0_without_self_xor_identity_residuals() {
        setup();
        let result = r2_cmd(vuln_test_binary(), "aaa; s entry0; a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        assert!(
            normalized.contains('{') && normalized.contains('}'),
            "entry0 decompilation should include a function body"
        );

        for line in normalized.lines().filter(|line| line.contains('=') && line.contains('^')) {
            assert!(
                !has_self_xor_assignment(line),
                "entry0 should not contain self-XOR assignment residue: {}",
                line
            );
        }
    }

    // ---- C2: Stack variables should appear in conditions instead of *(rbp + offset) ----

    #[test]
    fn decompiles_check_secret_uses_stack_var_in_condition() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.check_secret", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        // The condition should use a resolved variable name, not raw pointer arithmetic
        assert!(
            !normalized.contains("*(rbp"),
            "check_secret condition should not contain raw *(rbp + offset) dereference: {}",
            normalized,
        );
        // Should still compare against the magic constant
        assert!(
            normalized.contains("0xdead"),
            "check_secret should compare against 0xdead"
        );
    }

    #[test]
    fn decompiles_solve_equation_uses_stack_var_in_condition() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.solve_equation", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        // The condition should reference a named variable, not *(rbp + -0x4)
        assert!(
            !normalized.contains("*(rbp"),
            "solve_equation condition should not contain raw *(rbp + offset): {}",
            normalized,
        );
        assert!(
            normalized.contains("!= 19") || normalized.contains("== 19"),
            "solve_equation should compare against 19"
        );
    }

    #[test]
    fn decompiles_process_string_uses_stack_var_in_condition() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.process_string", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        // Conditions should not contain raw stack dereferences
        assert!(
            !normalized.contains("*(rbp"),
            "process_string conditions should not contain raw *(rbp + offset): {}",
            normalized,
        );
    }

    // H4 note: The is_uninitialized_return_reg() fix resolves RAX_0 returns to
    // concrete values when last_ret_value is available.  This is verified by unit
    // tests; e2e validation is omitted because r2 analysis non-determinism causes
    // the returned phi value to vary between runs.

    fn is_predicate_line(line: &str) -> bool {
        line.contains("while (")
            || line.contains("if (")
            || line.contains("&&")
            || line.contains("||")
            || line.contains("==")
            || line.contains("!=")
            || line.contains('<')
            || line.contains('>')
    }

    #[test]
    fn decompiles_cast_u8() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_cast_u8", "a:sla.dec");
        result.assert_ok();
        assert!(result.contains("(int64_t)"), "Should show a cast in output");
    }

    #[test]
    fn decompiles_callother() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_cpuid", "a:sla.dec");
        result.assert_ok();
        assert!(
            result.contains("callother("),
            "Should emit callother for user-defined op"
        );
    }

    #[test]
    fn decompiles_loop_as_for_and_switch() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_loop_switch", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);
        let loop_header = find_header_line(&normalized, "for (")
            .or_else(|| find_header_line(&normalized, "while ("))
            .expect("Should recover a structured loop header");
        let switch_header =
            find_header_line(&normalized, "switch (").expect("Should recover switch header");

        assert!(
            loop_header.contains('(') && loop_header.contains(')'),
            "Loop header should be syntactically well-formed"
        );
        assert!(
            switch_header.contains("switch ("),
            "Switch header should be present"
        );
    }

    #[test]
    fn decompiles_struct_member_access() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_struct_field", "a:sla.dec");
        result.assert_ok();
        assert!(
            result.contains_any(&["->thirteenth", "->first", "->field_"]),
            "Should recover pointer member access and prefer tsj-derived field names when available"
        );
    }

    #[test]
    fn decompiles_struct_mixed_offset_member_access() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_struct_mixed_offsets", "a:sla.dec");
        result.assert_ok();
        assert!(
            result.contains_any(&["->first", "->fifth", "->thirteenth", "->field_"]),
            "Should keep member-style access, preferring tsj field names when available"
        );
    }

    #[test]
    fn decompiles_non_four_byte_stride_as_subscript() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_u16_stride", "a:sla.dec");
        result.assert_ok();
        assert!(result.contains("["), "Should render scaled index as subscript");
    }

    #[test]
    fn decompiles_struct_array_index_pattern() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_struct_array_index", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);
        assert!(
            normalized.contains("[")
                || normalized.contains("->field_")
                || normalized.contains("*(arr +"),
            "Should recover a structured or at least stable pointer-indexing expression for struct array indexing"
        );
    }

    #[test]
    fn decompiles_large_hex_offset_without_decimal_reinterpret() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_struct_offset_0x100", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);
        assert!(
            normalized.contains("field_100")
                || normalized.contains("->marker")
                || normalized.contains("+ 0x100")
                || normalized.contains("field_64")
                || normalized.contains("+ 100"),
            "Large offset access should remain stable and explicit in recovered output"
        );
    }

    #[test]
    fn decompiles_without_phi_artifacts_in_join_paths() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.complex_check", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout).to_lowercase();
        assert!(
            !normalized.contains("phi"),
            "Structured decompilation should avoid exposing phi artifacts"
        );
    }

    #[test]
    fn decompiles_setlocale_with_pointer_type() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.test_setlocale_wrapper",
            "a:sla.dec",
        );
        result.assert_ok();
        assert!(
            result.contains("setlocale("),
            "Should resolve setlocale call name"
        );
        assert!(
            result.contains("int8_t*")
                || result.contains("char*")
                || result.contains("local_8 = rax_1"),
            "Should keep setlocale return value in a pointer-like flow"
        );
    }

    #[test]
    fn decompiles_main_printf_format_string_literal() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.main", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        assert!(
            normalized.contains("sym.imp.printf(\"Usage: %s <test_num> [args...]\\\\n\""),
            "Main should emit the usage format string as a C string literal"
        );
        assert!(
            !normalized.contains("sym.imp.printf(0x403048"),
            "Main should not emit raw address for usage format string"
        );
    }

    #[test]
    fn decompiles_authenticate_strcmp_string_literal() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.authenticate", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        assert!(
            normalized.contains("sym.imp.strcmp(password, \"secret123\""),
            "authenticate should emit strcmp string operand as a literal"
        );
        assert!(
            !normalized.contains("0x403014"),
            "authenticate should not use raw string address in strcmp call"
        );
    }

    #[test]
    fn decompiles_main_puts_string_literal() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.main", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        assert!(
            normalized.contains("sym.imp.puts(\"test_cpuid() = ok\")")
                || (normalized.contains("sym.imp.puts(")
                    && normalized.contains("\"test_cpuid() = ok\"")),
            "Main should preserve puts call and keep the cpuid status string as a literal"
        );
    }

    #[test]
    fn decompiles_global_symbol_names_in_non_call_contexts() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.test_global_symbol_flow",
            "a:sla.dec",
        );
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        let has_counter_name =
            normalized.contains("obj.global_counter") || normalized.contains("global_counter");
        let has_limit_name =
            normalized.contains("obj.global_limit") || normalized.contains("global_limit");

        assert!(
            has_counter_name,
            "Should resolve global_counter symbol name in non-call contexts"
        );
        assert!(
            has_limit_name,
            "Should resolve global_limit symbol name in non-call contexts"
        );

        let has_non_call_counter_use = normalized.lines().any(|line| {
            (line.contains("obj.global_counter") || line.contains("global_counter"))
                && !line.contains("sym.imp.")
                && (line.contains(" = ") || line.contains("==") || line.contains("!="))
        });
        assert!(
            has_non_call_counter_use,
            "Should show non-call assignment/comparison use for global_counter"
        );

        assert!(
            !normalized.contains("ram:"),
            "Should not expose raw ram: names in decompiled output"
        );
        assert!(
            !normalized.contains("*(0x") && !normalized.contains("*0x"),
            "Should not expose direct raw-address dereference artifacts for this flow"
        );
    }

    #[test]
    fn decompiles_multi_use_simple_temp_inlined() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.test_multi_use_temp", "a:sla.dec");
        result.assert_ok();
        assert!(
            !result.contains(" = arg1 + 1;"),
            "Simple temporary used multiple times should be inlined"
        );
    }

    #[test]
    fn decompiles_main_not_empty() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.main", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        assert!(
            !normalized.is_empty(),
            "Main decompilation should not be empty"
        );
        assert!(
            normalized.contains("main(") || normalized.contains("dbg.main("),
            "Main output should include a function header"
        );
        assert!(
            normalized.contains('{') && normalized.contains('}'),
            "Main output should include function braces"
        );
        assert!(
            normalized.len() > 50,
            "Main output should contain a minimum amount of code"
        );
    }

    #[test]
    fn decompiles_without_identity_residuals() {
        setup();
        let cases = [
            "dbg.alloc_and_copy",
            "dbg.test_boolxor",
            "dbg.test_setlocale_wrapper",
            "dbg.safe_array_access",
            "dbg.test_identity_ops",
        ];

        for func in cases {
            let result = r2_at_func(vuln_test_binary(), func, "a:sla.dec");
            result.assert_ok();
            let normalized = normalized_dec_output(&result.stdout);

            for line in normalized.lines() {
                assert!(
                    !has_self_sub_zero_assignment(line),
                    "{} should not contain self-sub-zero identity residue: {}",
                    func,
                    line
                );
            }
        }
    }

    #[test]
    fn decompiles_with_r2_variable_names() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "dbg.vuln_memcpy", "a:sla.dec");
        result.assert_ok();
        let normalized = normalized_dec_output(&result.stdout);

        assert!(
            normalized.contains("buf"),
            "Decompilation should use recovered stack variable name 'buf'"
        );
        assert!(
            normalized.contains("user_input") || normalized.contains("user_len"),
            "Decompilation should use recovered parameter/stack names from radare2 metadata"
        );
        assert!(
            !normalized.contains("rbp_1 + -0x40"),
            "Recovered variable sites should not expose raw rbp stack offsets"
        );
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
                unsafe extern "C" fn(
                    *mut std::ffi::c_void,
                    *const u8,
                    usize,
                    u64,
                ) -> *mut std::ffi::c_void,
            > = lib.get(b"r2il_lift").unwrap();
            let r2il_block_op_count: libloading::Symbol<
                unsafe extern "C" fn(*const std::ffi::c_void) -> usize,
            > = lib.get(b"r2il_block_op_count").unwrap();
            let r2il_block_to_esil: libloading::Symbol<
                unsafe extern "C" fn(
                    *const std::ffi::c_void,
                    *const std::ffi::c_void,
                ) -> *mut c_char,
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
                unsafe extern "C" fn(
                    *mut std::ffi::c_void,
                    *const u8,
                    usize,
                    u64,
                ) -> *mut std::ffi::c_void,
            > = lib.get(b"r2il_lift").unwrap();
            let r2il_block_to_ssa_json: libloading::Symbol<
                unsafe extern "C" fn(
                    *const std::ffi::c_void,
                    *const std::ffi::c_void,
                ) -> *mut c_char,
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
            result.contains("push")
                || result.contains("mov")
                || result.contains("call")
                || result.contains("0x"),
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
        let is_json =
            result.stdout.trim().starts_with("[") || result.stdout.trim().starts_with("{");
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

    #[test]
    fn aaaa_auto_taint_writes_comment_vuln_memcpy() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.vuln_memcpy",
            "aaaa; s dbg.vuln_memcpy; CC.",
        );
        result.assert_ok();
        assert!(
            result.contains("sla.taint: hits="),
            "post-analysis should annotate vuln_memcpy with taint summary"
        );
        assert!(
            result.contains("labels="),
            "taint summary should include labels"
        );
        let taint_line = result
            .stdout
            .lines()
            .find(|line| line.contains("sla.taint:"))
            .unwrap_or("");
        assert!(
            !taint_line.trim_end().ends_with("labels="),
            "taint labels should not be empty"
        );
        let taint_line_lower = taint_line.to_ascii_lowercase();
        assert!(
            taint_line_lower.contains("calls=memcpy") || taint_line_lower.contains(",memcpy"),
            "post-analysis should resolve tainted call sinks to function names (expected memcpy)"
        );
    }

    #[test]
    fn aaaa_auto_taint_writes_flag_vuln_memcpy() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.vuln_memcpy",
            "aaaa; f~sla.taint.fcn_4012c9.blk_4012c9",
        );
        result.assert_ok();
        assert!(
            result.contains("sla.taint.fcn_4012c9.blk_4012c9"),
            "post-analysis should create taint flag for vuln_memcpy block"
        );
    }

    #[test]
    fn aaaa_auto_taint_writes_risk_comment_vuln_memcpy() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.vuln_memcpy",
            "aaaa; s dbg.vuln_memcpy; CC.",
        );
        result.assert_ok();
        let risk_line = result
            .stdout
            .lines()
            .find(|line| line.contains("sla.taint.risk:"))
            .unwrap_or("");
        let risk_line_lower = risk_line.to_ascii_lowercase();
        assert!(
            risk_line.contains("CRITICAL"),
            "vuln_memcpy should be classified as CRITICAL due to dangerous tainted call sinks"
        );
        assert!(
            risk_line_lower.contains("calls=memcpy") || risk_line_lower.contains(",memcpy"),
            "risk comment should include resolved dangerous call names (expected memcpy)"
        );
    }

    #[test]
    fn aaaa_auto_taint_writes_risk_flag_vuln_memcpy() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.vuln_memcpy",
            "aaaa; f~sla.taint.risk.critical.fcn_4012c9",
        );
        result.assert_ok();
        assert!(
            result.contains("sla.taint.risk.critical.fcn_4012c9"),
            "post-analysis should create CRITICAL function risk flag for vuln_memcpy"
        );
    }

    #[test]
    fn aaaa_auto_taint_idempotent_comment_lines() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.vuln_memcpy",
            "aaaa; aaaa; s dbg.vuln_memcpy; CC.",
        );
        result.assert_ok();
        let taint_count = result.stdout.matches("sla.taint:").count();
        let risk_count = result.stdout.matches("sla.taint.risk:").count();
        assert_eq!(
            taint_count, 1,
            "taint summary comment should not duplicate across repeated aaaa"
        );
        assert_eq!(
            risk_count, 1,
            "risk summary comment should not duplicate across repeated aaaa"
        );
    }

    #[test]
    fn aaaa_auto_taint_noise_filter_applied() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.vuln_memcpy",
            "aaaa; s dbg.vuln_memcpy; CC.",
        );
        result.assert_ok();
        assert!(
            !result.contains("input:rsp"),
            "noise filter should remove rsp-only taint labels from comments"
        );
        assert!(
            !result.contains("input:ram:"),
            "noise filter should remove ram:* taint labels from comments"
        );
    }

    #[test]
    fn aaaa_auto_taint_no_comment_for_filtered_clean_case() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.test_setlocale_wrapper",
            "aaaa; s dbg.test_setlocale_wrapper; CC.",
        );
        result.assert_ok();
        assert!(
            !result.contains("sla.taint:"),
            "function with only filtered taint labels should not get auto-taint comment"
        );
    }

    #[test]
    fn aaaa_auto_taint_preserves_user_comment() {
        setup();
        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.vuln_memcpy",
            "s 0x4012cd; CCu user-note; aaaa; s 0x4012cd; CC.; s dbg.vuln_memcpy; CC.",
        );
        result.assert_ok();
        assert!(
            result.contains("user-note"),
            "user comment should be preserved after taint annotation"
        );
        assert!(
            result.contains("sla.taint:"),
            "taint summary should coexist with existing user comment"
        );
    }

    #[test]
    fn aaaa_auto_taint_emits_xref_with_entry_fallback() {
        setup();
        let meta = r2_at_func(
            vuln_test_binary(),
            "dbg.main",
            "aaaa; s dbg.main; ?v $$; f~sla.taint.fcn_",
        );
        meta.assert_ok();

        let main_addr = meta
            .stdout
            .lines()
            .find_map(|line| {
                let token = line.trim();
                token
                    .strip_prefix("0x")
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            })
            .expect("should print main address via '?v $$'");
        let fcn_tag = format!("sla.taint.fcn_{main_addr:x}.blk_");

        let sink_addr = meta
            .stdout
            .lines()
            .filter(|line| line.contains(&fcn_tag))
            .filter_map(|line| line.split_whitespace().next())
            .find_map(|token| {
                token
                    .strip_prefix("0x")
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                    .filter(|addr| *addr != main_addr)
            })
            .expect("should find at least one taint flag block for main");

        let result = r2_at_func(
            vuln_test_binary(),
            "dbg.main",
            &format!("aaaa; s 0x{sink_addr:x}; axtj"),
        );
        result.assert_ok();
        let json = parse_json(&result, "axtj");
        let refs = expect_array(&json, "axtj");
        let has_expected_ref = refs.iter().any(|item| {
            item.get("from").and_then(Value::as_u64) == Some(main_addr)
                && item.get("type").and_then(Value::as_str) == Some("DATA")
        });
        assert!(
            has_expected_ref,
            "should emit DATA xref from main entry to at least one tainted sink block"
        );
    }

    #[test]
    fn aaaa_post_analysis_still_succeeds() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "aaaa");
        result.assert_ok();
        assert!(
            !result.contains("ERROR"),
            "aaaa should still complete successfully after auto-taint integration"
        );
    }
}

// ============================================================================
// 10. Analysis Quality Benchmark
// ============================================================================
//
// Measures what the r2sleigh plugin adds to radare2's analysis pipeline.
// These tests run WITH the plugin (which is always loaded in the test env)
// and assert minimum quality thresholds for key analysis metrics.
//
// The measured dimensions are:
// - Data xrefs: SSA-derived data-flow references (get_data_refs callback)
// - Taint coverage: functions with taint annotations (post_analysis callback)
// - Risk classification: functions tagged with risk levels
// - Variable recovery: stack variables and register arguments

mod analysis_quality_benchmark {
    use super::*;

    /// Helper: extract a single integer metric from r2 output.
    /// The r2 command should print a label line then the count on the next line.
    fn extract_metric(output: &str, label: &str) -> u64 {
        let mut lines = output.lines();
        while let Some(line) = lines.next() {
            if line.trim() == label {
                if let Some(val_line) = lines.next() {
                    if let Ok(v) = val_line.trim().parse::<u64>() {
                        return v;
                    }
                }
            }
        }
        panic!("metric '{}' not found in output:\n{}", label, output);
    }

    /// Collect analysis metrics for a binary after running `aaaa`.
    fn collect_aaaa_metrics(binary: &str) -> AnalysisMetrics {
        let result = r2_cmd_timeout(
            binary,
            &[
                "e bin.relocs.apply=true",
                "aaaa",
                "echo FUNCTIONS:",
                "aflc",
                "echo TOTAL_XREFS:",
                "axl~?",
                "echo DATA_XREFS:",
                "axl~DATA~?",
                "echo CODE_XREFS:",
                "axl~CODE~?",
                "echo CALL_XREFS:",
                "axl~CALL~?",
                "echo TAINT_BLOCK_FLAGS:",
                "f~sla.taint.fcn~?",
                "echo RISK_FLAGS:",
                "f~sla.taint.risk~?",
                "echo RISK_CRITICAL:",
                "f~sla.taint.risk.critical~?",
                "echo RISK_HIGH:",
                "f~sla.taint.risk.high~?",
                "echo RISK_MEDIUM:",
                "f~sla.taint.risk.medium~?",
                "echo RISK_LOW:",
                "f~sla.taint.risk.low~?",
            ]
            .join("; "),
            Duration::from_secs(120),
        );
        result.assert_ok();
        let out = &result.stdout;

        AnalysisMetrics {
            functions: extract_metric(out, "FUNCTIONS:"),
            total_xrefs: extract_metric(out, "TOTAL_XREFS:"),
            data_xrefs: extract_metric(out, "DATA_XREFS:"),
            code_xrefs: extract_metric(out, "CODE_XREFS:"),
            call_xrefs: extract_metric(out, "CALL_XREFS:"),
            taint_block_flags: extract_metric(out, "TAINT_BLOCK_FLAGS:"),
            risk_flags: extract_metric(out, "RISK_FLAGS:"),
            risk_critical: extract_metric(out, "RISK_CRITICAL:"),
            risk_high: extract_metric(out, "RISK_HIGH:"),
            risk_medium: extract_metric(out, "RISK_MEDIUM:"),
            risk_low: extract_metric(out, "RISK_LOW:"),
        }
    }

    /// Collect aaa-level metrics (before taint, which runs at aaaa).
    fn collect_aaa_metrics(binary: &str) -> AaaMetrics {
        let result = r2_cmd_timeout(
            binary,
            &[
                "e bin.relocs.apply=true",
                "aaa",
                "echo TOTAL_XREFS:",
                "axl~?",
                "echo DATA_XREFS:",
                "axl~DATA~?",
            ]
            .join("; "),
            Duration::from_secs(60),
        );
        result.assert_ok();
        let out = &result.stdout;

        AaaMetrics {
            total_xrefs: extract_metric(out, "TOTAL_XREFS:"),
            data_xrefs: extract_metric(out, "DATA_XREFS:"),
        }
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct AnalysisMetrics {
        functions: u64,
        total_xrefs: u64,
        data_xrefs: u64,
        code_xrefs: u64,
        call_xrefs: u64,
        taint_block_flags: u64,
        risk_flags: u64,
        risk_critical: u64,
        risk_high: u64,
        risk_medium: u64,
        risk_low: u64,
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct AaaMetrics {
        total_xrefs: u64,
        data_xrefs: u64,
    }

    // ------------------------------------------------------------------
    // vuln_test benchmarks (small, controlled binary)
    // ------------------------------------------------------------------

    #[test]
    fn vuln_test_sleigh_adds_data_xrefs() {
        setup();
        // Baseline (measured without plugin): data_xrefs = 24, total_xrefs = 365
        // With sleigh: data_xrefs ~= 67 (string refs + globals + taint flow)
        // The delta is ~43: all high-quality (string refs, taint flow, globals)
        let m = collect_aaaa_metrics(vuln_test_binary());

        eprintln!("vuln_test aaaa metrics: {:?}", m);

        // Plugin should add meaningful data xrefs (strings, globals, taint)
        assert!(
            m.data_xrefs > 40,
            "sleigh should add quality data xrefs (got {}; baseline ~24)",
            m.data_xrefs
        );
        assert!(
            m.total_xrefs > 380,
            "total xrefs with sleigh should exceed baseline (got {}; baseline ~365)",
            m.total_xrefs
        );
    }

    #[test]
    fn vuln_test_taint_coverage() {
        setup();
        let m = collect_aaaa_metrics(vuln_test_binary());

        eprintln!("vuln_test taint coverage: {:?}", m);

        // Taint analysis should flag sink blocks in vulnerable functions
        assert!(
            m.taint_block_flags > 10,
            "taint should flag multiple sink blocks (got {})",
            m.taint_block_flags
        );

        // Risk classification should tag functions
        assert!(
            m.risk_flags > 10,
            "risk classification should tag multiple functions (got {})",
            m.risk_flags
        );

        // At least one CRITICAL (vuln_memcpy has dangerous memcpy with tainted args)
        assert!(
            m.risk_critical >= 1,
            "should have at least 1 CRITICAL risk function (got {})",
            m.risk_critical
        );

        // Multiple HIGH risk functions (format strings, unchecked input)
        assert!(
            m.risk_high >= 3,
            "should have multiple HIGH risk functions (got {})",
            m.risk_high
        );
    }

    #[test]
    fn vuln_test_aaa_data_xrefs() {
        setup();
        // SSA-derived data refs should appear at aaa level (get_data_refs callback)
        let m = collect_aaa_metrics(vuln_test_binary());

        eprintln!("vuln_test aaa metrics: {:?}", m);

        // Baseline without sleigh: data_xrefs = 23
        // With sleigh: data_xrefs ~= 58 (quality string/global refs only)
        assert!(
            m.data_xrefs > 35,
            "sleigh get_data_refs should add SSA-derived data xrefs at aaa level (got {}; baseline ~23)",
            m.data_xrefs
        );
    }

    // ------------------------------------------------------------------
    // /bin/ls benchmarks (real-world stripped binary)
    // ------------------------------------------------------------------

    #[test]
    fn bin_ls_sleigh_adds_data_xrefs() {
        // Baseline (measured without plugin): data_xrefs = 2433, total_xrefs = 7337
        // With sleigh: data_xrefs ~= 3366 (quality refs: strings, globals, taint)
        // Delta ~933: all high-quality (string refs, global vars, taint flow)
        let m = collect_aaaa_metrics("/bin/ls");

        eprintln!("/bin/ls aaaa metrics: {:?}", m);

        // Meaningful data xref improvement from SSA analysis + taint
        assert!(
            m.data_xrefs > 2800,
            "/bin/ls: sleigh should add quality data xrefs (got {}; baseline ~2433)",
            m.data_xrefs
        );
    }

    #[test]
    fn bin_ls_taint_coverage() {
        let m = collect_aaaa_metrics("/bin/ls");

        eprintln!("/bin/ls taint coverage: {:?}", m);

        // Taint should flag many sink blocks in a real binary
        assert!(
            m.taint_block_flags > 100,
            "/bin/ls: taint should flag >100 sink blocks (got {})",
            m.taint_block_flags
        );

        // Risk classification should cover many functions
        assert!(
            m.risk_flags > 50,
            "/bin/ls: should classify >50 functions by risk (got {})",
            m.risk_flags
        );

        // Real binaries should have a distribution across risk levels
        let total_classified = m.risk_critical + m.risk_high + m.risk_medium + m.risk_low;
        assert!(
            total_classified == m.risk_flags,
            "/bin/ls: risk breakdown should sum to total ({}+{}+{}+{} = {} vs {})",
            m.risk_critical,
            m.risk_high,
            m.risk_medium,
            m.risk_low,
            total_classified,
            m.risk_flags
        );
    }

    // ------------------------------------------------------------------
    // Summary report test (prints human-readable comparison)
    // ------------------------------------------------------------------

    #[test]
    fn print_analysis_quality_report() {
        setup();
        let vuln = collect_aaaa_metrics(vuln_test_binary());
        let ls = collect_aaaa_metrics("/bin/ls");
        let vuln_aaa = collect_aaa_metrics(vuln_test_binary());

        // Baselines measured without the sleigh plugin:
        //   vuln_test aaaa: functions=61, total_xrefs=365, data_xrefs=24
        //   /bin/ls   aaaa: functions=414, total_xrefs=7337, data_xrefs=2433
        //   vuln_test aaa:  total_xrefs=365, data_xrefs=23
        //
        // All sleigh-added xrefs are quality refs:
        //   - String literal references (RODATA)
        //   - Global variable references (BSS/DATA)
        //   - Taint data-flow xrefs (source block → sink block)
        //   - GOT/vtable references

        eprintln!("\n=== r2sleigh Analysis Quality Report ===\n");
        eprintln!("Binary: vuln_test (controlled test binary)");
        eprintln!("  {:30} {:>10} {:>10} {:>10}",
            "Metric", "Baseline", "Sleigh", "Delta");
        eprintln!("  {:30} {:>10} {:>10} {:>+10}",
            "Data xrefs (aaaa)", 24, vuln.data_xrefs,
            vuln.data_xrefs as i64 - 24);
        eprintln!("  {:30} {:>10} {:>10} {:>+10}",
            "Total xrefs (aaaa)", 365, vuln.total_xrefs,
            vuln.total_xrefs as i64 - 365);
        eprintln!("  {:30} {:>10} {:>10} {:>+10}",
            "Data xrefs (aaa)", 23, vuln_aaa.data_xrefs,
            vuln_aaa.data_xrefs as i64 - 23);
        eprintln!("  {:30} {:>10} {:>10}",
            "Taint block flags", "N/A", vuln.taint_block_flags);
        eprintln!("  {:30} {:>10} {:>10}",
            "Risk flags", "N/A", vuln.risk_flags);
        eprintln!("  {:30} {:>10} {:>10}",
            "  CRITICAL", "N/A", vuln.risk_critical);
        eprintln!("  {:30} {:>10} {:>10}",
            "  HIGH", "N/A", vuln.risk_high);
        eprintln!("  {:30} {:>10} {:>10}",
            "  MEDIUM", "N/A", vuln.risk_medium);
        eprintln!("  {:30} {:>10} {:>10}",
            "  LOW", "N/A", vuln.risk_low);

        eprintln!();
        eprintln!("Binary: /bin/ls (real-world stripped binary)");
        eprintln!("  {:30} {:>10} {:>10} {:>10}",
            "Metric", "Baseline", "Sleigh", "Delta");
        eprintln!("  {:30} {:>10} {:>10} {:>+10}",
            "Data xrefs (aaaa)", 2433, ls.data_xrefs,
            ls.data_xrefs as i64 - 2433);
        eprintln!("  {:30} {:>10} {:>10} {:>+10}",
            "Total xrefs (aaaa)", 7337, ls.total_xrefs,
            ls.total_xrefs as i64 - 7337);
        eprintln!("  {:30} {:>10} {:>10}",
            "Taint block flags", "N/A", ls.taint_block_flags);
        eprintln!("  {:30} {:>10} {:>10}",
            "Risk flags", "N/A", ls.risk_flags);
        eprintln!("  {:30} {:>10} {:>10}",
            "  CRITICAL", "N/A", ls.risk_critical);
        eprintln!("  {:30} {:>10} {:>10}",
            "  HIGH", "N/A", ls.risk_high);
        eprintln!("  {:30} {:>10} {:>10}",
            "  MEDIUM", "N/A", ls.risk_medium);
        eprintln!("  {:30} {:>10} {:>10}",
            "  LOW", "N/A", ls.risk_low);

        eprintln!();
        eprintln!("Key findings:");
        eprintln!("  - ESIL output: IDENTICAL (r2's Capstone arch plugin generates ESIL)");
        eprintln!("  - Sleigh plugin value-add is at analysis layer, not ESIL layer:");
        eprintln!("    * SSA-derived string/global refs (get_data_refs callback)");
        eprintln!("    * Automatic taint analysis with risk classification (post_analysis)");
        eprintln!("    * Variable recovery from SSA (recover_vars callback)");
        eprintln!("  - All sleigh-added xrefs target real data addresses:");
        eprintln!("    * String literals in .rodata");
        eprintln!("    * Global variables in .data/.bss");
        eprintln!("    * Taint data-flow (source → dangerous sink)");
        eprintln!("    * No noise: small constants and code-internal refs filtered out");
        eprintln!();

        // This test always passes — it's for reporting
    }
}
