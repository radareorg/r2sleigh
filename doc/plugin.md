radare2 Plugin
==============

Architecture
------------

The r2sleigh radare2 plugin consists of two layers:

1. Rust cdylib (libr2sleigh_plugin.so) -- exports C-ABI functions
2. C wrapper (r_anal_sleigh.c) -- implements RAnalPlugin/RArchPlugin

Architecture Detection
----------------------

Reads anal.arch and anal.bits from radare2:
- x86 + 64 bits -> x86-64
- x86 + 32 bits -> x86
- arm -> arm
- mips -> mips

Override with: a:sla.arch x86-64

Plugin Callbacks
----------------

sleigh_op: Lifts instructions during aaa. Generates ESIL.
sleigh_recover_vars: Provides SSA-derived variables for afva.
sleigh_analyze_fcn: Per-function SSA analysis after af.
sleigh_get_data_refs: Def-use xrefs after aar.
sleigh_post_analysis: Auto-taint + signature/CC write-back during aaaa.

Command Reference
-----------------

Instruction-Level:
- a:sla -- Status and help
- a:sla.info -- Architecture info
- a:sla.arch [name] -- Get/set architecture
- a:sla.json -- R2IL ops as JSON
- a:sla.regs -- Registers read/written
- a:sla.mem -- Memory accesses
- a:sla.vars -- All varnodes
- a:sla.ssa -- SSA for instruction
- a:sla.defuse -- Def-use analysis

Function-Level:
- a:sla.ssa.func -- Function SSA with phi nodes
- a:sla.ssa.func.opt -- Optimized function SSA
- a:sla.defuse.func -- Function-wide def-use
- a:sla.dom -- Dominator tree
- a:sla.cfg -- ASCII CFG
- a:sla.cfg.json -- CFG as JSON
- a:sla.taint -- Taint analysis
- a:sla.sym -- Symbolic execution summary
- a:sla.sym.paths -- Path exploration
- a:sla.slice [var] -- Backward slice
- a:sla.dec -- Decompile to C

Both a:sla and a:sleigh prefixes work.

Configuration
-------------

SLEIGH_TAINT_MAX_BLOCKS: Max blocks for auto-taint. Default 200.
SLEIGH_SIG_WRITEBACK_MAX_BLOCKS: Max blocks for automatic signature/CC write-back. Default 200.
SLEIGH_SIG_MIN_CONFIDENCE: Minimum confidence for signature overwrite. Default 70.
SLEIGH_CC_MIN_CONFIDENCE: Minimum confidence for calling convention overwrite. Default 80.
SLEIGH_CALLER_PROP_MAX_CALLEES: Max propagated callees per `aaaa` run. Default 128.
SLEIGH_CALLER_PROP_MAX_CALLERS_PER_CALLEE: Max direct callers reanalyzed per callee. Default 32.
SLEIGH_CALLER_PROP_MAX_CALLERS_TOTAL: Max caller reanalysis updates per `aaaa` run. Default 256.

Automatic Signature Write-Back (aaaa)
-------------------------------------

During `aaaa`, the plugin also performs function signature + calling convention
write-back for x86/x86-64 functions:

- Builds SSA and infers return/parameter types.
- Applies inferred signature via direct `RAnal` update first (`r_anal_str_to_fcn`), then verifies from type DB (`r_type_func_*`); falls back to `afs` only when API apply is unverified.
- Applies inferred calling convention via direct function update first (`fcn->callconv`), verifies on function state, and falls back to `afc` only when API apply is unverified.
- Confidence-gated overwrite: signature `>= 70`, calling convention `>= 80`.
- Practical consistency check:
  - `afcfj` is validated against inferred return/args.
  - `afij.calltype` is validated when CC write-back was applied.
  - `afij.signature` drift is tracked and logged (best-effort, non-fatal).
- After verified signature apply, direct caller xrefs are propagated in a
  targeted pass:
  - xref scope: direct `CALL/CODE/JUMP` refs only.
  - caller reanalysis: type-match + `afva` var recovery.
  - bounded by callee/per-callee/total caller caps (non-fatal when exceeded).
  - each caller function is updated at most once per `aaaa` run.
- Propagation metrics are logged in summary (`prop_*`) with
  `sample_callees=` trace for up to 5 triggered callees.
- Write-back metrics include apply path counters (`sig_api_apply_ok`,
  `sig_api_verify_fail`, `sig_cmd_fallback_attempted`, `sig_cmd_apply_ok`,
  `sig_cmd_apply_fail`, `cc_api_apply_ok`, `cc_api_verify_fail`,
  `cc_cmd_fallback_attempted`, `cc_cmd_apply_ok`, `cc_cmd_apply_fail`).
- Preserves existing function names (no rename during write-back).
- Skips functions above `SLEIGH_SIG_WRITEBACK_MAX_BLOCKS`.
