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
- riscv + 64 bits -> riscv64
- riscv + 32 bits -> riscv32
- mips -> mips

Override with: a:sla.arch x86-64

Plugin Callbacks
----------------

sleigh_op: Lifts instructions during aaa. Generates ESIL.
sleigh_recover_vars: Provides SSA-derived variables for afva.
sleigh_analyze_fcn: Per-function SSA analysis after af.
sleigh_get_data_refs: Def-use xrefs after aar.
sleigh_post_analysis: Auto-taint during aaaa.

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

Instruction Export Path
-----------------------

Instruction-level plugin renderers now use the shared `r2sleigh-export`
pipeline internally:

- `r2il_block_op_json_named`
- `r2il_block_to_esil`
- `r2il_block_to_ssa_json`
- `r2il_block_defuse_json`
- `r2dec_block`

This keeps CLI and plugin output logic aligned while preserving plugin ABI.
The external C-ABI signatures are unchanged.

The shared action/format policy is:

- `lift`: `json`, `text`, `esil`, `r2cmd`
- `ssa`: `json`, `text`
- `defuse`: `json`, `text`
- `dec`: `c_like`, `json`, `text`

Endianness Compatibility
------------------------

- `r2il_is_big_endian(ctx)` remains ABI-stable.
- It now derives from `arch.memory_endianness` via legacy shim mapping.
- New canonical endianness fields live in `ArchSpec` (`instruction_endianness`, `memory_endianness`).

Configuration
-------------

`a:sla.mem` JSON is backward compatible and keeps legacy keys:

- `addr`
- `size`
- `write`

When available, it also emits additive memory semantics/topology fields:

- `ordering`
- `atomic_kind`
- `guarded`
- `permissions`
- `range`
- `bank_id`
- `segment_id`
- `memory_class`

SLEIGH_TAINT_MAX_BLOCKS: Max blocks for auto-taint. Default 200.
