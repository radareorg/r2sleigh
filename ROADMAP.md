r2sleigh Roadmap
================

> Vision: r2sleigh is not a separate plugin the user needs to know about.
> It is the **analysis brain** of radare2 — transparently lifting, typing,
> decompiling, tainting, and solving every function the user touches.
> The user runs `aaa`, `a:sla.dec`, or just browses code, and the best
> analysis in the industry happens automatically behind the scenes.

Current State (Feb 2026)
-------------------------

~200 tests passing across 8 crates. 20+ plugin commands working in radare2.

Working features:
- 60+ R2IL opcodes from Ghidra Sleigh specifications
- Full SSA pipeline: CFG, dominator tree, phi nodes, optimization (SCCP, DCE, CSE, copy-prop, inst-combine)
- Z3-backed symbolic execution with path exploration
- SSA-based taint analysis with automatic radare2 integration during aaaa
- Decompiler producing C code with expression folding, predicate simplification, for-loops, switches, string literals, and symbol resolution
- Constraint-based type inference with struct/signature support
- Backward slicing
- 20+ radare2 plugin commands with automatic analysis hooks
- Deep integration callbacks: `analyze_fcn`, `recover_vars`, `get_data_refs`, `post_analysis`

Supported architectures: x86, x86-64, ARM, MIPS.

Planned Features
----------------

### Phase 1 — Seamless r2 Integration (make the seams invisible)

The user should never feel they are using a separate tool. r2sleigh must
consume everything radare2 already knows and push results back into r2's
native data structures so every existing r2 command benefits.

| # | Feature | Description | Effort | Impact |
|---|---------|-------------|--------|--------|
| 1.1 | **DWARF signature pipeline** | Verify DWARF-imported function signatures (via r2 `sdb_types` / `afcfj`) flow end-to-end into r2dec's `VariableRecovery` and `TypeInference`. DWARF variable names, parameter types, and return types must appear in decompiled output automatically. | Low | High |
| 1.2 | **DWARF struct/enum type feeding** | In `sleigh_cmd` (`a:sla.dec`), query r2's `tsj` for DWARF-imported structs/unions/enums and feed into `ExternalTypeDb`. The type solver already has `FieldAccess` constraints and `lookup_field_name`; wire them to real DWARF data. | Medium | High |
| 1.3 | **DWARF-assisted struct field recovery** | When type inference resolves `*(ptr+offset)` and the `ExternalTypeDb` has a matching struct with a field at that offset, emit `ptr->field` in decompiled C. Combines DWARF data + existing `detect_addr_pattern` + `lookup_field_name`. | Medium | High |
| 1.4 | **Transparent `pdd` alias** | Register `pdd` (or `pdD`) as an r2 command alias that calls `a:sla.dec` for the current function. Users get decompilation from the standard r2 command vocabulary without knowing r2sleigh exists. | Low | High |
| 1.5 | **Write-back inferred types to r2** | After decompilation or `aaaa`, push inferred struct shapes, function signatures, and variable types back into `sdb_types` (via `r_anal_save_parsed_type`/`r_anal_import_c_decls`). This means `t` commands, `afvt`, and future analysis passes all benefit. | Medium | High |
| 1.6 | **Global variable recognition** | Use SSA data-flow analysis to detect accesses to fixed RAM addresses, cross-reference with r2's `r_anal_global_get`/flags, and emit named globals in decompiled output instead of raw hex constants. | Low | Medium |
| 1.7 | **Autoname functions from decompiler** | After decompilation, heuristically derive function names from string arguments to known calls (e.g., a function whose first call is `printf("usage: ...")` → `print_usage`). Feed names back via `r_anal_function_rename`. Integrate with `aan`. | Medium | Medium |
| 1.8 | **Calling convention auto-detection** | During `analyze_fcn`, determine calling convention (cdecl/stdcall/fastcall/sysv/win64/arm-aapcs) from SSA parameter-register usage patterns. Write back to r2's `afcc` so all downstream commands agree. Currently hardcoded to SysV x86-64. | Medium | Medium |

### Phase 2 — Decompiler Quality (match Ghidra, exceed it)

| # | Feature | Description | Effort | Impact |
|---|---------|-------------|--------|--------|
| 2.1 | **Phi node elimination** | Convert `phi(x1,x2)` to proper variable assignments at predecessor edges. Removes the last SSA artifacts from decompiled output. | Medium | High |
| 2.2 | **Register coalescing** | Merge `RAX_1`, `RAX_2`, ... into a single C variable when the live ranges don't interfere. Dramatically reduces variable clutter. | Medium | High |
| 2.3 | **Short-circuit operators** | Detect `if(a) { if(b) { X } }` → `if(a && b) { X }` and the OR variant. | Low | Medium |
| 2.4 | **Condition inversion / early return** | Prefer `if(!x) return;` over `if(x) { ...long body... }`. Reduces nesting. | Low | Medium |
| 2.5 | **No More Gotos** | Handle irreducible CFGs with region-based restructuring instead of gotos. The `structure.rs` already has region analysis; extend with node splitting or controlled duplication. | High | High |
| 2.6 | **Pointer type propagation** | Track pointer types through Load/Store chains. When `p = malloc(sizeof(Foo))`, propagate `Foo*` to all uses of `p`. | Medium | High |
| 2.7 | **Array access patterns** | Detect `base + i*stride` as `arr[i]`. The type solver already has `stride` detection in `detect_addr_pattern`; surface it in codegen. | Medium | Medium |
| 2.8 | **Enum constant folding** | When a comparison operand matches an enum variant from `ExternalTypeDb`, emit the enum name instead of the raw integer. | Low | Medium |
| 2.9 | **String constant propagation** | When a local variable is assigned a string address and only used in one call, inline the string literal at the call site. | Low | Medium |
| 2.10 | **sizeof() recovery** | Detect `malloc(N)` where N matches `sizeof(struct X)` from the type DB. Emit `malloc(sizeof(X))`. | Low | Low |

### Phase 3 — Vulnerability Intelligence (the killer feature)

No other open-source tool provides automatic, per-function vulnerability
assessment integrated directly into the reversing workflow.

| # | Feature | Description | Effort | Impact |
|---|---------|-------------|--------|--------|
| 3.1 | **Vulnerability pattern library** | Detect buffer overflow, format string, UAF, double-free, integer overflow at IL/SSA level. Each pattern is a taint policy + SSA matcher. Ship as data files, not code. | Medium | Critical |
| 3.2 | **Risk scoring engine** | Assign per-function risk scores based on: sink severity × input reachability × sanitizer presence. Rank all functions by exploitability during `aaaa`. Write `sla.risk` flag + comment. | Medium | Critical |
| 3.3 | **Guided vuln discovery** | `a:sym.vuln <sink>` — use symbolic execution to find concrete input reaching a dangerous sink (e.g., `gets()` or unchecked `memcpy`). Output includes input constraints in SMT-LIB2 and concrete model. | Medium | High |
| 3.4 | **Crypto detection** | Detect crypto algorithms by IL patterns: S-box constants (AES), round constants (SHA), Feistel structure. Flag functions as `sla.crypto.aes`, etc. | Medium | Medium |
| 3.5 | **Integer overflow detection** | Flag arithmetic operations on user-controlled values that lack bounds checks before use as array indices or allocation sizes. | Medium | High |
| 3.6 | **Path predicate export** | Export path constraints as SMT-LIB2 for external solvers or integration with fuzzing harnesses. | Low | Medium |

### Phase 4 — Inter-Procedural Analysis (the hard problems)

| # | Feature | Description | Effort | Impact |
|---|---------|-------------|--------|--------|
| 4.1 | **Function summaries** | Cache per-function symbolic summaries: which inputs affect which outputs, what gets tainted, what's returned. Enables inter-procedural without full inlining. | High | Critical |
| 4.2 | **Inter-procedural taint** | Taint analysis spanning function boundaries using summaries. `input:argv` reaching `strcpy` in a callee three levels deep. | High | Critical |
| 4.3 | **Call graph with data flow** | Build a call graph where edges carry data-flow information (which args of caller flow to which params of callee). | High | High |
| 4.4 | **Whole-program type inference** | Unify types across function boundaries: if `foo()` returns a `struct stat*` and `bar()` receives it, propagate the struct type into `bar`'s parameter. | High | High |
| 4.5 | **Context-sensitive decompilation** | When decompiling `foo(x)`, look at callers to determine likely type/range of `x`. Annotate decompiled output with "called from: ..." context. | High | Medium |

### Phase 5 — Symbolic Execution & Concolic (the smart engine)

| # | Feature | Description | Effort | Impact |
|---|---------|-------------|--------|--------|
| 5.1 | **Interactive symbolic execution** | `a:sym.explore` and `a:sym.solve` commands with user-specified targets, constraints, and hooks. | Medium | High |
| 5.2 | **Memory in solutions** | Include concrete memory layout (heap, stack, globals) in symbolic path output, not just register values. | Low | Medium |
| 5.3 | **Concolic execution** | Concrete + symbolic hybrid guided by ESIL traces from r2's debugger. Run the binary, record a trace, symbolically explore alternatives. | High | High |
| 5.4 | **Symbolic call stubs** | Auto-generate symbolic stubs for common libc functions (`strlen` returns symbolic length, `malloc` returns fresh symbolic pointer). | Medium | High |
| 5.5 | **Constraint caching** | Cache Z3 queries per function so repeated solves (e.g., during fuzzing integration) don't redundantly re-solve. | Medium | Medium |

### Phase 6 — Platform & Architecture Expansion

| # | Feature | Description | Effort | Impact |
|---|---------|-------------|--------|--------|
| 6.1 | **ABI/calling-convention model** | Abstract architecture-specific assumptions (arg registers, stack direction, alignment) into a data model. Currently hardcoded for SysV x86-64 in `variable.rs`, `types.rs`, `taint.rs`. | Medium | High |
| 6.2 | **RISC-V support** | Add RISC-V Sleigh spec + register profile + calling convention. | Medium | Medium |
| 6.3 | **AArch64 / ARM64 support** | Full ARM64 support with AAPCS64 calling convention. | Medium | Medium |
| 6.4 | **PPC / AVR / SPARC** | Additional architecture support with per-arch test fixtures. | Medium | Low |
| 6.5 | **Register naming policy** | Normalize register names, resolve overlapping aliases (RAX vs EAX vs AX vs AL). Use canonical names in decompiled output. | Low | Medium |
| 6.6 | **Floating-point type inference** | Properly distinguish float/double from integer types using SSA float opcodes. | Low | Low |

### Phase 7 — Advanced Analysis & Research

| # | Feature | Description | Effort | Impact |
|---|---------|-------------|--------|--------|
| 7.1 | **Memory/value-set analysis** | Alias-aware abstract interpretation tracking value ranges and pointer targets. Enables more precise taint, slicing, and decompilation. | High | High |
| 7.2 | **R2IL VM + event tracing** | Make R2IL executable with concrete values. Record execution traces with events (mem read/write, branch taken). Compare static vs dynamic analysis. | High | Medium |
| 7.3 | **Semantic diff** | Compare two functions (or two versions of a binary) for semantic differences at the SSA level. Highlight what changed in the decompiled output. | High | Medium |
| 7.4 | **Pattern matching DSL** | User-defined IL patterns for custom detection. "Find all functions that read from `[user_input + *]` and pass it to `exec*`." | Medium | Medium |
| 7.5 | **Incremental analysis** | When the user annotates a type or renames a variable, incrementally update SSA/taint/decompilation without re-lifting the whole function. | High | Medium |
| 7.6 | **Decompiler output diffing** | When types/signatures change, show a diff of the decompiled C output. Useful for iterative reverse engineering. | Low | Low |

Integration Architecture
------------------------

The key insight: r2sleigh hooks into radare2's analysis pipeline at every
stage, consuming r2's metadata and pushing results back. The user never
invokes r2sleigh directly — it's just "r2 but smarter."

```
radare2 analysis pipeline          r2sleigh hooks
─────────────────────────          ──────────────
aa  (basic analysis)
 └─ af (find functions)     ──→   analyze_fcn: SSA + annotations
 └─ afva (find vars)        ──→   recover_vars: SSA-derived stack vars + reg args
 └─ aar (find refs)         ──→   get_data_refs: SSA-derived data/code/string refs

aaa (deeper analysis)
 └─ aan (autoname)          ──→   [NEW] autoname from decompiler heuristics
 └─ DWARF integration       ──→   [NEW] DWARF types → ExternalTypeDb → decompiler
 └─ afcfj (signatures)      ──→   already consumed by a:sla.dec
 └─ tsj (type structs)      ──→   already consumed by a:sla.dec

aaaa (experimental)
 └─ post_analysis            ──→   taint analysis + risk scoring + xrefs
 └─ [NEW]                   ──→   write-back inferred types to sdb_types
 └─ [NEW]                   ──→   write-back function signatures to afcc
 └─ [NEW]                   ──→   flag risky functions with sla.risk.*

User commands (transparent)
 └─ pdd / pdD               ──→   [NEW] alias to a:sla.dec
 └─ a:sla.dec               ──→   decompile with full context from r2
 └─ a:sla.taint             ──→   taint current function
 └─ a:sym.solve <addr>      ──→   solve for reachability
```

### Data Flow: r2 → r2sleigh → r2

```
                    ┌──────────────┐
                    │   radare2    │
                    │              │
  ┌─────────────────┤  sdb_types   │◄──────── DWARF / PDB / user annotations
  │                 │  flags       │
  │                 │  xrefs       │
  │                 │  afcfj       │
  │                 │  afvj        │
  │                 │  tsj         │
  │                 │  aflj        │
  │                 └──────┬───────┘
  │                        │ JSON
  │                        ▼
  │                 ┌──────────────┐
  │                 │  r2sleigh    │
  │                 │              │
  │                 │  R2IL lift   │
  │                 │  SSA build   │
  │                 │  Type infer  │
  │                 │  Decompile   │
  │                 │  Taint       │
  │                 │  SymExec     │
  │                 └──────┬───────┘
  │                        │ JSON + C strings
  │                        ▼
  │                 ┌──────────────┐
  │ write-back ────►│   radare2    │
  │  types          │              │
  │  signatures     │  sdb_types ← inferred struct shapes
  │  variables      │  afcc     ← detected calling convention
  │  names          │  flags    ← taint/risk/crypto flags
  │  xrefs          │  xrefs   ← taint-flow + data refs
  │  comments       │  comments ← taint summaries, risk scores
  └─────────────────┤  afn     ← auto-named functions
                    └──────────────┘
```

Comparison
----------

### vs radare2 (stock)

r2sleigh adds: SSA form, phi nodes, def-use chains, dominator tree,
symbolic execution, taint analysis, path exploration, Z3 solving, typed
decompilation, constraint-based type inference, vulnerability detection,
risk scoring, automatic function naming from decompiler heuristics.

### vs angr

r2sleigh provides: zero-friction radare2 integration (no Python, no
separate process), CLI-first workflow, Sleigh specs (vs VEX), JSON
output for scripting, per-function taint during `aaaa`, decompiler
output, no Python overhead. angr has: mature inter-procedural analysis,
larger community, more memory models.

### vs Ghidra

r2sleigh provides: exposed SSA for scripting, integrated symbolic
execution, automatic taint analysis with risk scoring, vulnerability
pattern detection, native CLI operation, no JVM dependency, incremental
results during analysis. Ghidra has: more mature decompiler,
inter-procedural type propagation (which we're building in Phase 4),
larger architecture coverage.

### vs Binary Ninja

r2sleigh provides: fully open source, no license cost, Sleigh specs
(broadest architecture coverage), integrated symbolic execution and
taint analysis, CLI-native workflow, r2pipe scriptability. Binary Ninja
has: polished GUI, MLIL/HLIL abstraction layers, commercial support.

**The goal**: combine the best of all four — Ghidra's Sleigh specs,
angr's symbolic execution, Binary Ninja's type inference quality, and
radare2's CLI-first hackability — into a single transparent analysis
engine that just works when you type `aaa`.

References
----------

- radare2 ESIL: https://book.rada.re/disassembling/esil.html
- Ghidra Sleigh: https://ghidra.re/courses/languages/html/sleigh.html
- P-code reference: https://ghidra.re/courses/languages/html/pcoderef.html
