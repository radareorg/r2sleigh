r2sleigh Roadmap
================

> Goal: bring Sleigh-powered, typed lifting to radare2 with backward-compatible
> ESIL and advanced analysis capabilities.

Current State (Feb 2026)
-------------------------

~200 tests passing across 8 crates. 20+ plugin commands working in radare2.

Working features:
- 60+ R2IL opcodes from Ghidra Sleigh specifications
- Full SSA pipeline: CFG, dominator tree, phi nodes, optimization (SCCP, DCE, CSE, copy-prop, inst-combine)
- Z3-backed symbolic execution with path exploration
- SSA-based taint analysis with automatic radare2 integration during aaaa
- Decompiler producing C code with expression folding, predicate simplification, for-loops, switches, string literals, and symbol resolution
- Constraint-based type inference
- Backward slicing
- 20+ radare2 plugin commands with automatic analysis hooks

Supported architectures: x86, x86-64, ARM, MIPS.

Planned Features
----------------

### High Priority

| Feature | Description | Effort |
|---------|-------------|--------|
| Vulnerability patterns | Detect overflow, format string, UAF at IL level | Medium |
| Interactive symbolic execution | a:sym.explore, a:sym.solve commands | Medium |
| Memory in solutions | Include memory values in symbolic path output | Low |
| Pointer type propagation | Track pointer types through Load/Store | Medium |
| Array access patterns | Detect base + i*size as arr[i] | Medium |
| Phi node elimination | Convert phi(x1,x2) to proper assignments | Medium |
| Register coalescing | Merge RAX_1, RAX_2 into single variable | Medium |
| Short-circuit operators | if(a) if(b) to if(a && b) | Low |
| Condition inversion | Prefer if(!x) return over if(x){...} | Low |

### Medium Priority

| Feature | Description | Effort |
|---------|-------------|--------|
| Concolic execution | Concrete + symbolic hybrid guided by ESIL traces | Medium |
| Guided vuln discovery | Find input reaching dangerous function | Medium |
| Path predicate export | Export constraints as SMT-LIB2 | Low |
| Crypto detection | Detect crypto by IL patterns (S-box, constants) | Medium |
| Memory region tracking | Track heap/stack/global regions with bounds | Medium |
| IL validation | R2IL/SSA validator with structured export | Medium |
| ABI/calling-convention model | Abstract architecture-specific assumptions | Medium |
| Register naming policy | Normalize register names, resolve overlaps | Low |

### Future

| Feature | Description | Effort |
|---------|-------------|--------|
| Struct field recovery | *(ptr+offset) to ptr->field | High |
| No More Gotos | Handle irreducible CFGs cleanly | High |
| Inter-procedural taint | Taint analysis spanning function boundaries | High |
| Call graph with data flow | Track data flow across functions | High |
| Function summaries | Cache symbolic summaries for callees | High |
| Memory/value-set analysis | Alias-aware value sets for taint/slicing/decomp | High |
| R2IL VM + event tracing | Executable R2IL with trace/events | High |
| Semantic diff | Compare two functions for semantic differences | High |
| Pattern matching DSL | User-defined IL patterns for custom detection | Medium |
| Architecture expansion | Add RISC-V, PPC, AVR with per-arch test fixtures | Medium |
| Incremental analysis | Update SSA/taint as user annotates types | High |

Comparison
----------

### vs radare2 (stock)

r2sleigh adds: SSA form, phi nodes, def-use chains, dominator tree,
symbolic execution, taint analysis, path exploration, Z3 solving, typed
decompilation.

### vs angr

r2sleigh provides: radare2 integration, CLI-first workflow, Sleigh specs
(vs VEX), JSON output, no Python overhead, r2pipe scripting.

### vs Ghidra

r2sleigh provides: exposed SSA, symbolic execution, taint analysis,
native CLI operation, no JVM dependency. Both use Sleigh specs.

References
----------

- radare2 ESIL: https://book.rada.re/disassembling/esil.html
- Ghidra Sleigh: https://ghidra.re/courses/languages/html/sleigh.html
- P-code reference: https://ghidra.re/courses/languages/html/pcoderef.html
