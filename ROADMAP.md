# r2sleigh Roadmap

> Goal: bring Sleigh-powered, typed lifting to radare2 with backward-compatible ESIL and advanced analysis capabilities.

## Snapshot (Jan 2025)

**135 tests passing** across 7 crates:
- `r2il` (26 tests) - Core IL types
- `r2sleigh-lift` (4 tests) - P-code translation
- `r2sleigh-cli` (9 tests) - CLI tool
- `r2ssa` (42 tests) - SSA transformation
- `r2sym` (51 tests) - Symbolic execution + taint analysis
- `r2dec` (3 tests) - Decompiler scaffolding
- `r2plugin` - radare2 integration

**18 plugin commands working** in radare2.

---

## Phase Status

| Phase | Status | Description |
|-------|--------|-------------|
| 1. Foundation | ✅ Complete | r2il types, P-code translator, ESIL output, CLI |
| 2. radare2 Plugin | ✅ Complete | FFI, C wrapper, RAnalPlugin, 8 instruction commands |
| 2.5. SSA | ✅ Complete | SSAVar, CFG, domtree, phi nodes, def-use analysis |
| 3. Symbolic Execution | ✅ Complete | Z3 solver, path exploration, taint analysis |
| 4. Decompiler | ⚠️ Scaffolding | AST types exist, codegen outputs raw SSA |
| 5. Advanced Analysis | 🔜 Planned | Slicing, vuln detection, concolic, crypto detection |

---

## Architecture

```
.sla → libsla (P-code) → r2sleigh-lift (r2il) → r2ssa (SSA) → r2sym (symbolic) | r2dec (decomp)
                                              ↓
                                           ESIL (legacy)
```

### Crates

| Crate | Purpose | Tests |
|-------|---------|-------|
| `r2il` | Core types: `Varnode`, `SpaceId`, `R2ILOp`, `R2ILBlock` | 26 |
| `r2sleigh-lift` | P-code → r2il translation, ESIL formatting | 4 |
| `r2sleigh-cli` | CLI: compile, disasm, info commands | 9 |
| `r2ssa` | SSA: `SSAVar`, `SSAOp`, `SSABlock`, CFG, domtree, phi | 42 |
| `r2sym` | Symbolic: `SymValue`, `SymState`, solver, paths, **taint** | 51 |
| `r2dec` | Decompiler: AST, expr, codegen (scaffolding) | 3 |
| `r2plugin` | Rust cdylib + C wrapper for radare2 | - |

---

## Plugin Commands (18 total)

### Instruction-level (8)
| Command | Description |
|---------|-------------|
| `a:sleigh` | Plugin status |
| `a:sleigh.info` | Architecture info |
| `a:sleigh.json` | R2IL ops as JSON |
| `a:sleigh.regs` | Registers read/written |
| `a:sleigh.mem` | Memory accesses |
| `a:sleigh.vars` | All varnodes |
| `a:sleigh.ssa` | SSA form (single instruction) |
| `a:sleigh.defuse` | Def-use analysis |

### Function-level (10)
| Command | Description |
|---------|-------------|
| `a:sleigh.ssa.func` | Function SSA with phi nodes |
| `a:sleigh.ssa.func.opt` | Optimized function SSA |
| `a:sleigh.defuse.func` | Function-wide def-use |
| `a:sleigh.dom` | Dominator tree (JSON) |
| `a:sleigh.cfg` | ASCII CFG |
| `a:sleigh.cfg.json` | CFG as JSON |
| `a:sleigh.sym` | Symbolic execution summary |
| `a:sleigh.sym.paths` | Path exploration with solutions |
| `a:sleigh.taint` | Taint analysis (sources → sinks) |
| `a:sleigh.dec` | Decompile to C (basic) |

### Planned Commands
| Command | Description | Priority |
|---------|-------------|----------|
| `a:sleigh.slice` | Backward slicing ("what affects X?") | High |
| `a:sleigh.vuln` | Vulnerability pattern detection | High |
| `a:sleigh.crypto` | Crypto algorithm detection | Medium |
| `a:sleigh.constraint` | Export path constraints (SMT-LIB2) | Medium |
| `a:sleigh.callgraph` | Inter-procedural data flow | Medium |
| `a:sleigh.regions` | Memory region tracking | Medium |
| `a:sleigh.diff` | Semantic diff of two functions | Low |

---

## What's Done

### Phase 1: Foundation ✅
- 60+ R2IL opcodes matching P-code semantics
- Varnode, SpaceId, ArchSpec types with serialization
- P-code → r2il translator using libsla
- ESIL output for backward compatibility
- CLI with compile/disasm/info commands
- x86/x86-64/ARM support via sleigh-config

### Phase 2: radare2 Plugin ✅
- FFI surface: `r2il_arch_init`, `r2il_lift`, `r2il_block_*`
- C wrapper: `RAnalPlugin` with `sleigh_op()` callback
- Makefile with `install`/`uninstall` targets
- 8 instruction-level commands
- Lazy architecture loading with caching

### Phase 2.5: SSA Foundation ✅
- `SSAVar`: versioned variables (name_version)
- `SSAOp`: all R2IL ops with SSA vars + Phi variant
- `SSABlock` and `SSAContext` for conversion
- `to_ssa()`: R2ILBlock → SSABlock
- Def-use analysis: inputs, outputs, live ranges
- Dead code detection, constant finding
- **CFG construction**: `BasicBlock`, edges, traversal
- **Dominator tree**: idom, children, dominance frontier
- **Phi node placement**: based on dominance frontiers
- **SSA renaming**: variable versioning algorithm
- **Function-level SSA**: `SSAFunction` with multiple blocks
- **SSA optimization pipeline**: const-prop, inst-combine, copy-prop, local CSE, DCE

### Phase 3: Symbolic Execution ✅
- `SymValue`: concrete, symbolic, unknown values
- **Taint tracking**: per-value taint masks, OR propagation
- `SymState`: registers, memory, constraints
- `SymMemory`: concrete/symbolic memory model
- `SymExecutor`: R2IL op interpreter
- `SymSolver`: Z3 integration for constraint solving
- `PathExplorer`: explore paths, collect results
- **Bitwidth normalization**: handle mixed-width operations
- **Path solving**: extract concrete solutions from Z3 models
- `SolvedPath`: inputs, registers, final_pc, constraints
- **Taint command**: `a:sleigh.taint` with configurable sources/sinks

### Phase 4: Decompiler (Scaffolding)
- AST node types defined
- Expression builder exists
- Codegen outputs raw SSA (not structured C)
- Type inference scaffolding
- Variable recovery scaffolding
- Region analysis (if/while/for detection)

---

## What's Left

### Tracking TODOs

- [ ] Add name-resolved register aliases to `a:sla.json` output (raw R2IL JSON still uses offsets)
- [ ] Verify register alias policy applies across all serialized outputs (R2IL JSON, plugin, CLI, ESIL)

### Tier 1: High Priority (Next Up)

| # | Feature | Command | Description | Effort |
|---|---------|---------|-------------|--------|
| 1 | ~~Taint command~~ | ~~`a:sleigh.taint`~~ | ✅ Exposed with JSON output | Done |
| 2 | **Backward Slicing** | `a:sleigh.slice` | "What code affects variable X at address Y?" | Low |
| 3 | **Vulnerability Patterns** | `a:sleigh.vuln` | Detect common vuln patterns (overflow, format string, UAF) | Medium |
| 4 | **Better register naming** | - | Map `reg:10_1` → `ESP_1` in all output | Low |
| 5 | **Memory in solutions** | - | Include memory values in symbolic path output | Low |

### Tier 2: Security Research Features

| # | Feature | Command | Description | Effort |
|---|---------|---------|-------------|--------|
| 6 | **Concolic Execution** | `a:sleigh.concolic` | Concrete + symbolic hybrid (guided by ESIL traces) | Medium |
| 7 | **Guided Vuln Discovery** | `a:sleigh.findpath` | "Find input reaching dangerous function with tainted arg" | Medium |
| 8 | **Path Predicate Export** | `a:sleigh.constraint` | Export constraints as SMT-LIB2 for external solvers | Low |
| 9 | **Crypto Detection** | `a:sleigh.crypto` | Detect crypto by IL patterns (S-box, constants, XOR chains) | Medium |
| 10 | **Memory Region Tracking** | `a:sleigh.regions` | Track heap/stack/global regions with bounds | Medium |

### Tier 3: Inter-procedural Analysis

| # | Feature | Command | Description | Effort |
|---|---------|---------|-------------|--------|
| 11 | **Call Graph with Data Flow** | `a:sleigh.callgraph` | Track data flow across function boundaries | High |
| 12 | **Inter-proc Taint** | `a:sleigh.taint.global` | Taint analysis spanning multiple functions | High |
| 13 | **Function Summaries** | - | Cache symbolic summaries for called functions | High |

### Tier 4: Decompiler Improvements

| # | Feature | Description | Effort |
|---|---------|-------------|--------|
| 14 | **Control flow structuring** | if/while/for/switch recovery (region-based) | Medium |
| 15 | **Expression folding** | Combine SSA ops into readable C expressions | Medium |
| 16 | **Type inference** | Propagate types through dataflow | Medium |
| 17 | **String recovery** | Detect and inline string literals | Low |
| 18 | **Proper CFG from r2** | Use radare2's function/block boundaries | Low |

### Tier 5: Advanced/Research Features

| # | Feature | Command | Description | Effort |
|---|---------|---------|-------------|--------|
| 19 | **Semantic Diff** | `a:sleigh.diff` | Compare two functions for semantic differences | High |
| 20 | **Incremental Analysis** | - | Update SSA/taint as user annotates types | High |
| 21 | **Pattern Matching DSL** | `a:sleigh.match` | User-defined IL patterns for custom detection | Medium |
| 22 | **Multi-architecture testing** | - | Verify ARM, MIPS, PPC, etc. | Medium |

### Long-Run Foundations (New)

| # | Feature | Description | Effort |
|---|---------|-------------|--------|
| 23 | **✅ SSA optimization pipeline** | DCE, copy-prop, local CSE, const-prop, inst-combine before decomp/analysis | Medium |
| 24 | **IL validation + structured export** | R2IL/SSA validator + JSON tree export with stable schema | Medium |
| 25 | **Memory/value-set analysis** | Alias-aware value sets and region modeling to improve taint/slicing/decomp | High |
| 26 | **Decompiler recovery pipeline** | Full control-flow structuring + type recovery + variable recovery integration | High |
| 27 | **ESIL-trace-guided analysis hooks** | Use ESIL traces for concolic guidance, watchpoints, path pruning | Medium |
| 28 | **Architecture expansion + lift tests** | Add Sleigh targets (RISC-V/MIPS/PPC/AVR/etc) with per-arch fixtures | Medium |
| 29 | **Register naming + alias policy** | Normalize reg names to profiles; resolve aliases/overlaps deterministically | Low |
| 30 | **Control-flow structuring parity** | Region/SESE + "No More Gotos" style recovery for irreducibles | High |
| 31 | **R2IL VM + event tracing** | Executable R2IL with trace/events for validation and guided analysis | High |
| 32 | **ABI/calling-convention modeling** | Signature recovery + argument/return tracking for inter-proc analysis | Medium |

### ROI/Benefit Priority Table

| Rank | Feature | User Usefulness | Effort |
|------|---------|-----------------|--------|
| 1 | Register naming + alias policy | High | Low |
| 2 | ✅ SSA optimization pipeline | High | Medium |
| 3 | Backward slicing | High | Low |
| 4 | IL validation + structured export | High | Medium |
| 5 | Memory in solutions | Medium | Low |
| 6 | Proper CFG from r2 | Medium | Low |
| 7 | Vulnerability patterns | High | Medium |
| 8 | Path predicate export | Medium | Low |
| 9 | Memory/value-set analysis | High | High |
| 10 | Memory region tracking | Medium | Medium |
| 11 | Control-flow structuring parity | High | High |
| 12 | Control flow structuring | High | Medium |
| 13 | Expression folding | Medium | Medium |
| 14 | Type inference | High | Medium |
| 15 | String recovery | Medium | Low |
| 16 | Decompiler recovery pipeline | High | High |
| 17 | ESIL-trace-guided analysis hooks | Medium | Medium |
| 18 | Concolic execution | Medium | High |
| 19 | Guided vuln discovery (findpath) | High | High |
| 20 | ABI/calling-convention modeling | Medium | Medium |
| 21 | Call graph with data flow | Medium | High |
| 22 | Function summaries | Medium | High |
| 23 | Inter-proc taint | Medium | High |
| 24 | R2IL VM + event tracing | Medium | High |
| 25 | Architecture expansion + lift tests | Medium | Medium |
| 26 | Multi-architecture testing | Medium | Medium |
| 27 | Pattern matching DSL | Medium | Medium |
| 28 | Crypto detection | Medium | Medium |
| 29 | Semantic diff | Low | High |
| 30 | Incremental analysis | Medium | High |

---

## Feature Details

### Backward Slicing (`a:sleigh.slice`)
**What:** Answer "What code affects variable X at point Y?"
**Use case:** "What determines the size argument to memcpy?"
**Implementation:** Traverse def-use chains backwards from target variable.
**Output:** List of SSA operations and their addresses.

### Vulnerability Pattern Detection (`a:sleigh.vuln`)
**What:** Detect common vulnerability patterns at IL level:
- Integer overflow before allocation (`malloc(a * b)` without check)
- Tainted data in dangerous function args (`memcpy(dst, src, tainted_size)`)
- Format string vulnerabilities (`printf(user_input)`)
- Double-free patterns (heuristic)
- Use-after-free patterns (heuristic)

**Use case:** Automated vulnerability scanning
**Implementation:** Combine taint analysis + pattern matching on SSA

### Concolic Execution (`a:sleigh.concolic`)
**What:** Use concrete execution traces to guide symbolic exploration
**Use case:** Avoid path explosion by following real execution paths
**Implementation:** 
1. Record path from r2's ESIL emulator
2. Use r2sym to explore branches off recorded path
3. Solve for alternate inputs at each branch

### Crypto Detection (`a:sleigh.crypto`)
**What:** Detect cryptographic algorithms by IL patterns:
- S-box lookups (256-byte table indexed by byte)
- Characteristic constants (SHA magic, AES rcon)
- XOR/shift patterns (TEA, RC4)
- Modular arithmetic patterns (RSA, DH)

**Use case:** Malware analysis, license checking analysis

### Guided Vulnerability Discovery (`a:sleigh.findpath`)
**What:** Combine taint + symbolic to find exploitable paths
**Workflow:**
1. Mark function inputs as tainted (sources)
2. Define sinks (memcpy size, system arg, indirect call target)
3. Symbolic execution finds paths from source to sink
4. Output concrete inputs that trigger vulnerability

### Path Predicate Export (`a:sleigh.constraint`)
**What:** Export the mathematical constraints of a path to standard SMT-LIB2 format.
**Use case:** Offload extremely complex constraints to specialized solvers (like integer programming solvers) or high-performance clusters to break obscure obfuscations.
**Implementation:** Serialize the internal Z3 `Solver` state to an SMT-LIB2 string.

### Inter-procedural Analysis (`a:sleigh.callgraph`)
**What:** Track data flow and taint propagation across function boundaries (e.g., `main` → `parser` → `validate`).
**Use case:** Detect bugs where tainted input passed to a parent function causes a crash deep in a helper function.
**Implementation:** 
1. Analyze leaf functions to generate "summaries" (input/output relationships).
2. Propagate symbolic states through `Call` ops instead of treating them as black boxes.

### Guided Fuzzing / DSE
**What:** Dynamic Symbolic Execution to assist fuzzers.
**Use case:** Help fuzzers (like AFL++) pass "magic byte" checks that random mutation cannot solve.
**Implementation:**
1. Listen to fuzzer coverage events.
2. On stuck branches: solve for the exact input required to flip the condition.
3. Feed the solved input back to the fuzzer queue.

### Taint-Guided Symbolic Execution
**What:** Optimization that limits symbolic execution scope.
**Use case:** Avoid state explosion in large binaries.
**Implementation:** 
1. Before forking state at a branch, check the taint mask of the condition.
2. If the condition is NOT tainted (not influenced by user input), execute it concretely and do not fork.

---

## What r2sleigh Does That Others Don't

### vs radare2

| Feature | radare2 | r2sleigh |
|---------|---------|----------|
| SSA form exposed | ❌ | ✅ |
| Function SSA with phi | ❌ | ✅ |
| Def-use chains | ❌ | ✅ |
| Dominator tree | ❌ | ✅ |
| Symbolic execution | ❌ | ✅ |
| Taint analysis | ❌ | ✅ |
| Path exploration | ❌ | ✅ |
| Z3 constraint solving | ❌ | ✅ |
| CFG as JSON | ⚠️ basic | ✅ |
| Backward slicing | ❌ | 🔜 |
| Vuln pattern detection | ❌ | 🔜 |

### vs angr

| Aspect | angr | r2sleigh |
|--------|------|----------|
| Integrated with r2 | ❌ | ✅ |
| CLI-first workflow | ⚠️ | ✅ |
| Uses Sleigh specs | ❌ (VEX) | ✅ |
| JSON output for tooling | ⚠️ | ✅ |
| Lightweight (no Python overhead) | ❌ | ✅ |
| Scriptable with r2pipe | ❌ | ✅ |

### vs Ghidra

| Aspect | Ghidra | r2sleigh |
|--------|--------|----------|
| SSA exposed to user | ❌ | ✅ |
| Symbolic execution | ❌ | ✅ |
| Taint analysis | ❌ | ✅ |
| CLI operation | ⚠️ headless | ✅ native |
| Lightweight (no JVM) | ❌ | ✅ |
| Uses Sleigh specs | ✅ | ✅ |

### Unique Value Proposition
> **angr's analysis power + radare2's workflow + Ghidra's Sleigh accuracy**

---

## Technical Notes

- **libsla quirk**: x86-64 needs 16 bytes minimum; plugin pads automatically
- **Taint**: 64-bit mask per value, OR'd through operations
- **Symbolic values**: concrete (u64), symbolic (Z3 BV), or unknown
- **Bitwidth**: `normalize_widths()` zero-extends smaller operand
- **Path limits**: default max_depth=100, max_states=1000
- **Memory model**: Flat symbolic memory with concrete fallback

---

## Implementation Notes

### For Backward Slicing
```rust
// Already have def-use chains in r2ssa
// Need: fn slice_backward(func: &SSAFunction, target: &SSAVar) -> Vec<(u64, SSAOp)>
// Traverse: for each source of target, add to slice, recurse
```

### For Vulnerability Patterns
```rust
// Pattern: tainted value flows to dangerous sink
struct VulnPattern {
    name: &'static str,
    sink_ops: Vec<&'static str>,  // "Call", "Store", etc.
    sink_targets: Vec<&'static str>,  // "memcpy", "system", etc.
    check: fn(&TaintResult, &SSAOp) -> bool,
}
```

### For Concolic Execution
```rust
// Hook into r2's ESIL trace
// Record: Vec<(addr, branch_taken: bool)>
// At each branch, fork symbolic state for unexplored direction
```

---

## References

- Agent guidelines: `Agent.md`
- ESIL reference: https://book.rada.re/disassembling/esil.html
- Sleigh docs: https://ghidra.re/courses/languages/html/sleigh.html
- P-code reference: https://ghidra.re/courses/languages/html/pcoderef.html
- angr docs: https://docs.angr.io/
- S2E docs: https://s2e.systems/docs/

---

## Legacy Phase Tracking

Phase 1: Foundation (what we have now)
  ✅ r2il types in Rust
  ✅ P-code → r2il translation
  ✅ r2il → ESIL for backward compat
  ✅ C-ABI plugin for radare2

Phase 2: Core Integration
  ✅ RAnalPlugin integration
  ⬜ Add libr/il/ to radare2 core (upstream)
  ⬜ RAnal uses r2il directly (not just ESIL)
  ⬜ Type-aware analysis passes

Phase 3: Advanced Features
  ✅ SSA transformation
  ✅ Symbolic execution engine
  ⬜ Memory region modeling
  ⬜ Inter-procedural analysis

Phase 4: Decompiler
  ⚠️ r2il → pseudo-C (scaffolding)
  ⬜ Type inference from r2il
  ⬜ Control flow structuring

Phase 5: Security Research
  ⬜ Backward slicing
  ⬜ Vulnerability pattern detection
  ⬜ Concolic execution
  ⬜ Crypto detection
