# r2sleigh Roadmap

> Goal: bring Sleigh-powered, typed lifting to radare2 with backward-compatible ESIL and advanced analysis capabilities.

## Snapshot (Feb 2025)

**164 tests passing** across 7 crates:
- `r2il` (26 tests) - Core IL types
- `r2sleigh-lift` (4 tests) - P-code translation
- `r2sleigh-cli` (9 tests) - CLI tool
- `r2ssa` (42 tests) - SSA transformation
- `r2sym` (51 tests) - Symbolic execution + taint analysis
- `r2dec` (32 tests) - Decompiler with expression folding
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
| 4. Decompiler | 🔨 In Progress | Expression folding done, control flow structuring basic |
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
| `r2dec` | Decompiler: AST, expr folding, control flow, codegen | 32 |
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
- **Backward Slicing**: `a:sla.slice` with JSON output (ops, blocks, phi nodes)

### Phase 3.5: Deep radare2 Integration ✅
- **New r2 callbacks**: `analyze_fcn`, `recover_vars`, `get_data_refs`, `post_analysis`
- **Plugin-provided variables**: SSA-based variable recovery feeds into `afv`
- **Plugin-provided refs**: Def-use xrefs integrated with `ax`
- **Seamless analysis**: Plugin hooks called automatically during `aaa`/`aaaa`

### Phase 4: Decompiler (In Progress)

#### 4.1 Expression Folding ✅
- **Use counting**: Track how many times each SSA variable is used
- **Single-use inlining**: Variables used once are inlined at use site
- **Dead code elimination**: Unused CPU flags (CF, ZF, SF, etc.) removed
- **Constant handling**: `const:xxx` → numeric literals (e.g., `0xfffffffffffffff0U`)
- **Condition pinning**: Branch conditions kept as named variables for readability

#### 4.2 Control Flow Structuring (Basic) ✅
- Region analysis: if/while/do-while detection
- Back edge detection for loops
- Merge point identification for diamonds
- Irreducible regions fall back to gotos

#### 4.3 Code Generation ✅
- Full C AST types (statements, expressions, types)
- Pretty-printing with proper operator precedence
- Configurable indent and C99 types

#### 4.4 Scaffolding (Needs Work)
- Type inference (size-based only, no pointer tracking)
- Variable recovery (basic stack/param detection)
- No for-loop or switch detection
- No string literal recovery
- No function signature integration

---

## What's Left

### Tracking TODOs

- [ ] Add name-resolved register aliases to `a:sla.json` output (raw R2IL JSON still uses offsets)
- [ ] Verify register alias policy applies across all serialized outputs (R2IL JSON, plugin, CLI, ESIL)
- [ ] Surface CALLOTHER/userop names in JSON/ESIL output (map `userop` index → name)
- [ ] Preserve analysis/pseudo P-code ops behind a debug flag (or emit marker ops)
- [ ] Capture Sleigh custom address-space metadata (name/word-size/semantics) instead of flattening to `Custom`
- [ ] Feed SSA/def-use info into radare2 analysis metadata (refs, vars, xrefs) instead of JSON-only

### Tier 1: High Priority (Next Up)

| # | Feature | Command | Description | Effort |
|---|---------|---------|-------------|--------|
| 1 | ~~Taint command~~ | ~~`a:sleigh.taint`~~ | ✅ Exposed with JSON output | Done |
| 2 | ~~Backward Slicing~~ | ~~`a:sla.slice`~~ | ✅ "What code affects variable X?" with JSON output | Done |
| 3 | **Vulnerability Patterns** | `a:sleigh.vuln` | Detect common vuln patterns (overflow, format string, UAF) | Medium |
| 4 | ~~Better register naming~~ | - | ✅ Map `reg:10_1` → `ESP_1` in all output | Done |
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

### Tier 4: Decompiler Improvements (r2dec Roadmap)

#### Phase 4.1: Expression Folding ✅ DONE
| # | Feature | Status | Description |
|---|---------|--------|-------------|
| 14 | Single-use inlining | ✅ Done | Inline variables used only once |
| 15 | Dead flag elimination | ✅ Done | Remove unused CPU flags (CF, ZF, SF, OF, etc.) |
| 16 | Constant folding | ✅ Done | Convert `const:xxx` to numeric literals |
| 17 | Condition pinning | ✅ Done | Keep branch conditions as named vars |

#### Phase 4.2: Quick Wins (Low Effort, High Impact)
| # | Feature | Status | Description | Effort |
|---|---------|--------|-------------|--------|
| 18 | **ptr_size from config** | 🔜 Next | Pass DecompilerConfig.ptr_size to FoldingContext | 5 min |
| 19 | **Function signatures from r2** | 🔜 | Read `afs`/`afi` for param/return types | Low |
| 20 | **String literal recovery** | 🔜 | Check if addr points to .rodata → inline | Low |
| 21 | **Function call names** | 🔜 | Replace `call(0x401234)` with `printf(...)` | Low |
| 22 | **Global variable names** | 🔜 | Use r2 flags for global addresses | Low |

#### Phase 4.3: Type Inference (Medium Effort, High Impact)
| # | Feature | Status | Description | Effort |
|---|---------|--------|-------------|--------|
| 23 | **Pointer type propagation** | 🔜 | Track pointer types through Load/Store | Medium |
| 24 | **Signed vs unsigned** | 🔜 | Use IntSLess/IntSDiv to infer signedness | Low |
| 25 | **Array access patterns** | 🔜 | Detect `base + i*size` → `arr[i]` | Medium |

#### Phase 4.4: Variable Recovery (Medium Effort, High Impact)
| # | Feature | Status | Description | Effort |
|---|---------|--------|-------------|--------|
| 26 | **r2 variable integration** | 🔜 | Read `afvj` for user-defined var names | Low |
| 27 | **Phi node elimination** | 🔜 | Convert φ(x₁,x₂) to proper assignments | Medium |
| 28 | **Register coalescing** | 🔜 | Merge RAX_1, RAX_2 into single variable | Medium |
| 29 | **Meaningful names** | 🔜 | Usage patterns (loop counter → `i`) | Medium |

#### Phase 4.5: Control Flow Polish (Medium Effort)
| # | Feature | Status | Description | Effort |
|---|---------|--------|-------------|--------|
| 30 | **For-loop detection** | 🔜 | Detect `init; while(cond) { body; update }` | Medium |
| 31 | **Switch detection** | 🔜 | Cascaded if-else on same var → switch | Medium |
| 32 | **Short-circuit && / \|\|** | 🔜 | `if(a) if(b)` → `if(a && b)` | Low |
| 33 | **Condition inversion** | 🔜 | Prefer `if(!x) return` over `if(x){...}` | Low |

#### Phase 4.6: Advanced (High Effort, Future)
| # | Feature | Status | Description | Effort |
|---|---------|--------|-------------|--------|
| 34 | **Struct field recovery** | 🔜 | `*(ptr+offset)` → `ptr->field` | High |
| 35 | **"No More Gotos"** | 🔜 | Handle irreducible CFGs cleanly | High |
| 36 | **Loop unrolling detection** | 🔜 | Collapse unrolled loops | High |
| 37 | **Inline small functions** | 🔜 | Inline trivial helpers | Medium |

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

#### r2dec Decompiler (Prioritized)
| Rank | Feature | User Usefulness | Effort | Status |
|------|---------|-----------------|--------|--------|
| 1 | ✅ Expression folding | High | Medium | Done |
| 2 | ✅ Dead flag elimination | High | Low | Done |
| 3 | ✅ Constant folding | High | Low | Done |
| 4 | ptr_size from config | High | 5 min | Next |
| 5 | Function signatures from r2 | High | Low | Next |
| 6 | String literal recovery | High | Low | Next |
| 7 | Function call names | High | Low | Next |
| 8 | Type inference (pointers) | High | Medium | Planned |
| 9 | r2 variable integration | High | Low | Planned |
| 10 | For-loop detection | Medium | Medium | Planned |
| 11 | Switch detection | Medium | Medium | Planned |
| 12 | Phi node elimination | Medium | Medium | Planned |
| 13 | Struct field recovery | High | High | Future |

#### Other Features
| Rank | Feature | User Usefulness | Effort |
|------|---------|-----------------|--------|
| 1 | Register naming + alias policy | High | Low |
| 2 | ✅ SSA optimization pipeline | High | Medium |
| 3 | Backward slicing | High | Low |
| 4 | IL validation + structured export | High | Medium |
| 5 | Memory in solutions | Medium | Low |
| 6 | Vulnerability patterns | High | Medium |
| 7 | Path predicate export | Medium | Low |
| 8 | Memory/value-set analysis | High | High |
| 9 | Memory region tracking | Medium | Medium |
| 10 | Control-flow structuring parity | High | High |
| 11 | ESIL-trace-guided analysis hooks | Medium | Medium |
| 12 | Concolic execution | Medium | High |
| 13 | Guided vuln discovery (findpath) | High | High |
| 14 | ABI/calling-convention modeling | Medium | Medium |
| 15 | Call graph with data flow | Medium | High |
| 16 | Function summaries | Medium | High |
| 17 | Inter-proc taint | Medium | High |
| 18 | R2IL VM + event tracing | Medium | High |
| 19 | Architecture expansion + lift tests | Medium | Medium |
| 20 | Multi-architecture testing | Medium | Medium |
| 21 | Pattern matching DSL | Medium | Medium |
| 22 | Crypto detection | Medium | Medium |
| 23 | Semantic diff | Low | High |
| 24 | Incremental analysis | Medium | High |

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

### r2dec Decompiler Implementation Guide

#### Quick Wins (do these first)

**1. Fix ptr_size (5 min)**
```rust
// In structure.rs, change:
let mut fold_ctx = FoldingContext::new(64); // TODO: get from config
// To:
let mut fold_ctx = FoldingContext::new(self.config.ptr_size);
```

**2. String literal recovery**
```rust
// In plugin, read string at address:
// r2pipe: pszj @ addr → returns string if valid
fn try_string_at(core: &RCore, addr: u64) -> Option<String> {
    // Check if addr is in .rodata/.data section
    // Check if it's a valid null-terminated string
    // Return quoted string literal
}
```

**3. Function signatures from r2**
```rust
// Use r2 command: afij @ func_addr
// Returns JSON with: name, args, ret type
// Map to CFunction params and ret_type
```

**4. Function call names**
```rust
// For Call { target }, if target is constant:
// Look up: fd @ target_addr → function name
// Or use: aflj to get function list
```

#### Type Inference Improvements

**Pointer detection heuristic:**
```rust
// If variable is used in Load/Store address position → it's a pointer
// If variable = result of malloc-like call → pointer
// If variable used in IntAdd with constant → likely pointer arithmetic
```

**Signedness inference:**
```rust
// IntSLess, IntSDiv, IntSRem, IntSRight → signed operands
// IntLess, IntDiv, IntRem, IntRight → unsigned
// Propagate through assignments
```

#### For-loop detection pattern

```rust
// Detect: init; while(cond) { body; update }
// Where update is: i = i + 1 (or similar)
fn detect_for_loop(header: &SSABlock, body: &[SSABlock]) -> Option<ForLoop> {
    // 1. Find loop-carried variable (defined in body, used in header condition)
    // 2. Check if update is simple increment/decrement
    // 3. Find initialization before loop entry
}
```

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

Phase 1: Foundation
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

Phase 4: Decompiler (r2dec)
  ✅ C AST types and codegen
  ✅ Expression folding (single-use inlining, dead flag elimination)
  ✅ Control flow structuring (if/while/do-while)
  ✅ Region analysis (back edges, merge points)
  🔨 Type inference (size-based, needs pointer tracking)
  🔨 Variable recovery (basic, needs r2 integration)
  ⬜ For-loop/switch detection
  ⬜ String literal recovery
  ⬜ Function signature integration

Phase 5: Security Research
  ✅ Backward slicing (a:sla.slice)
  ✅ Taint analysis (a:sla.taint)
  ⬜ Vulnerability pattern detection
  ⬜ Concolic execution
  ⬜ Crypto detection
