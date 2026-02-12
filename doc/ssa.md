SSA -- Static Single Assignment
================================

Background
----------

Static Single Assignment (SSA) form is a program representation where every
variable is defined exactly once. When a variable might have different values
depending on which control flow path was taken, a special phi function merges
the possibilities.

SSA enables precise dataflow analysis: def-use chains are trivially computed,
constant propagation becomes straightforward, and dead code is easy to detect.

r2sleigh constructs SSA from R2ILBlocks at two levels:

1. **Single-block SSA** -- one machine instruction, no phi nodes
2. **Function-level SSA** -- multiple blocks with CFG, dominator tree, and phi nodes

SSA Variables (SSAVar)
----------------------

```rust
pub struct SSAVar {
    pub name: String,    // Base name: "rax", "tmp:1000", "const:42"
    pub version: u32,    // SSA version number
    pub size: u32,       // Size in bytes
}
```

**Display format:** `rax_0`, `rax_1`, `tmp:1000_2`, `const:42_0`

**Naming conventions:**

| Pattern | Meaning |
|---------|---------|
| `rax_0` | Input value of RAX (live-in, version 0) |
| `rax_1` | First definition of RAX in the function |
| `tmp:xxxx_N` | Temporary from Unique space |
| `const:xxxx_0` | Immediate value (always version 0) |
| `ram:xxxx_0` | RAM address (rarely used as SSA var) |

The name is derived from the Varnode: registers get their Sleigh name,
temporaries use `tmp:offset`, constants use `const:offset`.

SSA Operations (SSAOp)
----------------------

`SSAOp` mirrors `R2ILOp` but uses `SSAVar` instead of `Varnode`, plus adds a
`Phi` variant:

```rust
pub enum SSAOp {
    Phi { dst: SSAVar, sources: Vec<SSAVar> },
    Copy { dst: SSAVar, src: SSAVar },
    Load { dst: SSAVar, space: String, addr: SSAVar },
    Store { space: String, addr: SSAVar, val: SSAVar },
    IntAdd { dst: SSAVar, a: SSAVar, b: SSAVar },
    // ... all R2ILOp variants with SSAVar fields
}
```

Each `SSAOp` implements `dst()` (output variable) and `sources()` (input
variables) for dataflow analysis.

Control Flow Graph (CFG)
------------------------

The CFG is built from a sequence of R2ILBlocks that make up a function.

```rust
pub struct CFG {
    graph: DiGraph<BasicBlock, CFGEdge>,   // petgraph directed graph
    addr_to_node: HashMap<u64, NodeIndex>, // address -> node lookup
    pub entry: u64,                        // entry block address
}

pub struct BasicBlock {
    pub addr: u64,
    pub size: u32,
    pub ops: Vec<R2ILOp>,
    pub terminator: BlockTerminator,
}
```

### Block Terminators

| Terminator | Description |
|------------|-------------|
| `Fallthrough { next }` | Falls through to next sequential block |
| `Branch { target }` | Unconditional jump |
| `ConditionalBranch { true_target, false_target }` | Two-way branch |
| `Switch { cases, default }` | Multi-way branch (jump table) |
| `Call { target, fallthrough }` | Function call (may have fallthrough) |
| `IndirectBranch` | Indirect jump (target unknown) |
| `IndirectCall { fallthrough }` | Indirect call |
| `Return` | Function return |

### CFG Construction

```rust
let cfg = CFG::from_blocks(&r2il_blocks);
```

The constructor:

1. Creates a graph node per R2ILBlock
2. Analyzes the last operation of each block to determine the terminator
3. Adds edges based on the terminator type
4. Validates that the entry block exists

Dominator Tree
--------------

The dominator tree is computed from the CFG using the Cooper-Harvey-Kennedy
algorithm (an iterative dataflow approach).

```rust
pub struct DomTree {
    idom: HashMap<u64, u64>,          // immediate dominator per block
    children: HashMap<u64, Vec<u64>>, // dominator tree children
    df: HashMap<u64, HashSet<u64>>,   // dominance frontier per block
}
```

**Key properties:**

- Block A *dominates* block B if every path from entry to B passes through A
- The *immediate dominator* of B is the closest strict dominator
- The *dominance frontier* of A is the set of blocks where A's dominance ends

The dominance frontier is critical for phi node placement.

### API

```rust
let domtree = DomTree::build(&cfg);
domtree.idom(block_addr)          // immediate dominator
domtree.children(block_addr)      // dominator tree children
domtree.dominance_frontier(block) // frontier set
```

Phi Node Placement
------------------

Phi nodes are placed at dominance frontier blocks for variables that are
defined in multiple blocks. The algorithm is the standard iterated dominance
frontier (IDF) approach:

1. Collect all definitions: for each variable, record which blocks define it
2. For each variable with multiple definitions:
   - Compute the IDF of the defining blocks
   - Place a phi node at each IDF block
3. Iterate until no new phi nodes are added

```
Block 0x1000: rax_1 = 42
Block 0x1004: rax_2 = 99
Block 0x1008: rax_3 = phi(rax_1, rax_2)  // merge point
```

Variable Renaming
-----------------

After phi placement, variables are renamed using a stack-based algorithm
(Cytron et al.):

1. Maintain a stack of versions per variable name
2. Walk the dominator tree in preorder
3. For each definition (including phi destinations), push a new version
4. For each use, read the current version from the stack
5. When leaving a block, pop versions pushed in that block

SSAFunction
-----------

`SSAFunction` combines all of the above into a complete function representation:

```rust
pub struct SSAFunction {
    pub cfg: CFG,
    pub domtree: DomTree,
    pub blocks: Vec<SSABlock>,  // FunctionSSABlock with phis
    pub entry: u64,
}
```

### Construction

```rust
let ssa_func = SSAFunction::from_blocks(&r2il_blocks).unwrap();
```

This performs the full pipeline:

1. Build CFG from blocks
2. Compute dominator tree
3. Collect variable definitions per block
4. Place phi nodes (iterated dominance frontier)
5. Rename variables (stack-based algorithm)

### FunctionSSABlock

```rust
pub struct SSABlock {           // In r2ssa::function
    pub addr: u64,
    pub size: u32,
    pub ops: Vec<SSAOp>,
    pub phis: Vec<PhiNode>,     // Phi nodes at block entry
}

pub struct PhiNode {
    pub dst: SSAVar,
    pub sources: Vec<(u64, SSAVar)>,  // (predecessor_addr, value)
}
```

**Important:** This is different from the single-instruction `SSABlock` in
`r2ssa/block.rs`. The decompiler and taint analysis use `FunctionSSABlock`.

Optimization Pipeline
---------------------

The SSA optimization pipeline applies a sequence of lightweight passes to
simplify the function before analysis or decompilation.

### Configuration

```rust
pub struct OptimizationConfig {
    pub max_iterations: usize,       // default: 4
    pub enable_sccp: bool,           // Sparse Conditional Constant Propagation
    pub enable_const_prop: bool,     // Simple constant propagation
    pub enable_inst_combine: bool,   // Instruction combining
    pub enable_copy_prop: bool,      // Copy propagation
    pub enable_cse: bool,            // Common subexpression elimination
    pub enable_dce: bool,            // Dead code elimination
    pub preserve_memory_reads: bool, // Keep loads even if unused
}
```

### Passes

| Pass | What it does |
|------|-------------|
| **SCCP** | Sparse Conditional Constant Propagation -- lattice-based analysis that simultaneously discovers constants and unreachable edges |
| **Constant propagation** | Replace uses of constant-defined variables with the constant value |
| **Instruction combining** | Simplify arithmetic patterns (e.g., `x + 0` to `x`, `x * 1` to `x`) |
| **Copy propagation** | Replace uses of `y = copy(x)` with `x` directly |
| **CSE** | Common subexpression elimination -- reuse results of identical operations |
| **DCE** | Dead code elimination -- remove operations whose results are never used |

### Running optimization

```rust
let config = OptimizationConfig::default();
let stats = optimize_function(&mut ssa_func, &config);
println!("Removed {} dead ops", stats.dce_removed_ops);
```

### Statistics

`OptimizationStats` tracks what each pass accomplished:

```rust
pub struct OptimizationStats {
    pub iterations: usize,
    pub sccp_constants_found: usize,
    pub sccp_edges_pruned: usize,
    pub constants_propagated: usize,
    pub ops_simplified: usize,
    pub copies_propagated: usize,
    pub cse_replacements: usize,
    pub dce_removed_ops: usize,
    pub dce_removed_phis: usize,
    // ...
}
```

Def-Use Analysis
----------------

Def-use chains track where variables are defined and used:

```rust
pub struct DefUseInfo {
    pub definitions: HashMap<String, Option<usize>>,  // var -> defining op index
    pub uses: HashMap<String, Vec<usize>>,            // var -> using op indices
    pub inputs: HashSet<String>,   // Live-in variables (not defined in block)
    pub outputs: HashSet<String>,  // Defined but not used within block
    pub live: HashSet<String>,     // Defined and used within block
}
```

### Backward Slicing

The backward slice from a variable answers "what operations affect this
variable?":

```rust
let slice = backward_slice_from_var(&ssa_func, &target_var);
```

The algorithm:

1. Start with the target variable
2. Find its definition (operation or phi node)
3. Add the definition's source variables to the worklist
4. For Load operations, find potentially-aliasing Stores
5. Repeat until the worklist is empty
6. Return all operations in the slice

Plugin Commands
---------------

| Command | Output | Description |
|---------|--------|-------------|
| `a:sla.ssa` | JSON | SSA form for current instruction |
| `a:sla.ssa.func` | JSON | Function SSA with phi nodes |
| `a:sla.ssa.func.opt` | JSON | Optimized function SSA |
| `a:sla.defuse` | JSON | Def-use analysis for current instruction |
| `a:sla.defuse.func` | JSON | Function-wide def-use analysis |
| `a:sla.dom` | JSON | Dominator tree |
| `a:sla.cfg` | text | ASCII CFG |
| `a:sla.cfg.json` | JSON | CFG as JSON |
| `a:sla.slice [var]` | JSON | Backward slice from variable |
