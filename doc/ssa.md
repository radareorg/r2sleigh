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

Value Ranges and Block Origins
------------------------------

Two forward domains answer "what can this value be". `values.rs` solves
strided intervals over a function's SSA graph; `origin.rs` reads one lifted
block forward and says where a value came from. The arguments their code
comments point to are here.

### Strided intervals (`strided.rs`)

An element is a width, a stride and two inclusive bounds read unsigned.

- **meet.** Two elements are arithmetic progressions, so their intersection is
  one too. `x = l1 (mod s1)` and `x = l2 (mod s2)` share a solution exactly
  when `g = gcd(s1, s2)` divides `l2 - l1` (Chinese remainder theorem);
  otherwise the meet is empty, which keeps the even numbers and the odd ones
  apart where a bounds-only meet would not. When it exists, `l1 + s1*t` lies
  on the right progression iff `(s1/g)*t = (l2 - l1)/g (mod s2/g)`, solved
  with the extended Euclidean inverse of `s1/g`, and the common values step by
  `lcm(s1, s2) = (s1/g)*s2`. The arithmetic runs in `u128`, where that product
  of two `u64` strides always fits. Cost `O(log stride)`, no search.
- **widen.** The stride is the join's, `s = gcd(old.stride, new.stride,
  |old.low - new.low|)`, so every value of both lies on it. A low that fell
  drops to `new.low mod s`, the least value on that residue; a high that grew
  rises to `mask - (mask - low) mod s`, the last value below the width's end on
  it. Both keep the residue, so nothing either side held is lost. Once
  widened, a bound moves again only when the stride shrinks, and a stride can
  only shrink to a proper divisor, at most sixty-four times.
- **shr.** Adding a multiple of `2^k` never carries into the bits a shift by
  `k` keeps, so the stride survives, divided, exactly when `2^k` divides it.
  Any other stride lets the dropped bits carry: `{1, 11, 21} >> 2` is
  `{0, 2, 5}`, which only a unit stride holds.
- **Kani.** CBMC settles the eight-bit proofs in a gate's time, but every
  `gcd` step and every product of two symbolic strides is a sixty-four-bit
  divider or multiplier circuit it does not; join, widen, meet, add, sub, mul
  and shl are instead checked exhaustively below six bits by unit tests.

### Termination of the value fixpoint (`values.rs`)

The solver widens at the phis of `W`, the targets of the back edges of a
depth-first walk from the entry. Every transfer reads values defined at a
dominator of the reader, or, for a phi input, at a dominator of the edge's
source. Dominators are DFS ancestors, so postorder never rises along a read
and strictly falls along a phi input on an edge that is not a back edge. A
cycle of reads therefore passes a phi at a target in `W`, on any graph,
reducible or not; natural loop headers are in `W`, so a reducible graph widens
where it always did. A widened phi moves at most once per stride change for
each bound, and a stride falls through at most sixty-four divisors; every other
value sits on no cycle that avoids a widened phi, so it moves only when
something it reads moved, and the ascent ends. The criterion is structural,
not a count of visits, because a count would be a number nothing derived.

A value wider than sixty-four bits is described at sixty-four, where top means
unknown rather than "below `2^64`". An operation that would read an unknown one
as below `2^64` -- a shift, a division, a select's narrowed arm, a piece cut
from it -- leaves its result unknown, and a comparison never narrows one.

### Branch assumptions

An assumption filed under block `B` by the edge `P -> B` holds at `B` only
when that edge dominates `B`: `B` is not the entry, which the call also enters,
and `B` dominates every other predecessor it has. Otherwise `B` is reached by a
path that never took the branch, as a merge is.

Inheritance down the dominator tree is sound by this lemma: if `def(v)`
dominates `P` and `P -> B` dominates `B`, then at every `C` that `B` dominates,
the live instance of `v` is the one tested on the last traversal of `P -> B`.
A path from a later `def(v)` to `C` that avoids `P -> B`, joined to an
entry-to-`def(v)` path that avoids `B`, would reach `B` for the first time
without `P -> B`. Such a prefix exists because `B` cannot dominate `def(v)`,
or it would dominate `P` and never be entered first through `P -> B`.

### Loop trip counts (`semantic/trips.rs`)

`StructuredLoopFact::trips` claims only this: if control leaves the loop through
its one exit edge, the header ran `N` times since the loop was entered. The
hypotheses are a body that neither returns nor branches out of the function, one
exit edge whose block dominates the one latch, and an exit test comparing an
induction's merge (`j = 0`) or update (`j = 1`) at its width `w` with a bound.
Every trip then tests once, and the header's `k`-th run sees
`X_k = c + (k + j)·s mod 2^w`.

An equality exit is solved in the ring: with `s = 2^t·u`, `u` odd, a solution
exists only if `2^t` divides `b − c`, and `k* = ((b − c)/2^t · u⁻¹ − j) mod
2^(w−t)`, exact through wrap. An ordered exit is solved over the integers and
stated only when the first and last iterates up to `k*` lie inside the width,
read signed or unsigned as the comparison reads them; monotone iterates then
never wrap in between. The start and bound are read as affine forms over entry
values modulo `2^w`, a value `ValueRanges` pins being its constant, so a
symbolic count arises only from an equality with an odd step. Its zero, which is
`2^w` trips, is excluded only by an assumption on an edge that dominates the
header (the rule above) whose two sides differ by an odd multiple of the count;
entry values never change, so what the edge tested holds at every run.

A count carries its evidence: the predicate, the induction, whether the update
or the merge is tested, the bound, and for a symbolic count the guarding
assumption. `StructuredLoopFact::validate_trips` recounts it from the graph. An
induction is stated only up to sixty-four bits, the widest a `u64` step
describes exactly, so no count is ever taken modulo a wider width. How control
leaves a loop is read once, when the loop is recovered (`LoopExits`), and the
loop's `exits` and the count's single exit edge both come from that walk.

### Block origins (`origin.rs`)

An origin maps a storage only while none of its bytes has been written since
and no call has intervened, so an older origin never survives a clobber and
becomes false evidence. Three kinds of operation write:

- **An output.** It forgets every tracked storage sharing a byte with it.
  Tracked storages never overlap, so at most one starts below the write and
  reaches into it, and the rest start inside it: one step back and a run
  forward over the ordered map, `O(log s + k)` for `s` tracked and `k` killed.
- **A memory write.** Sleigh writes registers through a space as well as by
  naming them: ARM NEON's `vld1.8 {d0[3]}, [r1]` is `*[register]:1 (&d0 + 3)`.
  A store, guarded or conditional store or compare-and-swap forgets the bytes
  it names where its address folds, and every storage in its space where it
  does not. A block transfer's extent turns on its count and direction, so it
  forgets its whole space. RAM is never tracked, since `of` reads a RAM
  varnode as the slot it names.
- **A call.** A callee may write any register, so every origin is forgotten.

An output's own origin: a copy keeps its source's, clearing the instruction-set
bit of a loaded value keeps its slot, a load through a folded address is that
slot, and every other operation `r2il::eval` models holds the number it
computes wherever all its operands fold, so `movw`/`movt` build one address.

`pdf` carries this fold from a line to the next only where both lie in one
block of the walked body and the next does not begin it; anywhere else it
starts afresh. A block is entered only at its top, so the state at a line is
exact on every execution of it; and the fold is monotone in its entry state,
so every access `pd` claims from one line alone `pdf` claims too.

Plugin Commands
---------------

| Command | Output | Description |
|---------|--------|-------------|
| `a:sla.debug.ssa` | JSON | SSA form for current instruction |
| `a:sla.debug.ssa.func` | JSON | Function SSA with phi nodes |
| `a:sla.debug.ssa.func.opt` | JSON | Optimized function SSA |
| `a:sla.debug.defuse.func` | JSON | Function-wide def-use analysis |
| `a:sla.debug.dom` | JSON | Dominator tree |
| `a:sla.debug.cfg` | text | ASCII CFG |
| `a:sla.debug.cfg.json` | JSON | CFG as JSON |
| `a:sla.debug.slice [var]` | JSON | Backward slice from variable |
