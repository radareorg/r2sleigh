# r2sleigh Technical Documentation

## Executive Summary

**r2sleigh** is a Sleigh-to-r2il compiler and radare2 analysis plugin that converts Ghidra P-code processor specifications into a typed intermediate language suitable for binary analysis, SSA transformation, and decompilation.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           r2sleigh Pipeline                                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  Ghidra SLA  │──▶│    libsla    │──▶│   P-code     │──▶│    r2il      │
│    Files     │   │  (bindings)  │   │  Operations  │   │   R2ILOp     │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
                                                                │
                   ┌────────────────────────────────────────────┴────────┐
                   │                                                     │
                   ▼                                                     ▼
           ┌──────────────┐                                     ┌──────────────┐
           │     ESIL     │                                     │     SSA      │
           │   (radare2)  │                                     │   (r2ssa)    │
           └──────────────┘                                     └──────────────┘
                                                                       │
                   ┌───────────────────────────────────────────────────┤
                   ▼                                                   ▼
           ┌──────────────┐   ┌──────────────┐               ┌──────────────┐
           │   Def-Use    │   │    Taint     │               │  Decompiler  │
           │   Analysis   │   │   Analysis   │               │   (r2dec)    │
           └──────────────┘   └──────────────┘               └──────────────┘
                                                                       │
                                                                       ▼
                                                             ┌──────────────┐
                                                             │   C Code     │
                                                             │   Output     │
                                                             └──────────────┘
```

---

## Component Deep Dive

### 1. Sleigh Integration (r2sleigh-lift)

#### 1.1 What is Sleigh?

Sleigh is Ghidra's processor specification language. It defines how machine code bytes translate into P-code operations—a register-transfer language that captures instruction semantics.

**Key Files:**

- `.sla` files: Compiled Sleigh specifications (binary format)
- `.pspec` files: Processor specification XML (register definitions, etc.)

#### 1.2 The Disassembler

The `Disassembler` struct in `r2sleigh-lift/src/disasm.rs` wraps `libsla` (Ghidra's native bindings) to convert machine code bytes into P-code operations.

**Initialization:**

```rust
pub fn from_sla(sla_bytes: &[u8], pspec: &str, arch_name: &str) -> Result<Self>
```

The disassembler:

1. Loads the compiled `.sla` file via `GhidraSleigh::builder()`
2. Applies the processor specification (register definitions)
3. Builds a register name map for human-readable output

**Lifting Process:**

```rust
pub fn lift(&self, bytes: &[u8], addr: u64) -> Result<R2ILBlock>
```

1. Creates an `Address` in the code space
2. Uses a `ByteLoader` to provide instruction bytes to libsla
3. Calls `sleigh.disassemble_pcode()` to get `PcodeDisassembly`
4. Translates each `PcodeInstruction` to `R2ILOp` via `translate_pcode_op()`

**Important Constraint:** libsla requires at least 16 bytes of input for x86-64 (variable-length instructions). The disassembler pads shorter inputs automatically.

#### 1.3 P-code to R2IL Translation

The translation happens in `translate_pcode_op()`, which uses a `PcodeSource` trait abstraction:

```rust
trait PcodeSource {
    fn output(&self) -> Option<Varnode>;
    fn input(&self, idx: usize) -> Option<Varnode>;
    fn input_raw_offset(&self, idx: usize) -> Option<u64>;
    fn input_count(&self) -> usize;
    fn space_from_index(&self, idx: u64) -> SpaceId;
}
```

**P-code Opcode Mapping:**

| P-code Operation | R2ILOp | Description |
|------------------|--------|-------------|
| `OpCode::Copy` | `R2ILOp::Copy` | Register-to-register move |
| `OpCode::Load` | `R2ILOp::Load` | Memory read |
| `OpCode::Store` | `R2ILOp::Store` | Memory write |
| `OpCode::Int(IntOp::Add)` | `R2ILOp::IntAdd` | Integer addition |
| `OpCode::Int(IntOp::Equal)` | `R2ILOp::IntEqual` | Equality comparison |
| `OpCode::BranchConditional` | `R2ILOp::CBranch` | Conditional branch |
| `OpCode::Piece` | `R2ILOp::Piece` | Concatenate two values |
| `OpCode::Subpiece` | `R2ILOp::Subpiece` | Extract byte range |

---

### 2. R2IL - The Intermediate Language (r2il crate)

R2IL is a strongly-typed intermediate representation based on Ghidra's P-code operations.

#### 2.1 Core Types

**SpaceId** (`r2il/src/space.rs`):

```rust
pub enum SpaceId {
    Ram,        // Main memory
    Register,   // CPU registers
    Unique,     // Temporaries (SSA-like temps for complex instructions)
    Const,      // Immediate values
    Custom(u32) // Architecture-specific spaces
}
```

**Varnode** (`r2il/src/varnode.rs`):

A `Varnode` is the fundamental data unit—a sized location in an address space:

```rust
pub struct Varnode {
    pub space: SpaceId,  // Where the data lives
    pub offset: u64,     // Location within the space
    pub size: u32,       // Size in bytes
}
```

Examples:

- `Varnode { space: Register, offset: 0x20, size: 8 }` → RSP on x86-64
- `Varnode { space: Const, offset: 42, size: 4 }` → literal value 42
- `Varnode { space: Unique, offset: 0x1000, size: 4 }` → temporary result

**R2ILOp** (`r2il/src/opcode.rs`):

The core operation enum with 60+ variants organized by category:

```rust
pub enum R2ILOp {
    // Data Movement
    Copy { dst: Varnode, src: Varnode },
    Load { dst: Varnode, space: SpaceId, addr: Varnode },
    Store { space: SpaceId, addr: Varnode, val: Varnode },
    
    // Integer Arithmetic
    IntAdd { dst: Varnode, a: Varnode, b: Varnode },
    IntSub { dst: Varnode, a: Varnode, b: Varnode },
    IntMult { dst: Varnode, a: Varnode, b: Varnode },
    // ... more arithmetic
    
    // Comparisons
    IntEqual { dst: Varnode, a: Varnode, b: Varnode },
    IntLess { dst: Varnode, a: Varnode, b: Varnode },
    IntSLess { dst: Varnode, a: Varnode, b: Varnode },  // signed
    // ... more comparisons
    
    // Control Flow
    Branch { target: Varnode },
    CBranch { target: Varnode, cond: Varnode },
    Call { target: Varnode },
    Return { target: Varnode },
    
    // Bit Manipulation
    Piece { dst: Varnode, hi: Varnode, lo: Varnode },
    Subpiece { dst: Varnode, src: Varnode, offset: u32 },
    
    // Special
    CallOther { output: Option<Varnode>, userop: u32, inputs: Vec<Varnode> },
    // ... and more
}
```

**R2ILBlock**:

```rust
pub struct R2ILBlock {
    pub addr: u64,              // Instruction address
    pub size: u32,              // Instruction size in bytes
    pub ops: Vec<R2ILOp>,       // Semantic operations
    pub switch_info: Option<SwitchInfo>,  // Jump table data
}
```

A single machine instruction can produce multiple R2ILOps. For example, x86's `ADD RAX, RBX` generates:

1. `IntAdd { dst: rax_new, a: rax, b: rbx }`
2. `IntCarry { dst: cf, a: rax, b: rbx }`
3. `IntEqual { dst: zf, a: result, b: 0 }`
4. (more flag updates...)

---

### 3. ESIL Generation (r2sleigh-lift/src/esil.rs)

ESIL (Evaluable Strings Intermediate Language) is radare2's RPN-based VM language.

**Function: `op_to_esil()`**

Converts R2ILOp to ESIL strings:

```rust
pub fn op_to_esil(disasm: &Disassembler, op: &R2ILOp) -> String
```

**ESIL Syntax:**

- Stack-based, comma-separated
- `a,b,+` → push a, push b, add
- `a,b,=` → b = a (assignment)
- `a,[N]` → read N bytes from address a
- `a,b,=[N]` → write N bytes of b to address a

**Translation Examples:**

| R2ILOp | ESIL Output |
|--------|-------------|
| `Copy { dst, src }` | `src,dst,=` |
| `Load { dst, addr }` | `addr,[8],dst,=` |
| `IntAdd { dst, a, b }` | `a,b,+,dst,=` |
| `IntSExt { dst, src }` | `src,bits,~~,dst,=` |
| `CBranch { target, cond }` | `cond,?{,target,pc,=,}` |

---

### 4. SSA Transformation (r2ssa crate)

SSA (Static Single Assignment) form ensures each variable is defined exactly once, enabling precise dataflow analysis.

#### 4.1 SSA Variables

**SSAVar** (`r2ssa/src/var.rs`):

```rust
pub struct SSAVar {
    pub name: String,    // Base name: "rax", "tmp:1000", "const:42"
    pub version: u32,    // SSA version number
    pub size: u32,       // Size in bytes
}
```

Display format: `RAX_0`, `RAX_1`, `tmp:1000_2`, `const:42_0`

**Naming conventions:**

- Version 0 = input value (live-in)
- Version 1+ = defined within the block/function
- `tmp:xxxx` = temporary from Unique space
- `const:xxxx` = immediate value

#### 4.2 SSA Operations

**SSAOp** (`r2ssa/src/op.rs`):

Mirrors R2ILOp but uses SSAVar instead of Varnode:

```rust
pub enum SSAOp {
    // SSA-specific
    Phi { dst: SSAVar, sources: Vec<SSAVar> },
    
    // Data movement
    Copy { dst: SSAVar, src: SSAVar },
    Load { dst: SSAVar, space: String, addr: SSAVar },
    Store { space: String, addr: SSAVar, val: SSAVar },
    
    // Arithmetic (uses SSAVar)
    IntAdd { dst: SSAVar, a: SSAVar, b: SSAVar },
    // ... same structure as R2ILOp
}
```

#### 4.3 Single-Block SSA Conversion

**Function: `to_ssa()`** (`r2ssa/src/block.rs`):

```rust
pub fn to_ssa(block: &R2ILBlock, disasm: &Disassembler) -> SSABlock
```

**Conversion Algorithm:**

```
1. Create SSAContext (tracks versions per variable)
2. For each R2ILOp in block:
   a. For each INPUT varnode:
      - Look up current version in context → SSAVar
   b. For each OUTPUT varnode:
      - Allocate new version in context → SSAVar
   c. Create corresponding SSAOp with versioned variables
3. Return SSABlock with all SSAOps
```

**Varnode-to-Name Mapping:**

```rust
fn varnode_to_name(vn: &Varnode, disasm: &Disassembler) -> String {
    match vn.space {
        SpaceId::Register => disasm.register_name(vn)  // "rax", "rbp"
            .unwrap_or(format!("reg:{:x}", vn.offset)),
        SpaceId::Unique => format!("tmp:{:x}", vn.offset),
        SpaceId::Const => format!("const:{:x}", vn.offset),
        SpaceId::Ram => format!("ram:{:x}", vn.offset),
        // ...
    }
}
```

#### 4.4 Function-Level SSA (with Phi Nodes)

**SSAFunction** (`r2ssa/src/function.rs`):

For multi-block functions, the algorithm is more complex:

```rust
pub fn from_blocks(blocks: &[R2ILBlock]) -> Option<Self>
```

**Full SSA Construction:**

```
1. Build CFG from blocks
2. Compute dominator tree (DomTree)
3. Collect variable definitions per block
4. Place phi nodes (using dominance frontiers)
5. Rename variables (with stack-based algorithm)
6. Return SSAFunction with all blocks
```

**Phi Node Placement:**

```rust
pub struct PhiPlacement {
    // For each block, which variables need phi nodes
    phi_vars: HashMap<u64, HashSet<String>>,
}
```

A phi node merges values from different control flow paths:

```
Block 0x1000: rax_1 = 1
Block 0x1004: rax_2 = 2
Block 0x1008: rax_3 = phi(rax_1, rax_2)  // Merge point
```

**FunctionSSABlock**:

```rust
pub struct SSABlock {
    pub addr: u64,
    pub size: u32,
    pub ops: Vec<SSAOp>,
    pub phis: Vec<PhiNode>,  // Phi nodes at block entry
}

pub struct PhiNode {
    pub dst: SSAVar,
    pub sources: Vec<(u64, SSAVar)>,  // (predecessor_addr, value)
}
```

#### 4.5 Control Flow Graph

**CFG** (`r2ssa/src/cfg.rs`):

```rust
pub struct CFG {
    graph: DiGraph<BasicBlock, CFGEdge>,
    addr_to_node: HashMap<u64, NodeIndex>,
    pub entry: u64,
}

pub enum BlockTerminator {
    Fallthrough { next: u64 },
    Branch { target: u64 },
    ConditionalBranch { true_target: u64, false_target: u64 },
    Switch { cases: Vec<(u64, u64)>, default: Option<u64> },
    Call { target: u64, fallthrough: Option<u64> },
    Return,
    // ...
}
```

---

### 5. Def-Use Analysis (r2ssa/src/defuse.rs)

Def-Use chains track where variables are defined and used.

**DefUseInfo**:

```rust
pub struct DefUseInfo {
    pub definitions: HashMap<String, Option<usize>>,  // var -> defining op index
    pub uses: HashMap<String, Vec<usize>>,            // var -> using op indices
    pub inputs: HashSet<String>,   // Live-in variables
    pub outputs: HashSet<String>,  // Defined but not used
    pub live: HashSet<String>,     // Defined and used
}
```

**Backward Slicing**:

```rust
pub fn backward_slice_from_var(func: &SSAFunction, sink: &SSAVar) -> BackwardSlice
```

Computes all operations that affect a given variable:

1. Start with sink variable
2. Find its definition (op or phi)
3. Add definition's sources to worklist
4. For Load operations, find aliasing Store operations
5. Repeat until worklist empty

---

### 6. Decompiler (r2dec crate)

The decompiler converts SSA form to readable C code.

#### 6.1 Decompilation Pipeline

```
SSAFunction
     │
     ▼
┌─────────────────────┐
│  FoldingContext     │  ← Expression folding, dead code elimination
│  (analyze_blocks)   │
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  RegionAnalyzer     │  ← Control flow structuring
│  (structure.rs)     │
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  CStmt / CExpr      │  ← C AST generation
│  (ast.rs)           │
└─────────────────────┘
     │
     ▼
┌─────────────────────┐
│  CodeGenerator      │  ← Pretty-print to C string
│  (codegen.rs)       │
└─────────────────────┘
```

#### 6.2 Expression Folding (r2dec/src/fold.rs)

**FoldingContext** performs three key optimizations:

1. **Use Counting**: Track how many times each SSA variable is used
2. **Single-Use Inlining**: Inline expressions used only once
3. **Dead Code Elimination**: Remove unused CPU flag computations

**Dead Flag Elimination:**

```rust
fn is_cpu_flag(name: &str) -> bool {
    matches!(name, "cf" | "pf" | "af" | "zf" | "sf" | "of" | "df" | "tf" | ...)
}
```

Flags like ZF, CF, SF are eliminated when not used in a branch condition.

**Comparison Reconstruction:**

x86 encodes comparisons as:

1. `CMP a, b` → generates SUB + flag updates
2. `JE label` → branches if ZF=1

The decompiler reconstructs:

```
// Before (SSA level):
tmp_1 = a - b
ZF_1 = (tmp_1 == 0)
CBRANCH target if ZF_1

// After (C code):
if (a == b) goto target;
```

**Flag Pattern Matching:**

```rust
fn try_reconstruct_condition(&self, expr: &CExpr) -> Option<CExpr> {
    // !ZF → a != b
    // ZF → a == b
    // !ZF && (OF == SF) → a > b (signed)
    // OF == SF → a >= b (signed)
    // CF → a < b (unsigned)
    // ...
}
```

#### 6.3 C AST Types (r2dec/src/ast.rs)

**CExpr**:

```rust
pub enum CExpr {
    IntLit(i64),
    UIntLit(u64),
    StringLit(String),
    Var(String),
    Binary { op: BinaryOp, left: Box<CExpr>, right: Box<CExpr> },
    Unary { op: UnaryOp, operand: Box<CExpr> },
    Call { func: Box<CExpr>, args: Vec<CExpr> },
    Deref(Box<CExpr>),
    Cast { ty: CType, expr: Box<CExpr> },
    Subscript { base: Box<CExpr>, index: Box<CExpr> },
    // ...
}
```

**CStmt**:

```rust
pub enum CStmt {
    Expr(CExpr),
    If { cond: CExpr, then_body: Box<CStmt>, else_body: Option<Box<CStmt>> },
    While { cond: CExpr, body: Box<CStmt> },
    DoWhile { body: Box<CStmt>, cond: CExpr },
    Switch { expr: CExpr, cases: Vec<(i64, CStmt)>, default: Option<Box<CStmt>> },
    Block(Vec<CStmt>),
    Return(Option<CExpr>),
    Break,
    Continue,
    // ...
}
```

---

### 7. Data Flow Example: End-to-End

Let's trace `mov rax, [rbp-8]` through the entire pipeline:

**Stage 1: Machine Code**

```
48 8b 45 f8  (at address 0x1000)
```

**Stage 2: P-code (from libsla)**

```
PcodeInstruction {
    opcode: Load,
    output: VarnodeData { space: register, offset: 0, size: 8 },  // RAX
    inputs: [
        VarnodeData { space: register, offset: 0x20, size: 8 },   // RBP
        VarnodeData { space: const, offset: -8, size: 8 }         // offset
    ]
}
```

**Stage 3: R2IL**

```rust
R2ILBlock {
    addr: 0x1000,
    size: 4,
    ops: [
        IntAdd {
            dst: Varnode { space: Unique, offset: 0x1000, size: 8 },
            a: Varnode { space: Register, offset: 0x20, size: 8 },  // RBP
            b: Varnode { space: Const, offset: 0xfffffffffffffff8, size: 8 }  // -8
        },
        Load {
            dst: Varnode { space: Register, offset: 0, size: 8 },   // RAX
            space: Ram,
            addr: Varnode { space: Unique, offset: 0x1000, size: 8 }
        }
    ]
}
```

**Stage 4: SSA**

```rust
SSABlock {
    ops: [
        SSAOp::IntAdd {
            dst: SSAVar { name: "tmp:1000", version: 1, size: 8 },
            a: SSAVar { name: "rbp", version: 0, size: 8 },
            b: SSAVar { name: "const:fffffffffffffff8", version: 0, size: 8 }
        },
        SSAOp::Load {
            dst: SSAVar { name: "rax", version: 1, size: 8 },
            space: "ram",
            addr: SSAVar { name: "tmp:1000", version: 1, size: 8 }
        }
    ]
}
```

**Stage 5: ESIL**

```
rbp,0xfffffffffffffff8,+,tmp:1000,=,tmp:1000,[8],rax,=
```

**Stage 6: Decompiled C**

```c
rax = *(rbp - 8);  // Or: rax = local_8;
```

---

### 8. Plugin Integration (r2plugin)

The radare2 plugin exposes r2sleigh functionality to the r2 framework.

**Plugin Commands:**

| Command | Function | Output |
|---------|----------|--------|
| `a:sla.info` | Architecture status | Text |
| `a:sla.json` | Raw R2ILOp for instruction | JSON |
| `a:sla.ssa` | SSA form of instruction | JSON |
| `a:sla.defuse` | Def-use analysis | JSON |
| `a:sla.dec` | Decompile function | C code |
| `a:sla.cfg` | Control flow graph | JSON |

**Architecture Auto-Detection:**

```rust
// Reads anal.arch and anal.bits from radare2
// Maps to Sleigh architecture names:
// - x86 + 64 bits → "x86-64"
// - x86 + 32 bits → "x86"
// - arm → "arm"
```

---

## Key Design Decisions

### 1. Two SSABlock Types

The codebase has two `SSABlock` types:

| Type | Location | Purpose |
|------|----------|---------|
| `SSABlock` | `r2ssa/block.rs` | Single instruction, no phi nodes |
| `SSABlock` (FunctionSSABlock) | `r2ssa/function.rs` | Function block with phi nodes |

r2dec uses the function-level `SSABlock` which includes `phis: Vec<PhiNode>`.

### 2. Varnode Naming Strategy

Register names are resolved using Sleigh's register map:

```rust
fn register_name(&self, vn: &Varnode) -> Option<String> {
    // Try cache first
    if let Some(name) = self.reg_name_map.get(&(vn.offset, vn.size)) {
        return Some(name.clone());
    }
    // Query libsla
    self.sleigh.register_name(&varnode_data)
}
```

For overlapping registers (e.g., RAX/EAX/AX/AL), `select_register_name()` chooses the canonical name.

### 3. Flag Handling

CPU flags are computed explicitly by Sleigh but are often unused. The decompiler:

1. Tracks flag usage during analysis
2. Eliminates unused flag computations
3. Reconstructs high-level comparisons from flag patterns

### 4. Memory Aliasing

Backward slicing considers memory aliasing:

```rust
fn addresses_may_alias(a: &SSAVar, b: &SSAVar) -> bool {
    match (const_value(a), const_value(b)) {
        (Some(a_val), Some(b_val)) => a_val == b_val,
        _ => true,  // Conservative: assume aliasing if not provable constants
    }
}
```

---

## Testing Strategy

**Unit Tests:** Each module has inline `#[cfg(test)]` modules testing individual functions.

**Integration Tests:** `tests/e2e/integration_tests.rs` provides end-to-end testing:

```rust
#[test]
fn test_ssa_output() {
    let result = r2_at_func(vuln_test_binary(), "main", "a:sla.ssa");
    result.assert_ok();
    assert!(result.contains("IntAdd"));
}
```

**Test Binary:** `tests/e2e/vuln_test.c` provides specific patterns for testing.

---

## Summary

r2sleigh implements a complete binary analysis pipeline:

1. **Sleigh → P-code**: Using libsla bindings to Ghidra's processor specifications
2. **P-code → R2IL**: Translation to a typed intermediate language
3. **R2IL → SSA**: Static single assignment transformation with phi nodes
4. **R2IL → ESIL**: Conversion to radare2's evaluation language
5. **SSA → C**: Decompilation with expression folding and control flow structuring

The modular architecture allows each stage to be used independently or combined for full decompilation.
