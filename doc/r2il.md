r2il -- Intermediate Language
=============================

Background
----------

Binary analysis tools traditionally use string-based intermediate
representations like radare2's ESIL. ESIL is compact and evaluable, but it
lacks type information, has no concept of address spaces, and encodes
everything as stack operations on opaque strings. This makes precise dataflow
analysis difficult.

r2il is a strongly-typed intermediate language based on Ghidra's P-code
operations. Every operation has explicit input and output varnodes with known
sizes and address spaces. This makes it suitable for SSA transformation,
symbolic execution, type inference, and decompilation -- while still being
convertible back to ESIL for backward compatibility with radare2.

### Comparison to Other ILs

| Aspect | r2il | P-code (Ghidra) | RzIL (rizin) | ESIL (radare2) |
|--------|------|-----------------|--------------|----------------|
| Typing | Sized varnodes | Sized varnodes | Typed (bitvectors, booleans) | Untyped strings |
| Address spaces | Yes (5 kinds) | Yes | Yes (variables + memory) | No |
| Serializable | Yes (serde/bincode) | Binary format | In-memory only | String |
| SSA-ready | Yes | No | No | No |
| Executable | Via r2sym | Via Ghidra emulator | Via RzIL VM | Via ESIL VM |
| Source | Sleigh specifications | Sleigh specifications | Hand-written per arch | Hand-written per arch |

r2il is intentionally close to P-code. Every Ghidra P-code opcode has a
direct r2il equivalent. The main differences are:

1. r2il uses Rust enums with named fields instead of generic instruction
   structs
2. Address spaces are an enum (`SpaceId`) rather than integer indices
3. Varnodes carry their space inline rather than referencing by index

Address Spaces (SpaceId)
------------------------

Every piece of data in r2il lives in an address space:

```rust
pub enum SpaceId {
    Ram,         // Main memory
    Register,    // CPU registers
    Unique,      // Temporaries (intermediate values within one instruction)
    Const,       // Immediate/literal values
    Custom(u32), // Architecture-specific spaces
}
```

| Space | Description | Example |
|-------|-------------|---------|
| Ram | Main memory addresses | `Ram:0x404000[4]` -- 4 bytes at 0x404000 |
| Register | Processor registers by offset | `Register:0x00[8]` -- RAX on x86-64 |
| Unique | Temporaries for complex instructions | `Unique:0x1000[8]` -- intermediate result |
| Const | Literal values (offset IS the value) | `Const:0x2a[4]` -- the integer 42 |
| Custom(n) | Architecture-specific (rare) | Used by some Sleigh specs |

Registers are addressed by offset within the register space. The mapping from
offset to register name (e.g., offset 0x00 = RAX, offset 0x20 = RSP on
x86-64) comes from the Sleigh processor specification.

Varnode
-------

A `Varnode` is the fundamental unit of data -- a sized location in an address
space:

```rust
pub struct Varnode {
    pub space: SpaceId,  // Where the data lives
    pub offset: u64,     // Location within the space
    pub size: u32,       // Size in bytes
}
```

### Construction

```rust
Varnode::constant(42, 4)          // 4-byte literal value 42
Varnode::register(0x00, 8)        // 8-byte register at offset 0 (RAX on x86-64)
Varnode::ram(0x404000, 4)         // 4-byte memory location
Varnode::unique(0x1000, 8)        // 8-byte temporary
```

### Display Format

```
0x2a:4                  -- constant 42, 4 bytes
reg:0x0[8]              -- register at offset 0, 8 bytes
ram:0x404000[4]         -- RAM at 0x404000, 4 bytes
uniq:0x1000[8]          -- temporary 0x1000, 8 bytes
```

R2ILOp
------

`R2ILOp` is the core operation enum with 60+ variants. Each variant has named
fields with `Varnode` inputs and outputs.

### Categories

#### Data Movement

| Operation | Semantics |
|-----------|-----------|
| `Copy` | `dst = src` -- register-to-register copy |
| `Load` | `dst = *[space]addr` -- read from memory |
| `Store` | `*[space]addr = val` -- write to memory |

#### Integer Arithmetic

| Operation | Semantics |
|-----------|-----------|
| `IntAdd` | `dst = a + b` |
| `IntSub` | `dst = a - b` |
| `IntMult` | `dst = a * b` |
| `IntDiv` | `dst = a / b` (unsigned) |
| `IntSDiv` | `dst = a / b` (signed) |
| `IntRem` | `dst = a % b` (unsigned) |
| `IntSRem` | `dst = a % b` (signed) |
| `IntNegate` | `dst = -src` (two's complement) |

#### Logical / Bitwise

| Operation | Semantics |
|-----------|-----------|
| `IntAnd` | `dst = a & b` |
| `IntOr` | `dst = a \| b` |
| `IntXor` | `dst = a ^ b` |
| `IntNot` | `dst = ~src` (bitwise NOT) |
| `BoolAnd` | `dst = a && b` (1-bit) |
| `BoolOr` | `dst = a \|\| b` (1-bit) |
| `BoolXor` | `dst = a ^ b` (1-bit) |
| `BoolNegate` | `dst = !src` (1-bit) |

#### Shift Operations

| Operation | Semantics |
|-----------|-----------|
| `IntLeft` | `dst = a << b` |
| `IntRight` | `dst = a >> b` (logical / unsigned) |
| `IntSRight` | `dst = a >>> b` (arithmetic / signed) |

#### Comparisons

| Operation | Semantics |
|-----------|-----------|
| `IntEqual` | `dst = (a == b)` |
| `IntNotEqual` | `dst = (a != b)` |
| `IntLess` | `dst = (a < b)` unsigned |
| `IntSLess` | `dst = (a < b)` signed |
| `IntLessEqual` | `dst = (a <= b)` unsigned |
| `IntSLessEqual` | `dst = (a <= b)` signed |
| `IntCarry` | `dst = carry(a + b)` |
| `IntSCarry` | `dst = signed_carry(a + b)` |
| `IntSBorrow` | `dst = signed_borrow(a - b)` |

#### Bit Manipulation

| Operation | Semantics |
|-----------|-----------|
| `Piece` | `dst = (hi << n) \| lo` -- concatenate two values |
| `Subpiece` | `dst = src[offset..offset+dst.size]` -- extract bytes |
| `IntZExt` | `dst = zero_extend(src)` |
| `IntSExt` | `dst = sign_extend(src)` |
| `PopCount` | `dst = popcount(src)` |
| `LzCount` | `dst = leading_zeros(src)` |

#### Control Flow

| Operation | Semantics |
|-----------|-----------|
| `Branch` | Unconditional jump to target |
| `CBranch` | If cond then jump to target |
| `BranchInd` | Indirect jump (target is register) |
| `Call` | Call subroutine |
| `CallInd` | Indirect call |
| `Return` | Return from subroutine |

#### Floating Point

| Operation | Semantics |
|-----------|-----------|
| `FloatAdd` | `dst = a + b` (float) |
| `FloatSub` | `dst = a - b` (float) |
| `FloatMult` | `dst = a * b` (float) |
| `FloatDiv` | `dst = a / b` (float) |
| `FloatNeg` | `dst = -src` (float) |
| `FloatAbs` | `dst = abs(src)` (float) |
| `FloatSqrt` | `dst = sqrt(src)` |
| `FloatEqual` | `dst = (a == b)` (float) |
| `FloatLess` | `dst = (a < b)` (float) |
| `FloatNaN` | `dst = isnan(src)` |
| `Int2Float` | `dst = (float)src` |
| `Float2Int` | `dst = (int)src` |
| `Float2Float` | `dst = (float_wider)src` |
| `FloatCeil` | `dst = ceil(src)` |
| `FloatFloor` | `dst = floor(src)` |
| `FloatRound` | `dst = round(src)` |
| `Trunc` | `dst = trunc(src)` |

#### Special

| Operation | Semantics |
|-----------|-----------|
| `CallOther` | Architecture-specific operation (userop index + inputs) |
| `Nop` | No operation |

R2ILBlock
---------

An `R2ILBlock` groups the operations for a single machine instruction:

```rust
pub struct R2ILBlock {
    pub addr: u64,                      // Instruction address
    pub size: u32,                      // Instruction size in bytes
    pub ops: Vec<R2ILOp>,              // Semantic operations
    pub switch_info: Option<SwitchInfo>, // Jump table metadata (if any)
}
```

A single machine instruction typically produces multiple R2ILOps. For example,
x86's `ADD RAX, RBX` generates:

```
IntAdd   { dst: tmp_result,  a: RAX,        b: RBX }
Copy     { dst: RAX,         src: tmp_result }
IntCarry { dst: CF,          a: RAX_old,    b: RBX }
IntEqual { dst: ZF,          a: tmp_result, b: 0 }
IntSLess { dst: SF,          a: tmp_result, b: 0 }
// ... more flag updates
```

The flag computations are generated by the Sleigh specification and are
explicit in r2il. The decompiler later eliminates unused flags
(see [decompiler.md](decompiler.md)).

End-to-End Example
------------------

Tracing `mov rax, [rbp-8]` (bytes `48 8b 45 f8`) at address 0x1000:

**P-code** (from libsla):

```
LOAD ram, (RBP + 0xfffffffffffffff8) -> RAX
```

**R2IL**:

```
IntAdd { dst: Unique:0x1000[8], a: Register:0x20[8](RBP), b: Const:0xfffffffffffffff8[8] }
Load   { dst: Register:0x00[8](RAX), space: Ram, addr: Unique:0x1000[8] }
```

**SSA** (after conversion):

```
tmp:1000_1 = rbp_0 + const:fffffffffffffff8_0
rax_1 = *[ram] tmp:1000_1
```

**ESIL**:

```
rbp,0xfffffffffffffff8,+,[8],rax,=
```

**Decompiled C**:

```c
rax = *(rbp - 8);   // or: rax = local_8;
```

Serialization
-------------

r2il types derive `serde::Serialize` and `serde::Deserialize`. The standard
serialization formats are:

- **JSON** (`serde_json`) -- for plugin output and debugging
- **bincode** -- for compact binary storage

The plugin command `a:sla.json` outputs the R2ILBlock for the current
instruction as JSON.
