r2il: the low tier
==================

r2il is the strongly typed intermediate language every lift produces. It is a
close transcription of Ghidra's P-code: every operation has explicit input and
output varnodes with known sizes and address spaces, and every P-code opcode
has a direct r2il equivalent. It differs from P-code in three ways:

1. operations are a Rust enum with named fields, not a generic instruction struct
2. address spaces are an enum (`SpaceId`), not integer indices
3. a varnode carries its space inline

The crate is `crates/r2il`. `r2s` prints a function's r2il with `pdil`.

Varnodes and spaces
-------------------

A `Varnode` is `{ space: SpaceId, offset: u64, size: u32, meta: Option<VarnodeMetadata> }`.
Equality and hashing use `(space, offset, size)` only; metadata is excluded.

| `SpaceId` | Meaning | `Display` |
|-----------|---------|-----------|
| `Ram` | main memory | `ram:0x404000[4]` |
| `Register` | registers, by offset in the register space | `reg:0x0[8]` |
| `Unique` | temporaries inside one instruction | `uniq:0x1000[8]` |
| `Const` | literals; the offset is the value | `0x2a:4` |
| `Custom(n)` | architecture-specific spaces | `space3:0x0[4]` |

Constructors: `Varnode::constant`, `register`, `ram`, `unique`. The offset to
register-name mapping comes from the Sleigh processor specification.

Operations
----------

`R2ILOp` (`crates/r2il/src/opcode.rs`) has 84 variants:

| Group | Variants |
|-------|----------|
| Data movement | `Copy`, `Load`, `Store`, `BlockTransfer` |
| Memory ordering | `Fence`, `LoadLinked`, `StoreConditional`, `AtomicCAS`, `LoadGuarded`, `StoreGuarded` |
| Integer arithmetic | `IntAdd`, `IntSub`, `IntMult`, `IntDiv`, `IntSDiv`, `IntRem`, `IntSRem`, `IntNegate`, `IntCarry`, `IntSCarry`, `IntSBorrow` |
| Bitwise and shifts | `IntAnd`, `IntOr`, `IntXor`, `IntNot`, `IntLeft`, `IntRight`, `IntSRight` |
| Comparison | `IntEqual`, `IntNotEqual`, `IntLess`, `IntSLess`, `IntLessEqual`, `IntSLessEqual` |
| Extension and pieces | `IntZExt`, `IntSExt`, `Piece`, `Subpiece`, `PopCount`, `Lzcount` |
| Boolean | `BoolNot`, `BoolAnd`, `BoolOr`, `BoolXor` |
| Control | `Branch`, `CBranch`, `BranchInd`, `Call`, `CallInd`, `Return` |
| Floating point | `FloatAdd`, `FloatSub`, `FloatMult`, `FloatDiv`, `FloatNeg`, `FloatAbs`, `FloatSqrt`, `FloatCeil`, `FloatFloor`, `FloatRound`, `FloatNaN`, `FloatEqual`, `FloatNotEqual`, `FloatLess`, `FloatLessEqual`, `Int2Float`, `Float2Int`, `FloatFloat`, `Trunc` |
| Special | `CallOther`, `Nop`, `Unimplemented`, `CpuId`, `Breakpoint` |
| P-code analysis forms | `Multiequal`, `Indirect`, `PtrAdd`, `PtrSub`, `SegmentOp`, `New`, `Cast`, `Extract`, `Insert` |
| Instruction-local merge | `Select`, produced when P-code control flow inside one instruction is normalized into a linear value graph |

`BlockTransfer` is one repeated string operation (`Move`, `Fill`, `Scan`,
`Compare`) over up to `count` elements. Memory-ordering operations are emitted
only when the Sleigh translator emits the corresponding P-code; a mnemonic or a
userop name never rewrites an operation or adds ordering metadata. An
instruction whose lift produces no P-code stays an exact native span and
residualizes as unsupported.

`R2ILOp` also answers questions consumers would otherwise pattern-match:
`ValueUse` (does an operation carry, derive, test or consume a value) and
`ControlTransfer` (which operand says where control goes).

`eval.rs` is the one statement of what a value operation computes on concrete
bytes; every constant fold in the engine answers through `r2il::eval::apply`.

Blocks
------

An `R2ILBlock` holds the operations of one machine instruction:
`{ addr, size, ops, switch_info: Option<SwitchInfo>, op_metadata: BTreeMap<usize, OpMetadata> }`.
Flag computations are explicit, as the Sleigh specification writes them; dead
flags are removed later in SSA.

Architecture specification
--------------------------

`ArchSpec` (`serialize.rs`) describes one language: `name`, `variant`,
`instruction_endianness`, `memory_endianness`, `addr_size`, `alignment`,
`spaces`, `registers`, `register_projections`, `return_registers`,
`program_counter`, `user_ops` (names indexed by a `CallOther`'s id),
`supervisor_calls` and `tracked_entry_values`.

- `register_projections` is the name-free register geometry table. Empty
  means the geometry is unavailable; otherwise it is strictly sorted, covers
  every unique declared storage exactly once, and each laminar overlap
  component shares one maximal carrier and byte orientation. Partial-overlap
  components refuse as a whole.
- Machine roles (`program_counter`, `return_registers`) are read from the
  specification. When it does not say, the field is empty and nothing
  downstream may claim to know.
- `AddressSpace` may carry `endianness`, `memory_class`, `permissions`,
  half-open `valid_ranges`, `bank_id` and `segment_id`.
- Endianness has exactly two architecture-level authorities,
  `instruction_endianness` and `memory_endianness`; spaces and metadata may
  override them. `Endianness` is `Little`, `Big`, `Mixed` or `Custom`; the
  last two are metadata only.

Metadata hints
--------------

`VarnodeMetadata` (storage class, scalar kind, pointer hint, float encoding,
endianness) and `OpMetadata` (memory class, ordering, permissions, valid range,
bank, segment, atomic kind, endianness) are advisory. They never change
execution semantics, and JSON omits absent fields.

Validation
----------

`validate.rs` aggregates every issue into one `ValidationError`:

| Function | Checks |
|----------|--------|
| `validate_op`, `validate_block` | non-zero sizes; no output in const space; `Load`/`Store` not const-addressed; `PtrAdd`/`PtrSub` element size > 0; `op_metadata` keys in range; switch metadata sane |
| `validate_op_semantic`, `validate_block_semantic` | operand widths for copy, extension, truncation, integer, boolean, compare, piece and memory-ordering ops; address width against the space; branch-target and `CBranch` condition widths |
| `validate_block_full` | both of the above |
| `validate_archspec`, `validate_register_geometry` | name, sizes, exactly one default space, unique spaces and registers, projection-table coherence, range and metadata schema |

Float-family operations, `CallOther` and the P-code analysis forms are checked
structurally only. The instruction exporter runs `validate_block_full`; the
Sleigh CLI runs `validate_archspec`.

Serialization
-------------

Every type derives serde. JSON is for debugging and the exporter. The binary
`.r2il` file has one format identity, `R2PSTC07` (`r2il::MAGIC`), with no
version field and no compatibility branch. Saving emits
`R2PSTC07 || payload_length_u64_le || postcard(ArchSpec)`; the reader
(`serialize::from_bytes`) requires exact payload consumption and rejects a
truncated file, trailing bytes, and any other discriminator or older encoding.
Older artifacts must be regenerated.

Sleigh CLI and instruction exporter
-----------------------------------

`r2sleigh` (`crates/r2sleigh-cli`) has `compile`, `info`, `test-arch`,
`version`, `image`, `disasm` and `run`. `run` lifts one instruction and hands
it to `r2sleigh-cli` (`export.rs`):

```bash
cargo run -p r2sleigh-cli --bin r2sleigh --features x86 -- \
  run --arch x86-64 --bytes "31c00000000000000000000000000000" --action lift --format json
```

| `--action` | `--format` |
|------------|------------|
| `lift`, `ssa`, `defuse` | `json`, `text` |
| `dec` | `c_like`, `json`, `text` |

Any other pair fails with `UnsupportedCombination`; nothing falls back.
