# ADR: a register family has one SSA identity, and a lane is a projection of it

Status: built. S1 and S2 landed together on 2026-09-10; section 10 records
what each stage actually cost and what it exposed, and supersedes any
"to check" above that it answers. Ordered after the dominator-tree structurer
(`doc/adr-structure-dominator-tree.md`), as decided with the user on
2026-09-10. Read `doc/handoff-location-ssa.md` from "A narrow formal, its
carrier, and why the last fix was reverted" for the evidence that four layers
carry their own reconciliation of the duality this removes.

Every claim below is marked **verified** (read from the code this session, with
the site named) or **to check** (a hypothesis with the check that decides it).

## 1. What is wrong, as one statement

The SSA gives one machine register as many identities as the lift has widths
for it, renames each independently, and then a fixed-point dataflow over the
renamed program guesses which identity's latest version each read meant.
Every layer above it carries a rule for the cases the guess gets wrong.

**Verified.** The identity phi placement and renaming work with is the exact
varnode -- name, width and canonical storage (`phi.rs:22` `RenameIdentity`,
built by `RenameIdentity::from_varnode`, `phi.rs:37`). `EDX` (4 bytes at
offset 8) and `RDX` (8 bytes at offset 8) are therefore two identities with two
version stacks (`rename.rs:143` `read_var`, `:155` `write_var`) and two entry
values (`rename.rs:95` `init_identity` seeds version 0 for each). Sleigh spells
a 32-bit write as both -- `EDX_1 = ...; RDX_1 = zext(EDX_1)` (a real function's
prepared SSA, `bzip2 generateMTFValues`) -- so straight-line code happens to
keep both current, but a wide write leaves the narrow identity's version stale
and a narrow write (`mov dl, ...`) leaves the wide one stale.

**Verified.** The repair is `function.rs:3287`
`materialize_register_alias_sources`, driven by a forward dataflow of
`FamilyRootState` (`function.rs:4398`, computed at `:3910` with a worklist and a
meet that drops any slot two predecessors disagree on, `:4680`
`meet_family_states`). It rewrites a read whose root is a wider definition into
`Subpiece(root)` named `tmp:regalias:<block>:<op>:<operand>` (`:4936`), a wide
read of separately written lanes into a `Piece` of tiles (`:4958`), and a phi
source likewise into `tmp:regalias:phi:...` (`:3413`). The pass and its helpers
are `function.rs:4372-5320`, about 950 lines, pinned by 28 tests.

**Verified.** The layers above reconcile the same duality again:

| layer | rule | site |
| --- | --- | --- |
| parameter entity | every version-0 value with a live use whose slot resolves is an "entry value" of the formal; the carrier width is the max of their widths | `r2types/function_facts.rs:2960-3000` |
| binding plan | a parameter home whose slot width differs from the parameter's width refuses `ParameterHomeWidthMismatch` | `binding_plan/construction.rs:1143` |
| ABI reaching-value walk | a definition whose storage is a slice of the wanted carrier fails closed; a `CallDefine` alias is skipped; a `tmp:regalias` definition has no canonical storage and is invisible | `semantic.rs:5130-5160` |
| call clobbers | one clobber is defined once per alias identity in scope (`CallDefine RAX` and `CallDefine EAX`) | `rename.rs:556-592` |
| machine projection | a use is a `MachineUseSlice { bit_offset, width_bits, carrier_width_bits }` of a carrier and a write is `Full`, `Lane`, `Insert` or `ZeroExtend` of one | `machine.rs:637`, `construction.rs:463-500` |

The last row is the tell: the projection and the plan already think in
"carrier plus slice". Only the SSA below them does not, and the family pass is
the bridge.

The refusal classes this accounts for, from the 2026-09-10 DecBench census
(`tests/decbench/artifacts/decbench-20260910T132813-5442/census`):
`OpLowering(calls.rs:N)` (13: `inflateSync`, `test_gzio`, `test_flush`,
`examplesh main`), a call argument the walk cannot reach because a lane
definition or a `regalias` temporary sits between it and the carrier; the
narrow-formal class (`gzputc`'s `int c` in `rsi` is absent from the rendered
signature and `RSI_0` is read undeclared -- observed this session on the
`example` binary; `deflatePrime`'s `value` in the handoff); and the
`RenderedValueRequired` left in `inflateSync` after the walk was made
cycle-aware, whose unobserved value is a phi read only through a
`tmp:regalias:phi` subpiece.

## 2. The object

An architecture's register file is a set of byte ranges; the lift names some of
them. **Verified** (`function.rs:4450` `RegisterFamilyInfo::from_register_storages`)
that overlapping named ranges are grouped by union-find into *families*, each
with a widest slot, and that any unnamed sub-range of a family is a member of
it (`:4647` `member_at_offset`).

Define, for the register space:

    root(F)          the widest slot of family F
    a varnode v      (F, o, w): family, byte offset within root(F), width
    a value of F     one SSA version of root(F): a bit vector of width |root(F)|

and for the other spaces (unique, memory-backed, constants) leave the identity
as it is: those are not aliased by geometry.

A **read** of v = (F, o, w) at a point is `Subpiece(current(F), o)` of width w.
A **write** of v = (F, o, w) with value x is a new version of root(F):

    root_{k+1} = Insert(root_k, x, o, w)          in general
    root_{k+1} = ZeroExtend(x, |root|)            when the architecture clears the rest
                                                  and Sleigh already spelled it so

**Verified** that Sleigh spells the second case itself: the 32-bit x86-64 write
lifts as the lane write followed by `RDX = zext(EDX)`, and the family pass
already relies on this ("a narrow write that clears the rest of its register
says so in the lift", `function.rs:5241`). So the rewrite never has to know an
architecture's clearing rule; the lift's own `IntZExt` of the root is the
root's definition, and the lane write before it defines nothing the program
reads except as that zext's input.

Under this object there is exactly one entry value per family (`root(F)`
version 0), exactly one phi per family per join, and no read whose meaning is
decided after renaming.

## 3. The invariant, which is the certificate

For every register read r = (F, o, w) at program point p, the value read is

    Subpiece(D(F, p), o, w)

where D(F, p) is the unique SSA definition of root(F) reaching p -- the nearest
dominating write of root(F), or the phi of root(F) at the head of the block,
or root(F)'s entry version. This is the ordinary SSA reaching-definition
property applied to one identity per family. It is what the family pass
approximates with its dataflow, and it is exact by construction once the
identity is the family: SSA renaming over a dominator tree gives each use the
unique reaching definition (Cytron et al. 1991), and there is nothing left for a
later pass to reconcile.

Two corollaries the layers above can rely on:

- **A formal is a projection of its carrier's entry value.** The interface says
  `int c` lives in `rsi` (`SourceParameterLocation::Register(storage)`, with a
  `SourceCarrierProjection { LowBits, 0, 32 }` for the logical value,
  `contracts.rs:222-232`). Its entry value is `Subpiece(RSI_0, 0, 4)` -- one
  value, minted where the interface says the formal is, not whichever of two
  version-0 identities the body happened to read first.
- **A call clobbers root(F) once.** `CallDefine RAX` is the only clobber of the
  family, so no walk has to skip an alias of it.

## 4. The totality theorem

Claim: every read and write the lift produces in the register space is
expressible under §2, so the rewrite loses nothing the current model handles.

Proof sketch. A read (F, o, w) with o + w ≤ |root(F)| is a `Subpiece` of a
value of width |root(F)|, which the SSA op vocabulary has (`SSAOp::Subpiece`,
`op.rs`). A write (F, o, w) is an `Insert` into the current root; the op
vocabulary has `Piece` (used by the family pass's tiling, `function.rs:4958`)
and the projection has `MachineWriteProjection::Insert` (`construction.rs:481`),
so the shape is already spelled downstream; **to check** whether `SSAOp` needs
an `Insert { dst, root, src, offset }` or whether `Piece` of three subpieces is
the spelling -- the check is whether `optimize.rs` and the machine projection
fold `Piece(Subpiece(root, 0), x, Subpiece(root, o + w))` to the same
`MachineWriteProjection::Insert` the plan already accepts; if not, `Insert` is
added as one op with one lowering. A write of the whole root is a plain
definition. A varnode straddling two families cannot occur: families are
unions of overlapping ranges (`:4470-4500`), so any range inside the register
file lies in one family or in none (unnamed and disjoint from every named
register, which keeps its own exact identity as today).

The entry: root(F) version 0 exists once per family; a read before any write of
any lane is `Subpiece(root_0)`. This is the case that today yields two entry
values for one incoming register and the carrier-versus-lane fork.

## 5. The quality layer

What the rendered C should say, given §3:

- A formal declared `int c` in `rsi` is declared `int c`. Its uses are
  `Subpiece(RSI_0, 0, 4)`, which the projection maps to a `LowBits` slice of the
  parameter binding and renders as `c`. A full-width read of `RSI_0` renders as
  `(uint64_t)c` -- **verified** the handoff records this as the user's stated
  preference for the narrow-formal case, and it is the honest spelling: the
  program reads the register whole, and the declaration says which bits the
  caller defined.
- A lane write `mov dl, x` renders as an assignment to the low byte of the
  carrier's binding, which is what `MachineWriteProjection::Lane` already
  renders; nothing new.
- `tmp:regalias:*` names disappear from the output. **Verified** they appear
  in rendered functions today (`gzputc` this session:
  `uint32_t tmp_regalias_d0fa_4_0_1 = (uint32_t)RSI_0;`), which is the missing
  formal read through the wrong identity.

## 6. What is deleted, what stays

Deleted:

| what | site |
| --- | --- |
| the family-root dataflow and alias materialisation | `function.rs:3270-3440`, `:3895-3960`, `:4680-5320` |
| `tmp:regalias` minting, both forms | `function.rs:4936`, `:3413` |
| per-alias call clobbers | `rename.rs:556-592` collapses to one identity per family |
| the walk's slice fail-closed and alias skip | `semantic.rs:5130-5160` |
| the parameter entity's "max width of the entry values" | `function_facts.rs:2960-3000` |
| `ParameterHomeWidthMismatch` as a refusal | `construction.rs:1143`, `seal.rs:1275` |

Stays: `RegisterFamilyInfo` (`function.rs:4372`) is the geometry the rewrite
is built on and is kept; the machine projection's slice and write vocabulary is
kept unchanged; `CanonicalStorageId` stays the storage identity but every
register value's storage is its root's.

**To check**: which of the 28 tests pinning the family pass state a fact about
the *program* (a lane read after a wide write yields the wide value's low
bytes) and which state a fact about the *mechanism* (a `tmp:regalias` op is
materialised). The first kind is rewritten against the new construction; the
second is deleted with the mechanism. The check is reading each test's
assertion, listed at `function.rs:6725`, `:6756`, `:10903-11795`.

## 7. Two things upstream of the rewrite

1. **Vector registers.** arm64 `Q0/D0/S0/H0/B0` and x86 `XMM/YMM` are families
   too, and the handoff's "arm64's ninety-six names" and "xmm6" entries are
   this defect on wide registers: per-lane identities at version zero with no
   merge. The rewrite covers them by the same rule; the `Piece` tiling the
   family pass does for lane-wise vector writes becomes a sequence of `Insert`s
   on the root. **To check** on `h_arm64_O2` that no lane identity survives.
2. **Sub-register names the arch does not declare.** A lift may name a range
   the `ArchSpec` does not (a Sleigh temporary aliased to a register byte).
   `member_at_offset` already answers for it; the rewrite inherits that.

## 8. Sequence and gates

- **S0.** An instrument: count, per function, the `tmp:regalias` ops and the
  number of register families with more than one version-0 value. Both must be
  zero after S2. Add to `control_census.sh`'s certificate line.
- **S1.** Identity = family root in `phi.rs` and `rename.rs`: `from_varnode`
  for a register varnode returns the root's identity; `read_varnode` emits
  `Subpiece` when the varnode is narrower than the root; `write_varnode` emits
  the `Insert` (or, when the next op in the same instruction is the lift's own
  `IntZExt` of the root from this lane, defines only a temporary). Keep the
  family pass running: it must become a no-op (S0 says zero materialisations).
- **S2.** Delete the family pass and the four reconciliations of §6. The
  parameter entity binds `Subpiece(root_0)` per the interface's carrier
  projection. The walk asks for root(F) only.
- **S3.** Local census and corpus gate at each of S1 and S2; DecBench once at
  the end. The gate to land: every function that rendered before renders
  after, or its loss is traced to a defect this exposed rather than caused.

## 9. Hypotheses, each with its check

| hypothesis | check |
| --- | --- |
| Sleigh always spells a clearing narrow write with an explicit root zext | **checked** on three prepared dumps (`gz_compress`, `generateMTFValues`, bzip2 `0x78b0`): 67 32-bit lane writes, 37 followed immediately by the root's `IntZExt`; every miss is either a per-alias `CallDefine EAX` beside `CallDefine RAX` (the clobber duplication §6 removes) or a zext that follows later in the same instruction, which the projection already reads non-adjacently (`machine.rs:2105`). No lane write without its root write was found. |
| the SSA has an insert op the projection can read as a carrier write | **verified** `SSAOp::Insert { dst, src, value, position }` exists (`op.rs:382`), lifted from p-code `INSERT` (`rename.rs:1425`); the projection has no arm for it yet and derives `MachineWriteProjection::Insert` from storage geometry instead (`machine.rs:2358`). S1 gives the projection the arm: `Insert` on a root is `Insert { bit_offset: position, width_bits: value.size*8, carrier: root.size*8 }`. |
| no consumer keys on the `tmp:regalias` name | `grep regalias` outside `function.rs` finds only `integrity.rs:880` (a test fixture) -- **verified** this session |
| the parameter entity's carrier width is always the declared carrier's | after S2 the max-of-entry-values rule has one input |

## 10. What S1 and S2 cost, and the three things they exposed

S1 and S2 landed together on 2026-09-11. The gate the ADR set -- every
function that rendered before renders after -- is met: the local census over
nine binaries rendered 699 of 720 against 697 before, gaining `bzip2-O2`
`0x7d70` and `0x8350` and losing nothing, and the corpus gate passes 54 of 54
on raw, differential, snapshot and all four audits. `split_entries` is zero on
every binary, which is the S0 instrument's whole point: no register family is
entered through more than one value anywhere in the census.

The rewrite is what §2 to §5 describe, with three corrections the measurements
forced.

**The root is the program's, not the architecture's.** Ghidra models `XMM2` as
a lane of a 512-bit `ZMM2` and `q0` as a lane of a 256-bit `z0`, and a function
doing legacy SSE or NEON work never mentions the wider register. Rooting at the
widest declared slot made every such function's first lane write read a value
nothing supplied, and the rendering an uninitialised read of a 512-bit object;
it also made the arm64 `-O2` `xxhash32` cell compute the wrong digest. The root
is therefore the narrowest declared slot containing every range the function
touches of the family, counting the convention's own boundary carriers and, in
a function that calls, its clobber list (`function.rs`
`RegisterFamilyInfo::with_program_roots`). The machine projection follows: a
register value's geometry is the whole of itself, because the SSA has already
made it its family's root, and re-basing it onto a register no program here
mentions is what the old `Lane` and `Insert` write projections existed to
paper over. Both are deleted, and a register write is now `Full` or the lift's
own `ZeroExtend`.

**A scratch register's incoming bits are not a value.** Even at the program's
own root, a lane written into a register nothing read is not preserving
anything. Where a root's entry value reaches nothing but inserts -- following
it through the merges that carry the same undefined bits -- and the convention
names no carrier there, the insert chain starts at zero
(`function.rs::zero_scratch_insert_roots`). The argument is the same one the
narrow-formal declaration rests on: nobody passed anything in that register, so
nothing the program computes depends on what it held, and C has to spell
something. A vector zero has no literal, so it is spelled as the prelude's
zero-extension of a narrow one, which also raised the constant ceiling: a
constant whose width is one the bit-vector prelude carries is now spellable
rather than refused.

**A lane read has to fold, or the rendering drowns in temporaries.** The lane
model turns every narrow read into a `Subpiece` of the root and every narrow
write into a temporary plus an `Insert`, so the optimizer needs to read a
`Subpiece` through the definition of its source: the constant copied there, the
value an `Insert` put at that position, the narrower value an extension
widened, or a slice of a slice (`optimize.rs::fold_through_definition`).
Constant propagation and instruction combining now run to a shared fixed point
rather than once each, because a fold turns a lane read into a constant copy
and that constant is what the next propagation round carries. A lane temporary
a fold reduced to a copy of another value is that value, and its readers take
it directly; a merge keeps its copy, because a merge's edge assignment is a
statement about an object rather than an expression read.

Two consequences reached the interface. A recovered parameter's width is now
the bytes the body observes of the entry value rather than the register's
(`deadphi.rs::observed_low_bytes`), which is what recovers `murmur3_32`'s and
`xxhash32`'s third argument -- both were `signature_mismatch` cells before.
And where the interface declares a narrow formal but the body reads the whole
register, the root is rebuilt from the declared lanes with zero above them,
because the declaration is the source's own statement of what the caller
passed and no source expression names the bytes outside it.

What §6 promised is done: the family pass, the alias temporaries, the
per-alias call clobbers, the walk's slice fail-closed, the parameter entity's
max-of-entry-values and `ParameterHomeWidthMismatch` are gone, and with them
the return-register composition facts, which existed only to reassemble a
register the SSA now assembles itself. About 5,500 lines were removed and
3,300 added.
