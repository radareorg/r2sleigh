# ADR: a register family has one SSA identity, and a lane is a projection of it

Status: done (S1 and S2 landed together in `719878ca`)

## Decision

The SSA used to give one machine register as many identities as the lift had
widths for it (`EDX` and `RDX` each with its own version stack and entry
value), and a fixed-point family pass guessed afterwards which identity a read
meant. Every layer above carried its own repair. Now the family is the
identity.

### §2 The object

- Overlapping named register ranges form a *family* (union-find in
  `RegisterFamilyInfo`); an unnamed sub-range of a family is a member of it.
- The family's **root** is the program's, not the architecture's: the
  narrowest declared slot containing every range the function touches,
  counting the convention's boundary carriers and, in a function that calls,
  its clobber list (`RegisterFamilyInfo::with_program_roots`). Rooting at the
  widest declared slot (`ZMM2` for `XMM2`, `z0` for `q0`) made legacy SSE/NEON
  code read 512-bit values nothing supplied.
- A read of varnode (F, o, w) is `Subpiece(current(F), o)` of width w. A write
  is a new version of the root: an `Insert` of the lane, or the lift's own
  `IntZExt` of the root when Sleigh spells a clearing write (it always does on
  x86-64), so the rewrite never needs an architecture's clearing rule.
- Unique, memory and constant spaces keep their exact-varnode identity
  (`RenameIdentity::for_varnode`).

### §3 The invariant

- Every register read at p is `Subpiece(D(F, p), o, w)`, where D(F, p) is the
  unique SSA definition of the root reaching p. This is ordinary SSA renaming
  over one identity per family, so it is exact by construction.
- One entry value per family, one phi per family per join, one call clobber
  per family. No read's meaning is decided after renaming.
- A machine-projection register write is `Full` or the lift's own
  `ZeroExtend`; a register value's geometry is the whole of itself.

### §5 Rendering and lane folds

- A formal declared narrower than its carrier (`int c` in `rsi`) renders as
  declared; a full-width read of the carrier is the root rebuilt from the
  declared lanes with zero above them (`SSAFunction::formal_roots`). That
  rebuild is not a body write: `SsaGraph::written_by_body` excludes it, so a
  call nothing declares takes its arity only from registers the body wrote.
- A scratch register's incoming bits are not a value: where a root's entry
  value reaches only inserts (through merges) and the convention names no
  carrier there, the insert chain starts at zero
  (`function.rs::zero_scratch_insert_roots`).
- A lane read folds through its source's definition: the copied constant, the
  value an `Insert` put there, the narrower value an extension widened, or a
  slice of a slice (`optimize.rs::fold_through_definition`). Constant
  propagation and instruction combining run to a shared fixed point. A merge
  keeps its copy, since an edge assignment is a statement about an object.
- A recovered parameter's width is the bytes the body observes of the entry
  value, not the register's (`recover_interface.rs`).

### §6 What is deleted, what stays

- Deleted: the family-root dataflow and alias materialisation, `tmp:regalias`
  temporaries, per-alias call clobbers, the ABI walk's slice fail-closed and
  alias skip, the parameter entity's max-of-entry-values, the `Lane`/`Insert`
  machine write projections, and the return-register composition facts.
- Stays: `RegisterFamilyInfo` as the geometry; `CanonicalStorageId` as the
  storage identity, with every register value's storage its root's.
- Entry-lane projections: a lane of an entry register is one projection
  minted at entry as a `Subpiece` of the root's entry value, and every
  entry-lane read becomes a copy of it. It has no register storage of its
  own; the boundary facts know it by `formal_projections` (lane storage by
  projection variable).

### §8 Gates

- S0: `R2DEC_CONTROL_CERTIFICATE` prints `register-identity {function}:
  split_entries=…` per function (`structure/certify.rs`); it must stay zero.
- The landing gate was that every function that rendered before renders after;
  it held at `719878ca`.

## Done

- S0: the `split_entries` instrument; zero on every census binary.
- S1: identity is the family root in `phi.rs` and `rename.rs`; reads emit `Subpiece`, writes `Insert` or the lift's zext.
- S2 (`719878ca`): the family pass and the reconciliations of §6 deleted; program-relative roots, zero-started scratch inserts and lane folds added.

## Left

- `StackObjectRefusal::ParameterHomeWidthMismatch` still exists in `binding_plan` (`construction.rs`, `seal.rs`), although S2 meant to delete it. Exit: either it is shown to be a genuine stack-home refusal and documented as such, or it is removed.
