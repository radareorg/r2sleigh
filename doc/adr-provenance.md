# ADR: provenance is part of every fact

Status: in progress (ROADMAP C, decision D4)

## Decision

How far a fact can be trusted has one vocabulary, in `r2source::confidence`.
It replaces about 45 ad hoc flags, scores and source enums.

- **`Basis`** names what a fact is read from: `Stated` and `DebugInfo`
  (stated); `Decoded`, `Called`, `Folded` and `Certified` (proven); `Solved`
  (bounded); `Handed` and `Declared` (declared; `Declared` is a library
  prototype found by an import's name); `Dereferenced`, `Reached` and
  `CarrierWidth` (read); `Convention` (assumed, the ABI's default with no
  evidence).
- **`Grade`** (`Stated > Proven > Bounded > Declared > Read > Assumed`) is
  derived by `Basis::grade()`, never stored. A stored grade beside a basis
  would be two owners of one fact.
- **`Confidence { basis, premises }`** orders by grade, then by basis, then by
  fewer premises, so a fact found twice keeps the stronger reason. The
  premises are `Premise::{ClosedWorld, UbFreeSource}`.
- **`Fact<T> { value, confidence }`.** A consumer states the least grade it
  accepts (`fact.at_least(Grade::Proven)`) instead of testing a flag. A fact
  derived from others takes the weakest of their confidences (`and`).
- **What it replaces:** provenance booleans become a `Confidence` or a
  `Fact`; every `confidence: u8` score becomes the basis it was computed from,
  so a rank becomes the `Confidence` order and a threshold becomes a stated
  least grade; a score that mixed two kinds of evidence becomes two facts, not
  a sum. Where an r2types source enum names the producing pass rather than
  what the fact rests on, that is identity, not trust: it moves to a separate
  field or is dropped. `body_proven_return_address` is a semantic fact and
  stays, as a `Fact`.
- **Public answers.** Every r2engine answer field that states something the
  engine derived is a `Fact`: argument type and name, result type,
  convention, local type, and syscall number and name. Fields that only
  restate the container stay plain (addresses, sizes, raw bytes). A Dylint
  rejects a `pub` answer field that is neither a `Fact` nor on the
  stated-passthrough list.
- **Text output does not change.** radare2's columns stay radare2's, so the
  differential gate still diffs. JSON (`aflj`, `pddj`, A's surface) carries
  each confidence. An existing mark such as `afi`'s `/* unproven */` comes
  from the grade.
- **Excluded** (they say which operation, value or pass a thing is, not how
  far to trust it): `OpOrigin`, `ValueOrigin`, the normalize `*Origin` types,
  `MachineAddressProvenance`, `AddressProvenanceFacts`, `CompareProvenance`,
  `ScalarSignednessEvidence`. `AssumptionProvenance` and
  `SsaArtifactProvenanceKind` qualify a whole artifact. They are reviewed
  again at A.

## Done

- C0 (e0c0b2e4): `Grade`, the extended `Basis`, `Fact<T>`; the order laws
  are checked over the whole finite domain; the spelling lives beside the
  type.
- C1, types (09bfbeb4): `SourceFunctionInterface::types` (debug info, a
  library prototype, a recovery's carrier widths, else convention) replaces
  the two type booleans; `callee_signature_types` replaces
  `callee_signature_from_source_types`.
- C1, format parameter (f0d3d9af): one `format_parameter: Option<Fact<u32>>`.
  A declaration's carries the types' basis; a body proof is `Certified` and
  fills only a gap that a declaration left.

## Left

- C1 rest: r2dec reads the grade. Exit: `from_source_signature` is deleted.
- C2: r2engine answers as `Fact`, read by `afi`, `afv`, `aflj` and `pddj`.
  Exit: `return_unproven` is deleted.
- C3 (with K's r2types loops): r2types candidates and source enums onto
  `Basis`. Exit: every `confidence: u8`, `TypeFactSource`, `StructDeclSource`,
  `ConstraintSource` and the projection-confidence fields are deleted.
- C4: references carry `Confidence`, and the answer-field Dylint lands. Exit:
  `query::Support` is deleted, and its one ordering disagreement is judged and
  pinned by a test. (`Support` ranks `Dereferenced` above `Declared`; the
  grades put it below.)

## Consequences

- P7 and A read grades instead of flags.
- C3 is the largest step. Each threshold must be justified as a grade
  requirement or removed, so rendered output may move; the certification gate
  and the coverage sweep run on it.
- Cost: a `Confidence` is a small enum plus a premise set that is usually
  empty, compared by `Ord`. Nothing is recomputed.
