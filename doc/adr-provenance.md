# ADR: provenance is part of every fact

Status: accepted, in progress (ROADMAP C, decision D4)

## Context

How far a fact can be trusted is recorded in about 45 different ways across
the crates, and only one answer uses the type built for it:

- `r2source::confidence::{Basis, Premise, Confidence}` qualifies one fact,
  `Discovered.confidence` (why an address is believed to be a function).
- `SourceFunctionInterface` carries three booleans:
  `prototype_from_source_types`, `types_are_carrier_widths` (the "minted
  interface" flag) and `body_proven_return_address`. It also carries two
  format-parameter fields, `body_proven_format_parameter` and
  `declared_format_parameter`, for one fact. The flags travel on as
  `callee_signature_from_source_types` (r2types) and `from_source_signature`
  (r2dec).
- r2types ranks candidates by `confidence: u8` (about 88 reads) next to
  six source enums: `TypeFactSource`, `TypeEvidence`, `StructDeclSource`,
  `ConstraintSource`, `SignatureCertificateSource` and `ReturnTypeEvidence`.
  A score compared with a threshold is a heuristic with no stated meaning.
- r2engine's references grade themselves with `query::Support`, a seven-rung
  ladder. The same notion has no type anywhere else.
- Public answers mostly drop provenance. `FunctionInfo` keeps one
  `return_unproven: bool`. An argument's type and name, the convention, a
  local's type and a syscall number all say nothing about whether they were
  stated, proven, declared by name or read from a carrier's width.

A consumer that cannot tell these apart has to treat every one as the
weakest, or worse, as the strongest.

## Decision

**One vocabulary, in `r2source::confidence`.**

- `Basis` names what a fact is read from. It is extended from discovery to
  every derived fact:
  - stated: `Stated` (the container), `DebugInfo`;
  - proven: `Decoded`, `Called`, `Folded`, `Certified`;
  - bounded: `Solved`;
  - declared: `Handed`, `Declared` (a library prototype found by an
    import's name);
  - read: `Dereferenced`, `Reached`, `CarrierWidth` (a type that is only a
    carrier's width);
  - assumed: `Convention` (the ABI's default, with no evidence).
- `Grade` (`Stated > Proven > Bounded > Declared > Read > Assumed`) is
  *derived*: `Basis::grade()`. D4 listed `grade` as a field; it is a
  function, because a stored grade beside a basis is two owners of one
  fact, and the two could disagree.
- `Confidence { basis, premises }` orders by grade, then basis, then fewer
  premises, so a fact found twice keeps the stronger reason, as today.
- `Fact<T> { value: T, confidence: Confidence }`. A consumer states the least
  grade it accepts (`fact.at_least(Grade::Proven)`) instead of testing a
  flag. Deriving a fact from others takes the weakest of their confidences.

**What it replaces.**

- The interface's provenance booleans become one `types: Confidence` (basis
  `DebugInfo`, `Declared` or `CarrierWidth`). The format parameter becomes one
  `Option<Fact<u32>>`.
- `body_proven_return_address` is a semantic fact, not provenance. It stays,
  as a `Fact`.
- `callee_signature_from_source_types`, `from_source_signature` and
  `return_unproven` are deleted. Their readers ask the grade.
- Every `confidence: u8` is deleted. A score was computed from some evidence:
  that evidence becomes the basis. A rank becomes the `Confidence` order, and
  a threshold becomes a stated least grade. Where a score mixed two kinds of
  evidence, the candidate carries both facts, not a sum.
- The r2types source enums map onto `Basis`. Where a variant names the pass
  that produced a fact, rather than what the fact rests on, that is identity,
  not trust: it moves to a separate field or is dropped.
- `Support` maps onto `Basis`, and references carry `Confidence`. The two
  orders differ in one place: `Support` ranks `Dereferenced` (a callee's
  body loads through the parameter) above `Declared`, but the grades put
  it below. C4 judges which is right and pins the answer with a test.

**Public answers.** Every r2engine answer field that states something about
the program which the engine derived is a `Fact`: argument type and name,
result type, convention, local type, syscall number and name. Fields that
only restate the container stay plain: addresses, sizes, raw bytes. A Dylint
in `tools/dylints/r2sleigh_lints` rejects a `pub` field of an answer type
that is neither a `Fact` nor on the stated-passthrough list.

**Text output does not change.** radare2's columns stay radare2's, so the
differential gate still diffs. JSON (`aflj`, `pddj`, A's surface) carries
each fact's confidence. A mark already printed, such as `afi`'s
`/* unproven */`, now comes from the grade.

**Excluded.** These types say which operation, value or pass a thing is,
not how far to trust it: `OpOrigin`, `ValueOrigin`, the normalize `*Origin`
types, `MachineAddressProvenance`, `AddressProvenanceFacts`,
`CompareProvenance`. `ScalarSignednessEvidence` is a value (signed or
unsigned), not provenance. `AssumptionProvenance` and
`SsaArtifactProvenanceKind` qualify a whole artifact, not a fact in it. They
stay, and are reviewed again at A.

## Migration

Each step keeps every gate green and deletes what it replaces.

| Step | Change | Deletes |
|------|--------|---------|
| C0 | `Grade`, the extended `Basis`, `Fact<T>`; the order laws (basis refines grade, fewer premises stronger, `and` idempotent, commutative, associative and never stronger) checked over the whole finite domain; spelling moved beside the type — **done** | the premise order `BTreeSet`'s lexicographic `Ord` gave, under which `{closed-world, ub-free}` outranked `{ub-free}`; r2s's own spelling of a basis |
| C1 | Interface provenance as `Confidence`/`Fact`; r2types and r2dec read the grade. **Types done**: `SourceFunctionInterface::types` (debug info, a library prototype, a recovery's carrier widths, else convention) replaces `prototype_from_source_types` and `types_are_carrier_widths`, and `callee_signature_types` replaces `callee_signature_from_source_types`. The old flag marked debug-info bodies and library imports alike; they are now told apart. The format pair and `seal_body_proven_interface` remain | the two type booleans, `callee_signature_from_source_types`; remaining: the format pair, `from_source_signature` |
| C2 | r2engine answers as `Fact`; `afi`, `afv`, `aflj` and `pddj` read them | `return_unproven` |
| C3 | r2types candidates and source enums onto `Basis` | every `confidence: u8`, `TypeFactSource`, `StructDeclSource`, `ConstraintSource`, the projection-confidence fields |
| C4 | References carry `Confidence`; the answer-field Dylint | `Support` |

## Consequences

- P7 (call contracts) and A (agent surface) read grades instead of flags. P4
  reports `afv`/`afi` from sealed entities with their facts attached.
- C3 is the largest step. Each threshold in it is a heuristic that has to be
  either justified as a grade requirement or removed, so it may change
  rendered output. The certification gate and the coverage sweep run on it.
- Cost: a `Confidence` is a small enum plus a set that is usually empty.
  Grades are compared by `Ord`, and nothing is recomputed.
