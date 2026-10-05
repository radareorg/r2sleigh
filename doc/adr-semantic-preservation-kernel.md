# ADR: semantic preservation kernel

Status: accepted in principle; to be rewritten against F2 and R

Only the surviving principles are kept here. The ownership spine, the FFI
table and the radare2 snapshot seam that this ADR used to describe are
superseded by AGENTS.md (one owner per fact, `r2engine::program::Source` as
the only input) and by doc/adr-renderer-printer.md.

## Decision

- **Exact-once preservation.** Every live effect in the canonical machine
  representation survives exactly once into an explicitly typed output node,
  or the function residualizes or refuses. Executable C is never justified by
  recognizing a benchmark, matching a symbol name, counting output statements
  or reproducing source-shaped text.
- **Obligation inventory** (`r2ssa::obligation`). Every canonical instruction
  has exactly one initial state (`SemanticInstructionState`): `LiveObligation`,
  `ProvenDead`, `StructuralControlOnly` or `UnsupportedUnknown`. The inventory
  covers observable reads and writes, calls with their arguments and results,
  returns, predicates and transfers, traps and ordering, loop-carried state,
  and every value producer that a live root needs. Obligation ids are
  independent of names, traversal order and output position.
- **Exactly one disposition.** Every obligation receives exactly one final
  disposition. A missing or duplicate disposition fails before structuring.
  Unsupported semantics stay residual or refused and never become guessed C.
- **Authority.** Only a source-retaining trusted lift produces a certifiable
  artifact (`TrustedSsaArtifact`). Hand-built blocks, interfaces or SSA may
  test analysis or an expected refusal, but they cannot produce a certified
  artifact, a ledger or executable C. Proofs derived from one artifact are
  valid only against that exact artifact. Function names are presentation
  only, and are excluded from semantic identities and fingerprints.
- **Typed output ownership.** An obligation is owned by an exact typed output
  node (an expression; a memory, call, control or return producer and
  component). Rendered text, names, output counts and AST positions never own
  an obligation. (R carries the obligations on the render tree.)
- **Structuring contract.** A structuring step consumes certified regions and
  returns the structured region, exact obligation-to-node ownership,
  control-domain evidence, residual obligations, and a deterministic refusal
  reason. A loop rewrite (for example, while to for) must map the exact
  initializer, phi, comparison, update and latch. Topology and widths alone do
  not justify it.
- **Admission rule.** Executable C is admitted only when all of these hold:
  - the source and machine context are coherent;
  - the inventory is complete;
  - every obligation has one preserving disposition with one exact typed
    owner;
  - widths, signedness, wrapping, shifts, casts, memory policy, ABI
    projections, the return address and the exit stack pointer are explicit;
  - no residual, refused, unsupported or open control obligation remains.

  Anything else residualizes or refuses.
- **Test policy.** Production code has no algorithm-specific recognizer,
  route, renderer, formula, binary offset or source-shaped template.
  Algorithm names appear only in test sources and fixtures. Positive tests
  start from real program bytes and drive the public pipeline. Generated C is
  checked against an independent oracle (the equivalence gate); comparing a
  renderer with itself is circular. Unsupported cases are refusal tests.

## Done

- The obligation inventory, the single disposition per obligation, and the
  `TrustedSsaArtifact` boundary exist in r2ssa.

## Left

- Rewrite this ADR against F2 (obligations and dispositions as indexes over
  dense ids) and R (obligations carried by the render tree, one linear
  checker). Exit: the rewritten ADR names the index and the checker that
  enforce each principle above.
- Exit for the principle as a whole: any deliberate deletion or duplication of
  an effect fails before rendering.
