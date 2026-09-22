# Agent Guidelines for r2sleigh

> LLM-focused working rules for contributors and coding agents.

## North Star

`r2image`, `r2abi`, `r2il`, `r2sleigh-lift`, `r2ssa`, `r2source`, `r2rewrite`,
`r2types`, `r2engine`, `r2dec` and `r2s` are one subsystem.

`r2s` is the tool. The radare2 plugin has been deleted, and `../radare2` is now
the differential target this engine is graded against plus a stream of upstream
fixes, not a host to live inside.

The goal is not "more commands" or "more crates doing similar work." The goal
is a binary analysis engine where:

- one canonical fact has one canonical owner
- facts flow through typed contracts, not JSON reparsing
- decompiler, types and analysis views agree
- expensive work is summarized and reused only when real session traces prove value
- output is deterministic
- architecture and API seams may be rewritten whenever the rewrite is cleaner

## Where A Fix Belongs

If a fix starts in `r2s` or `r2dec`, first prove the missing fact really
belongs there. Most semantic, type, cost and route fixes belong further up: in
`r2ssa` where the evidence is, or in `r2engine` where the request is built.

## Non-Negotiables

1. One fact, one owner.
2. `r2s` is a command surface only: it opens the binary and spells the answer.
3. Every fact the engine reads about a program arrives through
   `r2engine::program::Source`: the bytes and what the container states.
   Nothing below `r2s` knows what a file is; the engine derives names, import
   stubs and definitions from what `Source` hands it.
4. Do not reconstruct missing semantics downstream.
5. Prefer typed contracts over JSON blobs and stringly maps.
6. `r2types::FunctionFacts` is the advisory combined type+semantic report;
   `r2types::SourceOwnedFunctionFacts`, retaining the exact
   `Arc<r2ssa::SsaArtifact>`, is the runtime authority seam.
7. `r2types::FunctionTypeFacts` is the canonical type/layout/signature payload.
8. `r2ssa::SsaArtifact`, with its prepared facts and
   `PreparedFunctionCertificates`, is the canonical semantic artifact.
9. `r2ssa` owns semantic evidence and refusal evidence; consumers interpret it.
10. `r2engine` owns request orchestration, route selection, and
    refusal/fallback policy.
11. Symbol names are hints, not authoritative semantic ownership.
12. Deterministic ordering beats cleverness.
13. Rewrite bad seams instead of patching around them.
14. Validation is part of the change, not optional cleanup.
15. Never fabricate C/control/type semantics just to avoid a residual.
16. Never land or preserve hacky behavior to make one case, benchmark, or
    snapshot look good.

## Anti-Hack Standard

Hacky shortcuts are correctness bugs, even when they improve a local score.
If you find one, do not normalize it, route around it, or add another layer on
top. Remove it, rewrite it, or replace it with a mathematically defensible
analysis path owned by the right crate.

Treat these as blockers:

- test-specific or fixture-specific semantic recovery
- source-gold, r2r, or benchmark expectations that bless source-shaped output
  generated from summary templates instead of reconstructed CFG/dataflow proof
- name-owned summaries that pretend to be structural proof
- fake helper calls, fake loops, fake switches, fake stack slots, or fake types
- output cleanup that hides missing upstream facts
- benchmark logic that rewards guessed semantics instead of source-gold behavior
- broad fallback behavior that silently turns unknown facts into confident C

The required standard is mathematical, not cosmetic:

- state the invariant being proven or refused
- state the canonical owner of the fact
- state the evidence needed to justify the output
- state the complexity target and why it avoids repeated weak scans
- prefer a visible residual/refusal over plausible but unproven C
- prefer manual source-gold reversing checks over benchmark-only confidence

If the clean fix requires a rewrite, do the rewrite. A smaller patch is not
better when it preserves a bad proof model.

### Synthetic Output Test Ban

Tests must not train the engine to look good. If a test expects source-shaped C,
the expected shape must be justified by native CFG/control/dataflow/type facts,
not by a summary template that happens to match the fixture source.

Rules:

- Do not add source-gold expectations that require `summary_*` locals, synthetic
  iterator names, or pretty source-shaped loops as a substitute for native proof.
- Do not accept "looks like source" output from summary routes unless the test
  also proves the output is visibly summary-only and not scored as native
  reconstruction.
- Do not keep a positive oracle whose only purpose is preserving a pretty
  synthetic projection. Delete it or convert it into a negative oracle that
  rejects fake C.
- Summary-only routes may render comments, facts, residuals, and explicit
  refusal. They must not emit executable C, even when summary evidence is exact;
  exact summaries should feed native render proofs first, then render through the
  normal CFG/control/dataflow path.
- Every time a clean-looking decompile appears too good for the available facts,
  stop feature work and audit the renderer, oracle, and benchmark gate first.

## Optimization Doctrine

Optimize the targets below rather than a local score.

The target is not a fantasy "`O(1)` whole-function proof." The target is:

- `O(1)` or `O(log n)` lookup for metadata, indexes, summaries, and caches
- `O(n)` passes over blocks, SSA ops, or facts whenever possible
- bounded search when search is unavoidable
- incremental recomputation instead of whole-function replay
- summary reuse across query, typing, and decompilation
- explicit budgets for solver work, symbolic exploration, and structuring

Use this mental model:

- repeated whole-function scans are a smell
- repeated solver queries for the same fact are a smell
- recomputing downstream what already exists upstream is a smell
- parallel representations of the same fact are a bug
- hash-order-dependent output is a bug
- decompiler-side cleanup of missing stack/call/type facts is a smell
- name-first semantic classification is a temporary hint path, not the target

If you cannot explain the asymptotic and practical cost of a new analysis path,
you do not understand it well enough to land it.

### Efficiency Rules

1. Prefer canonical summaries over re-analysis.
2. Prefer incremental updates over full rebuilds.
3. Prefer typed caches over ad hoc memoization.
4. Prefer `BTreeMap` / `BTreeSet` when ordering affects output or tests.
5. Prefer one richer pass over many weak overlapping passes.
6. Prefer explicit budgets and refusal modes over silent blowups.
7. Prefer stronger upstream facts over downstream heuristics.

## Architectural Stance

This system should move toward a gold-standard analysis architecture even when
that requires invasive refactors.

- It is acceptable to redesign contracts, move logic across crates, or change
  FFI and `../radare2` seams when the result is cleaner.
- Do not preserve a bad abstraction because it already exists.
- Do not add end-stage hacks in `r2s` or `r2dec` to hide a fact that was never
  derived.
- If hacky behavior is found anywhere in the pipeline, remove or rewrite it
  before building more behavior on top of it.
- If a crate is carrying policy it should not own, move that policy.
- Keep the next major direction as a spine rewrite, not a blank-slate rewrite:
  move orchestration to `r2engine`, dataflow facts and evidence to `r2ssa`,
  type constraints to `r2types`, term rewriting to `r2rewrite`, rendering to
  `r2dec`, and command integration to `r2s`.

The right question is not "what is the smallest diff?" It is "what is the
cleanest owner and the cheapest long-term design?"

## Fake-Semantics Ban

The fake `while { ... }` pattern was a concrete failure mode: output looked
structured but was not justified by canonical facts. Treat the following as the
same class of bug:

- invented loop/switch/control structure without CFG or semantic evidence
- invented switch case values when jump-table facts are missing
- summary pseudo-calls presented as full native decompilation
- summary templates that emit source-shaped loops, switches, struct walks, or
  returns from bounded/likely evidence
- hardcoded function-name summaries treated as proof
- hardcoded role signatures overriding stronger typed context
- decompiler-side call argument repair hiding missing callsite provenance
- decompiler-side stack placeholder cleanup hiding missing stack-slot facts
- plugin-side route/fallback decisions that bypass typed request policy

Correct responses:

- push the missing fact upstream to the canonical owner
- render an explicit residual/refusal when evidence is insufficient
- use symbol names only as weak hints unless backed by typed context or
  structural evidence
- add benchmark/r2r checks that detect the fake output class
- convert source-gold tests that bless fake C into negative/refusal tests
- remove existing fake-output paths when discovered, even if doing so makes a
  benchmark temporarily worse

## Task-Start Protocol

For any non-trivial change, follow this order:

1. Identify the user-visible behavior or broken invariant.
2. Identify the canonical owner: `../radare2`, lift, SSA, source snapshot,
   types, engine, decompiler, export, CLI, or plugin.
3. Identify the existing typed contract to extend before creating a new one.
4. State the complexity target: lookup, traversal, search, cache, summary.
5. Push facts upstream to the owner instead of reconstructing them downstream.
6. Add the smallest deterministic test at the layer users actually exercise.
7. Prefer one behavior-level test that exercises the whole relevant pipeline
   over several helper tests that only lock the current implementation shape.
8. If the change touches rendering, state why the rendered C is justified by
   canonical facts or mark it as residual/summary-driven.
9. If the change affects semantic quality, decompilation, types, summaries, or
   route policy, manually inspect at least one real command/session path instead
   of trusting benchmark deltas alone.
10. If the seam crosses into `../radare2`, validate both repos before claiming
   the work is complete.
11. If the task reveals hacky behavior, remove or rewrite that behavior before
   adding new feature work that depends on it.
12. If the failure mode is common enough, encode it as a Dylint, proof, fuzz
   target, mutation target, benchmark gate, or script.

## Ownership Boundaries

Use this map by default:

- `../radare2`
  - core analysis facts
  - typed collectors
  - native analysis metadata and persistence
  - library seams that should exist for radare2 consumers generally
- `crates/r2il`
  - canonical IL data model and serialization
- `crates/r2sleigh-lift`
  - Sleigh/P-code lifting
  - register naming
  - disassembly formatting
  - ESIL formatting
- `crates/r2ssa`
  - SSA construction
  - phi handling
  - dominators / def-use
  - prepared function facts
  - semantic certificates and refusal evidence
  - determinism and SSA-local transforms
- `crates/r2source`
  - the trusted radare2 snapshot and its wire decoding
  - source-owned facts the engine may treat as authority
- `crates/r2rewrite`
  - the term arena over the machine projection
  - canonical term rewriting and its rule proofs
- `crates/r2types`
  - signature parsing and normalization
  - type inference
  - layout inference
  - external type context normalization
  - canonical `FunctionTypeFacts`
  - advisory combined `FunctionFacts` reports
  - exact source-owned runtime authority through `SourceOwnedFunctionFacts`
- `crates/r2engine`
  - typed request orchestration
  - route selection for decompile/type/query requests
  - refusal boundaries and request-local execution metrics
  - shared cost/metrics/refusal policy
  - cross-crate request/response API used by plugin glue
- `crates/r2dec`
  - lowering
  - semantic interpretation of canonical facts
  - structuring
  - rendering
  - no global route ownership
- `crates/r2sleigh-export` / `crates/r2sleigh-cli`
  - shared export/CLI plumbing
- `crates/r2image` / `crates/r2abi`
  - what the container states: bytes, sections, symbols, relocations, entries,
    debug information, conventions, library prototypes
  - no inference, and no opinion about what a function is
- `crates/r2s`
  - command dispatch
  - opening the binary, and the only implementor of `Source`
  - spelling an answer for a human
  - no semantic, type, cache or route policy ownership

Do not let the same policy exist in two crates "for now."

## Canonical Contracts

These are the preferred subsystem seams:

- `r2ssa::SsaArtifact` and `PreparedFunctionFacts`
  - canonical SSA/dataflow preparation
- `r2ssa::PreparedFunctionCertificates`
  - canonical evidence carrier for prepared facts
- `r2source::OwnedFunctionSnapshot`
  - canonical way radare2's facts reach the engine
- `r2types::FunctionTypeFacts`
  - canonical type/layout/signature payload
- `r2types::FunctionFacts`
  - advisory combined type+semantic report
- `r2types::SourceOwnedFunctionFacts`
  - canonical runtime authority retaining the exact `Arc<r2ssa::SsaArtifact>`
- `r2engine` typed request/response APIs
  - canonical orchestration surface for plugin command paths
- `r2types::DecompileRouteFacts`
  - render route selected by `r2engine` and sealed into
    `SourceOwnedFunctionFacts`

If a caller needs more information, extend these contracts instead of creating
parallel wrappers.

## The `../radare2` Relationship

radare2 is the differential validation target for discovery, naming, decoding
and cross-references, and nothing more. The engine links nothing from `libr`.

Rules:

- a disagreement with radare2 may be radare2's defect; judge which side is
  right rather than matching it
- a radare2 correctness fix unrelated to Sleigh is raised as its own upstream
  pull request, one idea per pull request
- upstream commits are one line, with no assistant attribution
- do not add anything to the fork that radare2 itself does not need

## Evidence-First Summaries

Native worker summaries are valuable, but they must move away from
name-authoritative behavior.

Rules:

- summary classification belongs in `r2engine`, beside route selection
- classify by CFG shape, loops, memory effects, callsites, constants, def-use,
  typed context, and evidence before trusting symbol names
- symbol/role names may seed weak hints and tie-breakers
- a name hint must not override stronger typed context, structural evidence, or
  explicit user assumptions
- `r2types` may project summary evidence into signatures/types, but it must keep
  confidence and refusal reasons explicit
- `r2dec` may render summary-backed comments, facts, residuals, and refusals
  when the route says the output is summary-driven; executable C comes only
  through the native path (see the Synthetic Output Test Ban)
- tests must distinguish summary-driven rendering from true reconstructed
  native control flow

## Command Surface Philosophy

`r2s` spells its commands as radare2 spells them, so the two can be diffed by
`scripts/diff_r2.py`. That compatibility is the point, not an accident: it is
what makes radare2 usable as an oracle and what lets a radare2 user move.

The surface should be workflow-oriented, not command-oriented:

- keep a small public surface, and make the common path automatic
- treat engine-inspection commands (`pdil`, `pdim`, `pdih`) as maintainer tools
- prefer configuration over inventing a verb

If you are about to add a command, stop and ask:

1. does radare2 already have a name for this? use that name
2. should this be automatic?
3. should this enrich an existing view instead?
4. is this just a debug surface?

## Rewrite Bias

When current architecture blocks correctness, composability, or efficiency:

- rewrite the seam
- move the owner
- shrink duplicated policy
- reshape FFI if needed
- change module layout if needed

Avoid:

- plugin-side reparsing
- plugin-side route or request policy
- decompiler-side type policy
- decompiler-side call argument or stack-slot repair that should be a canonical fact
- consumer-local semantic policy that should live in `r2ssa` or `r2engine`
- name-first summaries as authoritative proof
- compatibility shims that silently become permanent

## Optimization Checklist

Before landing any non-trivial change, check these explicitly:

1. Did I add a second owner for an existing fact?
2. Did I add a repeated full-function walk?
3. Did I add repeated solver work that should be cached or summarized?
4. Did I add a new JSON-shaped internal type where a Rust type should exist?
5. Did I add ordering nondeterminism?
6. Did I move policy downstream instead of upstream?
7. Did I preserve a bad seam instead of rewriting it?
8. Did I add name-first semantic ownership instead of evidence-first classification?
9. Did I make `r2dec` or `r2s` repair facts that `r2ssa`, `r2source`,
   `r2types` or `r2engine` should own?
10. Did I render fake C/control/type information instead of an explicit
    residual or summary route?
11. Did I leave a repeated bad pattern as a reminder instead of encoding it in
    a lint, proof, regression, benchmark gate, or script?
12. Did I remove, weaken, or ignore a quality gate because it made the current
    patch harder?
13. Did I add dependency or feature complexity without checking whether it
    belongs in the subsystem spine?
14. Did I claim semantic or decompiler quality from a benchmark score without
    manually inspecting representative real output?

If any answer is "yes", the design is probably wrong.

## Quality Ratchet

Quality tooling is part of the architecture. It is not cleanup after the real
work. When a failure mode repeats, turn it into a mechanical guardrail at the
right layer.

Use the existing repo gate for rewrite and architecture-sensitive work:

```bash
# Show the commands without running expensive phases
scripts/quality-gate.sh --dry-run

# Run the local rewrite quality gate
scripts/quality-gate.sh

# Make existing local Dylint findings fatal for a cleaned slice
scripts/quality-gate.sh --strict-dylint
```

`scripts/quality-gate.sh` is documented in `doc/rewrite_quality_gates.md`. It
currently covers dependency hygiene, `cargo fmt`, workspace Clippy, local
Dylint rules, focused Kani harnesses, and targeted mutation testing. It
complements the required validation bar below; it does not replace subsystem
tests, plugin install, r2r, or `../radare2` validation when those apply.

Currently enforced guardrails:

- use `tools/dylints/r2sleigh_lints` for forbidden ownership and flow patterns:
  plugin-side route policy, decompiler-side fact repair, string-prefix
  semantic classification, nondeterministic render maps, summary routes that
  masquerade as native C, and other repo-specific architectural seams
- use Kani for bounded algebraic and policy invariants: width/sign-extension
  rules, address intervals, lattice laws, cache-key separation, refusal policy,
  and authority matrices
- use `cargo machete` and `cargo +nightly udeps` for dependency hygiene
- use `cargo mutants` when tests need to prove behavior, not just execute code

Candidate guardrails to add when a failure mode earns them:

- use `cargo-fuzz` or another coverage-guided fuzzer for parsers, binary/JSON
  payload normalization, IL/SSA serialization, FFI boundary decoding, and
  address/type syntax
- use Miri for focused unsafe, aliasing, and FFI-adjacent Rust tests where the
  code can run under the interpreter
- use `cargo deny` for duplicate-version pressure, advisories, and license policy
- use `cargo llvm-cov` to find unexercised surfaces, then decide whether
  behavior-level tests or mutation targets are the right ratchet
- use broad maintainability scanners such as `rustqual` only as triage signals;
  promote real findings into repo-owned tests, Dylints, scripts, or docs

Never delete or weaken a proof, lint, fuzz target, mutation target, or benchmark
gate just to make progress. If a guardrail is wrong, replace it with a stronger
one and state the invariant, owner, evidence, and removal condition in the same
change.

## Build And Run

Use these commands from the workspace root unless noted otherwise.

```bash
# Build the shell
cargo build --release -p r2s --features sleigh

# Run the whole test suite. --no-fail-fast, always.
cargo test --workspace --all-features --no-fail-fast

# Run the Sleigh toolchain explicitly
cargo run -p r2sleigh-cli --bin r2sleigh --features x86 -- \
  disasm --arch x86-64 --bytes "31c00000000000000000000000000000" --format json

# The certification gate: every named function renders and reads nothing
# that was never written
python3 scripts/certify_render.py --bins <radare2>/test/bins/elf \
  --limit 24 --functions 8

# The differential gate
python3 scripts/diff_r2.py --bins <radare2>/test/bins/elf --limit 30

# Whole-binary render coverage against a blessed baseline
./tests/coverage/run_coverage.sh

# Rewrite/architecture quality gates when the change warrants it
scripts/quality-gate.sh --dry-run
scripts/quality-gate.sh
```

Notes:

- `cargo run --features x86 -- ...` at the workspace root is stale; use
  `-p r2sleigh-cli --bin r2sleigh`
- **build before measuring**: the harnesses default to `target/debug/r2s`,
  which `cargo build --release` does not touch
- x86/x86-64 lifting still expects 16 bytes minimum

## Testing Policy

### Behavior-First Tests

One strong test that drives the real user-facing or contract-facing path is
usually better than a chain of helper tests. Tests should prove that facts flow
through the intended owner and typed contract, not that today's private helper
calls happen in today's order.

When adding or changing tests:

- prefer a single deterministic `r2r`, e2e, or crate-level pipeline test that
  exercises lift, SSA, semantic evidence, type facts, engine routing, and render
  behavior as far as the change requires
- assert the important contract facts, residuals, refusal reasons, ordering, and
  output shape in one informative scenario instead of scattering weak asserts
  across private helpers
- delete or collapse helper-level tests when a higher-level test covers the same
  invariant with better evidence
- keep focused helper tests only for local algebra, parser edge cases, proof
  harnesses, fuzz regressions, or failure localization that would be noisy or
  impractical through the full pipeline
- do not test private helper names, temporary locals, summary-shaped variables,
  or incidental traversal order unless that detail is itself the canonical
  contract
- when replacing helper tests, preserve the invariant they were meant to protect
  and make the new test fail for the old bug, not merely pass on the new code

The target is not fewer tests for its own sake. The target is higher signal:
tests that catch broken ownership, broken evidence flow, fake semantics,
missing residuals, nondeterminism, and real user-visible regressions.

### Manual Verification

Manual testing is required for quality claims about semantics, types,
decompilation, summaries, route selection, and radare2 integration. Benchmarks
and scripts can find suspicious cases, but they do not prove the output is
right. A higher score can still mean the engine learned to emit prettier fake C.

Manual verification should inspect the real workflow a user or maintainer would
see:

- run the relevant radare2/plugin/CLI command on at least one representative
  binary or fixture
- compare the rendered output with CFG, SSA/dataflow, type facts, semantic
  evidence, residuals, and refusal reasons
- check that clean-looking C is backed by native facts, not summary templates,
  source-shaped local names, or benchmark-friendly guesses
- look for exposed issues that scripts miss: misleading confidence, missing
  residuals, bad command UX, unstable ordering, awkward facts, and incorrect
  fallback routes
- record the exact command, fixture, and observed behavior when the manual check
  justifies a quality claim or a benchmark interpretation; put it in the final
  response, PR description, commit message, or benchmark report, whichever is
  the durable artifact for the change

Do not replace manual inspection with a new benchmark script. Write scripts to
reproduce and track what manual testing found, then keep using manual checks to
audit whether the metric is still measuring the right thing.

### Where a new test goes

| What changed | Where the test goes |
|---|---|
| A lowering, predicate, certificate or fold | Inline `#[cfg(test)]` beside it |
| A crate's public surface | `crates/<crate>/tests/` |
| A command's output | `crates/r2s/tests/` |
| What a whole function renders | The certification gate, plus a unit test for the rule |
| Discovery, naming or decoding | The differential gate, with the disagreement judged |

`crates/r2engine/tests/native.rs` is the model for an integration test: an
in-memory program built from byte literals, the six-method `Program` trait
implemented over it, and an assertion on what the engine renders. No binary on
disk, no external tool, no fixture to regenerate.

## Required Validation Bar

If you touch `r2ssa`, `r2source`, `r2rewrite`, `r2types`, `r2engine`, `r2dec`
or `r2s`, the minimum bar is:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features --no-fail-fast
bash scripts/structure-report.sh
```

**`--no-fail-fast` is not optional.** Without it `cargo test` stops at the first
failing target, so one crate's known failure hides every failure after it. A
gate reported selectively is worse than a gate not run: report the count the
suite printed rather than the class you expected, and give every standing
failure a recorded cause.

If the change can move rendered output, add the certification gate and the
coverage sweep. If you also changed `../radare2`, add:

```bash
make -C ../radare2 -j4
cd ../radare2/test && r2r -L -o results.json db/cmd/cmd_af db/json/json1
```

## Common Change Workflows

### Change the type / decompiler seam

1. Choose the owner. If the answer is "more than one", the design is wrong.
2. Extend `r2types` first for signatures, layouts, and type facts.
3. Keep route policy in `r2engine`; keep `r2dec` on semantic interpretation
   and rendering only.
4. If the engine needs a fact it does not have, add it where it is derived,
   not where it is missed.
5. If the seam is wrong, redesign it instead of layering adapters.
6. Add the test before the broad snapshot churn.

### Change symbolic / query behavior

1. Put semantic policy in `r2ssa`.
2. Put evidence and ambiguity in the prepared facts and certificates.
3. Put request routing and route policy in `r2engine`.
4. Let `r2types` / `r2dec` consume those facts; do not reinvent them.
5. Add solver-budget and determinism coverage where applicable.

### Change summary/native-worker behavior

1. Prefer structural/evidence classifiers over symbol-name lists.
2. Keep symbol names as weak hints unless backed by typed context or structural
   evidence.
3. Put summary policy/evidence in `r2engine`.
4. Put signature/type projection in `r2types`.
5. Put route selection and any trace-proven reuse in `r2engine`.
6. Put rendering only in `r2dec`.
7. Add a negative test for the fake-output class you are preventing.

### Add or change an `r2s` command

1. Decide whether the feature should really be automatic.
2. Use radare2's name for it, so the two can be diffed.
3. One arm in the flat verb `match` in `crates/r2s/src/commands.rs`, and one
   function beside it. `run` already supplies `~` grep and `@` temporary seek.
4. Add coverage for the happy path and the failure path in
   `crates/r2s/tests/`.

## Command Surface

Two tiers:

- public: `q ?e s i ie iS is ir iz px pd pdf pdd afl f ax axt w wx wc wcr`
- maintainer: `pdil`, `pdim`, `pdih` — the three IL tiers

Do not expand the public surface casually. Prefer deeper integration over more
verbs, and radare2's spelling over an invented one.

## Two SSA Block Types

There are two different block types in `r2ssa`:

| Type | Location | Purpose |
|------|----------|---------|
| `SSABlock` | `crates/r2ssa/src/block.rs` | single-instruction SSA block |
| `FunctionSSABlock` | `crates/r2ssa/src/function.rs` | function block with phi nodes |

`r2dec` works with `FunctionSSABlock`.

## File Quick Reference

| File | Edit this when... |
|------|--------------------|
| `crates/r2il/src/opcode.rs` | adding or changing IL ops |
| `crates/r2sleigh-lift/src/disasm.rs` | changing P-code lifting or register naming |
| `crates/r2sleigh-lift/src/esil.rs` | changing text or ESIL rendering |
| `crates/r2ssa/src/` | changing SSA construction, def-use, prepared facts |
| `crates/r2ssa/src/semantic.rs` | changing prepared facts, certificates, or refusal evidence |
| `crates/r2source/src/` | changing the facts a capture owns, or their contracts |
| `crates/r2rewrite/src/` | changing term rewriting or its rule proofs |
| `crates/r2types/src/` | changing type inference, layouts, canonical function facts |
| `crates/r2engine/src/` | changing request orchestration, route selection, or engine metrics |
| `crates/r2dec/src/` | changing lowering, structuring, rendering |
| `crates/r2image/src/` | changing container parsing or DWARF reading |
| `crates/r2abi/src/` | changing conventions, prototypes or the sdb data |
| `crates/r2engine/src/native.rs` | changing the walk, the capture or the two-pass preparation |
| `crates/r2engine/src/discovery.rs` | changing which addresses are believed to be functions |
| `crates/r2s/src/commands.rs` | adding or changing a command |
| `tests/coverage/coverage-baseline.json` | re-blessing coverage, after reading it |

## Benchmark Triage

Use `scripts/reversing_benchmark.py --closure-gate` when a corpus run is meant
to check closure pressure rather than just gather signal. The report includes
owner buckets for `../radare2`, `r2ssa`, `r2types`, `r2engine`, `r2dec`, and
plugin glue; treat those buckets as triage hints, then verify the
canonical owner before editing.

Benchmark scores are never semantic proof. Before claiming a benchmark
improvement is a real quality improvement, manually inspect representative
outputs from the improved and regressed buckets. If the score improves by hiding
residuals, emitting source-shaped summaries, trusting names, or rewarding fake
control flow, fix the benchmark gate before using it to guide more work.

## Gotchas

1. x86/x86-64 lifting still expects 16 bytes minimum.
2. ESIL subtraction must use ASCII `-`, not Unicode minus.
3. `Const` means literal; `Unique` means temporary SSA-like storage, not memory.
4. Width mismatches usually need explicit sign/zero extension.
5. Register aliasing must stay deterministic.
6. `#[no_mangle]` is now `#[unsafe(no_mangle)]` under Rust 2024.
7. Plugin, CLI, and export feature matrices are not identical.
8. If output stability matters, hash-order nondeterminism is a bug.
9. On the `r2dec` lowering path, resolve call targets through
   `r2types::CalleeResolutionFacts` rather than parsing `const:` / `ram:`
   names locally; `tools/dylints/r2sleigh_lints` enforces this.
10. On the decompiler/type path, do not reintroduce `r2dec` type ownership just
    to make an old test compile.
11. Summary-driven output must remain visibly summary-driven until real
    loop/control reconstruction is backed by canonical facts.
12. Do not invent switch case values, stack locals, call args, or signatures to
    make output look cleaner.

## Useful References

- `README.md` for current build and testing quick-start
- `ROADMAP.md` for current system direction and priority order
- `doc/engine-vision.md` for where this is going and why
- `doc/rewrite_quality_gates.md` for the local rewrite quality gate and tooling
- `doc/testing.md` for where a new test goes
- `doc/` for IL, SSA, ESIL, decompiler, taint and type-system notes
- radare2 ESIL docs: <https://book.rada.re/disassembling/esil.html>
- Ghidra P-code reference: <https://ghidra.re/courses/languages/html/pcoderef.html>
