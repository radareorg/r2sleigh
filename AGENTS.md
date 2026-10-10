# Agent Guidelines for r2sleigh

Working rules for contributors and coding agents. Order and status are in
[ROADMAP.md](ROADMAP.md); design in the ADRs it links.

## North Star

`r2image`, `r2abi`, `r2il`, `r2sleigh-lift`, `r2ssa`, `r2source`, `r2rewrite`,
`r2types`, `r2engine`, `r2dec`, `r2s` and `r2s-tui` are one subsystem. `r2s` is
the tool; `../radare2` is the differential target the engine is graded against
and a source of upstream fixes, not a host.

The goal is an engine where one fact has one owner, facts flow through typed
contracts, decompiler, types and analysis views agree, expensive work is
summarized and reused only where real sessions prove value, and output is
deterministic. Any seam may be rewritten when the rewrite is cleaner: the
question is never "what is the smallest diff?" but "what is the cleanest owner
and the cheapest long-term design?"

## Non-Negotiables

1. One fact, one owner. Never let one policy live in two crates "for now".
2. `r2s` is a command surface only: it opens the binary and spells the answer.
3. Every fact about a program arrives through `r2engine::program::Source`: the
   bytes and what the container states. Nothing below `r2s` knows what a file
   is; the engine derives names, stubs and definitions from `Source`.
4. Typed contracts, not JSON reparsing or stringly maps.
5. Push a missing fact upstream to its owner; never reconstruct it downstream.
6. Symbol names are hints, never semantic proof.
7. Deterministic ordering beats cleverness; hash-order output is a bug.
8. Never fabricate C, control or type semantics to avoid a residual. A visible
   residual or refusal beats plausible unproven C.
9. Rewrite a bad seam instead of patching around it; remove hacky behavior
   before building on it, even if a benchmark gets worse.
10. Validation is part of the change.

## Where A Fix Belongs

If a fix starts in `r2s` or `r2dec`, first prove the fact belongs there. Most
semantic, type, cost and route fixes belong in `r2ssa` (where the evidence is)
or `r2engine` (where the request is built).

| Crate | Owns |
|-------|------|
| `r2image` | What the container states: bytes, sections, symbols, relocations, entries, CFI, DWARF. No inference |
| `r2abi` | What an ABI or C library states that no specification does: library prototypes, cited platform/ABI rows, syscalls |
| `r2il` | The low IL, its serialization and executable semantics (`r2il::eval`) |
| `r2sleigh-lift` | Sleigh decoding and lifting, register naming, the `LanguageProfile` read from the trusted bundle |
| `r2ssa` | The IR and its indexes: stable ids, SSA, def-use, liveness, values, memory, the frame model, prepared facts, certificates and refusal evidence; the fixpoint driver |
| `r2source` | Contracts between layers, the trusted snapshot, `Confidence` |
| `r2types` | Type inference, layouts, signatures; `FunctionTypeFacts`, `FunctionFacts`, `SourceOwnedFunctionFacts` |
| `r2rewrite` | The term arena and term rewriting with rule proofs |
| `r2engine` | The query database, request orchestration, route selection, refusal/fallback policy, discovery, summaries |
| `r2dec` | Lowering, structuring, rendering; no route or type ownership |
| `r2s` | Command dispatch, the verb table, the only implementor of `Source` |
| `r2s-tui` | The visual mode: layout, keys, drawing; no program facts |

Canonical contracts — extend these rather than wrapping them:
`r2ssa::SsaArtifact` with `PreparedFunctionFacts` and
`PreparedFunctionCertificates` (the semantic artifact; `r2ssa` owns evidence
and refusal, consumers interpret it); `r2source::OwnedFunctionSnapshot`;
`r2types::FunctionTypeFacts` (type/layout/signature payload);
`r2types::FunctionFacts` (advisory combined report);
`r2types::SourceOwnedFunctionFacts` retaining the exact `Arc<SsaArtifact>`
(runtime authority); `r2types::DecompileRouteFacts` (route chosen by
`r2engine`); the `r2engine` typed request/response APIs.

## Anti-Hack Standard

Hacky shortcuts are correctness bugs even when they improve a score. Blockers:

- test-, fixture- or benchmark-specific semantic recovery;
- name-owned summaries or hardcoded role signatures presented as proof, or
  overriding stronger typed context;
- invented loops, switches, switch case values, helper calls, stack slots,
  locals, call arguments or types;
- decompiler-side repair of call arguments, stack slots or types that an
  upstream owner should state;
- route or fallback decisions outside `r2engine`'s typed policy;
- output cleanup that hides a missing upstream fact;
- broad fallbacks that turn unknown facts into confident C.

For any non-trivial analysis, state the invariant proven or refused, its
canonical owner, the evidence that justifies the output, and the complexity
target.

**Summaries.** Classification belongs in `r2engine`, from CFG shape, loops,
memory effects, callsites, constants, def-use and typed context; names are
weak hints and tie-breakers only. `r2types` may project summary evidence into
signatures with confidence and refusal reasons explicit. Summary-only routes
render comments, facts, residuals and refusals, never executable C, even when
the summary is exact: exact summaries feed native proofs, then render through
the normal CFG/dataflow path.

**Tests must not train the engine to look good.** A source-shaped expectation
must be justified by native CFG/control/dataflow/type facts. Never bless
`summary_*` locals, synthetic iterators or pretty loops from templates; convert
such oracles into negative tests that reject the fake output. When output
looks too good for the available facts, stop and audit the renderer, oracle and
gate first.

## Performance

Targets: `O(1)`/`O(log n)` lookup for metadata, indexes and caches; `O(n)`
passes over blocks, ops or facts; bounded search with explicit budgets and
refusal modes; incremental recomputation; summary reuse across query, typing
and decompilation. If you cannot state the asymptotic and practical cost of a
new path, it is not ready.

Smells: repeated whole-function scans, repeated solver queries for one fact,
recomputing downstream what exists upstream, parallel representations of one
fact, name-first classification.

Structural rules (ROADMAP D11, Dylint-enforced as owners land):

- an iteration runs on `r2ssa::fixpoint` or is a worklist whose termination is
  stated where it is written; a cap that silently keeps a partial result is a bug;
- a fact about a function's values, instructions or blocks is an index over
  their dense ids ([doc/adr-one-ir.md](doc/adr-one-ir.md)), not a map keyed by
  `SSAVar`, `ValueId` or `InstId`, and not a graph rebuilt for one pass;
- a computed program fact lives only in the query database
  ([doc/adr-query-database.md](doc/adr-query-database.md)), never in a
  `Mutex` table or a private memo;
- prefer `BTreeMap`/`BTreeSet` where ordering reaches output.

Large functions hide regressions the census does not show: time release `pdd`
on the big 0pack/pumasim functions for any change on a hot path.

## Comments

A comment is one or two lines: what the code cannot say for itself, such as
the invariant, the reason, or the ADR section. Design, derivations, history,
worked examples and measurements go in the architecture docs (`doc/adr-*.md`)
and the comment links there. `scripts/structure-report.sh` counts runs of more
than two `//` lines (`long_comments`), and the count only falls at an item's
exit (see Validation Bar): when you touch a long comment, shorten it.

## radare2

radare2 is the differential target for discovery, naming, decoding and
cross-references. The engine links nothing from `libr`.

- A disagreement may be radare2's defect: judge who is right.
- A radare2 fix unrelated to Sleigh goes upstream as its own PR, one idea each,
  one-line commit messages, no assistant attribution.
- Add nothing to the fork that radare2 itself does not need.

## Command Surface

`r2s` spells commands as radare2 does so `scripts/diff_r2.py` can diff them.
Keep the public surface small and the common path automatic. Before adding a
command, ask: does radare2 have a name for it (use it)? should it be automatic?
should it enrich an existing view? is it only a debug surface? A command is one
entry in `VERBS` in `crates/r2s/src/commands.rs` plus one handler, with
happy- and failure-path tests in `crates/r2s/tests/`. Maintainer tier:
`pdil`, `pddo`.

## Task Protocol

1. Name the broken invariant or user-visible behavior.
2. Name the canonical owner and the existing contract to extend.
3. State the complexity target.
4. Fix at the owner; add the smallest deterministic test at the layer users
   exercise.
5. If rendering changes, state why the C is justified by canonical facts.
6. For semantic, type, summary, route or decompiler changes, inspect real
   output by hand (command, fixture, what you saw) — a better score is not
   proof — and record it in the commit or PR.
7. If the seam crosses into `../radare2`, validate both repos.
8. If a failure mode repeats, encode it as a Dylint, proof, fuzz or mutation
   target, gate or script.

Before landing, check: no second owner, no new full-function rescans or
repeated solver work, no JSON-shaped internal type, no nondeterminism, no
policy moved downstream, no name-first ownership, no fake C, no weakened gate.
If any answer is yes, the design is probably wrong.

## Testing

One behavior-level test through the real pipeline beats several helper tests
locked to today's implementation. Assert contract facts, residuals, refusal
reasons and ordering; make the test fail on the old bug. Keep helper tests for
local algebra, parser edges, proofs and fuzz regressions. Do not test private
helper names or incidental traversal order.

| What changed | Where the test goes |
|---|---|
| A lowering, predicate, certificate or fold | inline `#[cfg(test)]` beside it |
| A crate's public surface | `crates/<crate>/tests/` |
| A command's output | `crates/r2s/tests/` |
| What a whole function renders | the certification gate, plus a unit test for the rule |
| Discovery, naming or decoding | the differential gate, with the disagreement judged |

`crates/r2engine/tests/native.rs` is the model integration test: an in-memory
program from byte literals, the `Program` trait over it, an assertion on what
the engine renders. More in [doc/testing.md](doc/testing.md).

## Validation Bar

Work runs one roadmap item per branch, with two tiers of checks. Each item's
pull request stacks on the one before it (`gh stack link`), so CI grades it
against its parent and the stack merges bottom first.

Inside an item, per edit: `cargo fmt`, clippy and the tests of the crates
touched. The old path is deleted when the new owner lands, without running
both (ROADMAP D1); the census may move. `scripts/structure-report.sh` and its
`long_comments` count are suspended until the item's exit.

At an item's exit, before it merges, the full bar below runs once: the
workspace suite, equivalence on x86-64 and aarch64, the census (each moved
line read and judged), certification, release `pdd` timing on the large
0pack and pumasim functions, and `scripts/structure-report.sh`, whose counts
are then blessed for the item. Equivalence, certification, tests, proofs and
Dylints are never suspended, except on `rebuild` (ROADMAP D27), where
equivalence, certification and the census report until it merges.

The exit bar, for any item touching `r2ssa`, `r2source`, `r2rewrite`,
`r2types`, `r2engine`, `r2dec` or `r2s`:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace --all-features --no-fail-fast
bash scripts/structure-report.sh
```

`--no-fail-fast` is mandatory: without it one failing target hides the rest.
Report the count the suite printed and give every standing failure a recorded
cause. If rendered output can move, add the census, the certification gate and
the coverage sweep. If `../radare2` changed:

```bash
make -C ../radare2 -j4
cd ../radare2/test && r2r -L -o results.json db/cmd/cmd_af db/json/json1
```

Quality gates (`scripts/quality-gate.sh [--dry-run|--strict-dylint]`,
[doc/rewrite_quality_gates.md](doc/rewrite_quality_gates.md)): dependency
hygiene, fmt, Clippy, the `tools/dylints/r2sleigh_lints` Dylints, Kani
harnesses for algebraic and policy invariants, targeted mutation testing.
Never delete or weaken a proof, lint, fuzz target, mutation target or
correctness gate to make progress; replace a wrong one with a stronger one and
state why. The structure ratchets are the one suspension, and only inside an
item.

## Build And Run

```bash
cargo build --release -p r2s --features sleigh
cargo run -p r2sleigh-cli --bin r2sleigh --features x86 -- \
  disasm --arch x86-64 --bytes "31c00000000000000000000000000000" --format json
python3 scripts/certify_render.py --bins <radare2>/test/bins/elf --limit 24 --functions 8
python3 scripts/diff_r2.py --bins <radare2>/test/bins/elf --limit 30
./tests/coverage/run_coverage.sh
```

Build before measuring: the harnesses default to `target/debug/r2s`, which a
release build does not touch.

## Gotchas

1. x86/x86-64 lifting expects at least 16 bytes.
2. `Const` is a literal; `Unique` is temporary SSA-like storage, not memory.
3. Width mismatches need explicit sign or zero extension.
4. Register aliasing must stay deterministic.
5. Rust 2024: `#[no_mangle]` is `#[unsafe(no_mangle)]`.
6. The shell, CLI and export feature matrices differ.
7. On the `r2dec` lowering path, resolve call targets through
   `r2types::CalleeResolutionFacts`, never by parsing `const:`/`ram:` names
   (Dylint-enforced).
8. Do not reintroduce `r2dec` type ownership to make an old test compile.

## References

[README.md](README.md) (quick start), [ROADMAP.md](ROADMAP.md),
[doc/engine-vision.md](doc/engine-vision.md),
[doc/rewrite_quality_gates.md](doc/rewrite_quality_gates.md), the other
`doc/` notes, and the Ghidra P-code reference:
<https://ghidra.re/courses/languages/html/pcoderef.html>.
