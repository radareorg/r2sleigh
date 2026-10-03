r2sleigh Roadmap
================

> The one ordered execution list. Why the project exists and what it is
> becoming is in [doc/engine-vision.md](doc/engine-vision.md); the working
> rules are in [AGENTS.md](AGENTS.md). The detailed specification of each
> phase below is in [doc/handoff/review-fixes/plan.md](doc/handoff/review-fixes/plan.md)
> and [plan-extension.md](doc/handoff/review-fixes/plan-extension.md); this file
> owns the order, the status and the decisions, and those own the detail.
> Where they disagree, this file wins and the disagreement is a defect.

What r2s is
-----------

The radare2 plugin is deleted. `r2s` is the tool, with three surfaces over one
engine that owns its facts:

1. **The engine**: discovery, lifting, SSA, memory, types and a certifying
   decompiler, answering typed queries. C is printed only where checked facts
   justify it; otherwise a counted residual or a refusal that says why.
2. **The shell and the visual mode**: radare2's command language and keys, so a
   radare2 user moves without relearning, with what radare2 never had —
   completion, discoverability, linked views, a graph you can read, and a UI
   that never blocks.
3. **The agent surface**: stateless addressed queries, confidence on every
   field, explain and verify.

How we measure, in order of authority:

| Gate | Question it answers |
|------|---------------------|
| Equivalence (`tests/equiv`) | Does the rendered C compute what the machine code computes? The north-star number. |
| Certification (`scripts/certify_render.py`) | Does every rendering read only what it assigns, and never panic? |
| Source-gold (`scripts/differential_truth.py`) | Are recovered signatures what the source declared, or marked when not? |
| Coverage (`tests/coverage`) | How much of a whole binary renders, and does any of it regress? |
| Differential (`scripts/diff_r2.py`) | Where discovery, naming and decoding disagree with radare2, and who is right. |

A benchmark score is never proof of quality; output is read by hand before a
quality claim (AGENTS.md, Manual Verification).

Where this stands
-----------------

Measured on `engine/review-fixes-vfmgfv` at `fe7698e8`, 2026-10-03.

| Measure | Value |
|---------|-------|
| Equivalence | 582 of 756 `equal` (x86-64, gcc 13 and clang 18, -O0..-O2). The rest: residual-trap 75, ub 37, refused 27, unsupported 20, differs 13, compile-error 1, slow 1 |
| Hash corpus (issue #61) | 85 of 98 `equal`, from 1 of 36 in August |
| Certification | 21 rendered, 4 refused, 0 undefined reads, 0 panics |
| Coverage | 554 of 562 rendered locally; 0 regressions against HEAD at one compiler |
| Workspace tests | 2072 passed; 2 fail only under Apple clang 21 (strict `main` and unused-helper diagnostics) |

Landed since the plugin was deleted (each gated, detail in the program docs):

- **P0**: dispatch soundness, per-function isolation, `pddj`, the equivalence
  gate, the plugin-era retirement.
- **P1 identity and reads**: one bit-identity fact (`ValueView`); a rendered read
  names a version some statement assigned, or it is a residual; the
  `SystemReserved` register class.
- **P2 container statements** and **P3 declarations**: one definition of every
  container statement, per-libc prototype tables, DWARF read once by address
  into one type graph.
- **H** (unused analyses wired or deleted), **K** immediate caps, the **core**
  tracks (INSERT mask, SSA entry edge, BSF/BSR/TZCNT and PSHUFLW lifting).
- **P4.1, P7 and P10, in part** (commits marked WIP): frame objects reached by
  callees, the variadic call contract, byte copies for byte-declared objects.
- **2026-10-03** (`fe7698e8`): the released wide INSERT base renders; a return
  register only partly filled is unproven, not a result; `__bzero` declared;
  pointer parameters from certified accesses; `ParamArray`/`PtrMember` only
  where the address is exactly the subscript or the field; the source-gold gate
  refuses a debug build whose truth is the engine's own guess.
- A visual mode (`V`, `VV`, `agf`) and radare2's layouts for `afl`, `afb`, `afi`.

What the last month taught
--------------------------

Leaf bugs get fixed fast: nine of the sixteen issues open in August are fixed
without structural change. What remains is structural, and it is concentrated.

1. **Facts are keyed by position and kept in sync by hand.** About eight r2ssa
   maps are keyed by `(block, op index)`; `get_block_mut` drops prepared facts;
   a revision assert catches staleness at run time; the graph is rebuilt after
   the demand pass; the memory-site remap is safe to run once only because a
   comment says so (`function/mod.rs:447`).
2. **A fact does not carry where it came from.** A recovered interface whose
   types are only carrier widths was read as the source's exact signature, which
   declared every dereferenced pointer an integer on every stripped binary.
   Fixed today with a flag; the class is open until provenance is a type.
3. **The renderer runs a second proof system.** r2dec's binding plan and
   observation journal are ~22k lines beside r2ssa's ~20k of certificates, with
   their own fixpoint (`binding_plan/rules.rs:1202`), ~15 refusal enums,
   first-writer-wins use claims, and spelling rules written three times. Correct
   pointer types today exposed three renderer defects at once, one of them fake
   C (`v->beta` for `v[i].beta`) already shipping on DWARF builds.
4. **One function lives in seven representations**, five rebuilt: SSA blocks,
   graph (up to twice), value views (three times), the machine projection (per
   plan build), the term arena (per inlining round), the binding plan (per
   render-loop iteration).
5. **The gates were dead for three weeks** (a self-hosted runner nobody
   watched), so ~185 commits merged unchecked and two baselines were blessed on
   one laptop, one of them vacuously.
6. **The visual mode blocks**: the engine is called from inside `draw`; one pane
   at a time; no completion, colour roles, mouse, or discoverability.

Decision: **restructure, not rewrite.** The lifter, r2image, r2abi, the
certificates, r2rewrite's proved rules, Kani and the gates are kept. Three parts
are replaced outright rather than ported, each running beside the old path until
the gates agree, then the old path is deleted in the same change:

- the mutable SSA core, by a staged, ID-keyed artifact (F1, F2);
- r2dec's accounting layer, by a render plan with one by-construction checker (R);
- `r2s-tui`, by a message-driven visual mode on a worker thread (V).

Tripwire: if F1 takes more than about four weeks, or touches most of r2ssa,
switch to a new core crate beside r2ssa and migrate passes into it.

Decisions
---------

Taken (2026-10-03):

- **D1. Restructure, not rewrite**, as above.
- **D2. Stable identity before more facts.** Op and value identities are stable
  and never reused; no fact is keyed by position. F1 lands before P4's memory
  SSA, so the memory model is not built on positions.
- **D3. Stages are types.** `Lifted → Prepared → Sealed`; a transform consumes a
  stage and returns the next. Remapping twice or editing a sealed artifact does
  not compile.
- **D4. Provenance is part of every fact.** Track C's `Confidence{grade, basis,
  premises}` is extended from discovery to interfaces, types, names and
  certificates, as `Fact<T>`; a consumer states the least grade it accepts, and
  a Dylint rejects an unwrapped answer field. It replaces
  `types_are_carrier_widths`.
- **D5. Gates are blessed in CI, never on a laptop**, from pinned containers. A
  queued run that no runner takes is an alert, not a silence.
- **D6. Equivalence runs on arm64 too**, under qemu-user, so "x86-64 only" stops
  being a limit of the oracle.
- **D7. The visual mode never calls the engine while drawing.**

To confirm (each reverses or retires an earlier decision):

- **D8. The observation journal is replaced, not kept.** plan-extension.md's
  track H says it stays because it feeds the obligation ledger. The month's
  evidence says the journal is where proofs are re-derived after rendering; a
  render tree built with its obligation ids, checked once, makes the journal
  redundant. Proposed: R replaces it.
- **D9. `doc/adr-location-ssa.md` is superseded**, not implemented: P1's
  `ValueView` answers bit identity and P4's partition answers frame identity.
  What the ADR wanted that neither yet gives — one liveness model over
  locations (issue #50) and pruned flag and temporary phis (#56) — moves to F2.
- **D10. DecBench is measured again** only once it runs on a machine that can
  reach PyPI; until then quality is the equivalence gate plus reading `pdd`.

The program
-----------

Identifiers are kept from plan.md and plan-extension.md (P*, PE, C, H, I, K, Q,
S, E, A); the new ones are G (gates), F (foundation), R (renderer as printer)
and V (visual mode and shell experience).

### G. Gates first — now, blocks everything

| Item | Exit |
|------|------|
| CI under ten minutes: one `ci`-profile build every gate downloads, equivalence in six shards held to the baseline by `tests/equiv/merge_shards.py`, the harness's own tests in their own job | The slowest job finishes in ten minutes; it was 33 for equivalence alone |
| CI green, with the equivalence, coverage and source-gold baselines re-blessed from CI's own run (the merge job writes `baseline.proposed.json`) | Every gate passes on a push with no laptop baseline |
| Queued-run alert; pinned containers for gcc 13, clang 18 and the macOS coverage compiler; compiled coverage cells replaced by pinned bytes | A gate result does not depend on the runner |
| Diagnose the equivalence `PipelineTests`/`SelfTestSuite` stall on hosted runners. From unittest a driver run never returns, and the step outlives even a step-level timeout, so some process is in an uninterruptible wait (the runtime's guard install is the first suspect); the same self-tests pass inside every equivalence shard. Reproduce on x86-64 Linux: `tests/equiv/bounded.sh 240 test_equiv.SelfTestSuite`. The two classes are out of CI until then | Both classes pass from `bounded.sh` and gate again in the harness job |
| arm64 equivalence under qemu-user (D6) | `tests/equiv` reports both architectures |
| SSA integrity: one definition per value, every use dominated | **Partly done.** The validator now checks dominance and holds over the whole corpus at construction. #56's "duplicate" is a display artefact: `pdim` prints `tmp:2c200` at two widths alike, and width is part of SSA identity. Validating the *sealed* function fails 626 times on one cause, P1.7's entry lanes (version-0 values given definitions), so the seal check lands with P1.7 inside F1 |
| Split PR #66 into reviewable pieces and merge | `master` carries the program |
| Close the issues fixed since August; update the partial ones; one tracking issue per item below | The issue board is the roadmap |

### F. Foundation — the spine (r2ssa, r2source)

| Item | Depends on | Exit |
|------|-----------|------|
| **F1** Stable op and value ids; every `(block, op index)` map re-keyed; stage types (D2, D3). Design and five-step migration: [doc/adr-stable-identity.md](doc/adr-stable-identity.md); step 0 (the remap), step 1 (the `OpId` arena) and step 2 (`Lifted -> Prepared -> Sealed`; passes edit through plans; prep facts only on `Sealed`) done | G | `get_block_mut`, `op_mut`, the revision asserts and the remap comment are gone |
| **F2** One IR with views: blocks, graph and value views built once at seal; the machine projection and term arena become indexes; one liveness model over locations; flag and temporary phis pruned by liveness | F1, P4 | No rebuild after seal; closes #47, #50, #56 |
| **K** One fixpoint driver: lattice height, widening and a visible budget for every iterative pass, Kani on the lattice laws (the rest of track K) | F1 | No bare `loop` until unchanged; `objects.rs:196` first |

### Analysis (detail in plan.md)

| Item | Depends on | Exit |
|------|-----------|------|
| **PE** Byte-dependency relation; result width from the written-lane lattice; `narrow_zero_extend_input_size` deleted | F1 | `main` returns `int`-width, `gt` is not `uint8_t`, `fnv1a32` returns 32 bits (#58, #63) |
| **P1.7** Entry lanes rewritten: `mint_entry_lane_projections` defines version-0 values (a live-in with a definition) and rebuilds a whole-register read from the declared lanes "with zero above them", which invents the caller's upper bytes. A formal becomes a view of a lane of its live-in (`ValueView`), and the bytes no declaration covers an `Unspecified(width)` leaf that renders as a residual | PE, F1 | The rotl listing makes no false claim; the sealed function validates |
| **C** Confidence everywhere as `Fact<T>` (D4) | — | Every public answer field is a `Fact`; the minted-interface flag is deleted. **Designed** in `doc/adr-provenance.md`: grade derived from basis, steps C0–C4; C0 (the vocabulary) done |
| **P4** Memory model: frame partition (P4.1 in part), MemorySSA on stable ids, stack-protector elision, `afv`/`afi` from sealed entities | F1, C | The canary traps in #61 are gone; one owner of frame objects |
| **Q** Demand-driven query database; `memo.rs` and the eight caches deleted | F1 | A random-write session equals a fresh open |
| **I** Unread container facts: CFI extents and save slots as stated entries, LSDA, IBT, RELRO, init arrays | Q | Stripped discovery finds every FDE start |
| **P5** Value domain completed; loads from immutable memory fold | K | The `optimize.rs` round cap is gone |
| **R** Renderer as printer: the render plan is one pure function of sealed facts with no rounds; the render tree carries obligation ids by construction; one linear checker; P10's render-only lowering and admissibility rules; the journal deleted (D8) | F2, P5 | r2dec reads only sealed facts; the three bound-address rules are one |
| **P6** One resolved body per function per revision, on Q; callee summaries bottom-up over SCCs | Q, I | `read_callees` is gone |
| **P7** Call contracts: one ABI classifier, variadic and format roles, result proof over the call graph | PE, P6, C | No dropped or invented argument; printf's stack tail renders |
| **P8** Data objects and strings | P5, P7 | `iz` lists proven strings |
| **P9** Types over the graph: declared-pointee propagation, inferred aggregates | P4, P8 | A struct pointer is not `uint32_t*` (`rec_index`) |
| **P11** Names and commands: one spelling of an unnamed function, aliases by occupancy | C, P6 | Differential disagreements all judged |

### Surface

| Item | Depends on | Exit |
|------|-----------|------|
| **V1** Visual-mode core: message-driven state, engine on a worker thread with a cache keyed by address and revision, a ticked event loop, mouse and resize; a `reedline` prompt with history shared by the shell and `:` | G | **Done** (merged `7b5f1d9e`, review fixes `0556f450`): no host call from the drawing thread, first frame 10 ms. The engine stays on the caller's thread because the Sleigh disassembler holds an `Rc`; quitting mid-decompile returns to the prompt only when it ends. The lists read each listing's rows with the address each is about (`commands::Table`), not the first `0x` on the line, which was the file offset for `iz`/`iS`/`is`; the function an address is in comes from discovery's `Holders` index, O(log n), with the resolved-graph check for switch arms kept until P6 |
| **S1** One verb table (verb, arity, help, JSON shape); `?` generated from it; `j` on every verb; `e` for presentation keys | — | Help and completion cannot disagree with dispatch. **Table, `?`, `verb?` and `e` done** (`e`/`-e` with the keys the shell acts on, `asm.bytes` and `scr.color`, by radare2's names; a value radare2 would coerce is refused); `j` on every verb remains |
| **V2** Colour from the engine: token roles from the disassembly speller and `pddj`, radare2's colour roles and `eco` themes, terminal detection, colour in the shell too | V1 | `pd` and `pdd` coloured identically in the shell and the visual mode. **Done** for disassembly and C: control flow from the lift, registers from the specification's table, numbers and names; C roles recorded by `r2dec`'s emitter as it writes (`CRole`), replacing both re-lexers; one palette (`r2s-tui::theme`). `eco` themes remain (they need `e`) |
| **V3** Completion and discoverability: grammar-aware tab completion from `line.rs` and S1's table; flags, functions, config keys; prefix-key hints; `Ctrl-P` palette; contextual `?` | V1, S1 | Every action is findable without documentation. **Shell completion done**: verbs from the table, names after `@` and as address arguments, keys after `e`; and the visual mode's hints, palette and `?` remain |
| **V4** Panels: a layout tree of splits and tabs (`V!`), linked cursors across C, disassembly and graph, breadcrumbs | V1 | A C line lights its instructions in every pane |
| **V5** Graphs: edge kinds coloured and labelled, back edges distinct, zoom levels, path highlighting, search, follow calls, loops shaded and folded from sealed loop facts, call and reference graphs through one renderer | V2; loop shading after F2 | `agf`, `agc` and `agx` share the renderer; layout off the UI thread |
| **S2** `@@` iterators, search, pipes and redirects, `-i`/`-q0` for r2pipe | Q | `diff_r2.py` covers the `j` forms |
| **E** Emulation over `r2il::eval`, then verify (`Proved`/`Disproved`/`Unknown`) | P2.3 | aarch64 originals checked against host-compiled renderings |
| **A** Agent surface: stateless typed queries, `Fact<T>` fields, budgets and elision, explain | Q, C | A transcript test and a shuffled-order determinism test |
| **V6** Annotation: rename, comment, retype and define as stored user facts, recompute through Q, undo | R, Q | An edit shows in every pane without reopening |

### Order

One engineer per track; a single engineer takes them in this order.

```
wave  engine                         analysis                 surface
W0    G                              —                        —
W1    F1                             PE, C, P1.7              V1, S1
W2    K                              P4, Q                    V2, V3
W3    F2                             I, P5                    V4, S2
W4    R                              P6                       V5
W5    —                              P7                       E, A
W6    —                              P8, P9                   V6
W7    —                              P11                      DecBench (D10)
```

Single-engineer order: G, F1, PE, C, V1, S1, V2, V3, K, P4, Q, F2, V4, I, P5,
R, V5, P6, P7, E, A, P8, P9, V6, P11.

Rules for every item: it runs beside the path it replaces and deletes it when
the gates agree; it deletes more than it adds or says why not; no new
renderer-side policy lands while R is open; no visual-mode feature calls the
engine synchronously.

### After the program

From the vision's tiers, in order, each only once its consumers exist: binary
diffing over callee summaries; exception-handler recovery; the outside
techniques of issue #65 (the switch prover's own harness, SAILR idioms as
r2rewrite rules one at a time, library identification measured before built,
Retypd revisited after P9); static rewriting; deobfuscation; trace recording
and query; the debugger (`doc/debugger-build-plan.md`).

Issues
------

Triaged against `fe7698e8` on 2026-10-03.

| Issue | State | Owner here |
|-------|-------|-----------|
| #49, #51, #52, #53, #54, #55, #59 | Fixed | close |
| #60 | Fixed on x86-64 | close after an arm64 -O0 check |
| #57 | Obsolete (the plugin is deleted) | close |
| #47, #50 | Partly fixed | F2 |
| #56 | Open; possible duplicate definition | G (integrity check), F2 |
| #58 | Partly: pointers fixed, return widths and pointee types open | PE, P9 |
| #63 | Partly: 21 of 24 equal; the rest is result width | PE |
| #61 | 85 of 98; tracker kept | P4 (canary), R (unaligned loads), P7 |
| #65 | Slice library and switch prover landed | After the program |

Standing debt
-------------

Carried with a cause, not as a baseline:

- The source-gold baseline lists the pointee `const` qualifier machine code does
  not carry, uncertified pointer parameters, `rotl32`'s signedness and the
  return widths PE removes. It was approximated with gcc 16 and clang ELF
  builds; G re-blesses it on CI's gcc 13.
- The coverage baseline's compiled cells come from CI's clang 17 run of
  `903718c5`, its pinned and system cells from a local run; G replaces the
  compiled cells with pinned bytes.
- Pointer parameters take the width every certified access reads, so `Rec *`
  renders as `uint32_t *`; correct at the machine level, not the source type
  (P9).
- `pdd` on ARM 32-bit is not admitted until the Sleigh tuple is verified.
- Entry condition flags cannot be booleans until the architecture specification
  carries a flag fact.
- `doc/wip/*.patch` are written against the deleted plugin; each is re-derived
  on the current tree or deleted.

Documents
---------

| Document | Status |
|----------|--------|
| `doc/engine-vision.md` | Live: the why. Its sequencing defers to this file |
| `doc/handoff/review-fixes/plan.md`, `plan-extension.md` | Live: per-phase specification; order and status here |
| `doc/adr-access-syntax.md`, `adr-partition-first.md`, `adr-register-identity.md`, `adr-structure-dominator-tree.md`, `adr-floating-point.md` | Live |
| `doc/adr-location-ssa.md` | Superseded by P1 and P4, remainder in F2 (D9, to confirm) |
| `doc/adr-semantic-preservation-kernel.md` | Live in principle; its spine still names the radare2 snapshot and `r2sym`/`r2cert`, which no longer exist — to be rewritten against F and R |
| `doc/architecture-plan.md` | History of the binding-spine rewrite; superseded by R |
| `doc/phase1-plan.md`, `phase1-design.md`, `handoff-engine-inversion.md`, `handoff-location-ssa.md` | Plugin era; to archive |
| `doc/beat-angr-end-to-end.md`, `decbench-plan.md` | Numbers measured through the plugin; kept for method, not for numbers |
| `doc/debugger-build-plan.md` | Proposed; after the program |

Ownership
---------

| Crate | Owns |
|-------|------|
| `r2image` | What the container states: bytes, sections, symbols, relocations, entries, CFI, DWARF |
| `r2abi` | Calling conventions, library prototypes per C library, platform register classes |
| `r2il` | The low tier and its executable semantics (`r2il::eval`) |
| `r2sleigh-lift` | Decoding and lifting through Sleigh |
| `r2ssa` | The medium tier: stable ids, SSA, values, memory, liveness, certificates, refusal evidence |
| `r2source` | Contracts between the layers, and `Confidence` |
| `r2types` | Type inference, layouts, signatures |
| `r2rewrite` | Term rewriting and its rule proofs |
| `r2dec` | The render plan, structuring and printing — no proof of its own after R |
| `r2engine` | Requests, discovery, the query database, summaries, emulation |
| `r2s` | Commands, the verb table, the prompt, and the only implementor of `Program` |
| `r2s-tui` | The visual mode: layout, keys, drawing; no fact about the program |

One fact, one owner. When two places answer the same question, one of them is
deleted.
