Caps, budgets and depth limits in `crates/*/src`
================================================

The tracking document for track K and for the W1 Dylint that forbids a
constant-bounded `depth` or `round` loop with no refusal path. Surveyed on
`track/k-caps` (base `d4ebc83d`); line numbers are at that branch's head.

The rule (plan-extension.md, "Invariants for every change"): **no depth or round
cap returns a silent answer.**

- A walk over a finite graph uses a visited set or an SCC memo, O(V+E).
- A fixpoint terminates by lattice height, and the argument is written beside it.
- Only a search whose termination is undecidable may carry a budget, and it
  refuses visibly, with a reason.

Classes used below:

- **(a)** removable: a visited set, a memo, the graph's own well-foundedness or
  the lattice's height already ends the walk, so the constant can go.
- **(b)** a genuine budget or policy bound, which must refuse visibly (and does
  unless the row says otherwise).
- **(c)** silent, with no termination argument available yet: removing the cap
  needs a design, not a deletion.

**When hit** says what the code answers at the cap. *Unsafe* means the answer
claims a fact the cap did not establish; *safe* means it withholds one. An
unsafe row is a miscompile waiting for an input, and goes first.

Fixed by track K (W0)
---------------------

| was | value | bounded | when hit | now | commit (subject) |
|---|---|---|---|---|---|
| r2ssa `semantic/shared.rs:2439` `value_depends_on` | depth 16 | def-chain walk: does the loop condition read this carrier | **unsafe**: "does not depend", so a condition reading the counter on both sides licensed a `for` clause | `dependence_cone`: a complete backward closure with a visited set, taken once per side per loop, O((V+E) log V) | "A loop condition's reads of a carrier are a complete closure" |
| r2types `external.rs:350` `resolve_typedef_aggregate`; `analysis/shared.rs:568` `external_named_aggregate_has_real_layout` | 16 steps, beside a `seen` set | typedef chains | "no aggregate" for a chain longer than 16 | one `ExternalTypeDb::typedef_chain_keys`, ended only by the followed-set: at most `typedefs.len() + 1` steps | "A typedef chain is read to its end" |
| r2engine `lib.rs:1161` `collect_external_struct_fields` | depth 4 | nesting of captured structs | fields five levels down dropped, unnamed | the r2source contract refuses a struct or union that holds itself by value; `external_struct_fields` walks to the end with an explicit stack | "A source type graph in which a struct or union holds itself by value is refused", then "Every scalar of a captured struct is named by its dotted path" |
| r2types `solver.rs:19` (loop ~613) | 64 rounds | the type solver's worklist | partial assignments with `converged = false`, which `evidence.rs` `read_back` never read | the loosening constraint kinds (joins, priority overrides, field rewrites; no producer) are deleted; a class is the left fold of `meet` over its bounds: no rounds, complete when it returns | "The type solve only tightens" |
| r2types `evidence.rs:87` `MAX_REFINEMENT_ROUNDS` | 4 | refinement rounds | stops with the last solve (unreachable: two solves always suffice) | runs until a round asserts nothing new, bounded by the at most 2A assertable pairs for A accesses | "Evidence refinement runs until a round asserts nothing new" |

Remaining, by owning phase
--------------------------

### P1: identity and root walks that `ValueView` replaces (p1-identity track)

Each becomes a view projection or a visited-set walk. Two are unsafe.

| file:line | value | bounds (function) | when hit | class |
|---|---|---|---|---|
| r2types `function_facts/prepared.rs:1431` | depth 8 | `prepared_address_base_offset`: base offset through copies, casts, adds and phis | **unsafe**: a `None` phi input is skipped, so a loop-carried input cut by the cap leaves the offset of the entry input alone: an offset that ignores the loop step | a |
| r2types `function_facts/prepared.rs:1535` | depth 8 | `prepared_address_base_param_slot` | **unsafe**, same skip-at-phi shape | a |
| r2ssa `optimize.rs:893` | `lane_copies.len()` hops | lane-copy chain in `inst_combine` | returns the var it reached (only on a cycle) | a |
| r2ssa `optimize.rs:960` | 16 | copy-root walk in `fuse_compare_chains_in_function` | returns a non-root; chains not fused (safe) | a |
| r2ssa `optimize.rs:987` | 16 | Copy/BoolNot equality walk, same function | `None`: not fused (safe) | a |
| r2ssa `optimize.rs:1383` | 8 hops | `define_through_copies` in `fold_condition_codes` | `None`: flag not folded (safe) | a |
| r2ssa `optimize.rs:1567` | depth 8 | `constant_through_definitions` | `None` (safe). No memo: exponential on a DAG once uncapped, so it needs the view, not just a deletion | a |
| r2ssa `semantic/predicates.rs:424` | depth 16 | `compare_values_equivalent_inner` | "not equivalent" (safe); the `visiting` set already ends cycles | a |
| r2ssa `semantic/certificates/expressions.rs:508` | depth 32 | `value_renderable_modulo_loop_phi` | "not renderable" (safe) | a |
| r2ssa `semantic/certificates/expressions.rs:31` | `values.len()` | `constant_root_through_copies` | `None` (safe); a cycle guard | a |
| r2ssa `semantic/certificates/expressions.rs:79` | `blocks.len()` | arm walk in `collect_two_way_selection_certificates` | partial chain; redundant with `chain.contains` | a |
| r2ssa `interproc/mod.rs:2582` | depth 8 | `classify_memory_access_location_value` | `unknown_location()` (safe) | a |
| r2ssa `function/mod.rs:2349` | `roots.len() + 1` | `canonical_root_in` | logs `canonical-root-cycle` and still returns the node it stopped at | a (P1 deletes the function) |
| r2ssa `liveness.rs:106` | `relocations.len()` | `relocate` in `compute_with_relocations` | returns the current instruction (only on a cycle) | a |
| r2ssa `address.rs:463` | `load_count` | pointee-path length in the `AddressCollector` load transfer | that load gets no pointee expression (safe) | a |
| r2dec `analysis/prepared_semantic/mod.rs:787` | 4 rounds | `populate_owner_exprs` | silent partial | a |
| r2dec `analysis/prepared_semantic/mod.rs:1441` | 4 rounds | `populate_derived_predicates` | silent partial | a |
| r2dec `analysis/prepared_semantic/mod.rs:1548`, `:1568` | depth 8 | `reconstruct_zero_compare_from_def` / `_from_nonzero_def` | `None` | a |
| r2dec `analysis/prepared_semantic/mod.rs:1631`, `:1660` | depth 8 | `predicate_expr_for_operand_with_depth`, `compare_def_expr_for_predicate_operand` | `None`; the caller spells the plain variable | a |
| r2dec `analysis/prepared_semantic/mod.rs:1909` | depth 8 | `authoritative_scalar_expr_for_value` | `None`; falls back to `scalar_owner_expr_for_value` | a |
| r2dec `analysis/prepared_semantic/mod.rs:3279` | depth 8 | `normalize_prepared_inline_expr` | returns the subtree unnormalized | a |
| r2dec `binding_plan/rules.rs:857` | 8 hops | `through_copies` in `escaped_pointee_reach` | the argument is not matched, so the escaped object gets no callee-reach extent | a |
| r2dec `binding_plan/rules.rs:956` | 8 hops | `constant_argument` | `None`: that call site contributes nothing | a |
| r2dec `observation_journal/mod.rs:2499` | depth 8 | `reaches_only_return` | "not a return-only carrier" | a |

### P3: declaration model (p3-decl rewrites `r2image/src/debug.rs`)

| file:line | value | bounds (function) | when hit | class |
|---|---|---|---|---|
| r2image `debug.rs:341` (`SPELLING_DEPTH`), checked at `:350` | 16 | `spell_at`: typedef, pointer, qualifier and array recursion | `None`, and the caller drops the whole declaration | a (memoise by DIE offset) |
| r2image `debug.rs:408` | 16 | `extent` | `size_bytes` is `None` | a |

### P4: memory model (`promote.rs` becomes a consumer of the partition)

| file:line | value | bounds (function) | when hit | class |
|---|---|---|---|---|
| r2ssa `promote.rs:133` | depth 8 | `r2il_constant_before` | `None`; redundant, since `upto` strictly shrinks | a |
| r2ssa `promote.rs:173` | depth 8 | `r2il_leading_zeros_before` | `None`, so `r2il_non_negative_before` is false | a |
| r2ssa `semantic/facts.rs:368` | `objects.len() + 1` | `root_parameter` (pointee chain) | `None`; a cycle guard | a |

### P5: value domain (`optimize.rs` fold rounds become a fixpoint)

| file:line | value | bounds (function) | when hit | class |
|---|---|---|---|---|
| r2ssa `optimize.rs:106`; defaults `:39` (4), `:50` and `function/build.rs:49`, `:258` (1, every production path) | 1 round in production | outer rounds of `optimize_function_with_interface_and_control` (condition-code fold, compare-chain fuse, inst-combine) | stops silently; only `stats.iterations` records it, and the comment at `:102-105` ("run until neither moves") does not hold at 1 | a (lattice-height argument, P5) |
| r2ssa `semantic/shared.rs:443`, seeded with 8 at `:534` | depth 8 | `induction_affine_parts` from `induction_step_for_update` | `None`: no induction step for that carrier (safe). The visited set is rebuilt per level, so uncapped it is exponential on a DAG; it needs a per-value memo | a |

### P8: data objects and strings

| file:line | value | bounds (function) | when hit | class |
|---|---|---|---|---|
| r2engine `names.rs:22` `LITERAL_LIMIT`, read at `native.rs:2402` | 4096 bytes | the string read in `text_at` | no NUL in the window, so "not text"; `program/naming.rs:131` scans whole sections unbounded, so the two disagree on a string over 4 KiB | b (kept; becomes the per-section NUL index in P8) |

### P9: types over the graph (`arrays.rs`, `globals.rs`, `structs.rs`)

| file:line | value | bounds (function) | when hit | class |
|---|---|---|---|---|
| r2types `analysis/globals.rs:158` `offset_bound` (checks `:234`, `:251`, `:271`, `:296`, `:321`, `:362`, `:379`) | ±0x4000 (16 KiB) | global base+offset window | the add is not propagated or the access is not a field: silent | c |
| r2types `analysis/globals.rs:160` | 6 rounds | `infer_global_field_profiles` fixpoint | silent partial `addr_exprs` | a |
| r2types `analysis/structs.rs:740` `offset_bound` (checks `:895`, `:922`, `:941`, `:968`, `:1000`, `:1029`, `:1138`, `:1190`) | ±0x4000 (16 KiB) | local struct offset window in `infer_local_struct_artifacts_from_blocks` | silent drop. It is also the only bound on offset growth in the uncapped `loop` at `:775`, so it cannot simply be deleted | c |
| r2types `analysis/arrays.rs:156` | 6 rounds | `scalar_array_access_certificates_from_ssa` fixpoint | silent partial | a |
| r2types `analysis/arrays.rs:1080` | depth 4 | `phi_source_is_const_stride_pointer_recurrence` | "not a recurrence" | a |
| r2types `analysis/arrays.rs:1273` | depth 8 | `scalar_index_matches_stride` | `false` | a |
| r2types `analysis/arrays.rs:1352` | depth 8 | `scalar_index_affine_factor` | `None` | a |

### Unassigned: the next K items

| file:line | value | bounds (function) | when hit | class |
|---|---|---|---|---|
| r2ssa `semantic/control_domains.rs:94-97`, checked at `:108` | `blocks × (guards + 2)`, at least 8 | the descending worklist in `collect_control_domain_facts` | **unsafe**: blocks still queued are skipped and keep their initial state, the whole guard universe with `complete: true`, which claims guards that do not hold on every path. Nothing is logged. The bound is stated as the lattice height, but a switch arm can widen once per case value, which `guards + 2` does not count, and the initial top holds one arm per case while a normalised state holds one per switch | c until the height is proved; then a |
| r2rewrite `driver.rs:438` (charged at `:302`) | `tree_measure(id)` per root | rule firings in `canonicalize_node` | records a `BudgetFailure` and maps the term to itself, but nothing reads `budget_failures()`, so it is silent in practice. The module states the budget follows from the rule-size proof, so a failure is a bug to surface | a (the proof) plus a reader for the failure (P10) |

### Derived bounds that already refuse (keep as backstops)

These are lattice heights computed from the data, and exceeding one produces a
typed refusal. They meet the rule; the W1 lint should accept them.

| file:line | value | bounds (function) | when hit |
|---|---|---|---|
| r2ssa `interproc/mod.rs:1121` (bound built at `:1828-1867`) | `scc.len() × fact universe + 1`, at least 2 | SCC fixpoint in `solve_interproc_summary_set_from_locals` | `interproc-summary-cap` evidence, `converged = false`, `Err(NonConverged)` on the prepared path, and a downgrade warning in r2types `analysis/mod.rs:951` |
| r2ssa `interproc/mod.rs:2808`, loop `:2842` | `blocks × (2 × carriers + 2) + 1` | `collect_call_arg_state_with_iteration_limit` | `converged = false`, then `Err(NonConverged)` from `require_converged_call_carriers` |
| r2ssa `slice.rs:188` | `graph.insts.len()` | `backward_slice` | appends "instruction-budget-exhausted"; unreachable beside the `discovered` set (H makes `slice.rs` the one slicer) |
| r2dec `fold/op_lower/lowering.rs:590` | arena length | `materialize_machine_expr` | `Err(InvalidPlannedInline)`: a DAG is no deeper than its arena |
| r2dec `fold/op_lower/lowering.rs:793` | arena length | `materialize_term` | `Err(InvalidPlannedInline)` |

### Genuine budgets and size policies (class b)

| file:line | value | bounds | when hit |
|---|---|---|---|
| r2il `eval.rs:242` (field `:96`) | set by the caller; only `r2engine/tests/oracle.rs:71` sets one (`1 << 14`) | concrete emulation, per operation and per string element | `Err(Stop::Exhausted)`. Whether a run halts is undecidable, so this is the model budget (track E) |
| core-lift branch, `internal_control/unroll.rs` (not merged here) | 16384 steps | unrolling instruction-local P-code loops decided by constants | refuses when exceeded |
| r2engine `route.rs:366`, `:373`, `:380` | loops > 8 or back edges > 16; other block/switch thresholds | `cfg_guard_reason_from_summary`: forces the bounded type plan | a typed refusal from `type_function_checked` (`lib.rs:2374-2381`) unless the `:406` exemption applies |
| r2engine `route.rs:394-398`, `:406` | blocks ≥ 200, or ≥ 96 with loops, back edges or a switch ≥ 32; exemption at ≤ 96 blocks | `type_cfg_prefers_bounded_plan`, `type_cfg_allows_semantic_plan` | same refusal |
| r2engine `route.rs:262`, `lib.rs:2071`, `lib.rs:3622` | blocks > 4 or ops > 96; `max_iters ≤ 1`; a caller's limit | `should_guard_program_orchestrator_decompile`, `type_analysis_interproc_prefers_bounded_plan`, `block_guard_fallback_comment` | no caller in the workspace: dead, for H to delete |
| r2sleigh-lift `esil.rs:626` (`MAX_FORWARDED_TOKENS`), `:683` | 4096 bytes of ESIL text | expression forwarding in `op_esil_with` | falls back to reading the register (same value); for unique storage the operation is dropped and the ESIL is marked partial (`:1159-1185`). An output-size policy, not an analysis cap |
| engine and SSA deadlines (`r2engine/src/lib.rs:681`, `r2ssa/src/control.rs:146`) | supplied by the caller, no default | request wall clock | a typed error |

Checked and excluded
--------------------

- `semantic/shared.rs:723` `chain.len() > 12`: the length of a diagnostic message.
- `trips.rs:659` `NEWTON_ROUNDS = 5`: exact modular inverse (Newton doubles the correct bits each round; five rounds cover 64).
- `naming.rs:7`, `function/mod.rs:3635`: a 64-entry cache cleared when full; no analysis answer depends on it.
- `body.rs:33` `WINDOW`, `DECODE_WINDOW` (`program/naming.rs:18`, `query/decode.rs:14`, cli `main.rs:685`), `MIN_BYTES`: instruction length and decode padding.
- Bit widths (`MAX_WIDTH_BITS`, `MAX_LITERAL_BITS`, `MAX_SPELLABLE_CONSTANT_BITS`, `MAX_TERM_WIDTH_BITS`), `SOURCE_REGISTER_NAME_MAX` (an array size), `context.rs:939` `max_register_params` (ABI arity).
- `.take(N)` in evidence strings, `eprintln!`, the cli listing and r2s output formats: display truncation.
- `r2engine/src/isolation.rs:66` `DEPTH`: a nesting counter.
- `canon.rs:142`: a guard that a rewrite does not grow the term.
- `values.rs` (widening only at back-edge phis), `strided.rs`, `deadphi.rs`, `indirect.rs`, `discovery.rs`, the rest of `native.rs`, `internal_control.rs` on this branch, and the r2dec structuring retry (`lib.rs:3744`), seed-gap loop (`lib.rs:3137`) and binding-plan rounds (`rules.rs:1391`): no numeric cap.

For the W1 Dylint
-----------------

Flag a loop or recursion whose bound is a literal or a named constant (`for _ in
0..N`, `depth > N`, `depth >= N`, `hops > N`, `rounds < N`) when the path taken
at the bound returns an ordinary value (`None`, `false`, a partial collection,
the current node) rather than a typed refusal (`Err`, a refusal enum, a
`refusal_evidence!` together with a refusal result). Accept a bound computed
from the data (`graph.values.len()`, `arena.len()`, a stated lattice height)
only when hitting it yields a typed refusal: the "derived bounds" table above.
Every class (b) row is an allowlist entry with its reason; every other row
above is a finding to burn down.
