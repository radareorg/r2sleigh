r2dec: the high tier
====================

`crates/r2dec` renders a prepared SSA artifact as C. It is a certifying
renderer: executable C is printed only where canonical facts justify it, and
everything else is a visible residual or a refusal. `r2s` runs it as `pdd`
(`pddj` for JSON) and prints its tree with `pdih`. The direction of the crate
is [adr-renderer-printer.md](adr-renderer-printer.md): r2dec reads only sealed
facts and owns no policy.

Input and route
---------------

`r2engine` builds the request: it prepares a `TrustedSsaArtifact`
([ssa.md](ssa.md)), derives type facts ([types.md](types.md)), selects a
`r2types::DecompileRouteKind` and seals it into `SourceOwnedFunctionFacts`,
which retains the exact `Arc<SsaArtifact>`. `r2dec::DecompilerInput::new`
takes that seal and nothing else.

| Route | Output |
|-------|--------|
| `Standard` | the native render below |
| `StructuredWorker`, `SummaryIslands`, `LinearWorker`, `VmSummary` | summary comment only, never executable C |
| `FallbackComment` | `/* r2sleigh refused <fn>: <reason> */` |

Pipeline
--------

The native render runs these stages in order (names as `R2SLEIGH_TIMING`
reports them):

| Stage | Module | Job |
|-------|--------|-----|
| binding plan | `binding_plan/` | project SSA identities into C bindings: which values are variables, which inline, which share an object; use and write geometry come from `r2ssa`'s `MachineProjection` |
| fold | `fold/`, `fold/op_lower/` | lower SSA operations to C expressions; calls, memory, subscripts and wide values each have a renderer; a call site is evaluated once (`single_evaluation.rs`) |
| structure | `structure/` | dominator-tree placement ([adr-structure-dominator-tree.md](adr-structure-dominator-tree.md)) |
| normalize | `normalize.rs` | operation, origin, certificate and liveness passes over the tree |
| seal | `structured_region.rs`, `placement/` | fix lexical regions, then place declarations by reaching definitions |
| effect ledger | `effect_ledger.rs`, `ledger.rs` | account for every source obligation |
| codegen | `codegen.rs` | print the AST (`ast.rs`) with the prelude |

A lowering refusal or a proof failure that names a cell is planned as a gap,
and a rendered read that does not see its value splits that value out of its
shared variable; the render then runs again. Each attempt adds an anchor or a
split no earlier one did, so the loop ends on a finite set.

Structuring
-----------

Placement is total for any CFG: every block is written once, in the region of
its immediate dominator or in the exit list of the outermost loop it leaves,
and every edge once, as adjacency, an `if` or `switch` arm, `continue` or
`goto` (`place.rs`). Rewrites in `shape.rs` and `rewrite.rs` then turn jumps
into `break`, loops and cleaner shapes, carrying no proof of their own.

The proof is the **control certificate** (`certify.rs`): the rendered body is
read back by a small interpreter of C control into a graph over block
occurrences, and that graph must equal the function's CFG, with every block
present, every exit as its terminator says, and every test the block's own. A
loop or switch is therefore never invented; it is only a spelling of edges the
CFG has.

Output authority
----------------

| Owner | Contributes |
|-------|-------------|
| `r2ssa` | certificates (`PreparedFunctionCertificates`: loop, switch, if-region, expression, memory access, stack slot, call site, return value) and the obligation inventory |
| `r2types` | signatures, layouts and type facts, with refusals |
| `r2engine` | the route, budgets and refusal policy |
| `r2dec` | rendering from those facts only |

- **Names.** `symbol.rs` types every identifier as declared or external;
  `unrendered.rs` reports any name that resolves to nothing (a Sleigh
  temporary, a raw register, a frame slot) instead of letting it pass as a
  variable.
- **Residuals.** A value the render cannot prove is a call to an
  `r2sleigh_residual_<type>(n)` helper. Flags, bit reinterpretation and other
  operations C lacks are `static inline` helpers from `prelude.rs`, defined
  above the function, so the output compiles with only `<stdint.h>`. Carriers
  wider than 128 bits are `struct r2sleigh_bits_N` (`bitvector.rs`).
- **The proof note.** Every rendering carries a `/* r2dec proof: ... */`
  comment stating how many constructs are marked, and the ledger: of the
  source obligations, how many were rendered, elided, refused or left
  residual. Silence would claim everything was shown right, which nothing
  here proves.

Rules
-----

1. Never invent case values, locals, stack slots, call arguments, signatures
   or struct fields.
2. Names are weak hints and never grant authority to print C.
3. Cache hits and budget caps never justify semantics.
4. Downstream cleanup that hides a missing upstream fact is a correctness bug;
   fix the owner (see AGENTS.md).

`R2DEC_TRACE_REFUSAL=1` prints the operands of every refusing predicate
([testing.md](testing.md)).
