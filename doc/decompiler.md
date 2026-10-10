r2dec: the high tier
====================

`crates/r2dec` renders a prepared SSA artifact as C. It is a certifying
renderer: executable C is printed only where canonical facts justify it, and
everything else is a visible residual or a refusal. `r2s` runs it as `pdd`
(`pddj` for JSON). The direction of the crate
is [adr-renderer-printer.md](adr-renderer-printer.md): r2dec reads only sealed
facts and owns no policy.

Input and route
---------------

`r2engine` builds the request: it prepares a `TrustedSsaArtifact`
([ssa.md](ssa.md)), derives type facts ([types.md](types.md)), selects a
`r2types::DecompileRouteKind` and seals it into `SourceOwnedFunctionFacts`,
which retains the exact `Arc<SsaArtifact>`. `r2dec::render::RenderInput::new`
borrows that seal and nothing else.

| Route | Output |
|-------|--------|
| `Standard` | the native render below |
| `StructuredWorker`, `SummaryIslands`, `LinearWorker`, `VmSummary` | summary comment only, never executable C |
| `FallbackComment` | `/* r2sleigh refused <fn>: <reason> */` |

Pipeline
--------

`render::render` runs one pass per stage over the sealed facts
([adr-decompiler-rewrite.md](adr-decompiler-rewrite.md)), with no retry:

| Stage | Module | Job |
|-------|--------|-----|
| control | `render/control.rs`, `structure/place.rs` | write every block once by the dominator-tree placement ([adr-structure-dominator-tree.md](adr-structure-dominator-tree.md)); an unresolved test or dispatch is a marked gap |
| values | `render/values.rs`, `render/calls.rs`, `render/frame.rs` | statements from the obligation inventory, one inline-or-bind rule, calls from their callsite certificates, the frame as one array |
| terms | `render/terms.rs` | operations spelled as C at their width, helpers from `prelude.rs` where C has none |
| shape | `structure/shape.rs` | jumps to the next position become fallthrough, `break` or a copied tail |
| certificate | `structure/certify.rs` | read the text back as control and check it against the CFG |
| ledger | `ledger.rs`, `render/proof.rs` | account for every source obligation on the proof line |
| codegen | `codegen.rs` | print the AST (`ast.rs`) with the prelude |

Structuring
-----------

Placement is total for any CFG: every block is written once, in the region of
its immediate dominator or in the exit list of the outermost loop it leaves,
and every edge once, as adjacency, an `if` or `switch` arm, `continue` or
`goto` (`place.rs`). Rewrites in `shape.rs` then turn jumps into fallthrough,
`break` and copied tails, carrying no proof of their own.

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

- **Names.** `symbol.rs` types every identifier as declared or external; a
  value with no spelling is a residual, never a raw register or Sleigh
  temporary passed off as a variable.
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
