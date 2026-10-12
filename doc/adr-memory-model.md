# ADR: memory is a linear budget

Status: proposed (2026-10-12). Amends PF3 (capacities in bytes) and D26 (the
allocator), and gives F2.5 and LX their per-operation target.

## Model

A request's peak resident memory is four terms:

```
M = F + R + P(f) + A
```

- `F`, fixed: the opened image, its symbol and name tables, and the Sleigh
  specifications. Paid once per process.
- `R`, retained: what the query database holds between requests (analyses,
  sealings, walks, renderings, callee reads).
- `P(f)`, the function's own peak: every representation of `f` live at the
  worst moment of its analysis and rendering.
- `A`, the allocator's retained pages: freed memory mimalloc has not returned.

Linear means `P(f) ≤ c · n(f)` with `n` the function's SSA operations and `c`
a stated constant, `R ≤` a stated byte budget, and no term that grows with a
product of two sizes. A function past the budget refuses with a typed reason
(AGENTS.md, bounded search); it never takes the machine down.

## Measured (2026-10-12, release `pdd`, macOS)

| Term | Measurement |
|---|---|
| `F` | 68 MB (0pack) to 90 MB (pumasim): a 5-byte function's whole RSS |
| `P(f)` growth | over 148 functions in six binaries (pumasim, 0pack, ts3server, vim, libstdc++, dwarf_rust_bubble), `RSS − F` grows as size^0.71 and time as size^0.67: no real function is superlinear |
| `c` | about 2.1 KB of heap per SSA operation at the top (pumasim `0x23fdf0`: 194.7 MB heap peak, 92,007 operations) |
| `F` and `c`, 2026-10-13 (#188) | `F`: 38.0 MB heap and 93.4 MB RSS (pumasim's 6-byte stub `0x1c3030`); pumasim `0x23fdf0`: 136.3 MB heap, so `c = (136.3 − 38.0) MB / 92,007` = 1.07 KB per operation. The cuts sized and left (the type interned 2.3 MiB, value geometries 3.4, obligation identities about 3, native spans 1.7) reach about 950 B: the 600 B exit is F2.5's single numbering (`GraphInst` and `GraphValue` are 64 bytes each, 12 MiB on 0pack) |
| largest real function | ts3server `fcn.004430b0`, 107 KB of code: 598 MB, 2.3 s |
| `R`, one session | 25 to 97 medium pumasim functions plateau at 445 to 484 MB; 50 functions including the largest reach 869 MB (heap 778.5 MB: render facts 52, liveness 48, graphs 48, value tables 43, ledgers 37, obligations 46) |
| program survey | `afl` on pumasim: 1.3 s and 156 MB, once per session; a 100-byte function whose indirect call asks the call graph's returns pays all of it (`init_fpri`) |
| `A` | 56 MB on the pumasim Gui constructor at the default purge delay (contabo, 2026-10-11) |

Every function over 1 GB in the sweep was the walk decoding a debug file's
zero fill as code (libc-2.26-debug.so: `_IO_vfscanf` 1.2 GB,
`__rpc_thread_destroy` 4.7 GB); the walk now stops at the file's last byte
(`UnresolvedReason::Unbacked`).

## Where `c` goes

At the Gui constructor's peak about ten representations of one function are
live together: the lift, the function's operations and value table, the graph
(instructions, values, uses), liveness, the obligation inventory, the semantic
facts and certificates, the type facts, the render facts, the machine
projection, the term arena, codegen's tokens and the ledger. Each is linear;
together they cost about 2 KB per operation, because every phase's output
stays alive until the response is built.

## Decisions

1. **Phases consume what only they read.** A representation whose last reader
   is the next phase is moved into it and dropped there (the machine
   projection into the term import, the term arena into codegen, tokens into
   text). The peak becomes the largest phase, not the sum of all. Target
   `c ≤ 600 B` per operation, then `c ≤ 300 B` with F2's single numbering
   (one variable table, the graph indexing the function's operations).
2. **Holding is no substitute for an algorithm.** The value of holding an
   answer is its recompute cost over its bytes: a whole analysis costs about
   8 ns per byte to compute again (pumasim's Gui constructor, 1.6 s for
   195 MB), a callee's summary microseconds per byte. A query is held only
   where it is a program-wide fact computed once (callee summaries, names,
   returns, the survey: `Retention::Held`, O(program) in all); a function's
   walk, analysis, sealing and rendering are held only while they are the
   newest (`Retention::Newest`), and asked again they are computed again,
   whose cost is the algorithm's to lower. Then `R` is the last function's
   answers, whatever the session's length.
3. **The allocator returns phase garbage at phase boundaries**: one forced
   collect after the analysis and after the render, measured on the four
   large functions, before any change of purge delay (D26).
4. **Superlinear shapes are replaced when a function shows one.** The audit
   (2026-10-12) found structures bounded by a product: memory SSA's per-block
   location maps `O(B·L)`, control-domain guard sets `O(B·D)`, per-call
   memory facts `O(C·F)`, per-block assumption and call-result maps cloned
   down the dominator tree, and phi placement before pruning. None dominated
   a measured peak. Each has a linear replacement: one memory chain with
   phis at the iterated frontier of all definitions and a memoised clobber
   walk (LLVM's MemorySSA); dominator pre/post intervals for guard
   membership; a scoped table with an undo log along the dominator walk;
   interned location sets for call effects; pruned SSA placed from liveness.
5. **A budget refuses.** A function whose operations exceed the budget's
   share refuses before its analysis with the count and the budget.

## Done (2026-10-12, stack #165)

| PR | Change | Measured |
|---|---|---|
| #166 | The walk stops at the file's last byte | the over-1 GB functions refuse in 0.44 s |
| #168 | A held rendering keeps text, ledger and premises | 50-function session 935 to 645 MB |
| #169 | Per-function answers held only while newest | session 441 to 385 MB, time unchanged |
| #170 | A prepared function keeps its walk's outline | heap peak 194.7 to 193.0 MB |
| #171 | Facts nothing reads are not kept | heap peak 193.0 to 183.6 MB, 471 lines deleted |
| #172 | Each obligation held once, columns by place | heap peak 183.4 to 180.6 MB |
| #173 | A value's definition, inputs and width are the graph's alone | heap peak 180.6 to 173.8 MB; the peak moves from render to preparation |
| #174 | The inventory's seeds a bit per whole-instruction kind; one backward pass taints the incomplete returns | heap peak 173.8 to 172.2 MB (the render phase's again), 0pack 199.5 to 189.4 MB; peak RSS 0pack 334 to 298 MB |
| #175 | The term arena interns its types (a node 56 to 32 bytes), its side tables dense and shrunk once canonical; root steps as runs; the unread `reads` lists and producer ids deleted | heap peak 172.2 to 166.7 MB (now the type seal's), 0pack 189.4 to 177.6 MB; pumasim 3% faster |
| #176 | The array inference borrows its operations; the inventory's table sized from its seeds and sorted in place; the import's roots recorded as runs as each completes | heap peak 166.7 to 158.6 MB; peak RSS 4 to 7% lower |
| #177 | The timing gate reports and holds each case's heap peak (1.05x) and times a 50-function session | gate |
| #178 | `dense::HashIndex`, slots of row ids and hash bits, owns the value table's and the graph's variable-to-id lookups | heap 1.2 to 2.4% lower, time unchanged |
| #183 | The seal drops the function's operations; the graph holds each once | heap peak 0pack 167.3 to 162.4 MB, pumasim 147.6 to 143.8 |
| #185 | The machine projection holds one root per instruction; an entity's output and producer are read from the graph and the obligations | heap peak 0pack 162.4 to 159.2 MB, pumasim 143.8 to 141.1 |
| #186 | The seal drops the value table and the operation origins; the reaching scan groups by the graph's instruction column | heap peak 0pack 159.1 to 158.3 MB, session 187.5 to 179.6 |
| #187 | A written-lane record of data throughout is its size; the pass keeps one copy | heap peak 0pack 158.3 to 148.2 MB, pumasim 139.9 to 133.1, session 179.6 to 168.5 |
| #188 | A graph instruction's disposition is its state and its run of the table; its identity is the graph's | heap peak 0pack 148.2 to 144.2 MB, pumasim 133.1 to 130.0, session 168.5 to 163.4 |
| #189 | The image maps its file rather than copying it into the heap | heap peak pumasim `afl` 95.4 to 86.4 MB, 0pack `afl` 57.5 to 50.0, session 163.4 to 154.3 |
| #191 | A relocation boxes its symbol; a symbol's name is one string shared by the name table and its seeks | `F` (pumasim's stub) 28.46 to 25.00 MB of heap |

## Left

The phases now peak within a few MB of each other, so a cut in one moves
the peak. 0pack's (177.6 MB) is render's: one numbering (MM.6, the
function, table and graph), the machine projection and render structures
(MM.8), compact identities (MM.7). Then the fixed cost (MM.4, 29.8 MB) and
the allocator's collect (MM.9). The facts only sealing reads (MM.3) are
5.3 MB of memory SSA at the render peak, and dropping them needs the
analysis and its sealing as one query: conditional. The ROADMAP (step 8.9)
orders them.

## Gates

- The heap peak, beside time, RSS and the allocation count: r2s's
  `alloc-count` build feeds r2il's counters and reports its peak live bytes
  (`r2s: heap peak`, equal to dhat's to 0.01%), and `census.py time` fails a
  case whose head exceeds 1.05x its base (`--heap-budget`, CI).
- Session retention: `census.py time` times one session over pumasim's 50
  functions (its largest and a sample down to its smallest) under the same
  RSS, heap and time budgets.
- The sweep that found the zero fill: every function over 512 MB in the
  measured binaries is named and judged.

## Cost

Each decision is linear: moving a phase's input is O(1); GreedyDual-Size is
O(log k) per access over `k` held entries; a forced collect is one walk of
the allocator's segments; the replacements in 4 are each O(n) or O(n log n).
