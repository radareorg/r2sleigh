Whole-binary render coverage
============================

The 54-cell matrix in `tests/corpus` scores nine hand-picked functions and
checks that what they render is *correct*. It is a canary, and it deliberately
says nothing about the other question: how much of a binary renders at all.

That question was answered by hand, and the answer was wrong twice. Once by a
factor of six, because ninety of the hundred and thirty-six entries radare2
lists in `/bin/ls` are sixteen-byte import thunks and were counted as functions.
Once by fourteen refusals, because a number measured in an earlier session was
carried forward instead of remeasured, and a change was credited with an
improvement that was partly not there.

So this gate measures it, over the corpus's own sources built at the same six
configurations. Every function radare2 finds is decompiled -- three hundred and
thirteen of them, against the matrix's fifty-four -- and one bit per function is
recorded, with the typed cause when it did not render.

```
tests/coverage/run_coverage.sh                    # measure and gate
tests/coverage/run_coverage.sh --accept-baseline  # record what it measured
```

What the gate fails on
----------------------

A function that rendered in the baseline and now refuses. That is the only hard
failure, and it is the one the matrix cannot catch: a change can leave all
fifty-four cells matching and still stop a hundred other functions rendering.

A function in the baseline that was not swept also fails, so a sweep that
silently stopped covering something cannot pass.

A function that rendered in the baseline and now gaps more of itself fails
too. A marked gap renders -- the rest of the body is still shown -- and is not
proven, and the proof line counts the obligations the gaps account for. A
function whose count rises, or which moves from clean to gapped, has lost part
of its body exactly as a refusal loses all of it: `_crc32_init` once scored
`rendered` with 242 of its 274 obligations gapped. The baseline records the
count for every gapped function; a baseline blessed before gaps were counted
has no such record, and the report refuses to compare against it until it is
re-blessed.

Everything else is reported and does not fail. A function that now renders, a
function that is new, a gap that narrowed, and a refusal whose cause changed
are all printed; the first three ask to be re-blessed. A cause is normalised
before comparison -- counts of refused obligations, addresses, and the line
numbers inside a refusal's site -- because a baseline that churns on those is a
baseline nobody re-blesses honestly. A digit inside a name is kept, so the
`vpmovsxbd_avx2` a refusal names stays distinct from `vpmovsxbd_avx512vl`.

Why the compiler is recorded
----------------------------

The binaries are built here, from checked-in sources, by whatever `clang` is on
the path. A different compiler is a different program, and comparing this
baseline against it would be comparing two different function sets. The baseline
carries the compiler's version string and the gate refuses rather than reports a
difference that is not about the decompiler.
