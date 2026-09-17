# Phase 1 plan

Design: `doc/phase1-design.md`. Baseline: `bzip2` arm64 -O2, 107 functions,
51 rendered, 3001 casts in 6017 statements, 1360 temporaries; r2r 95 of 97;
corpus 60/60. One commit per step, one-line message. Gates: T = `cargo test`
and clippy `-D warnings` on the crates touched; C = the corpus with
`--gate snapshot`, every changed cell read before `--accept-baseline`;
R = `make -C tests/r2r run`; B = the `bzip2` census and cast count from the
design's measurement scripts. Anything found wrong in radare2 is fixed in
the fork and raised upstream one idea per pull request.

## 1a. Import stubs render as proved forwardings

1. Trace the slot address. The capture's tail-slot advisory carries the
   `adrp` page; the lifted transfer reads page plus the `ldr` displacement.
   Find whether radare2's arm64 analysis sets the `br`'s `op.ptr` to the
   page or the capture drops the displacement; fix at the source. If it is
   radare2, the fix goes upstream. (T, one r2r test against `vuln_test`'s
   stubs.)
2. Correlate the tail slot on the Rust side by the recovered slot storage
   as it already does, and give the stub a call-site certificate with the
   import's prototype where Phase 0 carried one.
3. Generalise `variadic_forwarding_stub` into one route for every import
   stub: the observable-state proof unchanged, the prototype required for a
   declaration, a residual naming the import where there is none. The
   variadic-only condition goes. Render the import's `extern` declaration
   and the comment naming it; mark the function as a declaration in the
   proof line.
4. Coverage: declarations counted as their own category; the census and
   the coverage scripts print bodies, declarations and total. (B: expect 51
   bodies + 43 declarations of 107.)

## 1b. Storage width is the maximum slice endpoint over every read

1. `binding_width` and `seal_width_evidence` take, per member, the maximum
   `offset + width` over: exact use slices; `MemoryAddress` uses (full
   width); call and store operands (full width unless the boundary states
   a narrower carrier); return boundary values; phi-edge conversions; the
   live-out set. A member with any use the projection cannot state keeps
   the carrier width. Address-exposed memory objects keep their layout
   width. The declared type comes from `declaration_type_for_binding` at
   the new width; the definition's write projection into the narrower
   object is `Truncate`, and the journal accounts it as the assignment.
2. Delete the call-result special case from both sites once the corpus and
   r2r show the general rule giving the same `int32_t RAX_1 = strcmp(...)`.
3. Measure: 188 declarations expected to narrow, 400 casts to go. (T, C
   with every changed cell read, R, B.) The differential gate is the
   arbiter: any wrong hash means a read the rule did not see, and the fix
   is to add that read kind, never to widen by default.

## 1c. Conversions decided at typed boundaries

1. Every conversion the lowering emits goes through one site that asks
   `TypedBoundaries`: the operand's produced type, the edge's required type
   after promotion, and the operation's width. `convert_from` in
   `lowering.rs` and `implementation.rs` and the `convert_typed` arms become
   that one site's rules. No behaviour change in this step; the count of
   casts is unchanged and each is now attributable to an edge. (T, C
   unchanged, R unchanged.)
2. Remove a conversion only where the edge proves identity: produced type
   equals required type after promotion, or the conversion is a `void *`
   to or from an object pointer at an assignment, argument or return. Keep
   every operation-width truncation, every sign or zero extension the
   machine made explicit, every shift count and every literal's spelled
   type. Evidence at `Bottom` refuses with the conflict named; `Top` keeps
   the machine type and the conversion.
3. Same-object width projections (a `Subpiece` or `Copy` of a bound value
   read once, at a width the object has) render as the use slice at the
   reader; the 234 copy-or-cast temporaries are the measurement.
4. Delete the implicit-pointer arms from `convert_typed` once 1c.2 proves
   the same cases. (T, C with every changed cell read, R, B: expect the
   1006 expression casts and most of the 1256 remaining name casts to fall;
   whatever remains is listed by edge kind in the handoff.)

## Verification

After 1a: r2r 95 of 97 or better; corpus unchanged; census 51 bodies + 43
declarations. After 1b: corpus and r2r green with changed cells read;
`(uint32_t)X` over a 32-bit object gone. After 1c: cast count per statement
recorded against the 0.50 baseline; `tests/corpus/locked_shapes.sh --gate
shapes-differential` and `--gate cutover` on a clean tree; the growth-curve
script over `bzip2` again, expecting slope at or under 1.10.

## Not Phase 1

Load folding into expressions (Phase 2, with alias, barrier and sequencing
proof). The thirteen refusing bodies, taken one class at a time after 1c.
The `audit` phase's 1.39 slope, re-measured on 100 or more functions before
anything is chased.
