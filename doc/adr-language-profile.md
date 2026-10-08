# ADR: the source language is a profile

Status: proposed (ROADMAP LP, decision D21, 2026-10-07)

## Why

The engine below r2dec reads what the machine does, and that is the same for
gcc, clang, rustc and the Go compiler: Sleigh lifting, SSA, values, liveness,
the frame model's escape analysis and the query database carry no language.
Four places assume C, and each fails on a Rust, Go or C++ binary:

| Assumption | Where | What fails |
|---|---|---|
| One platform calling convention per binary | `r2abi` rows; `calling_convention` in r2ssa, r2engine, r2types | Go's internal convention (ABIInternal, Go 1.17 and later) passes integers in RAX, RBX, RCX, RDI, RSI, R8 to R11 on x86-64 and X0 to X15 on arm64, and returns several values. Rust passes a slice or `&str` as two registers and returns small aggregates in two. |
| `Premise::UbFreeSource` stated as C's undefined behaviour | r2ssa (stack protector, frame reach), r2engine, r2dec | Go and Rust guarantee more (memory safety), and insert their own checks: Go's stack-growth prologue (`morestack`), Rust's bounds, overflow and unwrap checks, each ending in a call that does not return. |
| Library models are libc's | r2abi (prototypes, `stack_guard`), r2ssa (`printf` formats) | Go's runtime (`runtime.newobject`, `runtime.growslice`, `runtime.panicIndex`) and Rust's `core` (`panic_bounds_check`, `alloc::alloc`) look like unknown calls. |
| C is the only type system and output | r2dec (`CType`, 29 files) | Fat pointers, tuples, multiple returns, enums with data and closures have no C spelling. Names are not demangled (Rust legacy and v0, C++ Itanium, Go). |

Each is a single seam, so it is cheaper to make them a profile now than to
retrofit a language later: D (doc/adr-decompiler-rewrite.md) is about to define
the render input, and the frame model's premise wording is fresh.

## Decision

A **language profile** says, per function, what its source language states
that the machine code does not. The language is a fact the container states,
read by r2image, never a guess from a symbol name (rule 6):

- Go: the `.go.buildinfo` section and `runtime.buildVersion`, the `pclntab`
  (which also names every function and its argument size);
- Rust: `.comment`'s `rustc` version, `DW_AT_language` (Rust), the v0 or legacy
  mangling scheme as a container fact of the symbol table;
- C++: `DW_AT_language`, Itanium mangling, `.gcc_except_table`;
- C: `DW_AT_language`, or no other statement (the default profile).

A binary may hold several (cgo, Rust calling C, C++ with C): the profile is
per function, from the compile unit that contains it, then the binary's.

The profile, owned by r2abi (the cited rows) and selected by r2engine, states:

1. **Conventions.** Which convention each function uses: the platform C ABI,
   Go's ABIInternal (a cited r2abi row per architecture), and Rust's scalar
   pairs (a `(ptr, len)` argument in two registers, a two-word result in two).
   A boundary carries several results natively, and an argument or a result
   may span two registers as one value.
2. **Premises.** What the language guarantees, as `Premise` values the
   consumer accepts or refuses: `UbFreeSource` for C and C++, `MemorySafe`
   for safe Rust and Go (a callee reaches the frame only through what it is
   handed, which is the frame model's escape rule already). The frame ADR's
   C wording becomes "under the profile's premise".
3. **Compiler-inserted checks.** The canary decision generalises: a check the
   compiler inserts and whose failing edge reaches a call that does not
   return is stated per profile (C's stack protector, Go's `morestack`
   prologue, Rust's bounds and overflow checks). It is decided in r2ssa,
   recorded as compiler-inserted, and counted in the proof's column, exactly
   as the canary is.
4. **Runtime models.** Library and runtime functions per language, in r2abi:
   libc for C, Go's runtime, Rust's `core` and `alloc`, the C++ ABI
   (`__cxa_throw`, operator `new`). A model names a callee's effect and
   whether it returns; it never names semantics a body would have to prove.
5. **Names.** A demangler per scheme, in r2engine's naming, producing a
   display name. A name stays a hint.
6. **Rendering.** The spelling of the language-neutral render tree.

## What stays neutral

The IR, the facts and the proof never name a language. A call boundary has
slots and values; a frame object has an extent; a premise is a value the
consumer accepts. r2dec's D0 contract takes the profile beside the sealed
facts, and D's render tree is language-neutral (tuples, multiple returns,
spans of two registers, an aggregate result). The C printer is the first
printer and spells those as structs and out-parameters; a Rust or Go printer
can follow without touching the analysis.

## How it lands

| Step | Exit |
|---|---|
| LP0 | r2image states each function's language from the container; `i` and `pddj` show it |
| LP1 | conventions per function: Go ABIInternal rows (x86-64, arm64); boundaries with several results and two-register values |
| LP2 | premises and compiler-inserted checks per profile; the frame ADR restated against the profile's premise |
| LP3 | runtime models for Go, Rust and C++; demangling |
| LP4 | equivalence corpora in Rust, Go and C++ on x86-64 and aarch64: Rust `extern "C"` functions are called directly, Go functions through a trampoline into ABIInternal |

LP0 and LP1 come before D: D0's input contract carries the profile, and a
boundary with several results is a render-tree node D2 must place.

## Consequences

- C binaries render as today: the C profile is the default, and every C
  assumption becomes that profile's row rather than code.
- A Go or Rust function whose convention the profile does not state refuses
  with that reason; it is never rendered under the C convention.
- Equivalence measures each language on its own corpus, so a gain on C cannot
  hide a loss on Go.
