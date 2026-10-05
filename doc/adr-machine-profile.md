# ADR: one machine profile

Status: in progress (ROADMAP M, before P4; decision D15)

## Decision

There is one typed `LanguageProfile` per (language, compiler). It is derived
from the trusted Sleigh bundle that `sleigh-config` embeds, owned by
r2sleigh-lift (`crates/r2sleigh-lift/src/profile.rs`), and it is the only
source below the lifter of what an architecture is. No crate below the lifter
matches an architecture name or a register name.

- **Fields, each read from the file that states it:**
  - `.cspec`: the stack pointer and its growth, the return address (a register
    or a stack slot), the pointer size, and the prototypes (input and output
    entries in order, with storage, class and extension; `killedbycall`;
    `unaffected`), plus `global` storage.
  - `.pspec`: the program counter and the registers tracked at entry.
  - `.sla`: the register file, where every lane is a projection of the
    register that holds it.
  - `.ldefs`: the language id and the compiler specification for each
    compiler.
  - `.dwarf`: DWARF register numbers, with the stack pointer marked.
- **Selection.** The container's (machine, bits, endianness) maps to a
  language id through the `.ldefs` external names, and the compiler is chosen
  by platform (`windows` for PE, otherwise `default`/`gcc`). The trusted set
  stays an allowlist of language ids, not a match arm per architecture.
- **Not in the bundle, and not guessed:**
  - the frame pointer is a fact about the body (a stack-pointer-derived
    address copied into a preserved register), proved in r2ssa;
  - the syscall register and library prototypes stay radare2's data in
    r2abi, keyed by language rather than by name;
  - the convention's name, red zone, variadic-tail placement, the direction
    flag across a call and platform-reserved registers are r2abi's cited ABI
    rows, keyed by (architecture, width, platform);
  - `killedbycall` is what a call certainly destroys, not the caller-saved
    set. The call effect is exhaustive (every register neither preserved nor
    reserved may change), so nothing relies on an enumerated clobber list;
  - whether a narrow write zeroes the rest is r2ssa's structural fact
    (`Written::is_conventional_extension`).
- **Consumers.** `SourceMachineRoles`, `SourceConventionSlots` and
  `SourceCallEffect` are built from the profile in `r2engine::native`. r2ssa,
  r2types and r2dec read those or the profile.
- **Where the sdb and the `.cspec` disagree,** the difference is listed and
  judged, and the bundle is the authority. Each step leaves the census
  byte-identical or names every line that moved.

## Done

- M0 (80b8e559): `LanguageProfile` parses the whole `.cspec`; r2abi's `CompilerSpec` is deleted.
- M1a (36f1d7b2): argument and result slots from the default prototype; a PE runs under the Windows `.cspec`.
- M1b (797e11f2): call effects from the prototype; callees are asked about the whole call universe.
- M1c (5a205ad2): convention name, red zone and variadic tail from r2abi's cited ABI rows by platform.
- M1d: float slots are the prototype's float entries (lanes such as `XMM0_Qa`), matched against the program root that holds them (B3, doc/adr-byte-relation.md); r2abi `Conventions` and its sdb files are deleted.
- M0 rest: `.pspec` tracked values, `.dwarf` numbers (M5) and `.ldefs` selection: a machine names one language id, and its sla, pspec, compiler specs and DWARF file are read from that `<language>` entry. AppleSilicon names no Windows compiler, so an arm64 PE runs under the default cspec.

## Left

- M2: r2ssa reads roles and slots only. Exit: `abi.rs` alias tables,
  `MachineArchitectureFamily::from_arch_spec`, `call_argument_register_defs`/
  `return_read_register_defs` by name, `call_moves_stack_pointer` by family
  and the direction-flag class check deleted.
- M3: r2types reads the profile through the facts. Exit: `prepare.rs` alias
  and frame tables, `arrays.rs` prefixes, `signature_infer`'s convention
  inference by name and the `assumptions.rs` lists deleted.
- M4: r2dec spells from the profile's register file. Exit: the label list,
  per-architecture `sp`/`fp`/argument/result names and the x86-64 default
  deleted.
- M5: r2image and r2engine. Exit: the DWARF tables, `map_architecture`'s
  RISC-V refusal, family-to-bits and back, and the program counter by name
  deleted.
- M6: RISC-V 64 end to end from its `.ldefs` and `riscv64-fp.cspec`. Exit: it
  renders with no arm added in r2ssa, r2types or r2dec.

## Consequences

- Name-matching sites to remove (survey of 2026-10-05): r2ssa 10, r2types 9,
  r2dec 8, r2engine 13, r2abi 6, r2image 6, r2source 2.
- A new architecture is a language id added to the trusted list, with its
  bundle, and nothing else.
