# ADR: one machine profile

Status: proposed (ROADMAP M, before P4; decision D15)

## Context

What an architecture is -- its registers and their lanes, its stack
pointer and return address, its calling conventions, what a call kills and
what it preserves, its pointer size, its thread pointer -- is decided in
about sixty places below the lifter, by matching an architecture's name or
a register's name. A survey of 2026-10-05 found them in every crate:

| Crate | Sites | What they decide |
|---|---|---|
| r2ssa | 10 | register alias tables (`abi.rs`), the family by name (`MachineArchitectureFamily::from_arch_spec`), call argument and return reads by register name, whether a call moves the stack pointer, the direction flag |
| r2types | 9 | argument alias tables, stack and frame bases, x86-only convention inference, SysV/AAPCS64 argument lists |
| r2dec | 8 | a register label list, `sp`/`fp`/argument/result names per architecture, parameter ranking by name |
| r2engine | 13 | the program counter by name, family to pointer size and back, the assembled machine by name |
| r2abi | 6 | conventions from radare2's sdb keyed by (family, bits), DWARF register numbers, platform registers, the syscall register |
| r2image | 6 | DWARF stack pointer per architecture, ARM by name, the architecture map that refuses RISC-V |
| r2source | 2 | convention spellings |

Two owners answer the same question in places: a call's arguments and what
it preserves come from radare2's sdb (r2abi `Conventions`), while the stack
pointer, the return address and the stack arguments come from the Ghidra
compiler specification (`CompilerSpec`). RISC-V cannot reach the trusted
path at all: no embedded machine, no arm in the lifter's tuple gate, and
r2image refuses it.

The Sleigh bundle the lifter already embeds (`sleigh-config`) states all of
it, per language:

- `.ldefs`: the language id (processor, endianness, size, variant), the
  compiler specification per compiler (`gcc`, `windows`, `default`,
  `swift`, `golang`) and the DWARF register mapping file;
- `.sla`: the register file, with every register's offset and size, so
  every lane is a projection of the register holding it;
- `.pspec`: the program counter and the registers tracked at entry (x86's
  `DF=0`);
- `.cspec`: the stack pointer and its growth, the return address (a
  register, or a stack slot), the pointer size, the prototypes -- input
  and output entries with their storage and extension, `killedbycall`,
  `unaffected` -- and `global` storage (MXCSR; RISC-V's `gp`, `tp`);
- `.dwarf`: DWARF register numbers, with the stack pointer marked.

## Decision

**One typed `MachineProfile` per (language, compiler), derived from the
trusted bundle, owned by r2sleigh-lift, and the only source below it of
what an architecture is.**

- **Fields**, each from the file that states it:
  - registers: name, storage, the containing register (the lane relation);
  - program counter, tracked entry values (`.pspec`);
  - stack pointer and growth, return address (register or stack slot),
    pointer size, endianness;
  - conventions: each prototype's argument and result entries in order
    (integer and float), stack argument placement, `killedbycall`,
    `unaffected`, `global`;
  - DWARF register numbers and the DWARF stack pointer (`.dwarf`).
- **Selection** is by the container's (machine, bits, endianness) mapped to
  a language id through the `.ldefs` external names (`gnu`), and the
  compiler by the container's platform (`windows` for PE, `default`/`gcc`
  otherwise). The trusted set stays an allowlist -- a language is trusted
  because it is listed, not because its files parse -- but it is a list of
  language ids, not a match arm per architecture.
- **Not in the bundle, and not guessed:**
  - the frame pointer is a fact about the body: promote.rs already proves
    it (an address derived from the stack pointer, copied into a register
    the convention preserves), and it moves to r2ssa as that fact;
  - the syscall number register and library prototypes stay radare2's
    data in r2abi, keyed by the profile's language rather than a name;
  - whether a narrow register write zeroes the rest is r2ssa's
    (`Written::is_conventional_extension`), already structural.
- **Consumers read it**: `SourceMachineRoles`, `SourceConventionSlots` and
  `SourceCallEffect` are built from the profile in `r2engine::native`; r2ssa,
  r2types and r2dec read those or the profile; `MachineArchitectureFamily`
  is deleted; r2abi's convention sdb files are deleted.

## Migration

| Step | Change | Deletes |
|------|--------|---------|
| M0 | `MachineProfile` in r2sleigh-lift: `.ldefs`, full `.cspec` (prototypes, killedbycall, unaffected, global), `.dwarf`, register lanes from `.sla`; a test that every listed language parses and states a stack pointer, a return address and a default prototype | `CompilerSpec`'s partial parse; the two `.pspec` program counter parsers |
| M1 | `native::machine()` builds roles, convention slots and call effects from the profile | r2abi `Conventions` and its sdb files; `platform_registers` |
| M2 | r2ssa reads roles and slots only | `abi.rs` alias tables, `from_arch_spec`, `call_argument_register_defs`/`return_read_register_defs` by name, `call_moves_stack_pointer` by family, the direction-flag class check |
| M3 | r2types reads the profile through the facts | `prepare.rs` alias and frame tables, `arrays.rs` prefixes, `signature_infer` convention inference by name, `assumptions.rs` lists |
| M4 | r2dec spells from the profile's register file | the label list, per-architecture `sp`/`fp`/argument/result names, the x86-64 default |
| M5 | r2image and r2engine | the DWARF tables, `map_architecture`'s refusal of RISC-V, family to bits and back, the program counter by name |
| M6 | RISC-V 64 end to end, from its `.ldefs` and `riscv64-fp.cspec` | — |

## Consequences

- Exit: no architecture or register name matched below the lifter; the
  tables deleted; RISC-V renders with no arm added in r2ssa, r2types or
  r2dec.
- Each step keeps the census byte-identical or names every line that moved
  and why. Where the sdb and the `.cspec` disagree (for instance on what a
  call preserves), the difference is listed and judged, and the bundle is
  the authority.
- A new architecture is a language id added to the trusted list and its
  bundle, nothing else.
