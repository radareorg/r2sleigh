# Listing spelling

How a listing writes an instruction is a fact of its own, separate from what the
instruction does. Sleigh prints the assembler's syntax of its time; radare2, the
Arm ARM and the other disassemblers print the alias each encoding prefers.
`r2sleigh-lift`'s `disasm/syntax.rs` is the one owner of that difference: the
decoder says the text and where its numbers and registers sit, and nothing
downstream reads the text again.

## AArch64 preferred aliases

The vendored specification names some aliases as constructors and omits or
guards others loosely (its `bfm` has no `bfi` or `bfc`, its `negs` wins over
`cmp`, its `mov` ignores the shift of an ORR). The pass `aarch64_alias` writes
what the Arm ARM prefers. Patching the specification was rejected: it is pinned
with the vendored engine, a rebuilt `.sla` moves the semantic artifact for a
spelling change, and the other constructors that are wrong would leave the
spelling in two places.

| Encoding | Preferred spelling | Precondition (Arm ARM) |
|---|---|---|
| BFM | `bfi Rd, Rn, lsb, width` | `imms < immr`; `lsb = -immr mod size`, `width = imms + 1` |
| BFM, Rn the zero register | `bfc Rd, lsb, width` | `imms < immr` |
| BFM | `bfxil Rd, Rn, immr, imms - immr + 1` | `imms >= immr`, so `immr = 0` with Rn zero is `bfxil` |
| SUBS shifted, Rd and Rn zero | `cmp` | CMP wins the tie with NEGS; `negs` needs a live Rd |
| ORR shifted, Rn zero | `mov Rd, Rm` | shift `lsl #0` only; any other shift stays `orr Rd, zr, Rm, shift` |
| ORR immediate, Rn zero | `mov Rd, imm` | not `MoveWidePreferred`: no one MOVZ or MOVN writes the value |
| MOVZ, MOVN | `mov Rd, imm` | not (`imm16 = 0` and `hw != 0`); MOVN 32-bit not `imm16 = 0xffff` |
| any `cs`, `cc` condition | `hs`, `lo` | the spelling LLVM, binutils and radare2 write |

`MoveWidePreferred` is a test on the encoding (`immN`, `imms`, `immr`), and the
MOVZ/MOVN rule on `hw`; the operands drop those fields, so the decoder passes
the instruction word. `move_wide_preferred` is checked against the value form
("one halfword is not zero, or one is not `0xffff`") on every encoding of both
widths, and against `llvm-mc` on the 11,328 valid bitmask immediates.

Not rewritten: SXTL and UXTL, which Sleigh already prints for a zero shift as the Arm ARM prefers (radare2 and
LLVM print `sshll`/`ushll #0`); and `sbfm`/`ubfm`, whose 15,360 encodings the sweep found already agreeing.

BFC and BFI are the one place the references split: LLVM prints `bfi Rd, wzr`;
the Arm ARM, binutils and radare2 print `bfc`, which is followed.

## Cost

One pass over an instruction's operands, `O(1)` per instruction; no table, no
scan of the function.

## Evidence

A synthetic AArch64 ELF holding every encoding of a class, listed by `r2s` and
radare2 and decoded by `llvm-mc`: bitfield moves (30,720 encodings), the
add/sub, logical, move-wide, conditional-select and multiply classes, the
bitmask immediates and SSHLL/USHLL. The disagreements with each reference, per
class, are in the commit that landed the pass.
