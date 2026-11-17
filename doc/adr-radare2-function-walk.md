# ADR: function walks without a depth limit

Status: engine side done; radare2 side partly upstreamed (differential target)

This ADR has two halves. The engine's own walk (`r2ssa::body`, driven by
`r2engine::discovery`) is what this repo runs. radare2's `fcn_recurse` in
`libr/anal/fcn.c` is the differential target, and the changes to it are
upstream pull requests, one idea each.

## Decision

**The engine walk** (`crates/r2ssa/src/body.rs`):

- It is a worklist over instruction addresses (`Walk::run`), with no
  recursion and no depth limit. Each address is decoded at most once
  (`decoded`), so the work is linear in the bytes decoded plus the edges.
- It carries no path state: no running stack delta, last compare or list of
  `lea` candidates is inherited from whichever path reached a block first.
  Stack deltas and compares are dataflow facts of the SSA, derived later.
- An indirect branch is followed only to the arms that a previous pass proved
  it reads (`dispatched`). Otherwise it is recorded as unresolved, and the
  body is an honest partial body.
- Nothing is decoded where the program maps no execute permission. A direct
  branch to another function's entry (`Program::is_entry`) is a tail call and
  ends the body. A call returns unless `Program::returns` says otherwise.
- Discovery (`crates/r2engine/src/discovery.rs`) is the least set of addresses
  closed under "walk it and take where it transfers", starting from what the
  image states, together with the least fixpoint of which functions return.
  Both are worklists that only grow over a finite image.

**radare2's walk, as the oracle reads it:**

- `anal.depth` (default 128, clamped to 192 by
  `R_ANAL_FCN_RECURSE_STACK_LIMIT`) bounds the depth-first chain, which is a
  property of the function's shape, not its size. It exists only to protect
  the C stack, at about 5.5 KB per frame at `-O0`.
- Running out of depth leaves edges into addresses that no block covers. A
  differential disagreement on a switch-heavy or long-chain function may be
  radare2's truncation, not the engine's defect.
- The entry stack delta, `anal->cmpval` and `anal->leaddrs` are path state in
  globals, so a block reached by two paths takes the first-walked path's
  value. Jump-table detection is therefore order-dependent.
- `fcn_recurse`'s return value is the rightmost assigning child's outcome,
  which sometimes leaks a byte count, and `__core_anal_fcn` branches on it.

## Done

- Engine: the body walk and discovery as worklists, with no depth limit.
- radare2 PR 26717 (open): `fcn_recurse` de-recursed with explicit
  `Enter`/`Exit` frames that replay the recursion's order exactly, so output
  is identical except for functions the old walk truncated. Nested switch-case
  walks keep their own frame vector. `anal.depth` is kept, because
  `r_core_anal_fcn` still uses it for callee recursion. Under `anal.jmp.indir`,
  an indirect jump's targets are walked after its block finishes. The
  frame-pointer fix found on the way (26718) is merged; the CFA location kind
  (26719) is open.

## Left (upstream radare2, each one PR in this order)

1. Give `ret` a definition. Measured on master with no payoff, not taken: no
   walk returns a byte count since it became non-recursive (`aa` returns
   ERROR/END/NOP: vim 2603/2029/74, libstdc++ 1626/3959/52, ls-m1 22/29/83), and
   `br`'s NOP as END moved nothing on ls-m1, libstdc++, TestApp.ios, 3 blocks on vim.
2. One read-ahead cache per walk instead of one per frame. Result-preserving;
   measured in IO reads per function. Open as radare2#26986: `aa` reads 109,762
   to 36,583 on 0pack, 94,428 to 23,866 on vim, CPU unchanged on local files.
3. Carry the predecessor in the frame. Measured with no CPU payoff, not taken:
   `try_get_jmptbl_info`'s block scan is 0 to 1 of 1746 to 2506 walk samples on
   vim, 0pack and libstdc++.
4. Edge-labelled path state with a join: the entry delta, the last compare and
   the live `lea` candidates become forward dataflow facts, where unequal
   labels become unknown. Result-changing, so it is measured separately; needs design.
5. Derive the cap on `r_core_anal_fcn`'s callee recursion. Measured with no
   payoff, not taken: `anal.depth` 128 or 4096 finds the same functions (`aa`:
   vim 4706, ls-linux64 121; `af @ main` with `anal.calls`: vim 215, 0pack 282);
   only 8 truncated anything (0pack 273).

## Unwind edges as built (D570)

A call inside a call-site range of its frame's LSDA unwinds to the range's landing pad. r2abi
states which personalities read that table, r2image reads it, and the body walk holds the pads
apart from the normal flow (`r2engine::body::Pads`), which every analysis keeps reading alone
until D598 states a pad's entry.

Sources, quoted at the tags named:

- LSB Core 5.0, generic part, 10.6 "Exception Frames", the CIE augmentation: "'P' ... indicates
  the presence of two arguments in the Augmentation Data of the CIE. The first argument is 1-byte
  and represents the pointer encoding used for the second argument, which is the address of a
  personality routine handler." and "'L' ... The argument in the Augmentation Data of the CIE is
  1-byte and represents the pointer encoding used for the argument in the Augmentation Data of the
  FDE, which is the address of a language-specific data area (LSDA)."
- GCC 14.2.0 `libstdc++-v3/libsupc++/eh_personality.cc`, `parse_lsda_header`:
  `info->Start = (context ? _Unwind_GetRegionStart (context) : 0);`,
  `if (lpstart_encoding != DW_EH_PE_omit) p = read_encoded_value (context, lpstart_encoding, p, &info->LPStart); else info->LPStart = info->Start;`,
  `if (info->ttype_encoding != DW_EH_PE_omit) { ... p = read_uleb128 (p, &tmp); info->TType = p + tmp; }`,
  `info->call_site_encoding = *p++; p = read_uleb128 (p, &tmp); info->action_table = p + tmp;`.
- The same file, `PERSONALITY_FUNCTION`: `if (! ip_before_insn) --ip;`, then for each record
  `// Note that all call-site encodings are "absolute" displacements.` `cs_start`, `cs_len`, `cs_lp`
  read in the call-site encoding and `cs_action` as uleb128;
  `else if (ip < info.Start + cs_start + cs_len) { if (cs_lp) landing_pad = info.LPStart + cs_lp;`.
  GCC 14.2.0 `libgcc/unwind-c.c` (`__gcc_personality_v0`) reads the same header and loop.
- GCC 14.2.0 `libgcc/unwind-pe.h`: `DW_EH_PE_omit 0xff`, `DW_EH_PE_uleb128 0x01`,
  `DW_EH_PE_udata2 0x02`, `DW_EH_PE_udata4 0x03`, `DW_EH_PE_udata8 0x04`, `DW_EH_PE_sleb128 0x09`,
  `DW_EH_PE_sdata2 0x0A`, `DW_EH_PE_sdata4 0x0B`, `DW_EH_PE_sdata8 0x0C`, `DW_EH_PE_pcrel 0x10`,
  `DW_EH_PE_indirect 0x80`.
- LLVM 19.1.0 `llvm/lib/CodeGen/AsmPrinter/EHStreamer.cpp`, `emitExceptionTable`: "The call-site
  table is a list of all call sites that may throw an exception ... Each record indicates: * The
  position of the call-site. * The position of the landing pad. * The first action record for that
  call site. A missing entry in the call-site table indicates that a call is not supposed to throw."

As built:

- r2abi `runtime::PERSONALITIES` holds one cited row each for `__gxx_personality_v0` and
  `__gcc_personality_v0`. `UnwindFrame` carries `pads` (absolute call-site ranges, sorted) and
  `lsda` (`None`, `Read(row)`, `Refused(reason)`, `PersonalityUnstated`); `UnwindFrames::pad_for`
  answers a call's pad from its last byte, the unwinder's `--ip`, in O(log F + log R).
- r2image `lsda.rs` reads one table, O(table bytes), failing closed per frame: an encoding outside
  the list, a record past the stated length (`Length`), a range outside its frame, and, once every
  frame is read, a pad outside every frame are refused with the reason kept. The personality is the
  import the loader writes at the CIE's indirect pointer (`DW.ref.__gxx_personality_v0`); an import's
  name is a declaration, so pad facts rest on `Basis::Declared`. A direct pointer, an unrowed import
  and a relocatable object's personality state no pad (`PersonalityUnstated`).
- r2engine `body.rs`: each call, returning or not, records its pad. After the normal walk the pads
  are walked by a second `Walk` that never writes the first and stops wherever the normal flow
  decoded; a resumed walk (`open`, `follow`) resumes the pads' walk too. An instruction both flows
  reach is the normal flow's. `Body::blocks`, `successors` and `calls` are byte for byte what they
  were; `Body::pads` holds the pad blocks, every unwind edge, and the calls made only there.
- Listing surfaces ask for both: `pdf`, `afb` (tag `u`, `EdgeKind::Unwind`), `afi`, `axt` and the
  survey's extents and holders. `pdd`, the seal and the lane passes read `Body::blocks`, and the
  proof line states `N landing pads not rendered: exceptional flow, a store read only there may be
  elided`. `Escapes` refuses the closed world of an image where any body unwinds
  (`closed-world: unwind flow unread (D598)`): no lane pass reads a call made in a pad.
- A pad's edge back into the normal flow (a `catch` that returns) lands inside a normal block,
  which is not split: `afb` lists no edge there. Splitting it is D598's, with the pad's entry state.
