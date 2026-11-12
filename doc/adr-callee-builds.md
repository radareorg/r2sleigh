# ADR: a callee is built once and its owners' statements update the build

Status: built 2026-11-12 (D226, D282 to D285). Owners: r2ssa `TrustedConstruction` and `BuildKey`, r2engine `resolved.rs`.

## Problem

A cold `pdd` prepared a callee twice where an owner's statement moves its result ([result-side](adr-result-side.md), D226). `CalleeReads` prepared it alone, and `outside_resolved` prepared it again against the owners that read named. On pumasim `pdd @ 0x23fdf0` S36's float-lane walk made `0x2312c0` (810 blocks) wait on `0x3f0010`, and the run went from 19.91 G to 24.46 G. The two preparations differ only in what the owners state.

## Decision

A cold `pdd` resolves a callee's result from one build of it. What a preparation is, by its stages:

| Stage | Reads of the callees | On an owner's statement |
|---|---|---|
| Lift and capture | none | kept |
| Build (CFG, phis, renaming, promotion, the decided checks, `prepare`) | `BuildKey` | kept where the key is equal, else run again |
| Provisional prep facts | none (the build alone) | kept with the build |
| Recovery (`recover_interface`, its fact collection) | every call-site interface | run again |
| Seal, collect, `CalleeFacts::derive` | the recovered interface | run once, on the stated build |

The owners:

- r2ssa `TrustedConstruction` is a function built and recovered, before its seal. `restated` takes other callee evidence and returns the construction against it.
- r2ssa `BuildKey` is everything the build reads of the callees. Its parts: the carriers a call defines, the carriers a callee keeps among them, a result carrier a call does not already define whole, the return-address proof, the security check, the narrower result widths, each call's argument area, the re-entering callees, the unstated imports and the premises.
- Slot promotion records whether its answer read an argument area (`argument_areas_read`: a frame address stored at or above some call's stack pointer). The areas compare only where it did. An owner's statement bounds its call's area, so without the record every restated function with a call to its owner would build again (10 of 38 on pumasim).
- r2engine `built_resolved` (`resolved.rs`) walks the owners depth-first for `Demand::Result`. It builds a function alone, resolves the owners its build names, then updates the build with their statements (`built_read`). A function with no owner, or whose owners prove nothing, is sealed alone and its read deposited as `CalleeReads`. The builds held are those on the path: O(depth) builds, each dropped when its function closes.
- `Demand::Arity` (`aa`) is unchanged: the alone read is the `CallBoundary` supply there (D317).

## Invariants

1. A restated construction equals `construct` over the same lift and evidence. Equal keys give the build equal inputs, so it holds by construction. A debug build checks it: `restated` builds both and compares the function, the machine context, the provisional facts, the body boundary and the premises, and panics on a difference.
2. The owners a build names are the owners its alone read names. They can differ where the alone resolution is not its first build: a second seal for folded text or a declared frame, or a collection that refuses. `close` pays for the alone read and compares where the stated resolution took a second seal, and always in a debug build, which counts a defect. A difference leaves the function to the component's path. Any owner set is sound, since each owner's read is a true statement.

## What runs again

- A callee that keeps a register a call would define removes `CallDefine`s. Renaming, phi placement and every pass after them read those definitions, so the build runs again from the held lift (6 of 38 restated functions on pumasim `pdd @ 0x23fdf0`, 1 of 4 on 0pack `pdd @ 0x62ecf0`).
- Recovery runs again on every restated function. Each phase of its collection takes the machine context, whose call-site interfaces the owner's statement changes (D285).
- An owner cycle, or an alone read that names other owners than its build, leaves the function to `Component` and `least_fixpoint` as before (0 on both commands).
- A callee resolved against owners holds no `CalleeReads`. A later listing that asks its pointer parameters computes `CalleeSummary`, one alone preparation.

## Two costs beside it

- Recovery derived every certificate and read one family, the return controls (`recover_interface.rs`, 3 reads). `Certified::ReturnControls` derives that family alone. A certificate pass that exhausts no longer refuses at recovery; the same pass runs on the sealed function and refuses there.
- `append_call_boundary_defs` initialized every clobbered identity at every call: 3 hashed lookups and 2 `String` clones each. `RenameContext` kept an identity's stack, discriminator and counter in three maps. One `Versions` per identity now serves a read or a write in one lookup, and a call initializes an identity once per function. This is the cost S16's +0.46 G on pumasim `aa; pdd` pointed at: the #371 profile puts `init_identity` under `append_call_boundary_defs` at 150 of 8,253 samples, and the build count is equal at #370 and #371, so the cost is per call, not per preparation. S16 did not change `rename.rs`.

## Measured

Release, Mac, instructions retired in G, median of 3 under one `heavy.sh` lock. Output is byte-identical to master on the four commands.

| Head | pumasim `pdd @ 0x23fdf0` | 0pack `pdd @ 0x62ecf0` | bash `aa; pdd @ 0x2e630` | pumasim `aa; pdd @ 0x3b6b20` |
|---|---|---|---|---|
| master ca413c45c | 23.96 | 15.46 | 14.42 | 64.48 |
| The head without D284 | 20.32 | 15.24 | 14.33 | 63.45 |
| The head | 19.49 | 14.83 | 14.34 | 63.45 |
| Bound | 20.32 | 15.69 | 15.43 | 64.46 |

- pumasim cold builds 123 functions where master builds 155; 9 are built twice (the 6 above, and 3 of 1 to 3 blocks whose alone resolution seals again). `0x2312c0` is built once: its 2 owners keep its build.
- Single runs of the steps on pumasim cold: no alone seal or collection, 22.14 G with 4 builds kept; result carriers a call defines whole and promotion's area record, 20.76 G with 32 kept; one lookup per renamed read or write, 20.65 G.
- The profile of the head before D284 (samply, 1,460 samples) put the second recoveries at 90 samples (6.2%), recovery's collection at 320 (22%) and its certificates at 60 (4.1%). D284 measures 0.83 G on pumasim cold. Under `aa; pdd` recovery is 24 of 8,253 samples, so D284 does not move those two commands.
- An exhausted certificate pass was not observed: 0 of 2,459 compared outputs differ.
- Peak RSS on pumasim cold is 235 MB against 246 MB.

## Checked

- Release, master against the head, cold `pdd` of every function of the 23 census fixtures (369 functions), of 30 aarch64 builds (1,214 functions), of 200 functions each of bash, ls, pumasim and 0pack, and `aa; pdd` of 30 each of bash and ls and 8 each of pumasim and 0pack: 0 outputs differ. The aarch64 builds restate no function and leave 3 to an owner cycle.
- A debug build, cold and traced, over pumasim `0x23fdf0`, 0pack `0x62ecf0`, 79 functions of bash, 69 of ls and 6 large pumasim functions: 160 builds kept and compared with a rebuild, 21 rebuilt, 0 differences, 0 defects, 0 cycles. The census fixtures restate no function cold: none has a callee whose owner proves its result.
- `crates/r2engine/tests/engine/builds.rs`: a kept build (`frees` calls `free`, so it keeps no register a call defines), a rebuilt one (a leaf that keeps every register but its result), and the root rendered the same after its callee was rendered first.
