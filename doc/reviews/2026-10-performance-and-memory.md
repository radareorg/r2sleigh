# r2s performance and memory analysis (master f49332cc, 2026-10-07)

Build: release, line tables, frame pointers (`target-prof`). Host: 4 cores, 7 GB.
Tools: perf + inferno flamegraphs, uprobe call counts, heaptrack, jemalloc `prof` + jeprof,
valgrind memcheck. Corpus: coreutils ls/sort, zlib 1.2.13 O0/O1, system libz,
radare2 `pumasim` (9.5 MB C++, 15,298 functions), `0pack` (8 MB, 8,699 functions), fuzzed/PE bins.
Flamegraphs were rendered with `perf record -g` + `inferno-flamegraph` and are not committed (2-4 MB each).

## Baseline

| Workload | Wall | Peak RSS |
|---|---|---|
| ls `i` | 0.01 s | 9 MB |
| ls `pdd` of a 12-instruction function | 0.47 s | 80 MB |
| ls `afl` | 0.77 s | 74 MB |
| ls `pdd` main (1,283 instrs) | 5.9 s | 165 MB |
| sort `pdd` 0x3f50 (526 blocks) | 11.8 s | 257 MB |
| libz O1 `pdd` inflate | 7.5 s | 190 MB |
| pumasim `afl` | 29.1 s | 304 MB (radare2 `aaa`: 606 s, 282 MB) |
| pumasim `pdd` Gui ctor (40 KB) | 18.9 s | 780 MB |
| 0pack `afl` | 16.4 s | 225 MB |

Scaling: pdd time grows as instrs^1.39 over the 47 functions with 300+ instructions.

## Critical: untrusted input drives unbounded work

1. `fuzzed/elf9` hangs on open (`-c q` never returns). 96% in `r2abi::statement::write_at`
   called from `r2image::initialisers` (`crates/r2image/src/lib.rs:164`): it loops
   `section.file_size / 8` slots from the header, never clamped to the file. Fix: clamp slots
   to bytes the file holds. Owner r2image.
2. `fuzzed/file12` (8.7 KB Mach-O): `pd 5` takes 14 s and 2.1 GB. A `__cstring` section claims
   0x4000000c bytes at a file offset past EOF. `naming::name_strings`
   (`crates/r2engine/src/program/naming.rs:131`) reads the full vsize through a zero-filling
   `source.read`, then copies it into `runs`: 2 x 1 GiB. Fix: scan only file-backed bytes. Owner r2engine.
3. `pe/65535sects.exe` `pdd` runs past 580 s. 83% self time in
   `r2ssa::semantic::private_objects::collect_memory_round_trips`: for every write it scans
   every access (`find`, then `any`), O(writes x accesses), more for later loads.
   Fix: index accesses by block and ordinal, and reads by value. Owner r2ssa.

## High

4. Sleigh cache clearing re-initializes the decoder. `SleighProxy::clearCache`
   (`vendor/libsla-sys/src/cpp/bridge.cc:170`) builds a new context, calls `reset`,
   `Sleigh::initialize` and re-parses the processor-spec XML. It runs at every
   non-contiguous lift: 70,543 calls for pumasim `afl` (~140 us each, ~36% of 29 s),
   4,919 for one sort `pdd`, 756 for a 12-instruction `pdd` (15% of it). Fix: replace only the
   disassembly cache, keep the context database. Owner r2sleigh-lift / vendored libsla.
5. A `pdd` prepares full SSA for every callee. `callee_read` > `resolved_alone` is 35-42%
   of pdd time. Counts: 114 prepares for sort 0x3f50 (271 call sites), 188 for the pumasim
   Gui ctor, 66 for ls main. A 52-instruction function (ls 0xbcc0) pays for its callee
   0x127a0's full body. Fix: a callee interface summary query that is cheaper than a full
   preparation. Owner r2engine (P6/Q3 summaries).
6. Allocation churn. One sort `pdd` makes 30.9 M allocation calls and allocates 6.5 GB
   cumulatively for a 218 MB peak. 40% of bytes come from `RawVec::finish_grow` (Vec growth
   without capacity); `IdMap::insert` alone grows 728 MB. glibc malloc/free is ~20% of self
   time. Swapping in jemalloc (LD_PRELOAD) cuts wall time 15-36%:
   pumasim `afl` 27.2 -> 17.4 s, sort `pdd` 11.2 -> 8.6 s, ls main 5.3 -> 4.2 s; RSS +1-12%.
   Fix: `#[global_allocator]` jemalloc or mimalloc in r2s; pre-size hot Vecs.

## Medium

7. Dense dataflow states cloned per block. `collect_call_result_certificates`
   (`crates/r2ssa/src/semantic/certificates/call_results.rs:55`) runs `fixpoint::forward` with a
   state holding `IdMap<ValueId, _>` (slots sized to the largest value id), clones `input` per
   visit and keeps entry and exit copies per block: O(blocks x values) copying and memory.
   Fix: sparse or persistent state. Owner r2ssa.
8. Sleigh specification loaded twice per process: `Machines::load` and
   `Disassembler::shared_loaded_profile`. 51% of a tiny `pdd` (0.47 s) is spec loading;
   the second load is 37%. About 0.17 s and 23 MB per process. Owner r2sleigh-lift.
9. Query database capacity: `Analysed` and `Sealed` hold 1 entry, `Walked` 64, `Rendered` 16
   (`crates/r2engine/src/program/analysis.rs`). Memory stays bounded, but a second pass over
   libz re-prepares 368 bodies and costs about as much as the first (32 s per pass).
10. Peak memory on large C++ functions: 420-870 MB per `pdd` on pumasim. Peak for sort is
    spec 46 MB, lifted body 29 MB, analysis 87 MB.

## Low: leaks

11. No real leak found. valgrind on `pdd` + `afl` (libz O1): 0 bytes definitely lost,
    0 indirectly lost, 0 errors. 3.1 MB "possibly lost" are hashbrown interior pointers held at
    `process::exit`. heaptrack's 124 MB "leaked" is live state at `process::exit`, which skips drops.
12. Session growth is flat: three `pdd` sweeps over all 190 libz functions in one session
    plateau at 256 MB; in-use heap at exit 56.4 MB after one pass, 60.0 MB after three.
13. `r2ssa::name::intern` (`crates/r2ssa/src/name.rs:84`) is a global `Mutex<HashMap>` that
    `Box::leak`s every spelling, including address-bearing ones (`tmp:lane:4f3e:...`).
    About 1 MB per binary, never freed. It only grows for a long-lived process that opens many
    binaries, and it is a cache outside the query database (ROADMAP D11).

## Good

- r2s `afl` on pumasim is 21x faster than radare2 `aaa` (29 s vs 606 s).
- All views of one function (pdd, pdf, afv, pddj, pddo) share one preparation.
- pdd output is deterministic, no panics.
