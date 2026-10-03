# Gaps against radare2

The R-loop's third step: run the same command in radare2 (master, built into
`/home/user/r2prefix-master`) and in r2s, and judge each disagreement. Being
different from radare2 does not by itself mean r2s is wrong. Each row says
which side is right and who owns the fix.

Fixture: `tests/fixtures/rv_O0g` (`tests/gold/review.c`, gcc -O0 -g).

## Closed

| Command | Was | Now | Owner |
|---|---|---|---|
| `agf` | missing | the layered graph, the same painting as the `VV` pane (`r2s-tui/src/graph`) | r2s-tui |
| `afb` | missing | radare2's lines: start, end, size, then `j`/`f`/`s`; identical on `classify` and `sum_array` | r2s over `function_graph` |
| `afl` | a header; `vaddr confidence name` | radare2's layout with no header: `addr nbbs size name`. Size is the bytes of the blocks, not the span (padding between blocks is not counted); confidence moved to `aflj`. 25 of 27 rows on `rv_O0g` are now identical to radare2's | r2s over the survey's `TraceExtent` |
| `afl` `_start` | 2 blocks, 38 bytes: the walk decoded the `hlt` after `call [__libc_start_main]` | 1 block, 37 bytes, as radare2. A call through a slot asks the program what the slot holds; the import the loader binds there is declared noreturn, so the fallthrough is closed. `pdd` no longer renders a `for (;;)` loop after it | r2ssa walk, r2engine `returns_through_slot` |
| `classify` -O0 switch | the walk stopped at `jmp rax`; radare2 lists 8 arms | 8 arms, and `pdd` renders the switch. The guard compares the parameter's home and the dispatch reloads it, so the home is now promoted (R4) | r2ssa `promote.rs` |

## Open

| Command | radare2 | r2s | Judgement | Owner |
|---|---|---|---|---|
| `afl` nbbs of a jump table | `classify` 11 blocks, 109 bytes | 3 blocks, 60 bytes | radare2 is right. The survey walk follows no dispatch table, so the arms are not counted (`pdd`, `afb` and `agf` do count them). P6, one resolved body for every consumer, closes this | r2engine survey (P6) |
| `afl` names | `entry0`, `entry.fini0`, `dbg.classify` | `sym._start`, `sym.__do_global_dtors_aux`, `sym.classify` | radare2 prefers the entry and DWARF flag spaces. Both are aliases of one address; ordering aliases by occupancy is P11a | r2engine naming |
| `afi` edges | `edges: 10`, `cyclomatic-complexity: 19` on `classify` | `edges: 18`, `cyclomatic-complexity: 9` | **radare2 is inconsistent here.** Its `edges` leaves out the 8 switch edges, while its complexity counts them twice. Ours is E − N + 2 = 18 − 11 + 2 on the graph `afb` lists. Keep ours | — |
| `afi` end-bbs | 2 | 1 | radare2 counts the `ja` default block (which ends in a jump to the return) as an end. We count blocks with no successor in the body. Keep ours | — |
| `afi` fields | `stackframe`, `bits`, `noreturn`, `in-degree`, `maxbbins`, `midbbins`, `ratbbins`, `file`, `type` | absent | `bits` and the block statistics follow from `function_graph`; `noreturn` from `comes_back`; `in-degree` from `axt`; `file` from DWARF. Each gets added when its fact is canonical, never as a default | r2s over r2engine |
| `pdd` switch | — | `case 7: default:` share an arm when every value in range has a case | Valid C and equivalent (the default can't be reached under the guard), but misleading to read. r2dec should emit no `default` when the cases cover the guarded range | r2dec structure |
| `VV` | `p` cycles block display modes, `"` comments | pan, `tab`, `t`/`f`, zoom to headers, recentre, minimap (`m`) | Still to add: comments, which need a comment store the shell does not have | r2s-tui |
