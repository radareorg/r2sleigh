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
| `classify` -O0 switch | the walk stopped at `jmp rax`; radare2 lists 8 arms | 8 arms, and `pdd` renders the switch. The guard compares the parameter's home and the dispatch reloads it, so the home is now promoted (R4) | r2ssa `promote.rs` |

## Open

| Command | radare2 | r2s | Judgement | Owner |
|---|---|---|---|---|
| `afl` | no header; `addr nbbs size name` | a header; `vaddr confidence name` | radare2's spelling is binding (decision 8). Confidence moves to `aflj`. `nbbs` needs one walk per function; the survey already walks every body, so the count should come from there, not from re-running `function_graph` | r2engine survey, then r2s |
| `afl` names | `entry0`, `entry.fini0`, `dbg.classify` | `sym._start`, `sym.__do_global_dtors_aux`, `sym.classify` | radare2 prefers the entry and DWARF flag spaces. Both are aliases of one address; ordering aliases by occupancy is P11a | r2engine naming |
| `afi` edges | `edges: 10`, `cyclomatic-complexity: 19` on `classify` | `edges: 18`, `cyclomatic-complexity: 9` | **radare2 is inconsistent here.** Its `edges` leaves out the 8 switch edges, while its complexity counts them twice. Ours is E − N + 2 = 18 − 11 + 2 on the graph `afb` lists. Keep ours | — |
| `afi` end-bbs | 2 | 1 | radare2 counts the `ja` default block (which ends in a jump to the return) as an end. We count blocks with no successor in the body. Keep ours | — |
| `afi` fields | `stackframe`, `bits`, `noreturn`, `in-degree`, `maxbbins`, `midbbins`, `ratbbins`, `file`, `type` | absent | `bits` and the block statistics follow from `function_graph`; `noreturn` from `comes_back`; `in-degree` from `axt`; `file` from DWARF. Each gets added when its fact is canonical, never as a default | r2s over r2engine |
| `pdd` switch | — | `case 7: default:` share an arm when every value in range has a case | Valid C and equivalent (the default can't be reached under the guard), but misleading to read. r2dec should emit no `default` when the cases cover the guarded range | r2dec structure |
| `VV` | minimap, `p` cycles block display modes, `tab` | pan, `tab`, `t`/`f`, zoom to headers, recentre | Still to add: a minimap, and `"` comments | r2s-tui |
