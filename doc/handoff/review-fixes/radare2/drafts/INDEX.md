# Pending radare2 PR actions (nothing pushed or posted)

Every push goes from /home/user/radare2 to `origin` (radareorg/radare2) with a pinned SHA. This session cannot push to the fork, and `gh` is not installed, so PRs are opened and comments posted in the web UI. The full commands and texts are in `short/<PR>.md`.

Local origin/master is 129e4c2. Upstream master is now a2fd2ba; it was fetched as objects only, with no ref updated. Every branch below merges into a2fd2ba without conflict (`git merge-tree`). a2fd2ba also raised `R2_ABIVERSION` from 144 to 145, which matters for #25942 and for the ABI question in the #26682 reply.

| PR | Action | Branch@SHA | Prerequisites | Needs your Mac |
|---|---|---|---|---|
| #26768 | Push, open the superseding PR, post the 2 thread replies, the reply to the 11:17 review and the one-line comment, close #26768 | upstream-pr/arm-thumb-data-symbols-v2@600026ccb9921aeb907214eba7a9f0435156ee2b | none | no |
| #26629 | Push, open the superseding PR, post the reply and the one-line comment, close #26629 | anal/argseq-hoist-v2@ec46325f125d092bb83f429c244e00c9c8444539 | none (based on a3072b9) | no |
| split-out of #26682 (xref delete missing edge, #NEW-DEL) | Push, open the PR "Keep the other xrefs of an address when deleting one it does not have ##analysis" | pr/xref-delete-missing-edge@7b9d2678ca6cb39040125c88e3d5767ab2c69724 | none; open it before the #26682 successor | no |
| #26682 | Push, open the superseding PR, post the reply (which asks the ABI question) and the one-line comment, close #26682 | pr/xref-invalidate-v2@4bb07b66cd3f4297e77fb1745317557688d92614 | The split-out PR must be open first, so its number can replace #NEW-DEL. The branch carries the split-out's patch as 8af3aa2 (same patch-id as 7b9d267); drop that commit once the split-out lands. | no |
| follow-up of #26762 (typedef cycle crash, #NEW-CYCLE) | Push, open the PR "Fix infinite recursion formatting a cyclic typedef ##crash" | pr/typedef-cycle-format@a84d02cf0812b3c6a1f6349c406e6e4bcde000db | none (based on a3072b9) | no |
| #26762 | Post the close note, then close; nothing to push (it landed in a756f85 via #26763) | none (the fork head pr/typedef-scalar-format@a7a616fe stays) | The typedef-cycle PR must be open first, so its number can replace #NEW-CYCLE | no |
| #26708 | Post the close note, then close without merging; nothing to push | none (the fork head pr/post-analysis-depth@bc38668 stays) | none | no |
| #26743 | Push, open the superseding PR (trufae's 5-patch series), post the 2 replies and the one-line comment, close #26743 | types/fortify-chk-v2@e3397763511fadf8be43da135cb664e74624d732 | none (its tests use malloc:// and bins/mach0/cat-macos-arm64, already in testbins) | no |
| radare2-testbins (syscall fixtures, #NEW-BINS) | Commit the six untracked `elf/syscall-*` files in /home/user/radare2-testbins on a new branch, push it to radareorg/radare2-testbins, open a PR | no commit yet (elf-syscall-fixtures@<SHA printed after committing>) | none | no |
| #25942 | Push, open the superseding PR, post the 2 replies and the one-line comment, close #25942 | search/syscall-candidates-v2@a230e887c6baddd9d7c043c5f01af61359f64be0, or 0c33db3 (full: see 25942.md) without the fixture tests (drop a230e88) | The testbins PR must land first for a230e88. Also decide whether the new `RArchPlugin` field rides a2fd2ba's bump to 145; a459505's own 144 -> 145 bump now merges as a no-op. | no |
| #26765 | Push, open the superseding PR, post the review reply and the one-line comment, close #26765 | debug/gdbr-lldb-capabilities-v2@80546b464df1c1bc29fac4908003ed172e38a163 | none | yes: debugserver has not been tested (the PR says so). Check a native arm64 launch and a Rosetta x86_64 launch and attach (arch/bits, `drp` offsets, `dr` against lldb, `ds`, `dr x0=1`, `QThreadSuffixSupported`, `g;thread:`); whether target.xml has `offset=`; the arch picked by an old debugserver without qXfer:features; and whether #25935 needs QSetDetachOnError:1 |
| strlcpy record fix (offered in the #26743 reply) | Write the one-line fix: `strlcpy` returns `size_t`, not `char *`, and its arg 2 name ` n` loses the leading space | no branch yet | none | no |

Optional, and proposed in the drafts with no branch yet:
- A radare2-testbins PR with the fortify fixture sources and `build-fortify.sh` (#26743). The local binaries are stub-linked, not NDK or 32-bit glibc builds.
- Moving #26768's four synthetic ARM ELFs (`mkarmelf.py`) to radare2-testbins, if trufae prefers files to `malloc://`.
- Caching `r_reg_32_to_64` at `r_reg_reindex` time (#26629 reply: "a separate PR").
- glibc `_chk` coverage: host ls still imports untyped `__mempcpy_chk`, `__readlink_chk` and `__mbstowcs_chk` (#26743).
- `gdbr_set_architecture`'s inverted check (libgdbr.c:65), plus the io_gdb.c session leak on a failed vAttach (#26765).
- `handle_arm_hint` (`libr/core/cbin.c`), which still sets bits=16 on odd data addresses, and `r_bin_get_vaddr`'s rounding in `*text*` sections (#26768, shared with other formats).

Suggested order:
1. Open the split-outs first: xref-delete, then typedef-cycle, then testbins.
2. Then open the superseding PRs, replacing #NEW, #NEW-DEL, #NEW-CYCLE and #NEW-BINS.
3. Then post the replies and comments, and close the old PRs.
