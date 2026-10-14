---
name: contabo-build-host
description: "heavy builds, the workspace suite and the Linux equivalence gate run on the contabo VM over SSH; the Mac only edits and runs touched-crate checks"
metadata:
  node_type: memory
  type: reference
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-13T05:31:56.595Z
---

From 2026-10-08 the user's Contabo VM is the build host: `ssh contabo` (host and key in `~/.ssh/config`; kept out of this public repo). It runs x86-64 Ubuntu (kernel 6.8), 4 cores, 7 GB RAM, about 75 GB free, with cargo, gcc, clang, `qemu-aarch64` and `aarch64-linux-gnu-gcc`, so `tests/equiv/run_equiv.py` runs there for both x86-64 and aarch64 without waiting on CI.

**Why:** the Mac's 228 GB disk filled twice with per-worktree `target` dirs (ENOSPC stopped every tool, the Bash tool included). The user said: "our contabo vm has lots of space, why don't we just mount it here and use it as build system".

**How to apply:**
- Build over SSH; never mount a target dir over sshfs, since cargo's many small writes make that slow.
- The stack workspace is `/root/r2s-stack`, a clone using `--reference /root/r2sleigh`; the Mac repo has remote `contabo` pointing at it. Push branches with `git push contabo <branches>`, then `ssh contabo 'cd /root/r2s-stack && git checkout -q <b> && CARGO_TARGET_DIR=/root/r2s-target ...'`. Logs go in `/root/r2s-logs`.
- `/root/r2sleigh` is the user's own checkout (master, local changes): never touch it.
- On the Mac, keep at most one big `target` dir; delete `target/debug/incremental` and idle worktrees' targets before they fill the disk. VM timings are not comparable to Mac baselines.
- Remote `rm` was denied by the permission classifier until 2026-10-12, when the user asked: "clean up contabo as well for what's already completed, we cannot afford wasting too much space". That cleanup freed 145G full to 95G free (r2s-agents, r2s-target, per-item targets, old logs). Keep one target (`/root/r2s-target`, recreated on the next build), delete per-item targets and worktrees when the item merges, and leave unrelated projects and `decbench-shared-target` alone.

- `ssh contabo '<cmd>'` exits 1 even for `true` (the remote logout script fails, printing "reset: ... Inappropriate ioctl"), so never loop on its exit status: `until ssh contabo 'grep -q ^EXIT log'` (or `'test -f log'`) never ends (2026-10-12, seven waiters hung). Poll on output: `until [ "$(ssh contabo 'grep -c ^EXIT log' 2>/dev/null)" = 1 ]`.
- Poll at 120 s or more, with one waiter per log. A run that is killed never writes EXIT, so TaskStop its waiter in the same step. On 2026-10-13, nine forgotten waiters polling at 15 to 30 s made sshd reset connections ("Connection reset by ... port 22") and then time out, while the VM's load was 0.1.

- `/root/r2s-stack` is a non-bare clone: `git push contabo <branch>` is refused while that branch is checked out there, and a following `git checkout <branch>` silently tests the old commit. Run `git checkout -q --detach` on contabo before each push. To stop a run, `pkill -f "[c]argo test --workspace"` (the bracket keeps pkill from matching its own ssh command).

Related: [[memory-footprint-priority]], [[large-function-perf-check]].
