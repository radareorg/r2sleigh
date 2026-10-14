---
name: mac-disk-full
description: "the Mac's 228 GB disk runs near full; each scratchpad worktree target is 7-11 GB; check df and cargo clean finished worktrees"
metadata:
  node_type: memory
  type: project
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-10T21:57:33.927Z
---

On 2026-10-11 the workspace suite failed to link (`linking with cc failed`) because the Mac's data volume had 154 MB free of 228 GB. Two scratchpad worktrees' `target/` dirs held 18 GB (w 11 GB, w2 6.9 GB); `cargo clean --target-dir <wt>/target` and `cargo clean --profile profiling` freed 7.6 GB.

**Why:** every extra worktree with its own `CARGO_TARGET_DIR` duplicates a full debug+release build; the disk is shared with the user's own work.

**How to apply:** run `df -h /System/Volumes/Data` before a workspace build; prefer one worktree's target per active branch; `cargo clean` a worktree once its branch is pushed; heavy suites go to contabo ([[contabo-build-host]]). A link failure across many test binaries at once is disk before code. Related: [[memory-footprint-priority]].

On 2026-10-13 the disk hit 0 bytes during a workspace `cargo check`. Every tool failed, because the shell could not create its own output file; Write and Edit failed too, since they need a temporary file. The `Monitor` tool still ran a shell command, and `rm -rf` of the worktree's 16 GB `target/debug` through it recovered the session. Keep at least 20 GB free: run `df` before any workspace build, and delete `target/debug` once a branch's checks pass, since the release binary is all that measurement needs.
