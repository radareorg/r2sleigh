---
name: worktree-target-dir-collision
description: "two worktrees sharing one CARGO_TARGET_DIR overwrite each other's path-crate builds; give each its own or touch sources before trusting a build"
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-11T21:17:25.222Z
---

Two git worktrees of r2sleigh built with the same `CARGO_TARGET_DIR` collide: cargo's `-C metadata` hash for path crates does not include the checkout path, so one worktree's r2il rlib replaces the other's and a later build links the wrong one (phantom "no field `instructions`" / "no method `get`" errors, wrong structure-report counts, 2026-10-12).

**Why:** cost an hour chasing errors that were not in the code, and made a structure report unreliable.

**How to apply:** give each worktree its own target dir when both build (disk permitting, see [[mac-disk-full]]), or `touch crates/<crate>/src/*.rs` in the active worktree before a build whose result matters; never compare two worktrees through one shared `target/structure`. Run comparisons on contabo in a clean dir ([[contabo-build-host]]).
