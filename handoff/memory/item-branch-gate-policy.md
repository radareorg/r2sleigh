---
name: item-branch-gate-policy
description: during a roadmap item's rewrite, structure-report and long_comments ratchets are suspended; re-armed at item exit
metadata:
  type: feedback
---

Approved 2026-10-06: while one roadmap item is being rewritten on its own branch, the structure-report and `long_comments` ratchets are suspended. They are re-armed when the item finishes; counts may then be re-blessed for that item.

**Why:** user wants roadmap speed first; code quality counts are deferred. Old paths are deleted outright (no D1 run-beside), census may move and its moved-line diff is read once at item exit.

**How to apply:** inside an item, run per-crate tests and clippy only. At item exit: full test suite, equivalence both arches, census, certification, release pdd timing on 0pack/pumasim, then structure-report and bless. Correctness gates (equivalence, certification, tests, Dylints) are never suspended. Supersedes [[structure-bless-only-falls]] and the ratchet part of [[short-comments]] inside an item only.
