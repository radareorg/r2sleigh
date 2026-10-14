---
name: structure-bless-only-falls
description: run structure-report.sh and read its exit code before --bless; bless only when every count fell
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-05T14:22:34.644Z
---

`scripts/structure-report.sh --bless` writes whatever the counts are, rises included. Exit 1 means a count rose: fix the code (bundle parameters, extract helpers), never bless it.

**Why:** blessing a rise weakens the ratchet the repo treats as a quality gate (AGENTS: never weaken a gate). Happened once on M3a (too_many_arguments 142→143) and had to be amended.

**How to apply:** run without `--bless`, check `sr=0` and that every line says "fell", then bless. Related: [[ci-ratchet-check]].
