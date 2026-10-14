---
name: ci-runner-queue
description: "r2sleigh CI runners are few; cancel runs above the merging stack, but cancelled lower runs skip per-PR timing and Dylint, so run those on contabo before merge"
metadata:
  node_type: memory
  type: project
  originSessionId: f617cb1c-6459-42bc-b410-ade5debf9280
  modified: 2026-10-13T18:50:57.754Z
---

The radareorg/r2sleigh runner pool runs about 4 workflow runs at once. On 2026-10-13, runs queued at 15:32 had still not started 5 hours later. The full-ci label puts about 24 equivalence shards on each PR.

**Why:** every push to a PR in the long stack (#188 to #228) queues a run. A run of a PR above the stack being merged grades a base that will change before it merges, so it wastes runner time the merging stack needs.

**How to apply:** while a stack is merging (see [[stacked-prs]]), cancel queued and in-progress runs of the PRs above it (`gh run list --branch B --status queued`, then `gh run cancel`). Avoid pushing upper-stack branches until the lower stack merges, or cancel the runs those pushes start. Contabo equivalence (see [[contabo-build-host]]) is the grade for upper-stack work until then.

**Cost of cancelling the lower PRs' runs (2026-10-14):** the top PR's gates compare it only with its parent, so the per-PR timing gate and Dylint never ran on the PRs below it. That hid two things until later. #213's stack-roots fix took 0pack `0x58e3d0` from a fast refusal to a full rendering, 1.89x on master's push run, a correct change no gate had seen. P9 used an entity-keyed `BTreeSet` that Q5's lint rejects. Before merge-async on a stack whose lower runs were cancelled, run on contabo `cargo dylint --path tools/dylints/r2sleigh_lints --workspace -- --all-features --lib --bins` for the top. Also time release `pdd` on the large functions at the stack's base and top. The user saw the cancelled runs as "all PR CI is red"; say so when cancelling.
