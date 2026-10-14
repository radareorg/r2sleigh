---
name: worktree-stash-shared
description: "git stash is shared across this repo's worktrees and holds the user's old WIP; never stash/pop blindly"
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-08T08:54:16.407Z
---

The repo's stash list (refs/stash) is shared by every worktree and holds the user's own old WIP entries (symex-rewrite, memory-value-provenance). On 2026-10-08 a `git stash -q && git rebase && git stash pop -q` in a clean worktree stashed nothing, so the pop applied the user's stash@{0} into the worktree (git kept the entry; undone with `git rm` of the conflicted paths).

**Why:** a quiet stash with nothing to save still lets the pop apply someone else's entry.

**How to apply:** before rebasing a worktree, commit or check `git status --short` is empty instead of stashing; if a stash is needed, use `git stash push -m <name>` and pop that exact entry by name. Related: [[item-branch-gate-policy]].
