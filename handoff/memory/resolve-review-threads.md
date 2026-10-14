---
name: resolve-review-threads
description: a PR is ready to merge only when every GitHub review conversation on it is addressed and resolved
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-08T17:13:48.237Z
---

From 2026-10-08 the user wants this rule: "if you consider a PR to be ready to be merged then all of the GH convos should be addressed and resovled".

**Why:** the user merges the stack bottom-first; an open review thread on a "ready" PR blocks or misleads the merge.

**How to apply:**
- Before calling any PR ready, list its review threads (`gh api graphql` on `pullRequest.reviewThreads` with `isResolved`).
- For each unresolved thread: fix the code or answer with the reason, reply in the thread, then resolve it (`resolveReviewThread` mutation).
- Check the whole stack, not only the PR being worked on. Related: [[stacked-prs]], [[ci-ratchet-check]].

A PR can merge while its review fixes are still being pushed: #143 merged at `d0286513`, and the fix `be66ed30` replied as "fixed in" never landed (redone as #146). Before pushing a fix or replying "fixed in X", check the PR is still OPEN (`gh pr view N --json state`); if it merged, put the fix in a new PR and say so on the old one.
