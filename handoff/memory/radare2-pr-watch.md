---
name: radare2-pr-watch
description: watch our upstream radare2 PRs for review comments (trufae, phix33, Codex) and address them promptly, verified and tested
metadata:
  type: feedback
---

On 2026-10-13 the user asked: "also keep an eye on r2 prs we raised if it has review comments to address". Our open radare2 PRs (author 0verflowme) get reviews from trufae, phix33 and the Codex bot, and trufae merges once every point is covered.

**Why:** upstream fixes stall unless each review point is answered with a fix, a test and numbers; the user does not want to track them by hand.

**How to apply:** keep a background watcher on the open PRs' comments, reviews and inline comments. Verify each point before acting (Codex is often right, sometimes wrong). Fix in the radare2 worktree, amend the PR's single commit as "Priyanshu Kumar <priyanshukumarpu@gmail.com>" with no assistant attribution, run the affected r2r suites, and reply in the thread with the commit and the test. A new fixture goes to radare2-testbins as its own PR (the Mac's testbins checkout has files XProtect deleted, so use the fork through the contents API). Related: [[advisor-for-design]].
