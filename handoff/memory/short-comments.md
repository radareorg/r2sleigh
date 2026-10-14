---
name: short-comments
description: code comments must be 1-2 lines; design/derivation goes in doc/adr-*.md
metadata:
  type: feedback
---

Code comments are one or two lines at most. The user strongly dislikes page-long comments.

**Why:** design, history, derivations and examples belong in the architecture docs, not in code.

**How to apply:** write 1-2 line comments with the invariant/reason and an ADR link. Move anything longer into `doc/adr-*.md`. Shorten long comments you touch. `structure-report.sh` ratchets `long_comments` (runs of more than two `//` lines), and the count must only fall. See [[user-facing-impact-table]].
