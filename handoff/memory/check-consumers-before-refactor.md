---
name: check-consumers-before-refactor
description: "Before typing or rewriting an r2types pipeline, grep who reads its output; several were dead and deletion beat refactoring"
metadata:
  node_type: memory
  type: feedback
  originSessionId: f617cb1c-6459-42bc-b410-ade5debf9280
  modified: 2026-10-14T07:50:58.751Z
---

On 2026-10-14 the planned T step "type the string-keyed variable maps" turned out to target a dead output: `FunctionTypeFacts::visible_bindings` was built, canonicalized and stored, and nothing outside r2types read it. Stack variables were also built with kind `v` while their keys parsed only `b`/`s`, so that half never ran at all. Deleting the pipeline removed 804 lines with a byte-identical census (#237). Typing it would have been days of exactness work on code that changes nothing.

**Why:** r2types still carries afvj-era plumbing whose consumers were deleted with legacy r2dec; the roadmap names some of it as "to type" when it is really "to delete".

**How to apply:** before rewriting a fact's representation, grep every crate for its readers (and check `is_empty`/equality users by renaming the method and compiling). If nothing outside the producer reads it, delete it; measure the census. Related: [[rate-every-fix]], [[cache-last-resort]].
