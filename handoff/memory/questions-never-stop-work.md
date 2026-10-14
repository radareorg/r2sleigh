---
name: questions-never-stop-work
description: "a user question mid-work adds a task; answer it in a line or two and keep working in the same turn, never end the turn while queued work remains"
metadata:
  node_type: memory
  type: feedback
  originSessionId: f617cb1c-6459-42bc-b410-ade5debf9280
  modified: 2026-10-13T10:07:48.968Z
---

On 2026-10-13 the user asked "why did we stopped, keep things running, our convos should only add things up what to do, not to stop", after a reply to a side question (whether a radare2 review was legitimate) ended the turn with stack merges, equivalence checks, the Q3 retention change and an upstream fix still queued.

**Why:** the user runs a long autonomous /goal; each message adds work to the queue and never replaces it. A turn that ends after an answer leaves background waiters and half-done items idle until the next prompt.

**How to apply:** answer the question briefly inside the turn, then continue the highest-value queued item at once: running jobs, the roadmap item, PR fixes. End a turn only when no actionable work remains, or when every remaining item waits on a background notification. Related: [[loop-never-idles-on-merge-questions]].
