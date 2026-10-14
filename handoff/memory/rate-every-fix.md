---
name: rate-every-fix
description: after each implementation rate the fix out of 10; under 8-9 means rethink the owner and rewrite before landing
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-10T19:26:37.454Z
---

After an implementation, rate the fix out of 10 and say why. A fix rated under 8 to 9 is not landed as is: rethink the seam (owner, contract, data shape) and rewrite it so it rates 8+. User, 2026-10-11: "After an implementation always ask yourself if that fix rating out of 10, if it comes under 8-9 we should rethink the whole system to optimise and rewrite".

**Why:** AGENTS.md non-negotiable 9 (rewrite a bad seam instead of patching around it); a working patch with plumbing smells (extra tuple parameters, a contract arm that accepts anything) accumulates debt.

**How to apply:** state the rating with its reason in the commit or PR ("Quality: N/10, because ..."); below 8, name the cleaner owner and do that instead. Related: [[short-comments]], [[structure-bless-only-falls]].
