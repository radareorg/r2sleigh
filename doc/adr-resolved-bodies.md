# ADR: One resolved body per function (P6)

Status: accepted, in progress.

## Context

A root function is walked, read for dispatch tables, walked again through
them, prepared, restated and prepared again. A callee gets none of that:
`prepare_callee` walks it once with no arms and prepares it against its
imports alone. So a callee's switch arms are never seen, a callee knows
nothing of its own callees, and a parameter a body hands to another body is
never followed (Q3e found the forwarding path unreachable). Two
preparations exist for one function, and which one a function gets depends
on who asked.

## Decision

One function has one resolved body, whoever asks, built by four queries:

1. `Walked(f)`: the walk, and where an indirect branch is unresolved, the
   dispatch pass: prepare against the imports' declarations alone, read
   the tables, walk again through them. Its value is the body, the tables
   and the direct callees. A table is intraprocedural, so the evidence a
   table read needs is the body and its imports, never another body.
2. `Component(f)`: the strongly connected component of the call graph
   `Walked` states, by Tarjan's algorithm from `f`; every component the
   search closes is deposited, so the closure is searched once.
3. `Summaries(component)`: each member resolved against the summaries of
   the components below it, then the members' summaries composed to a
   fixpoint with r2ssa's interprocedural transfer (`resolve_summary`,
   whose lattice and round bound already terminate). No member is
   prepared again inside the fixpoint.
4. `Resolved(f)`: `f` prepared, restated and prepared again against its
   callees' summaries: those of lower components, and for members of its
   own component the composed ones.

The call graph is the resolved walks' own, so no query reads a callee
outside the components that order them; a `Cycle` the database still
meets (a call no walk states) degrades that callee to unknown and is
`Hold::Transient`.

### Demand

A callee is resolved only where its caller's preparation has a call it
cannot prove (an argument or a return); other callees keep their walk.
Measured 2026-10-06: walking pumasim `main`'s reachable graph alone is 1949
walks and 2.6 s, so resolving the whole closure is not the default.

### Budget

Resolving a root resolves what its unproven calls demand. A request carries a
work budget in preparations; a summary the budget stops is the request's
stop (`Hold::Stopped`): never held, the call rendered as a callee not read
for the budget, and the summaries finished before the stop are held, so
the next request goes further. Every held answer is still a function of
the program alone.

## Complexity

Walks: one per function in the closure, held. Components: Tarjan, O(V + E)
over the closure, once. Preparations: three per function at most (dispatch
pass, first, restated), each once per state of what it read. Composition:
r2ssa's bound per component, over summaries, never bodies.

## Steps

- P6a: `Walked` is a query and the root analysis reads it.
- P6b: `Component` and the closure measured on 0pack and pumasim.
- P6c: `Summaries` and `Resolved` with the budget; `read_callees`,
  `CalleeReads`, `prepare_callee` and `callee_summary` deleted.
- P6d: composition inside a component; pointer forwarding through bodies
  reachable.
