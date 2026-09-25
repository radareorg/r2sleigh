Taint Analysis
==============

There is no taint analysis in the tree at present.

`r2ssa/src/taint.rs` was deleted. Nothing outside its own tests called it, and
the radare2 plugin that ran it during `aaaa` was deleted before it. It was also
not a sound base to build on:

- sources were keyed by register name (`input:rdi`), with the x86-64 SysV
  argument registers hard-coded as the default policy, so a name stood in for
  what the calling convention and the entry storage state;
- its label sets and per-variable state were `HashMap`/`HashSet`, so the order
  in which it reported anything depended on hashing;
- it was a second walk over def-use, beside the slicer, answering a question
  the slicer's forward direction already answers once labels are carried.

What replaces it
----------------

Taint is to be rebuilt as the labelled forward mode of the one slicer,
`r2ssa::slice` (plan track H, "wire or delete"):

- one slicer, three directions: backward, forward, and forward with labels,
  which is taint;
- it runs over SSA plus the memory SSA, so a store and the load it reaches are
  one edge rather than an alias guess;
- a seed is a typed value or entry storage (`CanonicalStorageId`), never a
  register name;
- it is exposed as the query `slice(entry, seed, dir)` and costs `O(V + E)` per
  query, with ordered sets so the answer is deterministic;
- interprocedural propagation uses callee summaries once those exist (P7).
