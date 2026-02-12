Taint Analysis
==============

Background
----------

Taint analysis tracks data flow from sources (user input, function arguments)
to sinks (dangerous calls, memory writes). r2sleigh implements SSA-based taint
analysis in `r2ssa/taint.rs`, propagating along precise def-use chains.

Core Types
----------

### TaintLabel

```rust
pub struct TaintLabel {
    pub id: String,
    pub description: Option<String>,
}
```

### TaintSet

`type TaintSet = HashSet<TaintLabel>` -- the set of labels tainting a variable.

### TaintPolicy Trait

```rust
pub trait TaintPolicy {
    fn is_source(&self, var: &SSAVar, block_addr: u64) -> Option<Vec<TaintLabel>>;
    fn is_sink(&self, op: &SSAOp, block_addr: u64) -> bool;
    fn is_sanitizer(&self, op: &SSAOp) -> bool { false }
    fn propagate(&self, op: &SSAOp, source_taints: &[&TaintSet]) -> Option<TaintSet> { None }
}
```

Implement this trait to customize taint behavior. The default propagation
rule is the union of all source taints.

### DefaultTaintPolicy

```rust
let policy = DefaultTaintPolicy::all_inputs();
let policy = DefaultTaintPolicy::all_inputs()
    .with_sinks(vec!["memcpy", "system"]);
```

Taints x86-64 SysV argument registers (rdi, rsi, rdx, rcx, r8, r9) by
default. Default sinks are Call and Store operations.

Running Analysis
----------------

```rust
let func = SSAFunction::from_blocks(&blocks).unwrap();
let policy = DefaultTaintPolicy::all_inputs();
let analysis = TaintAnalysis::new(&func, policy);
let result = analysis.analyze();
for hit in &result.sink_hits {
    println!("Taint at 0x{:x}: {:?}", hit.block_addr, hit.labels);
}
```

### TaintResult

```rust
pub struct TaintResult {
    pub sink_hits: Vec<SinkHit>,
    pub per_block: HashMap<u64, BlockTaintSummary>,
}
```

Propagation: taint is the union of all input taints. Phi nodes take the union
of all predecessors. Sanitizers (if configured) clear taint from their output.

Auto-Taint During aaaa
-----------------------

The radare2 plugin runs taint analysis automatically during `aaaa`
(post-analysis hook) for each function with at most 200 basic blocks. The
limit is configurable via the `SLEIGH_TAINT_MAX_BLOCKS` environment variable.

Results written to radare2:

**Comments** at each block with taint hits:

```
sla.taint: hits=3 calls=2 stores=1 labels=input:rdi,input:rsi
```

**Flags** for scripting and navigation:

```
sla.taint.fcn_0x401000.blk_0x401020
```

**Xrefs** from source blocks to sink blocks using `R_ANAL_REF_TYPE_DATA`.

Noise Filtering
---------------

Stack and frame pointer operations generate taint that is rarely interesting.
The plugin filters:

- `input:rsp` and `input:rbp` (stack/frame pointers)
- `input:ram:*` (memory-sourced taint)

Remaining labels are ranked by interestingness: function arguments first, then
other registers. User comments at the same address are preserved (merged, not
overwritten). Old taint artifacts are cleared before writing, ensuring
idempotent re-analysis.

Plugin Command
--------------

`a:sla.taint` outputs JSON taint analysis for the current function.

Example:

```bash
r2 -qc 'aaaa; s sym.vulnerable_function; a:sla.taint' ./target
```
