//! Which entries of a pointer table a call can actually reach.
//!
//! A call through `table[index]` reaches exactly the entries `index` can
//! select, and nothing else. What the dispatch reads is the whole of the
//! question: the value analysis answers what the load's address can be, and
//! a bounded strided interval over it *is* the read -- its low bound is the
//! first entry, its stride is the entry size, its high bound is the last.
//! Nothing here decomposes the address into a table and an index, or walks
//! the dominators for a bound on that index; the analysis has both already,
//! narrowed by the branches that had to be taken to arrive.
//!
//! The read is reported whether or not any table is known at it, because on
//! the native route nothing has read that memory yet and the description is
//! what says where to look.
//!
//! Failing closed is the point. An unproven target set would be a guess about
//! control flow, and a wrong edge is worse than a missing one.

use crate::SSAOp;
use crate::function::{SSAFunction, SsaArtifact};
use crate::graph::{GraphInst, InstPayload, SsaGraph, UseSite, ValueId};

pub(crate) fn exact_input(graph: &SsaGraph, inst: &GraphInst, input_idx: usize) -> Option<ValueId> {
    let value = *inst.inputs.get(input_idx)?;
    graph
        .use_sites(value)
        .binary_search(&UseSite {
            inst: inst.id,
            input_idx,
        })
        .is_ok()
        .then_some(value)
}

/// How a dispatch turns a table entry into the address it goes to.
///
/// `target = scale * entry + displacement`, read signed where the machine
/// sign-extended the entry. An absolute table is the identity; the compact
/// forms store an offset from a base the instruction stream carries, which is
/// the displacement, at the instruction size, which is the scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryTransform {
    pub scale: u64,
    pub displacement: u64,
    pub signed: bool,
}

impl EntryTransform {
    const IDENTITY: Self = Self {
        scale: 1,
        displacement: 0,
        signed: false,
    };

    /// Where the entry read out of the table sends control.
    pub fn target(&self, entry: u64, entry_size: u32) -> u64 {
        let entry = match self.signed {
            true => sign_extend(entry, entry_size),
            false => entry,
        };
        self.scale
            .wrapping_mul(entry)
            .wrapping_add(self.displacement)
    }
}

/// Read a table entry of `size` bytes as a signed value of the machine's width.
fn sign_extend(entry: u64, size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    match bits == 0 || bits >= 64 {
        true => entry,
        false => ((entry << (64 - bits)) as i64 >> (64 - bits)) as u64,
    }
}

/// How the address a dispatch reads is built from the value it switches on:
/// `address = scale * selector + displacement`, the index chain folded.
///
/// Kept apart from [`EntryTransform`], which says what an entry read *means*;
/// this says which entry a selector value *reads*, and its inverse is the case
/// label. A sign extension on the way is a fact about the entry, not about
/// the index, so nothing here carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexChain {
    pub scale: u64,
    pub displacement: u64,
}

impl IndexChain {
    /// The selector value that reads the entry at `address`, where exactly one does.
    fn preimage(&self, address: u64) -> Option<u64> {
        let offset = address.checked_sub(self.displacement)?;
        (self.scale != 0 && offset.is_multiple_of(self.scale)).then(|| offset / self.scale)
    }
}

/// Where a dispatch reads its target, before anything has read that memory.
///
/// The native route captures a function's own bytes and nothing else, so a
/// jump table in another section is unread at this point. This says where it
/// is, how far it runs, and what the entries mean, which is what a reader
/// needs to go and fetch it.
///
/// **Nothing here is sized by the count.** The value analysis proves how many
/// entries the selector can reach, and that proof is sound however large it
/// is: a spilled 32-bit index nothing guards reaches 2^32 of them. Whether
/// that much memory exists at the address, and holds what the program reads,
/// is the memory owner's question, which is asked before any entry is read.
/// So the read states `count`, `stride` and `size` and labels an entry only
/// when asked for it, and the O(1) span check that owner makes is what
/// refuses a table the program does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTableRead {
    pub block_addr: u64,
    pub op_index: usize,
    /// The instruction that makes the transfer, where the lift recorded it.
    /// What the body walk is keyed by, so it can be told where to continue.
    pub instruction: Option<u64>,
    /// The first entry the dispatch can read.
    pub address: u64,
    /// Bytes from one entry to the next.
    pub stride: u64,
    /// Bytes one entry read takes.
    pub size: u32,
    /// How many entries it can reach, counted from `address`: at least one,
    /// and at most 2^64 - 1, since a reach of every 64-bit address is refused
    /// before it is counted.
    pub count: u64,
    pub transform: EntryTransform,
    /// The value the dispatch switches on.
    pub selector: ValueId,
    /// How the address read is built from `selector`, whose inverse labels each entry.
    pub indexing: IndexChain,
}

impl DispatchTableRead {
    /// The address entry `k` is read from, for `k` below `count`.
    pub fn entry_address(&self, k: u64) -> Option<u64> {
        if k >= self.count {
            return None;
        }
        k.checked_mul(self.stride)?.checked_add(self.address)
    }

    /// What the selector is when the dispatch reads entry `k`, for `k` below `count`.
    ///
    /// Every label is exact: the read is refused at construction unless the
    /// first entry's preimage is whole and the stride is a multiple of the
    /// scale, which is when every entry's is.
    pub fn case(&self, k: u64) -> Option<u64> {
        self.indexing.preimage(self.entry_address(k)?)
    }

    /// Bytes from the first entry's start to the last entry's end, where that fits a `u64`.
    pub fn span(&self) -> Option<u64> {
        (self.count.checked_sub(1)?)
            .checked_mul(self.stride)?
            .checked_add(u64::from(self.size))
    }
}

/// Walk an index chain down to its end, folding the arithmetic on the way.
///
/// At every step `end = scale * value + displacement` holds of the value
/// reached, so the walk answers two questions at once: which value a target
/// or an address is built from, and how. A table of absolute addresses takes
/// one step with the identity; a compact table takes the add and the shift
/// that turn a byte into an instruction address.
///
/// The transform is dropped where a coefficient is not a constant, and the
/// walk goes on. Such a table's entries cannot be read, but which value it is
/// indexed by is still a fact, and naming it is what a switch needs.
fn walk_index(
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
    from: ValueId,
) -> (ValueId, Option<EntryTransform>) {
    let constant = |value: ValueId| values.get(value).and_then(|range| range.as_constant());
    let mut transform = Some(EntryTransform::IDENTITY);
    let mut at = from;
    while let Some(carries) = index_operand(graph, values, at) {
        let Some(inst) = graph.def_inst(at).and_then(|inst| graph.inst(inst)) else {
            break;
        };
        let InstPayload::Op(op) = &inst.payload else {
            break;
        };
        let coefficient = inst
            .inputs
            .iter()
            .find(|input| **input != carries)
            .and_then(|input| constant(*input));
        transform = transform.and_then(|mut transform| {
            match op {
                SSAOp::IntAdd { .. } => {
                    transform.displacement = transform
                        .displacement
                        .wrapping_add(transform.scale.wrapping_mul(coefficient?));
                }
                SSAOp::IntMult { .. } => {
                    transform.scale = transform.scale.wrapping_mul(coefficient?);
                }
                SSAOp::IntLeft { .. } => {
                    let places = u32::try_from(coefficient?).ok()?;
                    transform.scale = transform.scale.wrapping_mul(1u64.checked_shl(places)?);
                }
                SSAOp::IntSExt { .. } => transform.signed = true,
                _ => {}
            }
            Some(transform)
        });
        at = carries;
    }
    (at, transform)
}

/// The load a dispatch's target comes from, and the arithmetic between them.
fn table_entry_of<'a>(
    graph: &'a SsaGraph,
    values: &crate::values::ValueRanges,
    value: ValueId,
) -> Option<(&'a GraphInst, Option<EntryTransform>)> {
    let (entry, transform) = walk_index(graph, values, value);
    let inst = graph.inst(graph.def_inst(entry)?)?;
    matches!(inst.payload, InstPayload::Op(SSAOp::Load { .. })).then_some((inst, transform))
}

/// The value a dispatch switches on, and how the address is built from it.
///
/// The address a table is read at is built from the program's own selector by
/// scaling it and adding where the table lives, so the selector is the end of
/// that arithmetic walked back down. That end is what the program wrote --
/// `switch (n)` rather than `switch (n * 4 + 0x100000628)`, and the byte
/// itself where a table of states was read through one.
///
/// Taking the selector and its case labels from the same walk is what makes
/// them agree: a label is the value of the selector that puts the read on
/// that entry, which is the transform run backwards. Every step is injective,
/// so this is exact. A truncation is the step that is not, which is why the
/// walk does not cross one: the program compared the low half, and the
/// register it was cut from can hold values that comparison never saw.
fn selector_of(
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
    address: ValueId,
) -> (ValueId, Option<IndexChain>) {
    let (selector, folded) = walk_index(graph, values, address);
    let indexing = folded.map(|folded| IndexChain {
        scale: folded.scale,
        displacement: folded.displacement,
    });
    (selector, indexing)
}

/// The operand an address step carries its index in, where the step is one.
///
/// Of a sum, the index is the side that is not the base: the side the
/// analysis pinned to a constant is where the table lives, and where neither
/// is constant the scaled side is the index, because scaling by the entry
/// size is what indexing is. A load ends the walk -- what it read is the
/// index, which is how `switch (table[c])` names `c`.
fn index_operand(
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
    value: ValueId,
) -> Option<ValueId> {
    let inst = graph.inst(graph.def_inst(value)?)?;
    let InstPayload::Op(op) = &inst.payload else {
        return None;
    };
    let constant = |value: ValueId| values.get(value).and_then(|range| range.as_constant());
    let input = |index: usize| inst.inputs.get(index).copied();
    let scaled = |value: ValueId| {
        graph
            .def_inst(value)
            .and_then(|inst| graph.inst(inst))
            .is_some_and(|inst| {
                matches!(
                    inst.payload,
                    InstPayload::Op(SSAOp::IntMult { .. } | SSAOp::IntLeft { .. })
                )
            })
    };
    let index_of =
        |left: ValueId, right: ValueId| match (constant(left).is_some(), constant(right).is_some())
        {
            (true, false) => Some(right),
            (false, true) => Some(left),
            _ => match (scaled(left), scaled(right)) {
                (true, false) => Some(left),
                (false, true) => Some(right),
                _ => None,
            },
        };
    match op {
        SSAOp::Copy { .. } | SSAOp::Cast { .. } | SSAOp::IntZExt { .. } | SSAOp::IntSExt { .. } => {
            input(0)
        }
        SSAOp::IntAdd { .. } => index_of(input(0)?, input(1)?),
        SSAOp::IntMult { .. } => match (constant(input(0)?), constant(input(1)?)) {
            (Some(_), None) => input(1),
            (None, Some(_)) => input(0),
            _ => None,
        },
        SSAOp::IntLeft { .. } => constant(input(1)?).and(input(0)),
        _ => None,
    }
}

/// The load one indirect transfer takes its target from, and how.
fn dispatch_load<'a>(
    graph: &'a SsaGraph,
    values: &crate::values::ValueRanges,
    block_addr: u64,
    op_index: usize,
    op: &SSAOp,
) -> Option<(Option<&'a GraphInst>, Option<EntryTransform>, ValueId)> {
    // A tail call through a table is a branch, not a call, and it reaches the
    // same set of functions either way.
    let (SSAOp::CallInd { target, .. } | SSAOp::BranchInd { target, .. }) = op else {
        return None;
    };
    let call_inst = graph
        .inst_id_for_op_site(block_addr, op_index)
        .and_then(|inst| graph.inst(inst))?;
    let target_value = exact_input(graph, call_inst, 0)?;
    if graph.value_id_for_var(target) != Some(target_value) {
        return None;
    }
    let target_value = crate::constant::root_of(graph, target_value);
    let Some((load_inst, transform)) = table_entry_of(graph, values, target_value) else {
        // Nothing read it: the branch goes through a register the walk cannot
        // see a producer for, and that register is what it switches on.
        return Some((None, None, target_value));
    };
    let address = exact_input(graph, load_inst, 0)?;
    Some((Some(load_inst), transform, address))
}

/// Where one indirect transfer reads its target, where that is a table read.
fn dispatch_table_read(
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
    block_addr: u64,
    op_index: usize,
    op: &SSAOp,
) -> Option<DispatchTableRead> {
    let (SSAOp::CallInd { instruction, .. } | SSAOp::BranchInd { instruction, .. }) = op else {
        return None;
    };
    // What stopped a dispatch resolving is the one thing worth saying about
    // it: either the target is not read out of memory, or what it reads is
    // not a bounded walk of one table.
    let evidence = |why: &str| {
        r2il::refusal_evidence!("dispatch-table", "{block_addr:#x}:{op_index}: {why}");
    };
    let Some((Some(load_inst), Some(transform), address)) =
        dispatch_load(graph, values, block_addr, op_index, op)
    else {
        evidence("the target is not a constant affine function of a load");
        return None;
    };
    let InstPayload::Op(SSAOp::Load { dst, .. }) = &load_inst.payload else {
        return None;
    };
    let reach = values
        .get(address)
        .unwrap_or_else(|| crate::StridedInterval::top(64));
    let (Some((base, last)), Some(stride)) = (reach.bounds(), reach.stride()) else {
        evidence(&format!("the address {address:?} reaches only {reach:?}"));
        return None;
    };
    // The entry size is how far the read steps and how wide it reads. A read
    // that steps by anything but what it reads leaves gaps or overlaps, and
    // neither is a table walk.
    if u64::from(dst.size) != stride {
        evidence(&format!(
            "it steps by {stride} and reads {} bytes",
            dst.size
        ));
        return None;
    }
    // Every 64-bit address is 2^64 entries, which is no table any program
    // holds and no count a `u64` can state.
    let Some(count) = reach.count() else {
        evidence(&format!(
            "the address {address:?} reaches every address of its width"
        ));
        return None;
    };
    let (selector, indexing) = selector_of(graph, values, address);
    // What the selector was on an entry is where that entry sits, put back
    // through the arithmetic that placed it. The entries are `base + k *
    // stride`, so every one has a whole preimage exactly when the first does
    // and the stride is a multiple of the scale: one test, not one per entry.
    let labelled = indexing.filter(|indexing| {
        indexing.preimage(base).is_some() && stride.is_multiple_of(indexing.scale)
    });
    let Some(indexing) = labelled else {
        evidence(&format!(
            "selector {selector:?} does not label {count} entries"
        ));
        return None;
    };
    r2il::refusal_evidence!(
        "dispatch-table",
        "{block_addr:#x}:{op_index} at {instruction:?} reads {count} entries {base:#x}..={last:#x} by {stride}, target = {}*entry + {:#x}, on {selector:?}",
        transform.scale,
        transform.displacement
    );
    Some(DispatchTableRead {
        block_addr,
        op_index,
        instruction: *instruction,
        address: base,
        stride,
        size: dst.size,
        count,
        transform,
        selector,
        indexing,
    })
}

/// What each dispatching block switches on.
///
/// Offered to the phase that records what a switch is about. Walking the
/// operations back from the branch is what this replaces: the arithmetic
/// between a selector and a table address is affine, and which of its
/// operands is the base is a question about values rather than about opcodes.
pub(crate) fn dispatch_selectors(
    function: &SSAFunction,
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
) -> std::collections::BTreeMap<u64, ValueId> {
    function
        .blocks()
        .iter()
        .filter_map(|block| {
            let (op_index, op) =
                block.ops.iter().enumerate().rev().find(|(_, op)| {
                    matches!(op, SSAOp::CallInd { .. } | SSAOp::BranchInd { .. })
                })?;
            let (_, _, address) = dispatch_load(graph, values, block.addr, op_index, op)?;
            Some((block.addr, selector_of(graph, values, address).0))
        })
        .collect()
}

/// Every dispatch in one function that reads its target from a table.
fn dispatch_table_reads_in_graph(
    function: &SSAFunction,
    graph: &SsaGraph,
    values: &crate::values::ValueRanges,
) -> Vec<DispatchTableRead> {
    function
        .blocks()
        .iter()
        .flat_map(|block| {
            block.ops.iter().enumerate().filter_map(|(op_index, op)| {
                dispatch_table_read(graph, values, block.addr, op_index, op)
            })
        })
        .collect()
}

/// Where every dispatch in one function reads its target.
///
/// Answered without any table in hand, which is how the native route learns
/// which memory it has to read before it can resolve anything.
pub fn dispatch_table_reads(artifact: &SsaArtifact) -> Vec<DispatchTableRead> {
    dispatch_table_reads_in_graph(
        artifact.function(),
        artifact.graph(),
        &artifact.facts().values,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SSAVar;
    use crate::cfg::CFG;
    use crate::domtree::DomTree;
    use crate::function::SSABlock;

    /// What each dispatch in these blocks says it reads.
    ///
    /// Answered without a table in hand, because that is how the engine asks:
    /// the read states where the table is and how far it runs, and whoever
    /// owns the bytes proves the rest.
    fn test_dispatch_reads(blocks: &[SSABlock], cfg: &CFG) -> Vec<DispatchTableRead> {
        let function = SSAFunction::from_exact_test_blocks(blocks, cfg.clone());
        let graph = SsaGraph::from_function(&function);
        // The dispatch is resolved from what the address can be, so the test
        // solves for that exactly as the analysis phase does.
        let predicates = crate::semantic::collect_predicate_facts_for_test(&function, &graph);
        let values = crate::values::solve_value_ranges(&graph, &function, &predicates);
        dispatch_table_reads_in_graph(&function, &graph, &values)
    }

    /// The graph for a straight guard: entry dominates both arms.
    fn graph_for(blocks: &[SSABlock], taken: u64, fallthrough: Option<u64>) -> (CFG, DomTree) {
        let entry = blocks[0].addr;
        let mut cfg = crate::cfg::CFG::new(entry);
        for block in blocks {
            let mut basic = crate::cfg::BasicBlock::new(block.addr);
            basic.size = block.size;
            basic.terminator = if block.addr != entry {
                crate::cfg::BlockTerminator::Return
            } else if let Some(next) = fallthrough {
                crate::cfg::BlockTerminator::ConditionalBranch {
                    true_target: taken,
                    false_target: next,
                }
            } else {
                crate::cfg::BlockTerminator::Return
            };
            cfg.add_block(basic);
        }
        cfg.rebuild_edges();
        let domtree = DomTree::compute(&cfg);
        (cfg, domtree)
    }

    fn input(name: &str, size: u32) -> SSAVar {
        SSAVar::new(name, 0, size)
    }

    fn temp(name: &str, size: u32) -> SSAVar {
        SSAVar::new(name, 1, size)
    }

    /// A guarded dispatch: `if (i >= 5) return; call table[i]`.
    ///
    /// Block 0 tests the bound and branches away on failure, so arriving at
    /// block 0x20 proves `i < 5`; the unsigned test proves `i >= 0`.
    fn guarded_dispatch(bound: u64) -> Vec<SSABlock> {
        let index = input("index", 8);
        let cond = temp("cond", 1);
        let scaled = temp("scaled", 8);
        let addr = temp("addr", 8);
        let callee = temp("callee", 8);
        let blocks = vec![
            SSABlock {
                addr: 0,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntLess {
                        dst: cond.clone(),
                        a: index.clone(),
                        b: SSAVar::constant(bound, 8),
                    },
                    SSAOp::CBranch {
                        target: SSAVar::constant(0x20, 8),
                        cond,
                    },
                ],
            },
            SSABlock {
                addr: 0x10,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![SSAOp::Return {
                    target: SSAVar::constant(0, 8),
                }],
            },
            SSABlock {
                addr: 0x20,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntMult {
                        dst: scaled.clone(),
                        a: index,
                        b: SSAVar::constant(8, 8),
                    },
                    SSAOp::IntAdd {
                        dst: addr.clone(),
                        a: SSAVar::constant(0xc000, 8),
                        b: scaled,
                    },
                    SSAOp::Load {
                        dst: callee.clone(),
                        space: r2il::SpaceId::Ram,
                        addr,
                    },
                    SSAOp::CallInd {
                        target: callee,
                        instruction: None,
                    },
                ],
            },
        ];
        blocks
    }

    #[test]
    fn a_guarded_index_reads_exactly_the_entries_it_can_select() {
        let blocks = guarded_dispatch(5);
        let (cfg, _) = graph_for(&blocks, 0x20, Some(0x10));
        let reads = test_dispatch_reads(&blocks, &cfg);
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].address, 0xc000);
        assert_eq!(reads[0].count, 5);
        assert_eq!((reads[0].stride, reads[0].size), (8, 8));
        // Entry k is where the selector is k: the scale is the entry size.
        assert_eq!(
            (0..5).map(|k| reads[0].case(k)).collect::<Vec<_>>(),
            (0..5).map(Some).collect::<Vec<_>>()
        );
        assert_eq!(reads[0].case(5), None);
        assert_eq!(reads[0].span(), Some(40));
    }

    #[test]
    fn a_guard_wider_than_the_table_reads_wider_than_the_table() {
        // The index may reach past the entries the table holds, and the read
        // says so rather than truncating: nine entries is what the guard
        // permits, and whoever owns the bytes refuses the four that are not
        // instructions.
        let blocks = guarded_dispatch(9);
        let (cfg, _) = graph_for(&blocks, 0x20, Some(0x10));
        let reads = test_dispatch_reads(&blocks, &cfg);
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].count, 9);
    }

    /// The shape hardware actually emits, taken from an arm64 -O1 dispatch.
    ///
    /// `cmp w0, 3` lands in a flag, `b.ls` tests its negation, the table base
    /// is built by `adrp`+`add`, and the transfer is a tail-call branch. None
    /// of it is a literal operand, and all of it is exact.
    fn hardware_dispatch() -> Vec<SSABlock> {
        let index = input("w0", 4);
        let flag = temp("cy", 1);
        let zero = temp("zr", 1);
        let negated = temp("tmp:b00", 1);
        let lower_or_same = temp("tmp:1000", 1);
        let page = temp("x8_page", 8);
        let base = temp("x8", 8);
        let widened = temp("x9", 8);
        let scaled = temp("tmp:7100", 8);
        let addr = temp("tmp:7580", 8);
        let callee = temp("x3", 8);
        let blocks = vec![
            SSABlock {
                addr: 0,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    // arm64 `cmp w0, 3` then `b.ls`: the branch tests
                    // `!cy || zr`, where cy is `3 <= w0` and zr is `w0 == 3`.
                    // Together they prove `w0 <= 3` and nothing narrower.
                    SSAOp::IntLessEqual {
                        dst: flag.clone(),
                        a: SSAVar::constant(3, 4),
                        b: index.clone(),
                    },
                    SSAOp::IntEqual {
                        dst: zero.clone(),
                        a: index.clone(),
                        b: SSAVar::constant(3, 4),
                    },
                    SSAOp::BoolNot {
                        dst: negated.clone(),
                        src: flag,
                    },
                    SSAOp::BoolOr {
                        dst: lower_or_same.clone(),
                        a: negated,
                        b: zero,
                    },
                    SSAOp::CBranch {
                        target: SSAVar::new("ram:20", 0, 8),
                        cond: lower_or_same,
                    },
                ],
            },
            SSABlock {
                addr: 0x10,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![SSAOp::Return {
                    target: SSAVar::constant(0, 8),
                }],
            },
            SSABlock {
                addr: 0x20,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    // adrp x8, 0xc000 ; add x8, x8, 0x10
                    SSAOp::Copy {
                        dst: page.clone(),
                        src: SSAVar::constant(0xc000, 8),
                    },
                    SSAOp::IntAdd {
                        dst: base.clone(),
                        a: page,
                        b: SSAVar::constant(0x10, 8),
                    },
                    SSAOp::IntZExt {
                        dst: widened.clone(),
                        src: index,
                    },
                    SSAOp::IntLeft {
                        dst: scaled.clone(),
                        a: widened,
                        b: SSAVar::constant(3, 8),
                    },
                    SSAOp::IntAdd {
                        dst: addr.clone(),
                        a: base,
                        b: scaled,
                    },
                    SSAOp::Load {
                        dst: callee.clone(),
                        space: r2il::SpaceId::Ram,
                        addr,
                    },
                    SSAOp::BranchInd {
                        target: callee,
                        instruction: None,
                    },
                ],
            },
        ];
        // The table was read from 0xc000, but the code indexes from 0xc010.
        blocks
    }

    #[test]
    fn a_flag_tested_by_its_negation_still_bounds_the_index() {
        // Two entries precede the base the code indexes from, and four follow,
        // so the read starts at the base rather than at the table.
        let blocks = hardware_dispatch();
        let (cfg, _) = graph_for(&blocks, 0x20, Some(0x10));
        let reads = test_dispatch_reads(&blocks, &cfg);
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].address, 0xc010);
        assert_eq!(reads[0].count, 4);
    }

    #[test]
    fn an_unguarded_index_resolves_to_nothing() {
        let index = input("index", 8);
        let scaled = temp("scaled", 8);
        let addr = temp("addr", 8);
        let callee = temp("callee", 8);
        let blocks = vec![SSABlock {
            addr: 0,
            phis: Vec::new(),
            size: 0x10,
            ops: vec![
                SSAOp::IntMult {
                    dst: scaled.clone(),
                    a: index,
                    b: SSAVar::constant(8, 8),
                },
                SSAOp::IntAdd {
                    dst: addr.clone(),
                    a: SSAVar::constant(0xc000, 8),
                    b: scaled,
                },
                SSAOp::Load {
                    dst: callee.clone(),
                    space: r2il::SpaceId::Ram,
                    addr,
                },
                SSAOp::CallInd {
                    target: callee,
                    instruction: None,
                },
            ],
        }];
        let (cfg, _) = graph_for(&blocks, 0, None);
        assert!(test_dispatch_reads(&blocks, &cfg).is_empty());
    }

    #[test]
    fn colliding_display_spelling_cannot_transfer_a_bound_between_values() {
        let narrow_index = input("index", 4);
        let wide_index = input("index", 8);
        assert_eq!(narrow_index.display_name(), wide_index.display_name());
        let condition = temp("condition", 1);
        let scaled = temp("scaled", 8);
        let address = temp("address", 8);
        let callee = temp("callee", 8);
        let blocks = vec![
            SSABlock {
                addr: 0,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntLess {
                        dst: condition.clone(),
                        a: narrow_index,
                        b: SSAVar::constant(2, 4),
                    },
                    SSAOp::CBranch {
                        target: SSAVar::constant(0x20, 8),
                        cond: condition,
                    },
                ],
            },
            SSABlock {
                addr: 0x10,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![SSAOp::Return {
                    target: SSAVar::constant(0, 8),
                }],
            },
            SSABlock {
                addr: 0x20,
                phis: Vec::new(),
                size: 0x10,
                ops: vec![
                    SSAOp::IntMult {
                        dst: scaled.clone(),
                        a: wide_index,
                        b: SSAVar::constant(8, 8),
                    },
                    SSAOp::IntAdd {
                        dst: address.clone(),
                        a: SSAVar::constant(0xc000, 8),
                        b: scaled,
                    },
                    SSAOp::Load {
                        dst: callee.clone(),
                        space: r2il::SpaceId::Ram,
                        addr: address,
                    },
                    SSAOp::CallInd {
                        target: callee,
                        instruction: None,
                    },
                ],
            },
        ];
        let (cfg, _) = graph_for(&blocks, 0x20, Some(0x10));
        assert!(test_dispatch_reads(&blocks, &cfg).is_empty());
    }

    /// gcc -O0's relative jump table read through an index nothing guards:
    /// `movsxd rax, [0x2018 + zext(eax) * 4]; add rax, 0x2018; jmp rax`.
    ///
    /// This is `classify` at -O0, whose `cmp [rbp-4], 7` guards a load the
    /// dispatch does not read: the index reaches every 32-bit value, which is
    /// a sound fact the value analysis proves.
    #[test]
    fn a_selector_every_thirty_two_bit_value_reaches_is_counted_and_labelled_on_demand() {
        let index = input("eax", 4);
        let widened = temp("rax", 8);
        let scaled = temp("scaled", 8);
        let address = temp("address", 8);
        let entry = temp("entry", 4);
        let extended = temp("extended", 8);
        let target = temp("target", 8);
        let blocks = vec![SSABlock {
            addr: 0,
            phis: Vec::new(),
            size: 0x10,
            ops: vec![
                SSAOp::IntZExt {
                    dst: widened.clone(),
                    src: index,
                },
                SSAOp::IntMult {
                    dst: scaled.clone(),
                    a: widened,
                    b: SSAVar::constant(4, 8),
                },
                SSAOp::IntAdd {
                    dst: address.clone(),
                    a: scaled,
                    b: SSAVar::constant(0x2018, 8),
                },
                SSAOp::Load {
                    dst: entry.clone(),
                    space: r2il::SpaceId::Ram,
                    addr: address,
                },
                SSAOp::IntSExt {
                    dst: extended.clone(),
                    src: entry,
                },
                SSAOp::IntAdd {
                    dst: target.clone(),
                    a: extended,
                    b: SSAVar::constant(0x2018, 8),
                },
                SSAOp::BranchInd {
                    target,
                    instruction: None,
                },
            ],
        }];
        let (cfg, _) = graph_for(&blocks, 0, None);
        // The old read built one label per entry before anything asked
        // whether 16 GiB of table exists at 0x2018: a 32 GiB vector.
        let reads = test_dispatch_reads(&blocks, &cfg);
        assert_eq!(reads.len(), 1);
        let read = &reads[0];
        assert_eq!((read.address, read.stride, read.size), (0x2018, 4, 4));
        assert_eq!(read.count, 1 << 32);
        assert_eq!(read.case(0), Some(0));
        assert_eq!(read.case(0xffff_ffff), Some(0xffff_ffff));
        assert_eq!(read.case(1 << 32), None);
        assert_eq!(read.span(), Some(1 << 34));
        assert_eq!(
            (read.transform.displacement, read.transform.signed),
            (0x2018, true)
        );
    }

    /// A one-byte load through an address nothing bounds: every 64-bit
    /// address, stepped by one, which is 2^64 entries.
    #[test]
    fn a_load_through_every_address_is_no_table_and_no_overflow() {
        let pointer = input("rdi", 8);
        let byte = temp("byte", 1);
        let target = temp("target", 8);
        let blocks = vec![SSABlock {
            addr: 0,
            phis: Vec::new(),
            size: 0x10,
            ops: vec![
                SSAOp::Load {
                    dst: byte.clone(),
                    space: r2il::SpaceId::Ram,
                    addr: pointer,
                },
                SSAOp::IntZExt {
                    dst: target.clone(),
                    src: byte,
                },
                SSAOp::BranchInd {
                    target,
                    instruction: None,
                },
            ],
        }];
        let (cfg, _) = graph_for(&blocks, 0, None);
        // The old count overflowed: a panic in debug, and a zero-entry table
        // in release that the engine then resolved to no successor at all.
        assert!(test_dispatch_reads(&blocks, &cfg).is_empty());
    }
}
