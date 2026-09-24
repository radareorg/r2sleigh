//! Merges that nothing observes.
//!
//! A lifted body merges every storage live across a join, so an exit block ends
//! up holding a phi for each condition-code bit and each Sleigh temporary that
//! happened to be written on either side. A twelve-instruction function produces
//! forty-nine of them, twenty-four at one loop header, and every rule that has to
//! decide what a loop carries, what deserves a name, or what the output owes has
//! to look at all of them and reject the ones that mean nothing.
//!
//! Removing them was not previously safe to attempt, because "nothing reads this"
//! was not a question the SSA could answer: the value a function returns has no
//! reader in its own body either. With [`crate::liveout`] saying what leaves
//! through the calling convention, the question is answerable, and the ordinary
//! answer applies -- a value is observed if something with an effect depends on
//! it, and a merge no observation depends on is not part of the program.
//!
//! This reports what it found rather than editing the function, and that is not
//! caution: the symbolic executor propagates machine state through merges, so a
//! merge no value observation depends on can still be the only thing telling the
//! executor what a register holds at a loop head. Removing them outright loses a
//! VM dispatch summary that depended on exactly such a merge. Two consumers hold
//! different and both-correct views of the same function, so the set is published
//! for the rules that reason about candidates and the function is left alone for
//! the rules that simulate it.

use std::collections::{BTreeSet, VecDeque};

use crate::graph::{InstId, SsaGraph, UseSite, ValueId};
use crate::liveout::FunctionLiveOut;
use crate::obligation::{SemanticInstructionState, SemanticObligationInventory};
use crate::semantic::{PreparedFunctionFacts, SourceBoundaryFacts, SourceCallArgumentValue};

/// Which merges no observation depends on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeadPhis {
    values: BTreeSet<ValueId>,
    /// Complete pure value domain on which no program observation depends.
    ///
    /// This includes dead merge inputs such as an entry condition-code value,
    /// not only the merge outputs. Outputs of effectful operations are kept out
    /// even when nobody consumes their result: the operation still owes its
    /// memory/control/call occurrence.
    unobserved_values: BTreeSet<ValueId>,
    unobserved_insts: BTreeSet<InstId>,
    unobserved_uses: BTreeSet<UseSite>,
}

/// Values with positive evidence that the program observes them.
///
/// This is deliberately not the complement of [`DeadPhis::unobserved_values`].
/// An unsupported instruction can prevent a value from being proven dead, but
/// that uncertainty is refusal evidence, not positive proof that the source
/// program reads the value. Consumers such as interface recovery may make a
/// positive claim only from this narrower certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenProgramObservations {
    values: BTreeSet<ValueId>,
    /// The bytes of each observed value some observation reaches.
    bytes: std::collections::BTreeMap<ValueId, ByteMask>,
    /// The value through which each observed value was reached, so a claim
    /// that something is observed can name the observation it rests on.
    parents: std::collections::BTreeMap<ValueId, ValueId>,
    /// Why each root is one: the obligation that reads it, or the return.
    roots: std::collections::BTreeMap<ValueId, String>,
}

struct Closure {
    values: BTreeSet<ValueId>,
    bytes: std::collections::BTreeMap<ValueId, ByteMask>,
    parents: std::collections::BTreeMap<ValueId, ValueId>,
}

/// The bytes of a value an observation reaches, one bit per byte.
///
/// Bit `b` stands for byte `b`, least significant first, so a slice offset, a
/// tile width, a widening and a constant's surviving bytes are all counted in
/// the one unit a value's size is counted in. One word names 64 bytes; a
/// value wider than that, and any shift that would carry an observed byte out
/// of the word, is [`ByteMask::All`]. Saturating to every byte is the side
/// this may err on: an unobserved byte called observed costs a formal or a
/// merge that was not needed, while an observed byte called unobserved drops
/// an argument the program reads and leaves its read uninitialised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteMask {
    /// Exactly these bytes, bit `b` for byte `b`.
    Bytes(u64),
    /// Every byte of the value, however wide.
    All,
}

impl ByteMask {
    /// No byte.
    pub const NONE: Self = Self::Bytes(0);

    /// Every byte of a value `size_bytes` wide.
    pub const fn whole(size_bytes: u32) -> Self {
        match size_bytes {
            0..64 => Self::Bytes((1u64 << size_bytes) - 1),
            64 => Self::Bytes(u64::MAX),
            _ => Self::All,
        }
    }

    /// The bytes of a constant `size_bytes` wide that are not zero, which
    /// are the only bytes an `and` with it lets through.
    ///
    /// A constant carries at most eight bytes of bits and is zero above them.
    fn nonzero_bytes_of(bits: u64, size_bytes: u32) -> Self {
        let mut mask = 0u64;
        for byte in 0..size_bytes.min(8) {
            if (bits >> (8 * byte)) & 0xff != 0 {
                mask |= 1 << byte;
            }
        }
        Self::Bytes(mask)
    }

    /// Whether the mask names no byte at all.
    pub const fn is_empty(self) -> bool {
        matches!(self, Self::Bytes(0))
    }

    /// The bytes in either mask.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bytes(a), Self::Bytes(b)) => Self::Bytes(a | b),
            _ => Self::All,
        }
    }

    /// The bytes in both masks.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bytes(a), Self::Bytes(b)) => Self::Bytes(a & b),
            (Self::All, other) | (other, Self::All) => other,
        }
    }

    /// The same bytes `bytes` places more significant, as a slice at offset
    /// `bytes` asks of the value it is cut from.
    ///
    /// A byte carried past the word saturates to every byte rather than
    /// falling off.
    #[must_use]
    pub const fn shifted_up(self, bytes: u32) -> Self {
        match self {
            Self::Bytes(0) => Self::NONE,
            Self::Bytes(mask) if bytes < 64 && mask.leading_zeros() >= bytes => {
                Self::Bytes(mask << bytes)
            }
            _ => Self::All,
        }
    }

    /// The same bytes `bytes` places less significant, as a concatenation
    /// asks of its high tile when the low tile is `bytes` wide.
    ///
    /// A byte below the shift belongs to the low tile. An exact mask names
    /// nothing at or above byte 64, so nothing observed falls off the top.
    #[must_use]
    pub const fn shifted_down(self, bytes: u32) -> Self {
        match self {
            Self::Bytes(mask) => Self::Bytes(if bytes < 64 { mask >> bytes } else { 0 }),
            Self::All => Self::All,
        }
    }

    /// How many least significant bytes the mask names, when it names exactly
    /// that low run and nothing above it; `None` for no byte, a gap, or a mask
    /// saturated past what one word can say.
    pub const fn low_bytes(self) -> Option<u32> {
        let Self::Bytes(mask) = self else {
            return None;
        };
        let bytes = mask.trailing_ones();
        if bytes > 0 && (bytes == 64 || mask >> bytes == 0) {
            Some(bytes)
        } else {
            None
        }
    }
}

impl std::fmt::Display for ByteMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(mask) => write!(f, "{mask:#x}"),
            Self::All => f.write_str("all"),
        }
    }
}

/// What an observation of `observed` bytes of a value asks of each input.
///
/// A slice, a concatenation, a widening, a copy, a merge and a mask with a
/// constant each read only some bytes of what feeds them; everything else is
/// taken to read all of its operands. A byte no observation reaches is not
/// observed, which is what stops a byte the program overwrote from admitting
/// the caller's register as a parameter.
///
/// Every rule here may name more bytes than an input has; the closure trims
/// each mask to its value's width, and a value whose width is unknown is
/// taken whole.
fn observed_input_bytes(
    graph: &SsaGraph,
    inst: &crate::graph::GraphInst,
    observed: ByteMask,
) -> Vec<(ValueId, ByteMask)> {
    use crate::graph::InstPayload;
    let size_of = |value: ValueId| graph.value(value).map(|value| value.var.size);
    let constant = |value: ValueId| {
        graph
            .value(value)
            .and_then(|value| value.var.constant_bits())
    };
    // Every byte, which the closure trims to the input's own width.
    let whole = |value: ValueId| (value, ByteMask::All);
    let inputs = &inst.inputs;
    match &inst.payload {
        InstPayload::Phi { .. } => inputs.iter().map(|input| (*input, observed)).collect(),
        InstPayload::Op(op) => match op {
            crate::SSAOp::Copy { .. } if inputs.len() == 1 => vec![(inputs[0], observed)],
            crate::SSAOp::Subpiece { offset, .. } if inputs.len() == 1 => {
                vec![(inputs[0], observed.shifted_up(*offset))]
            }
            crate::SSAOp::Piece { .. } if inputs.len() == 2 => match size_of(inputs[1]) {
                Some(lo_bytes) => vec![
                    (inputs[0], observed.shifted_down(lo_bytes)),
                    (inputs[1], observed.intersection(ByteMask::whole(lo_bytes))),
                ],
                None => inputs.iter().map(|input| whole(*input)).collect(),
            },
            crate::SSAOp::IntZExt { .. } if inputs.len() == 1 => {
                let source = size_of(inputs[0]).map_or(ByteMask::All, ByteMask::whole);
                vec![(inputs[0], observed.intersection(source))]
            }
            crate::SSAOp::IntAnd { .. } if inputs.len() == 2 => {
                let mask_of = |value: ValueId| {
                    constant(value)
                        .zip(size_of(value))
                        .map(|(bits, size)| ByteMask::nonzero_bytes_of(bits, size))
                };
                match (mask_of(inputs[0]), mask_of(inputs[1])) {
                    (None, Some(mask)) => vec![(inputs[0], observed.intersection(mask))],
                    (Some(mask), None) => vec![(inputs[1], observed.intersection(mask))],
                    _ => inputs.iter().map(|input| (*input, observed)).collect(),
                }
            }
            _ => inputs.iter().map(|input| whole(*input)).collect(),
        },
    }
}

/// Every value some root depends on, with the bytes of it that dependence
/// reaches.
///
/// A mask only grows, by union, and is trimmed to its value's width, so a
/// value is queued again only when it gains a byte or saturates -- at most 65
/// times -- and the walk stays linear in the graph's edges.
fn dependency_closure(graph: &SsaGraph, roots: impl IntoIterator<Item = ValueId>) -> Closure {
    let width = |value: ValueId| {
        graph
            .value(value)
            .map_or(ByteMask::All, |value| ByteMask::whole(value.var.size))
    };
    let mut bytes: std::collections::BTreeMap<ValueId, ByteMask> =
        std::collections::BTreeMap::new();
    let mut parents = std::collections::BTreeMap::new();
    let mut pending = VecDeque::new();
    for value in roots {
        let mask = width(value);
        if !mask.is_empty() && bytes.insert(value, mask).is_none() {
            pending.push_back(value);
        }
    }
    while let Some(value) = pending.pop_front() {
        let observed = bytes.get(&value).copied().unwrap_or(ByteMask::NONE);
        let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
            continue;
        };
        for (input, mask) in observed_input_bytes(graph, inst, observed) {
            let mask = mask.intersection(width(input));
            if mask.is_empty() {
                continue;
            }
            let entry = bytes.entry(input).or_insert(ByteMask::NONE);
            let before = *entry;
            *entry = before.union(mask);
            if before.is_empty() {
                parents.insert(input, value);
            }
            if *entry != before {
                pending.push_back(input);
            }
        }
    }
    Closure {
        values: bytes.keys().copied().collect(),
        bytes,
        parents,
    }
}

impl ProvenProgramObservations {
    /// Close exact live outputs and non-refusal obligations over SSA def-use.
    pub fn find(
        graph: &SsaGraph,
        live_out: &FunctionLiveOut,
        facts: &PreparedFunctionFacts,
    ) -> Option<Self> {
        if !facts.obligations.is_complete() {
            return None;
        }
        let mut roots = std::collections::BTreeMap::new();
        for value in live_out.iter() {
            roots.entry(value).or_insert_with(|| "return".to_string());
        }
        for obligation in facts.obligations.obligations().values() {
            if !obligation.id.kind.is_positive_observation_root() {
                continue;
            }
            for input in obligation.inputs.iter().copied() {
                roots
                    .entry(input)
                    .or_insert_with(|| format!("{:?}", obligation.id));
            }
        }
        let closure = dependency_closure(graph, roots.keys().copied());
        Some(Self {
            values: closure.values,
            bytes: closure.bytes,
            parents: closure.parents,
            roots,
        })
    }

    pub fn contains(&self, value: ValueId) -> bool {
        self.values.contains(&value)
    }

    /// The bytes of a value some observation reaches.
    pub fn observed_bytes(&self, value: ValueId) -> Option<ByteMask> {
        self.bytes.get(&value).copied()
    }

    /// How many of a value's least significant bytes some observation
    /// reaches, when the observed bytes are exactly that low run; `None` for
    /// a value nothing observes, one observed at a higher lane only, or one
    /// observed past the bytes a mask can name.
    pub fn observed_low_bytes(&self, value: ValueId) -> Option<u32> {
        self.bytes.get(&value)?.low_bytes()
    }

    /// The chain of values from the root that observes `value` down to it.
    pub fn witness(&self, value: ValueId) -> (Option<&str>, Vec<ValueId>) {
        let mut chain = vec![value];
        let mut current = value;
        while let Some(parent) = self.parents.get(&current) {
            chain.push(*parent);
            current = *parent;
        }
        chain.reverse();
        (self.roots.get(&current).map(String::as_str), chain)
    }
}

impl DeadPhis {
    /// Find the merges nothing observes, following what observation depends on.
    pub fn find(
        graph: &SsaGraph,
        live_out: &FunctionLiveOut,
        facts: &PreparedFunctionFacts,
    ) -> Self {
        Self::find_from(graph, live_out, &facts.obligations, &facts.boundaries)
    }

    /// The same answer, from the two fact tables it actually reads.
    ///
    /// Fact collection itself needs this set: a rule that asks whether the
    /// program reads a value must ask it before the certificates that depend
    /// on the answer are formed, and both inputs are complete by then.
    pub(crate) fn find_from(
        graph: &SsaGraph,
        live_out: &FunctionLiveOut,
        obligations: &SemanticObligationInventory,
        boundaries: &SourceBoundaryFacts,
    ) -> Self {
        // The obligation inventory is the canonical answer to whether an
        // instruction is observable. In particular, exact ABI call arguments
        // are boundary inputs rather than graph inputs, so reconstructing the
        // answer here from opcodes would silently delete their producers.
        if !obligations.is_complete() {
            return Self::default();
        }
        let mut roots = BTreeSet::from_iter(live_out.iter());
        for obligation in obligations.obligations().values() {
            roots.extend(obligation.inputs.iter().copied());
        }
        // Parameters are rendered program variables even when the body does
        // not read them, so their canonical entry values remain in the named
        // domain independently of effect liveness.
        for parameter in boundaries.parameters.values() {
            roots.insert(parameter.value);
        }
        for boundary in boundaries.calls.values() {
            for argument in &boundary.arguments {
                if let SourceCallArgumentValue::Value(value) = argument.value {
                    roots.insert(value);
                }
            }
        }
        // Whatever an observation depends on is observed, transitively. The walk
        // is over the graph's own instruction inputs, so it visits each edge once.
        let observed = dependency_closure(graph, roots).values;

        let unobserved_values = graph
            .values
            .iter()
            .filter(|value| {
                !observed.contains(&value.id)
                    && graph
                        .def_inst(value.id)
                        .and_then(|inst| obligations.instruction_for_inst(inst))
                        .is_none_or(|instruction| {
                            instruction.state == SemanticInstructionState::ProvenDead
                        })
            })
            .map(|value| value.id)
            .collect();
        let mut dead = Self {
            unobserved_values,
            ..Self::default()
        };
        for inst in &graph.insts {
            // An operation the inventory proved dead and that produces no value
            // is unobserved too. Only outputs were asked about, so a store that
            // owes nothing -- the write half of a memory round trip is the
            // case -- was never marked, and the renderer went on to lower it
            // and ask for an operand the plan had already elided.
            let proven_dead_effect = inst.output.is_none()
                && obligations
                    .instruction_for_inst(inst.id)
                    .is_some_and(|instruction| {
                        instruction.state == SemanticInstructionState::ProvenDead
                    });
            if !proven_dead_effect
                && !inst
                    .output
                    .is_some_and(|output| dead.unobserved_values.contains(&output))
            {
                continue;
            }
            dead.unobserved_insts.insert(inst.id);
            dead.unobserved_uses
                .extend((0..inst.inputs.len()).map(|input_idx| UseSite {
                    inst: inst.id,
                    input_idx,
                }));
        }
        for inst in &graph.insts {
            if matches!(inst.payload, crate::graph::InstPayload::Phi { .. })
                && inst
                    .output
                    .is_some_and(|value| dead.unobserved_values.contains(&value))
            {
                dead.values.insert(inst.output.expect("checked phi output"));
            }
        }
        dead.report_values_observed_only_through_dead_merges(
            graph,
            live_out,
            obligations,
            &observed,
        );
        dead
    }

    /// Name a value this analysis calls observed and also renders unreachable.
    ///
    /// A value whose every graph use sits inside an instruction the same walk
    /// proved unobserved has no occurrence any rendering can own, so the plan
    /// binds a cell the seal then demands and nothing can fill. It is reached
    /// from a root rather than through its uses, and which root decides whether
    /// the obligation's inputs are wrong or the merge is not dead.
    fn report_values_observed_only_through_dead_merges(
        &self,
        graph: &SsaGraph,
        live_out: &FunctionLiveOut,
        obligations: &SemanticObligationInventory,
        observed: &BTreeSet<ValueId>,
    ) {
        if !r2il::refusal_evidence::tracing() {
            return;
        }
        for value in &graph.values {
            if self.unobserved_values.contains(&value.id) {
                continue;
            }
            let uses = graph.use_sites(value.id);
            if uses.is_empty()
                || !uses
                    .iter()
                    .all(|site| self.unobserved_insts.contains(&site.inst))
            {
                continue;
            }
            let rooted_by = obligations
                .obligations()
                .values()
                .filter(|obligation| obligation.inputs.contains(&value.id))
                .map(|obligation| {
                    format!("{:?}/{:?}", obligation.id.kind, obligation.id.instruction)
                })
                .collect::<Vec<_>>();
            let definition = graph
                .def_inst(value.id)
                .and_then(|inst| obligations.instruction_for_inst(inst));
            let definition_state = definition.map(|instruction| format!("{:?}", instruction.state));
            let own_obligations = definition
                .map(|instruction| {
                    instruction
                        .obligations
                        .iter()
                        .map(|id| format!("{:?}/{:?}/{}", id.kind, id.component, id.instruction))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let definition_site = graph.def_inst(value.id).map(|inst| {
                (
                    inst,
                    graph.op_site_for_inst(inst),
                    graph.inst(inst).map(|inst| format!("{:?}", inst.payload)),
                )
            });
            r2il::refusal_evidence!(
                "observed-through-dead-merge",
                "{:?} keeps a cell while every one of its {} uses is inside an unobserved merge; in_observed_closure={} live_out={} definition_state={definition_state:?} definition={definition_site:?} own_obligations={own_obligations:?} obligations={rooted_by:?}",
                value.id,
                uses.len(),
                observed.contains(&value.id),
                live_out.contains(value.id)
            );
        }
    }

    pub fn contains(&self, value: ValueId) -> bool {
        self.values.contains(&value)
    }

    pub fn iter(&self) -> impl Iterator<Item = ValueId> + '_ {
        self.values.iter().copied()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Every pure value outside the transitive observation slice.
    pub const fn unobserved_values(&self) -> &BTreeSet<ValueId> {
        &self.unobserved_values
    }

    /// Every pure definition whose output is in [`Self::unobserved_values`].
    pub const fn unobserved_insts(&self) -> &BTreeSet<InstId> {
        &self.unobserved_insts
    }

    /// Complete input-use domain of [`Self::unobserved_insts`].
    pub const fn unobserved_uses(&self) -> &BTreeSet<UseSite> {
        &self.unobserved_uses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalStorageId, CanonicalStorageSpace, SSAFunction};
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn return_storages() -> [CanonicalStorageId; 1] {
        [CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        }]
    }

    fn arch() -> ArchSpec {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::new("RCX", 8, 8));
        arch.add_register(RegisterDef::new("RDX", 16, 8));
        arch.add_register(RegisterDef::new("ZF", 0x206, 1));
        arch.add_register(RegisterDef::new("RIP", 0x288, 8));
        arch
    }

    /// A diamond that merges one effect input and one dead condition code at exit.
    fn merging_function() -> SSAFunction {
        let entry = R2ILBlock {
            addr: 0x1000,
            size: 4,
            ops: vec![
                R2ILOp::IntEqual {
                    dst: reg(0x206, 1),
                    a: reg(8, 8),
                    b: Varnode::constant(0, 8),
                },
                R2ILOp::CBranch {
                    cond: reg(0x206, 1),
                    target: Varnode::constant(0x1008, 8),
                },
            ],
            ..R2ILBlock::default()
        };
        let left = R2ILBlock {
            addr: 0x1004,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: reg(0, 8),
                    src: Varnode::constant(1, 8),
                },
                R2ILOp::IntEqual {
                    dst: reg(0x206, 1),
                    a: reg(16, 8),
                    b: Varnode::constant(0, 8),
                },
                R2ILOp::Branch {
                    target: Varnode::constant(0x100c, 8),
                },
            ],
            ..R2ILBlock::default()
        };
        let right = R2ILBlock {
            addr: 0x1008,
            size: 4,
            ops: vec![
                R2ILOp::Copy {
                    dst: reg(0, 8),
                    src: Varnode::constant(2, 8),
                },
                R2ILOp::IntEqual {
                    dst: reg(0x206, 1),
                    a: reg(16, 8),
                    b: Varnode::constant(1, 8),
                },
                R2ILOp::Branch {
                    target: Varnode::constant(0x100c, 8),
                },
            ],
            ..R2ILBlock::default()
        };
        let exit = R2ILBlock {
            addr: 0x100c,
            size: 4,
            ops: vec![R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::constant(0x2000, 8),
                val: reg(0, 8),
            }],
            ..R2ILBlock::default()
        };
        SSAFunction::from_blocks_with_arch(&[entry, left, right, exit], Some(&arch())).expect("ssa")
    }

    #[test]
    fn a_flag_merged_at_a_join_and_never_tested_again_is_not_part_of_the_program() {
        let func = merging_function();
        let graph = SsaGraph::from_function(&func);
        let live = FunctionLiveOut::compute(&func, &graph, &return_storages());

        let facts = crate::semantic::PreparedFunctionFacts::collect(&func, &graph);
        let dead = DeadPhis::find(&graph, &live, &facts);

        let exit = func.get_block(0x100c).expect("exit block");
        let zf = exit
            .phis
            .iter()
            .find(|phi| phi.dst.name().eq_ignore_ascii_case("zf"))
            .and_then(|phi| graph.value_id_for_var(&phi.dst));
        assert!(
            zf.is_some_and(|value| dead.contains(value)),
            "a condition code merged and never tested is dead"
        );
        let zf = zf.expect("dead condition-code merge");
        let definition = graph
            .def_inst(zf)
            .and_then(|inst| graph.inst(inst))
            .expect("dead merge definition");
        assert!(dead.unobserved_values().contains(&zf));
        assert!(dead.unobserved_insts().contains(&definition.id));
        for (input_idx, input) in definition.inputs.iter().copied().enumerate() {
            assert!(
                dead.unobserved_values().contains(&input),
                "a value used only by the dead merge belongs to its pure support domain"
            );
            assert!(dead.unobserved_uses().contains(&UseSite {
                inst: definition.id,
                input_idx,
            }));
        }
    }

    #[test]
    fn the_merge_consumed_by_an_observable_effect_survives() {
        let func = merging_function();
        let graph = SsaGraph::from_function(&func);
        let live = FunctionLiveOut::compute(&func, &graph, &return_storages());

        let facts = crate::semantic::PreparedFunctionFacts::collect(&func, &graph);
        let dead = DeadPhis::find(&graph, &live, &facts);

        let exit = func.get_block(0x100c).expect("exit block");
        let rax = exit
            .phis
            .iter()
            .find(|phi| phi.dst.name().eq_ignore_ascii_case("rax"))
            .and_then(|phi| graph.value_id_for_var(&phi.dst))
            .expect("the return register is merged at the exit");
        assert!(
            !dead.contains(rax),
            "the value written to memory is observed"
        );
        assert_eq!(graph.use_sites(rax).len(), 1, "the store owns its use site");
    }

    /// Registers of the widths the observation masks have to count: a word,
    /// a vector, and one wider than a mask word names.
    fn wide_arch() -> ArchSpec {
        let mut arch = arch();
        arch.add_register(RegisterDef::new("XMM0", 0x1200, 16));
        arch.add_register(RegisterDef::new("WIDE", 0x2000, 80));
        arch
    }

    /// What the proven observations of `ops`, followed by a return of RAX,
    /// reach of the value `register` holds on entry.
    fn observed_on_entry(ops: Vec<R2ILOp>, register: &str) -> Option<ByteMask> {
        let mut block = R2ILBlock::new(0x1000, 4);
        for op in ops {
            block.push(op);
        }
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&wide_arch())).expect("ssa");
        let graph = SsaGraph::from_function(&func);
        let live = FunctionLiveOut::compute(&func, &graph, &return_storages());
        let facts = crate::semantic::PreparedFunctionFacts::collect(&func, &graph);
        let observations =
            ProvenProgramObservations::find(&graph, &live, &facts).expect("complete obligations");
        let entry = graph
            .values
            .iter()
            .find(|value| {
                value.var.version == 0 && value.var.name().eq_ignore_ascii_case(register)
            })?
            .id;
        let bytes = observations.observed_bytes(entry);
        assert_eq!(
            bytes.is_some(),
            observations.contains(entry),
            "a value is observed exactly when some byte of it is"
        );
        bytes
    }

    #[test]
    fn a_slice_past_the_eighth_byte_observes_the_bytes_it_cuts() {
        // movhlps then movq: the returned word is the vector's high half.
        let high_half = observed_on_entry(
            vec![R2ILOp::Subpiece {
                dst: reg(0, 8),
                src: reg(0x1200, 16),
                offset: 8,
            }],
            "XMM0",
        );
        assert_eq!(high_half, Some(ByteMask::Bytes(0xff00)));

        // pextrd lane 3: four bytes at offset twelve, widened into the result.
        let top_lane = observed_on_entry(
            vec![
                R2ILOp::Subpiece {
                    dst: reg(8, 4),
                    src: reg(0x1200, 16),
                    offset: 12,
                },
                R2ILOp::IntZExt {
                    dst: reg(0, 8),
                    src: reg(8, 4),
                },
            ],
            "XMM0",
        );
        assert_eq!(top_lane, Some(ByteMask::Bytes(0xf000)));
    }

    #[test]
    fn the_high_tile_of_a_concatenation_is_observed_through_the_bytes_above_the_low_one() {
        // RAX = (RCX:RDX)[8..16], which is RCX and nothing of RDX.
        let ops = || {
            vec![
                R2ILOp::Piece {
                    dst: reg(0x1200, 16),
                    hi: reg(8, 8),
                    lo: reg(16, 8),
                },
                R2ILOp::Subpiece {
                    dst: reg(0, 8),
                    src: reg(0x1200, 16),
                    offset: 8,
                },
            ]
        };
        assert_eq!(observed_on_entry(ops(), "RCX"), Some(ByteMask::whole(8)));
        assert_eq!(observed_on_entry(ops(), "RDX"), None);
    }

    #[test]
    fn an_and_that_clears_one_bit_still_reads_every_byte() {
        // and rax, -2 keeps a bit of every byte, so the whole word is read.
        let and = |constant: u64| {
            vec![R2ILOp::IntAnd {
                dst: reg(0, 8),
                a: reg(8, 8),
                b: Varnode::constant(constant, 8),
            }]
        };
        let cleared_bit = observed_on_entry(and((-2i64).cast_unsigned()), "RCX");
        assert_eq!(cleared_bit, Some(ByteMask::whole(8)));
        assert_eq!(cleared_bit.and_then(ByteMask::low_bytes), Some(8));

        // A constant that clears whole bytes still narrows what is read.
        assert_eq!(
            observed_on_entry(and(0xff), "RCX").and_then(ByteMask::low_bytes),
            Some(1)
        );
        let second_byte = observed_on_entry(and(0xff00), "RCX");
        assert_eq!(second_byte, Some(ByteMask::Bytes(0b10)));
        assert_eq!(second_byte.and_then(ByteMask::low_bytes), None);
    }

    #[test]
    fn a_value_wider_than_a_mask_word_saturates_rather_than_losing_bytes() {
        let at = |offset: u32| {
            observed_on_entry(
                vec![R2ILOp::Subpiece {
                    dst: reg(0, 8),
                    src: reg(0x2000, 80),
                    offset,
                }],
                "WIDE",
            )
        };
        assert_eq!(at(0), Some(ByteMask::Bytes(0xff)));
        assert_eq!(at(72), Some(ByteMask::All));
        assert_eq!(at(72).and_then(ByteMask::low_bytes), None);
    }

    #[test]
    fn a_byte_mask_counts_bytes_and_saturates_on_overflow() {
        assert_eq!(ByteMask::whole(0), ByteMask::NONE);
        assert_eq!(ByteMask::whole(16), ByteMask::Bytes(0xffff));
        assert_eq!(ByteMask::whole(64), ByteMask::Bytes(u64::MAX));
        assert_eq!(ByteMask::whole(65), ByteMask::All);
        assert_eq!(ByteMask::whole(64).low_bytes(), Some(64));

        assert_eq!(
            ByteMask::Bytes(0xff).shifted_up(56),
            ByteMask::Bytes(0xff << 56)
        );
        assert_eq!(ByteMask::Bytes(0xff).shifted_up(57), ByteMask::All);
        assert_eq!(ByteMask::Bytes(1).shifted_up(64), ByteMask::All);
        assert_eq!(ByteMask::NONE.shifted_up(64), ByteMask::NONE);

        assert_eq!(
            ByteMask::Bytes(0xff00).shifted_down(8),
            ByteMask::Bytes(0xff)
        );
        assert_eq!(ByteMask::Bytes(u64::MAX).shifted_down(64), ByteMask::NONE);
        assert_eq!(ByteMask::All.shifted_down(64), ByteMask::All);

        assert_eq!(
            ByteMask::All.intersection(ByteMask::whole(16)),
            ByteMask::whole(16)
        );
        assert_eq!(ByteMask::Bytes(0xf0).union(ByteMask::All), ByteMask::All);
        assert_eq!(ByteMask::Bytes(0b101).low_bytes(), None);
        assert_eq!(ByteMask::NONE.low_bytes(), None);
    }

    #[test]
    fn a_flag_a_branch_still_tests_survives() {
        let func = merging_function();
        let graph = SsaGraph::from_function(&func);
        let live = FunctionLiveOut::compute(&func, &graph, &return_storages());

        let facts = crate::semantic::PreparedFunctionFacts::collect(&func, &graph);
        let dead = DeadPhis::find(&graph, &live, &facts);

        // The entry block's condition is tested by its own CBranch, so nothing
        // about merging flags elsewhere may reach back and call it unobserved.
        let entry = func.get_block(0x1000).expect("entry block");
        let tested = entry
            .ops
            .iter()
            .find_map(|op| op.dst())
            .and_then(|dst| graph.value_id_for_var(dst))
            .expect("a defined condition");
        assert!(!dead.contains(tested));
    }
}
