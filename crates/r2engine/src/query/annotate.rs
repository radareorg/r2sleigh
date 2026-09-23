//! What one instruction's own lift says about the addresses it touches.
//!
//! Lifting is the whole point: a number in the operands is an address because
//! the instruction transfers to it or reads it, not because it looks like one.

use r2il::ValueUse;
use r2il::{R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{NumberSpan, Syntax};
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};
use r2ssa::{CanonicalStorageId, CanonicalStorageSpace, InstPayload, SsaGraph, ValueId};
use std::collections::BTreeSet;

use super::Support;
use super::Work;
use super::decode::Lookahead;
use super::records::{Annotation, AnnotationKind, Answered, Line, Memory};
use super::references::ReferenceKind;

/// How far on a run is lifted again to see which numbers move with it.
///
/// A multiple of every rounding a specification applies to the program
/// counter, so a number the program computes from its own position moves by
/// exactly this much: AArch64's `adrp` rounds to a four-kilobyte page, the
/// widest there is, and Thumb's aligned `pc` rounds to four bytes.
const PAGE: u64 = 0x1000;

/// The lifts of a run of lines, and the bytes each lift read.
pub(super) struct Run<'a> {
    pub lifts: &'a [Option<r2il::R2ILBlock>],
    pub windows: &'a [Option<Vec<u8>>],
}

/// Say what each line's own lift says, and what the run says about it.
///
/// Two passes, because they answer different questions. What an instruction
/// transfers to or reads is a fact about the instruction. Whether the number
/// it computes is an address or a step towards one is a fact about what the
/// next instruction does with it: `adrp x17, 0x100008000` computes a page
/// base, and only the `add` after it says the address is fifty bytes further
/// on.
///
/// This is the one place a number becomes an address claim, and `referenced`
/// the one place a claim becomes a reference, so the index `ax` reads is
/// exactly what these lines claim.
pub(super) fn over_run(
    answered: &Answered<'_>,
    work: Work,
    run: &Run<'_>,
    beyond: &mut Lookahead<'_, '_>,
    lines: &mut [Line],
) {
    if work == Work::Decode {
        return;
    }
    let memory = &answered.memory;
    let clobbered = answered.clobbered;
    // A function listing's run is one block, entered only at its top, so what one line leaves the next reads.
    let carry = work >= Work::Function;
    let mut named = named_over(run.lifts, carry, clobbered);
    // A number the program does not map names nothing in it, whatever it moves with.
    for one in named.iter_mut().flatten() {
        if one
            .computed
            .as_ref()
            .is_some_and(|computed| !memory.maps(computed.value))
        {
            one.computed = None;
        }
    }
    let relative = relative_over(answered, run, lines, &named, carry);
    let graph = (work >= Work::Function).then_some(answered.fate).flatten();
    for (index, line) in lines.iter_mut().enumerate() {
        let (Some(lift), Some(Some(named))) = (
            run.lifts.get(index).and_then(Option::as_ref),
            named.get(index),
        ) else {
            continue;
        };
        let mut claims = named
            .touched
            .iter()
            .map(|(kind, own)| (*kind, folded_support(*own)))
            .collect::<Vec<_>>();
        if work >= Work::BlockLocal
            && let Some(computed) = &named.computed
            // A number that stays put is an address candidate only where a section the program loads holds it: NULL and the header are not objects.
            && (relative.get(index).copied() == Some(true) || memory.declares(computed.value))
        {
            let relative = relative.get(index).copied() == Some(true);
            let mut after = After {
                rest: &run.lifts[index + 1..],
                beyond: &mut *beyond,
                clobbered,
                graph,
                parameters: (!relative).then_some(answered.parameters).flatten(),
                used: None,
            };
            // A number that moves with the program is an address; one that stays put is one only where it is used as one.
            let support = match relative {
                true => (fate_of(lift, &mut after, &computed.output, line.address) == Fate::Result)
                    .then(|| folded_support(computed.own)),
                false => {
                    straight_line_fate(lift, &mut after, &computed.output);
                    after.used
                }
            };
            if let Some(support) = support {
                let kind = AnnotationKind::Computes {
                    value: computed.value,
                };
                claims.push((kind, support));
            }
        }
        let held = held_at(memory, &claims);
        claims.extend(held.into_iter().map(|kind| (kind, Support::Folded)));
        if work >= Work::Function {
            let proved = proved_about(answered, line.address);
            claims.extend(proved.into_iter().map(|kind| (kind, Support::Solved)));
        }
        line.annotations = claims
            .into_iter()
            .map(|(kind, support)| Annotation {
                kind,
                support,
                operand: line
                    .syntax
                    .as_ref()
                    .and_then(|syntax| sole_operand(syntax, kind.address())),
                reference: referenced(memory, kind),
            })
            .collect();
    }
}

/// Whether a claim names an address of this program.
///
/// An address the instruction transfers to or accesses is used as one, and a
/// number it computes is claimed at all only where it moves with the program
/// or is handed to a parameter its callee takes an address in; either names
/// this program wherever the program maps it. What a read holds
/// is data, and a pool word is a pc-relative or thread offset as often as a
/// pointer, so the read is the reference and the word it holds is not.
fn referenced(memory: &Memory<'_>, kind: AnnotationKind) -> Option<ReferenceKind> {
    match kind {
        AnnotationKind::Target { address, .. } => {
            memory.maps(address).then_some(ReferenceKind::Code)
        }
        AnnotationKind::Reads { address, .. }
        | AnnotationKind::Writes { address, .. }
        | AnnotationKind::Computes { value: address } => {
            memory.maps(address).then_some(ReferenceKind::Data)
        }
        AnnotationKind::Holds { .. } | AnnotationKind::Bounds { .. } => None,
    }
}

/// Decoded where the instruction's own operations fold the number, folded where the block before it had to.
fn folded_support(own: bool) -> Support {
    match own {
        true => Support::Decoded,
        false => Support::Folded,
    }
}

/// What one instruction names, folded as far as its run allows.
struct Named {
    /// Every address its operations transfer to or access, and whether its own operations fold it.
    touched: Vec<(AnnotationKind, bool)>,
    /// The number it leaves, where it computes one rather than copying one it read.
    computed: Option<Computed>,
}

/// A number one instruction leaves, where it leaves it, and whether its own operations fold it.
struct Computed {
    value: u64,
    output: Varnode,
    own: bool,
}

/// Name each line of a run, carrying what one line leaves into the next where the run is one block.
fn named_over(
    lifts: &[Option<r2il::R2ILBlock>],
    carry: bool,
    clobbered: &[CanonicalStorageId],
) -> Vec<Option<Named>> {
    let mut carried = BlockOrigins::default();
    lifts
        .iter()
        .map(|lift| {
            if !carry {
                carried = BlockOrigins::default();
            }
            let Some(lift) = lift else {
                carried = BlockOrigins::default();
                return None;
            };
            Some(named_by(lift, &mut carried, clobbered))
        })
        .collect()
}

/// What one instruction names, from what the block held before it.
fn named_by(
    lift: &r2il::R2ILBlock,
    carried: &mut BlockOrigins,
    clobbered: &[CanonicalStorageId],
) -> Named {
    let before = carried.clone();
    let mut own = BlockOrigins::default();
    let mut touched: Vec<(AnnotationKind, bool)> = Vec::new();
    for op in &lift.ops {
        let alone = touched_at(&own, op);
        for kind in touched_at(carried, op) {
            if !touched.iter().any(|(held, _)| *held == kind) {
                touched.push((kind, alone.contains(&kind)));
            }
        }
        carried.step(op);
        own.step(op);
        if matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. }) {
            carried.forget(clobbered);
        }
    }
    // A number the instruction only copies from a register it read was computed where that was.
    let copied = lift
        .ops
        .iter()
        .flat_map(R2ILOp::inputs)
        .filter(|input| input.space == SpaceId::Register)
        .filter_map(|input| before.of(input).and_then(ValueOrigin::constant))
        .collect::<BTreeSet<_>>();
    // An address fills a register, so of the registers left holding a number the widest is the result; a flag is one bit.
    let computed = lift
        .ops
        .iter()
        .filter_map(R2ILOp::output)
        .filter(|output| output.space == SpaceId::Register)
        .filter_map(|output| Some((output, carried.of(output)?.constant()?)))
        .filter(|(_, value)| !copied.contains(value))
        .max_by_key(|(output, _)| output.size)
        .map(|(output, value)| Computed {
            value,
            output: output.clone(),
            own: own.of(output).and_then(ValueOrigin::constant) == Some(value),
        });
    Named { touched, computed }
}

/// The number one named line computes, where it computes one.
fn computed(one: &Option<Named>) -> Option<&Computed> {
    one.as_ref().and_then(|one| one.computed.as_ref())
}

/// Whether each line's computed number moves with the program: lifted a page on, it is a page further.
fn relative_over(
    answered: &Answered<'_>,
    run: &Run<'_>,
    lines: &[Line],
    named: &[Option<Named>],
    carry: bool,
) -> Vec<bool> {
    // Only as far as the last number that needs it: what the block carries runs forward.
    let Some(last) = named.iter().rposition(|one| computed(one).is_some()) else {
        return vec![false; lines.len()];
    };
    let shifted = super::decode::lift_run(answered, &lines[..=last], &run.windows[..=last], PAGE);
    let there = named_over(&shifted, carry, answered.clobbered);
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let (Some(here), Some(there)) = (
                named.get(index).and_then(computed),
                there.get(index).and_then(computed),
            ) else {
                return false;
            };
            let bits = answered
                .decoders
                .at(line.address)
                .map_or(64, |machine| machine.arch.addr_size.saturating_mul(8));
            let mask = u64::MAX >> 64u32.saturating_sub(bits).min(63);
            there.value.wrapping_sub(here.value) & mask == PAGE & mask
        })
        .collect()
}

/// What this revision holds wherever the instruction reads.
///
/// Said beside the read rather than folded into it: the bytes there are a fact
/// about this revision, and the load is a fact about the instruction.
fn held_at(memory: &Memory<'_>, claims: &[(AnnotationKind, Support)]) -> Vec<AnnotationKind> {
    claims
        .iter()
        .filter_map(|(kind, _)| match kind {
            AnnotationKind::Reads { address, width } => Some(AnnotationKind::Holds {
                address: *address,
                width: *width,
                value: memory.word(*address, *width)?,
            }),
            _ => None,
        })
        .collect()
}

/// What the analysis proved about the machine words one instruction defines.
///
/// One range per value, and the range is the value's own: it is narrowed where
/// the value is defined, so it holds wherever the value is live rather than at
/// this instruction in particular.
fn proved_about(answered: &Answered<'_>, address: u64) -> Vec<AnnotationKind> {
    let (Some(facts), Some(machine)) = (answered.facts, answered.decoders.at(address)) else {
        return Vec::new();
    };
    let graph = facts.graph();
    // A flag is proved to hold nought or one on every line that sets it, which says only that it is a flag.
    let word = |storage: &r2ssa::CanonicalStorageId| {
        storage.space == r2ssa::CanonicalStorageSpace::Register
            && storage.size == machine.arch.addr_size
    };
    graph
        .insts_for_instruction(address)
        .iter()
        .filter_map(|inst| {
            let instruction = graph.inst(*inst)?;
            let storage = instruction.canonical_storage.filter(word)?;
            let range = facts.values().get(instruction.output?)?;
            if !bounded_beyond_its_operation(facts, instruction, range) {
                return None;
            }
            let (low, high) = range.bounds()?;
            Some(AnnotationKind::Bounds {
                storage,
                low,
                high,
                stride: range.stride().unwrap_or(0),
            })
        })
        .collect()
}

/// Whether a range says more than the operation that defines the value.
///
/// A range spanning the width written proves nothing, and a zero extension of
/// an unbounded narrower value spans exactly that narrower width: `xor eax, edx`
/// said `rax in [0x0, 0xffffffff]`, which is only that a 32-bit write clears the rest.
fn bounded_beyond_its_operation(
    facts: &r2ssa::SsaArtifact,
    instruction: &r2ssa::GraphInst,
    range: r2ssa::StridedInterval,
) -> bool {
    let graph = facts.graph();
    let mut defined = (instruction, range);
    loop {
        let (instruction, range) = defined;
        if range.is_top() || range.is_bottom() {
            return false;
        }
        let InstPayload::Op(r2ssa::SSAOp::IntZExt { .. }) = &instruction.payload else {
            return true;
        };
        // The extension's range is its operand's, so the operand's width is the one written.
        let Some(extended) = instruction.inputs.first().copied() else {
            return true;
        };
        let Some(operand) = facts.values().get(extended) else {
            return true;
        };
        let Some(producer) = graph.def_inst(extended).and_then(|inst| graph.inst(inst)) else {
            return !operand.is_top();
        };
        defined = (producer, operand);
    }
}

/// What can be known of the program after one instruction.
struct After<'a, 'r, 'b> {
    /// The lifts of the lines that follow it in the run.
    rest: &'a [Option<r2il::R2ILBlock>],
    /// The instructions past the run, read as far as a question needs them.
    beyond: &'a mut Lookahead<'r, 'b>,
    /// The registers the convention says a call leaves undefined.
    clobbered: &'a [CanonicalStorageId],
    /// The function's def-use, where the request paid for it.
    graph: Option<&'a super::records::DefUse<'a>>,
    /// Which parameters of a callee take an address, where the number's use decides whether it is one.
    parameters: Option<&'a dyn super::records::Parameters>,
    /// The strongest support a call handing the number to such a parameter gave.
    used: Option<Support>,
}

/// Whether the number an instruction leaves in `output` is a step or its result.
///
/// A value a later instruction builds a number on is a step towards an address
/// rather than one: spelling `adrp x17, reloc.humanize_number` named the page
/// base the `add` after it was about to move fifty bytes past. Copying, storing,
/// comparing, loading through or passing the number is using it as it stands.
fn fate_of(
    lift: &r2il::R2ILBlock,
    after: &mut After<'_, '_, '_>,
    output: &Varnode,
    address: u64,
) -> Fate {
    match straight_line_fate(lift, after, output) {
        Fate::Unknown => after
            .graph
            .and_then(super::records::DefUse::graph)
            .map_or(Fate::Unknown, |graph| defined_fate(graph, address, output)),
        settled => settled,
    }
}

/// Whether a number an instruction leaves is a step, and who can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Something derives another number from it.
    Step,
    /// Every copy of it is gone before anything derives from it.
    Result,
    /// The evidence at hand does not reach far enough to say.
    Unknown,
}

/// Whether a storage is a temporary one instruction's operations share.
fn scratch(space: SpaceId) -> bool {
    space == SpaceId::Unique
}

/// What the run after an instruction says, as far as it is one straight line.
///
/// The number is followed through every storage a copy puts it in; a number
/// derived from it is followed only through temporaries, because a flag is
/// computed that way and a flag is a test rather than a step.
fn straight_line_fate(
    lift: &r2il::R2ILBlock,
    after: &mut After<'_, '_, '_>,
    output: &Varnode,
) -> Fate {
    // Past a branch the run is no longer every path the value takes, so it settles nothing.
    if lift.ops.iter().any(R2ILOp::is_control_flow) {
        return Fate::Unknown;
    }
    let mut holders = vec![output.clone()];
    // A callee may have left a register as it found it, so a read after a call proves no step.
    let mut called = false;
    let listed = after.rest.len();
    for index in 0.. {
        let block = match after.rest.get(index) {
            Some(block) => block.as_ref(),
            None => after.beyond.at(index - listed).flatten(),
        };
        let Some(block) = block else {
            return Fate::Unknown;
        };
        let mut derived: Vec<Varnode> = Vec::new();
        for (at, op) in block.ops.iter().enumerate() {
            if let Some(parameters) = after.parameters
                && let Some(support) = pointer_use(parameters, block, at, &holders)
            {
                after.used = Some(after.used.map_or(support, |held| held.min(support)));
            }
            match op_fate(op, &mut holders, &mut derived, after.clobbered) {
                Some(Fate::Step) if called => return Fate::Unknown,
                Some(fate) => return fate,
                None => {}
            }
            called |= matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. });
            if holders.is_empty() && derived.is_empty() {
                return Fate::Result;
            }
        }
        holders.retain(|held| !scratch(held.space));
        if holders.is_empty() {
            return Fate::Result;
        }
    }
    Fate::Unknown
}

/// How a call hands on the number where a register holding it is a parameter its callee takes an address in.
fn pointer_use(
    parameters: &dyn super::records::Parameters,
    block: &r2il::R2ILBlock,
    at: usize,
    holders: &[Varnode],
) -> Option<Support> {
    use super::records::Callee;
    let callee = match block.ops.get(at)? {
        R2ILOp::Call { target } => Callee::At(encoded_target(target)?),
        R2ILOp::CallInd { target } => match BlockOrigins::upto(block, at).of(target)? {
            ValueOrigin::Constant { value, .. } => Callee::At(value),
            ValueOrigin::LoadedSlot(slot) => Callee::ThroughSlot(slot.offset),
        },
        _ => return None,
    };
    let held = |storage: &CanonicalStorageId| {
        holders
            .iter()
            .any(|held| held.space == SpaceId::Register && held.offset == storage.offset)
    };
    parameters.pointer_use(callee, &held)
}

/// What one operation does to the storages holding the number, where it decides.
fn op_fate(
    op: &R2ILOp,
    holders: &mut Vec<Varnode>,
    derived: &mut Vec<Varnode>,
    clobbered: &[CanonicalStorageId],
) -> Option<Fate> {
    let inputs = op.inputs();
    let reads = |set: &[Varnode]| {
        inputs
            .iter()
            .any(|input| set.iter().any(|held| overlaps(held, input)))
    };
    let (held, built) = (reads(holders), reads(derived));
    match op {
        R2ILOp::Call { .. } | R2ILOp::CallInd { .. } => {
            holders.retain(|held| {
                !clobbered
                    .iter()
                    .any(|storage| covers(&storage_varnode(*storage), held))
            });
            return built.then_some(Fate::Step);
        }
        _ if op.is_control_flow() => return Some(Fate::Unknown),
        _ => {}
    }
    let carried = match op.value_use() {
        ValueUse::Derives if held || built => Some(true),
        ValueUse::Carries if built => Some(true),
        ValueUse::Carries if held => Some(false),
        ValueUse::Consumes if built => return Some(Fate::Step),
        _ => None,
    };
    let written = op.output()?;
    holders.retain(|held| !covers(written, held));
    derived.retain(|held| !covers(written, held));
    match carried {
        Some(true) if !scratch(written.space) => return Some(Fate::Step),
        Some(true) => derived.push(written.clone()),
        Some(false) => holders.push(written.clone()),
        None => {}
    }
    None
}

/// Whether two storages share a byte.
fn overlaps(left: &Varnode, right: &Varnode) -> bool {
    left.space == right.space
        && left.offset < right.offset + u64::from(right.size)
        && right.offset < left.offset + u64::from(left.size)
}

/// Whether a write to `outer` replaces every byte of `inner`.
fn covers(outer: &Varnode, inner: &Varnode) -> bool {
    outer.space == inner.space
        && outer.offset <= inner.offset
        && inner.offset + u64::from(inner.size) <= outer.offset + u64::from(outer.size)
}

/// A register storage, as the lift spells it.
fn storage_varnode(storage: CanonicalStorageId) -> Varnode {
    Varnode::new(SpaceId::Register, storage.offset, storage.size)
}

/// What the function's def-use says of the value this instruction leaves in `output`.
fn defined_fate(graph: &SsaGraph, address: u64, output: &Varnode) -> Fate {
    let storage = CanonicalStorageId::from_varnode(output);
    let defined = graph
        .insts_for_instruction(address)
        .iter()
        .rev()
        .filter_map(|inst| graph.inst(*inst))
        .find(|inst| inst.canonical_storage == Some(storage))
        .and_then(|inst| inst.output);
    match defined {
        Some(defined) if derived_from(graph, defined) => Fate::Step,
        Some(_) => Fate::Result,
        None => Fate::Unknown,
    }
}

/// Whether an operation builds a number on this value, through the copies and merges it flows into.
fn derived_from(graph: &SsaGraph, defined: ValueId) -> bool {
    let mut seen = BTreeSet::from([(defined, false)]);
    let mut pending = vec![(defined, false)];
    while let Some((value, built)) = pending.pop() {
        let users = graph
            .use_sites(value)
            .iter()
            .filter_map(|site| graph.inst(site.inst));
        for user in users {
            let carried = match &user.payload {
                InstPayload::Phi { .. } => built,
                InstPayload::Op(op) => match op.value_use() {
                    ValueUse::Carries => built,
                    ValueUse::Derives => true,
                    ValueUse::Consumes if built => return true,
                    ValueUse::Consumes | ValueUse::Tests => continue,
                },
            };
            let Some(next) = user.output else {
                continue;
            };
            let temporary = graph
                .value(next)
                .and_then(|value| value.canonical_storage)
                .is_some_and(|storage| storage.space == CanonicalStorageSpace::Unique);
            if carried && !temporary {
                return true;
            }
            if seen.insert((next, carried)) {
                pending.push((next, carried));
            }
        }
    }
    false
}

/// The addresses one operation names, as far as the block so far shows.
fn touched_at(origins: &BlockOrigins, op: &R2ILOp) -> Vec<AnnotationKind> {
    let folded = |addr: &Varnode| origins.of(addr).and_then(ValueOrigin::constant);
    let mut found = Vec::new();
    match op {
        R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } => found.extend(
            encoded_target(target).map(|address| AnnotationKind::Target {
                address,
                call: false,
            }),
        ),
        R2ILOp::Call { target } => {
            found.extend(
                encoded_target(target).map(|address| AnnotationKind::Target {
                    address,
                    call: true,
                }),
            )
        }
        // A conditional or linked access names the address it would use as surely as a plain one does.
        R2ILOp::Load {
            dst,
            space: SpaceId::Ram,
            addr,
        }
        | R2ILOp::LoadLinked {
            dst,
            space: SpaceId::Ram,
            addr,
            ..
        }
        | R2ILOp::LoadGuarded {
            dst,
            space: SpaceId::Ram,
            addr,
            ..
        } => found.extend(folded(addr).map(|address| AnnotationKind::Reads {
            address,
            width: dst.size,
        })),
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr,
            val,
        }
        | R2ILOp::StoreConditional {
            space: SpaceId::Ram,
            addr,
            val,
            ..
        }
        | R2ILOp::StoreGuarded {
            space: SpaceId::Ram,
            addr,
            val,
            ..
        } => found.extend(folded(addr).map(|address| AnnotationKind::Writes {
            address,
            width: val.size,
        })),
        R2ILOp::AtomicCAS {
            space: SpaceId::Ram,
            addr,
            expected,
            ..
        } => {
            let width = expected.size;
            found.extend(folded(addr).into_iter().flat_map(|address| {
                [
                    AnnotationKind::Reads { address, width },
                    AnnotationKind::Writes { address, width },
                ]
            }));
        }
        _ => {}
    }
    found
}

/// The one number in the operands that spells this address, where there is one.
fn sole_operand(syntax: &Syntax, address: u64) -> Option<NumberSpan> {
    let mut spelling = syntax
        .numbers
        .iter()
        .filter(|number| number.value == i128::from(address));
    let found = spelling.next()?;
    spelling.next().is_none().then_some(*found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storages_overlap_by_a_shared_byte_in_one_space_only() {
        let rax = Varnode::register(8, 8);
        assert!(overlaps(&rax, &Varnode::register(8, 1)));
        assert!(overlaps(&rax, &Varnode::register(15, 1)));
        // The neighbours on either side share no byte.
        assert!(!overlaps(&rax, &Varnode::register(0, 8)));
        assert!(!overlaps(&rax, &Varnode::register(16, 8)));
        assert!(!overlaps(&rax, &Varnode::unique(8, 8)));
    }

    #[test]
    fn a_write_covers_only_what_it_replaces_whole() {
        let rax = Varnode::register(8, 8);
        assert!(covers(&rax, &rax));
        assert!(covers(&rax, &Varnode::register(9, 1)));
        assert!(!covers(&Varnode::register(8, 1), &rax));
        assert!(!covers(&Varnode::register(12, 8), &rax));
        assert!(!covers(&Varnode::register(4, 8), &rax));
        assert!(!covers(&Varnode::unique(8, 8), &rax));
    }
}
