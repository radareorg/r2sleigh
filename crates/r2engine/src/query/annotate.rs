//! What one instruction's own lift says about the addresses it touches.
//!
//! Lifting is the whole point: a number in the operands is an address because
//! the instruction transfers to it or reads it, not because it looks like one.

use r2il::ValueUse;
use r2il::{R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{NumberSpan, Syntax};
use r2ssa::CanonicalStorageId;
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};
use std::collections::{BTreeMap, BTreeSet};

use super::Support;
use super::Work;
use super::decode::Lookahead;
use super::records::{Annotation, AnnotationKind, Answered, Line, Memory, WalkedBody};
use super::references::Role;

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
    let call_effect = answered.call_effect;
    let body = (work >= Work::Function).then_some(answered.body).flatten();
    let fresh = fresh_over(lines, body);
    let mut named = named_over(run.lifts, &fresh, call_effect);
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
    let relative = relative_over(answered, run, lines, &named, &fresh);
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
            .map(|(kind, own)| (kind.clone(), folded_support(*own)))
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
                call_effect,
                body,
                parameters: (!relative).then_some(answered.parameters).flatten(),
                used: None,
            };
            // A number that moves with the program is an address; one that stays put is one only where it is used as one.
            let support = match relative {
                true => result_of(lift, &mut after, &computed.output, line.address)
                    .map(|settled| settled.max(folded_support(computed.own))),
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
        // What the bytes hold is for a reader; the reference index reads only what the lines claim.
        if answered.holdings {
            let revision = revision_at(memory, &claims);
            claims.extend(revision);
        }
        if work >= Work::Function {
            let folded = |storage| named.left(storage);
            claims.extend(super::proved::proved_about(answered, line.address, &folded));
        }
        line.annotations = claims
            .into_iter()
            .map(|(kind, support)| Annotation {
                operand: line
                    .syntax
                    .as_ref()
                    .zip(kind.address())
                    .and_then(|(syntax, address)| sole_operand(syntax, address)),
                reference: referenced(memory, &kind),
                kind,
                support,
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
fn referenced(memory: &Memory<'_>, kind: &AnnotationKind) -> bool {
    kind.role().is_some() && kind.address().is_some_and(|address| memory.maps(address))
}

/// Decoded where the instruction alone folds the number, folded where the block before it had to.
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
    /// The number the run leaves in each register it writes, where the run folds one.
    folded: Vec<(CanonicalStorageId, u64)>,
}

impl Named {
    /// The number the run leaves in a storage after this instruction, where it folds one.
    fn left(&self, storage: CanonicalStorageId) -> Option<u64> {
        self.folded
            .iter()
            .find(|(held, _)| *held == storage)
            .map(|(_, value)| *value)
    }
}

/// A number one instruction leaves, where it leaves it, and whether its own operations fold it.
struct Computed {
    value: u64,
    output: Varnode,
    own: bool,
}

/// Where the fold starts afresh: everywhere but the next line of one block of the body, which control reaches only from the line before.
fn fresh_over(lines: &[Line], body: Option<&WalkedBody<'_>>) -> Vec<bool> {
    let Some(body) = body else {
        return vec![true; lines.len()];
    };
    let mut before = None;
    let fresh = |line: &Line| {
        let block = body.block_of(line.address);
        let carried = block.is_some_and(|start| start != line.address && before == block);
        before = block;
        !carried
    };
    lines.iter().map(fresh).collect()
}

/// Name each line of a run, carrying what one line leaves into the next except where `fresh` starts the fold again.
fn named_over(
    lifts: &[Option<r2il::R2ILBlock>],
    fresh: &[bool],
    call_effect: Option<&r2ssa::SourceCallEffect>,
) -> Vec<Option<Named>> {
    let mut carried = BlockOrigins::default();
    lifts
        .iter()
        .zip(fresh)
        .map(|(lift, fresh)| {
            if *fresh {
                carried = BlockOrigins::default();
            }
            let Some(lift) = lift else {
                carried = BlockOrigins::default();
                return None;
            };
            Some(named_by(lift, &mut carried, call_effect))
        })
        .collect()
}

/// What one instruction names, from what the block held before it.
fn named_by(
    lift: &r2il::R2ILBlock,
    carried: &mut BlockOrigins,
    call_effect: Option<&r2ssa::SourceCallEffect>,
) -> Named {
    let before = carried.clone();
    let mut own = BlockOrigins::default();
    let mut touched: Vec<(AnnotationKind, bool)> = Vec::new();
    for op in &lift.ops {
        let alone = touched_at(&own, op);
        for kind in touched_at(carried, op) {
            if !touched.iter().any(|(held, _)| *held == kind) {
                let own = alone.contains(&kind);
                touched.push((kind, own));
            }
        }
        carried.step_under(op, call_effect);
        own.step_under(op, call_effect);
    }
    // A number the instruction only copies from a register it read was computed where that was.
    let copied = lift
        .ops
        .iter()
        .flat_map(R2ILOp::inputs)
        .filter(|input| input.space == SpaceId::Register)
        .filter_map(|input| before.of(input).and_then(ValueOrigin::constant))
        .collect::<BTreeSet<_>>();
    let left = lift
        .ops
        .iter()
        .filter_map(R2ILOp::output)
        .filter(|output| output.space == SpaceId::Register)
        .filter_map(|output| Some((output, carried.of(output)?.constant()?)))
        .collect::<Vec<_>>();
    // An address fills a register, so of the registers left holding a number the widest is the result; a flag is one bit.
    let computed = left
        .iter()
        .filter(|(_, value)| !copied.contains(value))
        .max_by_key(|(output, _)| output.size)
        .map(|(output, value)| Computed {
            value: *value,
            output: (*output).clone(),
            own: own.of(output).and_then(ValueOrigin::constant) == Some(*value),
        });
    let folded = left
        .into_iter()
        .map(|(output, value)| (CanonicalStorageId::from_varnode(output), value))
        .collect();
    Named {
        touched,
        computed,
        folded,
    }
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
    fresh: &[bool],
) -> Vec<bool> {
    // Only as far as the last number that needs it: what the block carries runs forward.
    let Some(last) = named.iter().rposition(|one| computed(one).is_some()) else {
        return vec![false; lines.len()];
    };
    let shifted = super::decode::lift_run(answered, &lines[..=last], &run.windows[..=last], PAGE);
    let there = named_over(&shifted, fresh, answered.call_effect);
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

/// What this revision holds at the addresses the line's claims use as data, each on the rung of the claim; a word read is data, not a use.
///
/// Text is said only where a claim reads, writes or computes the address.
/// Where the line transfers control there, its own lift says the bytes are
/// executed, so a string there would contradict the claim it hangs on.
fn revision_at(
    memory: &Memory<'_>,
    claims: &[(AnnotationKind, Support)],
) -> Vec<(AnnotationKind, Support)> {
    let mut said = Vec::new();
    // Each address a claim uses as data, with how many bytes the claim itself accesses there.
    let mut used = BTreeMap::<u64, Vec<(u32, Support)>>::new();
    for (kind, support) in claims {
        if let AnnotationKind::Reads { address, width } = *kind
            && let Some(value) = memory.word(address, width)
        {
            let kind = AnnotationKind::Holds {
                address,
                width,
                value,
            };
            said.push((kind, *support));
        }
        let (Some(address), Some(accessed)) =
            (kind.address(), kind.role().and_then(Role::data_access))
        else {
            continue;
        };
        used.entry(address).or_default().push((accessed, *support));
    }
    for (address, uses) in used {
        let Some(text) = memory.text(address) else {
            continue;
        };
        // Text an access holds whole is only that word's bytes spelled by chance, so only text running past the access is claimed.
        let past = |accessed: u32| usize::try_from(accessed).is_ok_and(|bytes| text.len() > bytes);
        let support = uses
            .iter()
            .filter(|(accessed, _)| past(*accessed))
            .map(|(_, support)| *support)
            .min();
        if let Some(support) = support {
            said.push((AnnotationKind::Text { address, text }, support));
        }
    }
    said
}

/// What can be known of the program after one instruction.
struct After<'a, 'r, 'b> {
    /// The lifts of the lines that follow it in the run.
    rest: &'a [Option<r2il::R2ILBlock>],
    /// The instructions past the run, read as far as a question needs them.
    beyond: &'a mut Lookahead<'r, 'b>,
    /// What a call does; without it a call leaves every holder standing.
    call_effect: Option<&'a r2ssa::SourceCallEffect>,
    /// The walked body and its def-use, where the request paid for it.
    body: Option<&'a WalkedBody<'a>>,
    /// Which parameters of a callee take an address, where the number's use decides whether it is one.
    parameters: Option<&'a dyn super::records::Parameters>,
    /// The strongest support a call handing the number to such a parameter gave.
    used: Option<Support>,
}

/// The rung that settles the number an instruction leaves in `output` as its result: the run after it, else the def-use.
///
/// A value a later instruction builds a number on is a step towards an address
/// rather than one: spelling `adrp x17, reloc.humanize_number` named the page
/// base the `add` after it was about to move fifty bytes past. Copying, storing,
/// comparing, loading through or passing the number is using it as it stands.
fn result_of(
    lift: &r2il::R2ILBlock,
    after: &mut After<'_, '_, '_>,
    output: &Varnode,
    address: u64,
) -> Option<Support> {
    match straight_line_fate(lift, after, output) {
        Fate::Result => Some(Support::Folded),
        Fate::Step => None,
        Fate::Unknown => {
            let settled = after
                .body?
                .fate_of(address, CanonicalStorageId::from_varnode(output))?;
            (settled == r2ssa::fate::Fate::Result).then_some(Support::Certified)
        }
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
            match op_fate(op, &mut holders, &mut derived, after.call_effect) {
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
    let op = block.ops.get(at)?;
    let call = op.transfer().filter(|transfer| transfer.call)?;
    let callee = if call.direct {
        Callee::At(encoded_target(call.target)?)
    } else {
        match BlockOrigins::upto(block, at).of(call.target)? {
            ValueOrigin::Constant { value, .. } => Callee::At(value),
            ValueOrigin::LoadedSlot(slot) => Callee::ThroughSlot(slot.offset),
        }
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
    call_effect: Option<&r2ssa::SourceCallEffect>,
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
            // A register the call may change no longer holds the number.
            holders.retain(|held| {
                call_effect.is_none_or(|effect| {
                    held.space != SpaceId::Register
                        || !effect.clobbers(CanonicalStorageId::from_varnode(held))
                })
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

/// The addresses one operation names, as far as the block so far shows.
fn touched_at(origins: &BlockOrigins, op: &R2ILOp) -> Vec<AnnotationKind> {
    let folded = |addr: &Varnode| origins.of(addr).and_then(ValueOrigin::constant);
    // A direct transfer encodes its target; a computed one names it wherever the block folds it, a loaded one only the slot it read.
    if let Some(transfer) = op.transfer() {
        let target = if transfer.direct {
            encoded_target(transfer.target)
        } else {
            folded(transfer.target)
        };
        let call = transfer.call;
        return target
            .map(|address| AnnotationKind::Target { address, call })
            .into_iter()
            .collect();
    }
    accessed(op)
        .into_iter()
        .filter_map(|(addr, width, access)| Some(access(folded(addr)?, width)))
        .collect()
}

/// How an access is claimed at the address it folds to.
type Access = fn(u64, u32) -> AnnotationKind;

const fn reads(address: u64, width: u32) -> AnnotationKind {
    AnnotationKind::Reads { address, width }
}

const fn writes(address: u64, width: u32) -> AnnotationKind {
    AnnotationKind::Writes { address, width }
}

/// Each address one operation reads or writes memory through, with the bytes it accesses there.
///
/// A conditional or linked access names the address it would use as surely as
/// a plain one does, and a repeated string operation names the first element
/// at each address it reads or writes through.
fn accessed(op: &R2ILOp) -> Vec<(&Varnode, u32, Access)> {
    match op {
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
        } => vec![(addr, dst.size, reads)],
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
        } => vec![(addr, val.size, writes)],
        R2ILOp::AtomicCAS {
            space: SpaceId::Ram,
            addr,
            expected,
            ..
        } => vec![(addr, expected.size, reads), (addr, expected.size, writes)],
        R2ILOp::BlockTransfer(transfer) if transfer.space == SpaceId::Ram => {
            let (kind, width) = (transfer.kind, transfer.element_size);
            let (source, destination) = (&transfer.source, &transfer.destination);
            [
                kind.source_is_address()
                    .then_some((source, width, reads as Access)),
                kind.stop().map(|_| (destination, width, reads as Access)),
                kind.writes_memory()
                    .then_some((destination, width, writes as Access)),
            ]
            .into_iter()
            .flatten()
            .collect()
        }
        _ => Vec::new(),
    }
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
