//! What one instruction's own lift says about the addresses it touches.
//!
//! Lifting is the whole point: a number in the operands is an address because
//! the instruction transfers to it or reads it, not because it looks like one.

use r2il::ValueUse;
use r2il::{R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{NumberSpan, Syntax};
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};
use r2ssa::{CanonicalStorageId, CanonicalStorageSpace};
use std::collections::{BTreeMap, BTreeSet};

use super::Work;
use super::decode::Lookahead;
use super::records::{Annotation, AnnotationKind, Answered, Line, Memory, WalkedBody};
use super::references::Role;
use r2source::confidence::Basis;

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
/// An address an instruction forms, transfers to or accesses is claimed where it is formed, whatever
/// the next instruction does with it (doc/adr-query-database.md, "Formed addresses").
/// This is the one place a number becomes an address claim, and `referenced` the one place a claim becomes a reference.
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
    let spelled = spelled_over(answered, lines);
    for (one, spelled) in named.iter_mut().zip(&spelled) {
        if let Some(one) = one {
            one.keep_named(memory, spelled.as_deref());
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
            // A number that moves with the program is an address where it is formed; one that stays put is one only where it is handed to a pointer parameter.
            let support = match relative.get(index).copied() == Some(true) {
                true => Some(folded_support(computed.own)),
                false => {
                    let mut after = After {
                        rest: &run.lifts[index + 1..],
                        beyond: &mut *beyond,
                        call_effect,
                        parameters: answered.parameters,
                    };
                    handed_to_pointer(lift, &mut after, &computed.output)
                }
            };
            if let Some(support) = support {
                let kind = AnnotationKind::Computes {
                    value: computed.value,
                };
                claims.push((kind, support));
            }
        }
        claims.extend(
            body.into_iter()
                .flat_map(|body| arms_of(body, line.address)),
        );
        // What the bytes hold is for a reader; the reference index reads only what the lines claim.
        if answered.holdings {
            let revision = revision_at(memory, &claims);
            claims.extend(revision);
        }
        if work >= Work::Function {
            let folded = |storage| named.left(storage);
            claims.extend(super::proved::proved_about(answered, line.address, &folded));
        }
        line.annotations = annotated(claims, line.syntax.as_ref(), memory);
    }
}

/// The claims of one line as annotations, each with the operand that spells its address.
fn annotated(
    claims: Vec<(AnnotationKind, Basis)>,
    syntax: Option<&Syntax>,
    memory: &Memory<'_>,
) -> Vec<Annotation> {
    let annotate = |(kind, support): (AnnotationKind, Basis)| Annotation {
        operand: syntax
            .zip(kind.address())
            .and_then(|(syntax, address)| sole_operand(syntax, address)),
        reference: referenced(memory, &kind),
        kind,
        support,
    };
    claims.into_iter().map(annotate).collect()
}

/// A dispatch the walk followed transfers to each of its arms, which no operation of the instruction names.
fn arms_of(
    body: &WalkedBody<'_>,
    instruction: u64,
) -> impl Iterator<Item = (AnnotationKind, Basis)> {
    let arms = body.arms_at(instruction).into_iter();
    arms.map(|address| {
        (
            AnnotationKind::Target {
                address,
                call: false,
            },
            Basis::Solved,
        )
    })
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
fn folded_support(own: bool) -> Basis {
    match own {
        true => Basis::Decoded,
        false => Basis::Folded,
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
    /// Forget a computed number the program does not map, whatever it moves with, and one left in a
    /// register no operand of the instruction names: the machine's own bookkeeping, like x87's
    /// instruction pointer, is no result.
    fn keep_named(&mut self, memory: &Memory<'_>, spelled: Option<&[CanonicalStorageId]>) {
        let named = |output: &Varnode| {
            spelled.is_none_or(|spelled| spelled.iter().any(|register| holds(register, output)))
        };
        let kept = (self.computed.as_ref())
            .is_none_or(|computed| memory.maps(computed.value) && named(&computed.output));
        if !kept {
            self.computed = None;
        }
    }

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
    claims: &[(AnnotationKind, Basis)],
) -> Vec<(AnnotationKind, Basis)> {
    let mut said = Vec::new();
    // Each address a claim uses as data, with how many bytes the claim itself accesses there.
    let mut used = BTreeMap::<u64, Vec<(u32, Basis)>>::new();
    for (kind, support) in claims {
        if let AnnotationKind::Reads { address, width } = *kind
            && let Some(word) = memory.word(address, width)
        {
            let kind = match word {
                crate::stated::StatedWord::Held(value) => AnnotationKind::Holds {
                    address,
                    width,
                    value,
                },
                crate::stated::StatedWord::Loaded(value) => AnnotationKind::Loaded {
                    address,
                    width,
                    value,
                },
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

/// What the run after an instruction shows of where the number it leaves goes.
struct After<'a, 'r, 'b> {
    /// The lifts of the lines that follow it in the run.
    rest: &'a [Option<r2il::R2ILBlock>],
    /// The instructions past the run, read as far as a question needs them.
    beyond: &'a mut Lookahead<'r, 'b>,
    /// What a call does; without it a call leaves every holder standing.
    call_effect: Option<&'a r2ssa::SourceCallEffect>,
    /// Which parameters of a callee take an address, where the number's use decides whether it is one.
    parameters: Option<&'a dyn super::records::Parameters>,
}

/// Whether a storage is a temporary one instruction's operations share.
fn scratch(space: SpaceId) -> bool {
    space == SpaceId::Unique
}

/// The weakest support among the calls that take the number in a pointer parameter, followed through copies.
///
/// Ends when no storage holds the number, at a branch, or where the lookahead stops; each is a bounded
/// step down the straight line, so it is linear in the lines read.
fn handed_to_pointer(
    lift: &r2il::R2ILBlock,
    after: &mut After<'_, '_, '_>,
    output: &Varnode,
) -> Option<Basis> {
    let parameters = after.parameters?;
    // Past a branch the run is no longer every path the value takes.
    if lift.ops.iter().any(R2ILOp::is_control_flow) {
        return None;
    }
    let mut holders = vec![output.clone()];
    let mut used: Option<Basis> = None;
    let listed = after.rest.len();
    for index in 0.. {
        let block = match after.rest.get(index) {
            Some(block) => block.as_ref(),
            None => after.beyond.at(index - listed).flatten(),
        };
        let Some(block) = block else {
            break;
        };
        for (at, op) in block.ops.iter().enumerate() {
            if let Some(support) = pointer_use(parameters, block, at, &holders) {
                used = Some(used.map_or(support, |held| held.min(support)));
            }
            if !follow_copies(op, &mut holders, after.call_effect) || holders.is_empty() {
                return used;
            }
        }
        holders.retain(|held| !scratch(held.space));
        if holders.is_empty() {
            break;
        }
    }
    used
}

/// How a call hands on the number where a register holding it is a parameter its callee takes an address in.
fn pointer_use(
    parameters: &dyn super::records::Parameters,
    block: &r2il::R2ILBlock,
    at: usize,
    holders: &[Varnode],
) -> Option<Basis> {
    use super::records::Callee;
    let op = block.ops.get(at)?;
    let call = op.transfer().filter(|transfer| transfer.call)?;
    let callee = if call.direct {
        Callee::At(encoded_target(call.target)?)
    } else if let Some(slot) = r2ssa::loaded_target_slot(block, at) {
        Callee::ThroughSlot(slot.offset)
    } else {
        Callee::At(BlockOrigins::upto(block, at).of(call.target)?.constant()?)
    };
    let held = |storage: &CanonicalStorageId| {
        holders
            .iter()
            .any(|held| held.space == SpaceId::Register && held.offset == storage.offset)
    };
    parameters.pointer_use(callee, &held)
}

/// Move the storages holding the number past one operation: a copy adds its output, a write replaces what it covers; false at a branch.
fn follow_copies(
    op: &R2ILOp,
    holders: &mut Vec<Varnode>,
    call_effect: Option<&r2ssa::SourceCallEffect>,
) -> bool {
    if op.is_call() {
        // A register the call may change no longer holds the number.
        holders.retain(|held| {
            call_effect.is_none_or(|effect| {
                held.space != SpaceId::Register
                    || !effect.clobbers(CanonicalStorageId::from_varnode(held))
            })
        });
        return true;
    }
    if op.is_control_flow() {
        return false;
    }
    let Some(written) = op.output() else {
        return true;
    };
    let copied = op.value_use() == ValueUse::Carries
        && op
            .inputs()
            .iter()
            .any(|input| holders.iter().any(|held| overlaps(held, input)));
    holders.retain(|held| !covers(written, held));
    if copied {
        holders.push(written.clone());
    }
    true
}

/// The registers each decoded line's operands spell, which is where the instruction states its result goes.
fn spelled_over(answered: &Answered<'_>, lines: &[Line]) -> Vec<Option<Vec<CanonicalStorageId>>> {
    let spelled = |line: &Line| {
        let syntax = line.syntax.as_ref()?;
        let arch = answered.decoders.at(line.address)?.tables();
        let names = arch.registers_by_name();
        let found = syntax.registers.iter().filter_map(|span| {
            let name = syntax.body.get(span.start..span.end)?.to_ascii_lowercase();
            names.get(&name).copied()
        });
        Some(found.collect())
    };
    lines.iter().map(spelled).collect()
}

/// Whether a register the operands name shares a byte with a storage the instruction writes.
fn holds(register: &CanonicalStorageId, output: &Varnode) -> bool {
    register.space == CanonicalStorageSpace::Register
        && register.offset < output.offset + u64::from(output.size)
        && output.offset < register.offset + u64::from(register.size)
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
    op.memory_accesses()
        .filter(|access| access.space == SpaceId::Ram)
        .filter_map(|access| {
            let (address, width) = (folded(access.addr)?, access.size);
            Some(match access.kind {
                r2il::eval::AccessKind::Read => AnnotationKind::Reads { address, width },
                r2il::eval::AccessKind::Write => AnnotationKind::Writes { address, width },
            })
        })
        .collect()
}

/// The one number in the operands that spells this address, where there is one.
fn sole_operand(syntax: &Syntax, address: u64) -> Option<NumberSpan> {
    let mut spelling = syntax.numbers.iter().filter(|number| {
        let exact = i128::from(address) == number.value;
        exact || (spells_address(number.value, address) && !beside_a_register(syntax, number))
    });
    let found = spelling.next()?;
    spelling.next().is_none().then_some(*found)
}

/// Whether a number shares its bracketed operand with a register: a displacement, which a wrapped
/// spelling never names, since the register's value is added to it.
fn beside_a_register(syntax: &Syntax, number: &NumberSpan) -> bool {
    let body = syntax.body.as_bytes();
    let before = &body[..number.start.min(body.len())];
    let Some(open) = before.iter().rposition(|byte| *byte == b'[') else {
        return false;
    };
    if before[open..].contains(&b']') {
        return false;
    }
    let after = body.get(number.end..).unwrap_or_default();
    let close = after.iter().position(|byte| *byte == b']');
    let close = close.map_or(body.len(), |at| number.end + at);
    (syntax.registers.iter()).any(|register| register.start > open && register.end <= close)
}

/// Whether a spelled number is this address: as written, or a negative spelling of it wrapped at
/// 64 or 32 bits, as Sleigh prints a computed address whose top bit is set.
fn spells_address(value: i128, address: u64) -> bool {
    let address = i128::from(address);
    value == address
        || (value < 0
            && (value.rem_euclid(1 << 64) == address
                || (address < 1 << 32 && value.rem_euclid(1 << 32) == address)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_displacement_beside_a_register_is_never_a_wrapped_address() {
        use r2sleigh_lift::Span;
        let syntax = |body: &str, number: (usize, usize, i128), registers: Vec<Span>| Syntax {
            mnemonic: "mov".into(),
            body: body.into(),
            size: 3,
            numbers: vec![NumberSpan {
                start: number.0,
                end: number.1,
                value: number.2,
            }],
            registers,
        };
        let eax = |start| Span {
            start,
            end: start + 3,
        };
        let displaced = syntax(
            "ecx, dword [eax - 0x10]",
            (16, 22, -0x10),
            vec![eax(0), eax(12)],
        );
        assert_eq!(sole_operand(&displaced, 0xffff_fff0), None);
        let absolute = syntax("ecx, dword [-0x10]", (12, 17, -0x10), vec![eax(0)]);
        assert!(sole_operand(&absolute, 0xffff_fff0).is_some());
        let named = syntax(
            "ecx, dword [eax + 0x4010]",
            (16, 24, 0x4010),
            vec![eax(0), eax(12)],
        );
        assert!(sole_operand(&named, 0x4010).is_some());
    }

    #[test]
    fn a_negative_spelling_is_the_address_it_wraps_to() {
        assert!(spells_address(-0xef18, 0xffff_ffff_ffff_10e8));
        assert!(spells_address(-0x10, 0xffff_fff0));
        assert!(spells_address(0x4010, 0x4010));
        assert!(!spells_address(-0x10, 0x10));
    }

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
