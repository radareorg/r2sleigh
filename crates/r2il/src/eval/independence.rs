//! What an operation's value does not depend on, derived from [`apply`](super::apply) and the
//! constants it is given (doc/adr-resolved-bodies.md, "Caller reads").

use std::collections::BTreeMap;

use super::{CARRIED, Operation, Word, apply, mask};
use crate::{Endianness, R2ILOp, SpaceId, Varnode};

/// One operand of an operation: its width, and what is known of its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub bytes: u32,
    pub known: Known,
}

/// What is known of one operand's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known {
    Nothing,
    /// Its value at its width.
    Value(u128),
    /// The same storage as the operand at this earlier position.
    Same(usize),
}

/// Bits set at the positions of `operands` the result does not depend on: one against a constant
/// that fixes it (zero for `and`, all ones for `or`), or both of one storage in `xor`, `-`, a comparison.
pub fn ignored_operands(operation: Operation, operands: &[Operand]) -> u32 {
    use Operation as O;
    let value = |at: usize| match operands.get(at) {
        Some(Operand {
            known: Known::Value(bits),
            bytes,
        }) => Some((*bits, *bytes)),
        _ => None,
    };
    if let [_, second] = operands
        && second.known == Known::Same(0)
    {
        let cancels = matches!(
            operation,
            O::Xor
                | O::Sub
                | O::SBorrow
                | O::Equal
                | O::NotEqual
                | O::Less
                | O::SLess
                | O::LessEqual
                | O::SLessEqual
        );
        return if cancels { 0b11 } else { 0 };
    }
    let mut ignored = 0;
    if let [first, second] = operands {
        for at in 0..2 {
            let (fixed, free) = match at {
                0 => (value(1), first.bytes),
                _ => (value(0), second.bytes),
            };
            if let Some(fixed) = fixed
                && fixes(operation, at, fixed, free)
            {
                ignored |= 1 << at;
            }
        }
    }
    if let (O::Select, [cond, _, otherwise]) = (operation, operands) {
        match cond.known {
            Known::Value(bits) => ignored |= if bits == 0 { 0b010 } else { 0b100 },
            _ if otherwise.known == Known::Same(1) => ignored |= 0b001,
            _ => {}
        }
    }
    ignored
}

/// Whether the result of `operation` is the same whatever its operand at `at` (`free` bytes wide)
/// holds, the other holding `fixed`.
fn fixes(operation: Operation, at: usize, (bits, bytes): (u128, u32), free: u32) -> bool {
    use Operation as O;
    // All ones, and the sign bit, are only as wide as the bits carried.
    let exact = bytes <= CARRIED;
    let ones = exact && bits == mask(bytes);
    let sign = if exact { 1u128 << (8 * bytes - 1) } else { 0 };
    match (operation, at) {
        (O::And | O::Mult | O::Carry | O::SCarry | O::BoolAnd, _) => bits == 0,
        (O::Or, _) => ones,
        (O::BoolOr, _) => bits == 1,
        // A shifted value is gone past its width; nothing shifts a nought, and an arithmetic shift
        // keeps a nought and all ones.
        (O::Left | O::Right, 0) => bits >= 8 * u128::from(free),
        (O::Left | O::Right, 1) => bits == 0,
        (O::SRight, 1) => bits == 0 || ones,
        (O::Less, 0) => bits == 0,
        (O::Less, 1) => ones,
        (O::LessEqual, 0) => ones,
        (O::LessEqual, 1) => bits == 0,
        (O::SLess, 0) => exact && bits == sign,
        (O::SLess, 1) => exact && bits == sign - 1,
        (O::SLessEqual, 0) => exact && bits == sign - 1,
        (O::SLessEqual, 1) => exact && bits == sign,
        // `x - 0` and `-1 - x` never overflow.
        (O::SBorrow, 0) => bits == 0,
        (O::SBorrow, 1) => ones,
        (O::Rem, 0) => bits == 1,
        (O::SRem, 0) => bits == 1 || ones,
        _ => false,
    }
}

/// What the operations of one instruction read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reads {
    /// Per operation, the bits of [`ignored_operands`] over `R2ILOp::inputs`; all of them for one
    /// that only feeds a temporary nothing reads.
    pub ignored: Vec<u32>,
    /// Whether a live operation cancels one register against itself (`xor eax, eax`, `sbb edx, edx`);
    /// the flags beside it read the register's bits, not its value.
    pub cancels_register: bool,
}

/// What the operations of one instruction read, following constants in temporaries (`imul edx, edx,
/// 0` ignores `edx`). `whole`: `ops` are all of an instruction; `endian` orders a truncation's bytes.
pub fn reads_of(ops: &[R2ILOp], whole: bool, endian: Endianness) -> Reads {
    let mut held = Held::new();
    // An instruction that branches within itself runs some of its operations on some paths only.
    let straight = !ops.iter().any(R2ILOp::is_control_flow);
    let mut numbers = Numbers::new(endian, straight);
    let mut ignored = Vec::with_capacity(ops.len());
    let mut cancels = Vec::with_capacity(ops.len());
    for op in ops {
        let inputs = op.inputs();
        let operands = operands_of(&inputs, &held, &numbers);
        let operation = Operation::of(op).map(|(operation, _, _)| operation);
        let mask = operation.map_or(0, |operation| ignored_operands(operation, &operands));
        ignored.push(mask);
        cancels.push(
            mask == 0b11
                && matches!(operands.as_slice(), [_, second] if second.known == Known::Same(0))
                && inputs[0].space == SpaceId::Register,
        );
        numbers.step(op);
        let Some(output) = op.output().filter(|output| output.space == SpaceId::Unique) else {
            continue;
        };
        forget(&mut held, output);
        let value = operation.and_then(|operation| {
            let words = (operands.iter())
                .map(|operand| match operand.known {
                    Known::Value(bits) => Word::new(bits, operand.bytes).ok(),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?;
            let value = apply(operation, &words, output.size).ok()?;
            Word::new(value, output.size).ok()
        });
        if let Some(word) = value {
            held.insert((false, output.offset), word);
        }
    }
    if whole {
        unused(ops, &mut ignored);
    }
    let cancels_register =
        (cancels.iter().zip(&ignored)).any(|(cancels, mask)| *cancels && *mask != u32::MAX);
    Reads {
        ignored,
        cancels_register,
    }
}

/// Whether `ops`, all of one instruction, leave every byte of the register `at` nought (`xor eax,
/// eax`, `mov eax, 0`); false where they leave it unstated or an unmodelled operation may write it.
pub fn leaves_zero(ops: &[R2ILOp], at: &Varnode) -> bool {
    if at.space != SpaceId::Register {
        return false;
    }
    let mut held = Held::new();
    for op in ops {
        let Some((operation, dst, inputs)) = Operation::of(op) else {
            match op {
                R2ILOp::Nop | R2ILOp::Store { .. } => {}
                R2ILOp::Load { dst, .. } => forget(&mut held, dst),
                _ => return false,
            }
            continue;
        };
        let value = constant_result(
            operation,
            &operands_of(&inputs, &held, &Numbers::new(Endianness::Custom, false)),
            dst.size,
        );
        forget(&mut held, dst);
        if let Some(word) = value
            && matches!(dst.space, SpaceId::Unique | SpaceId::Register)
        {
            held.insert((dst.space == SpaceId::Register, dst.offset), word);
        }
    }
    covered_by_nought(&held, at)
}

/// What `operation` computes at `width` where its operands state it: an operand it ignores may be
/// anything, so it is taken as nought.
fn constant_result(operation: Operation, operands: &[Operand], width: u32) -> Option<Word> {
    let ignored = ignored_operands(operation, operands);
    let words = (operands.iter().enumerate())
        .map(|(position, operand)| match operand.known {
            Known::Value(bits) => Word::new(bits, operand.bytes).ok(),
            _ if position < 32 && ignored >> position & 1 == 1 => Word::new(0, operand.bytes).ok(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Word::new(apply(operation, &words, width).ok()?, width).ok()
}

/// Whether the nought registers `held` names cover every byte of `at`. Words do not overlap, so the
/// nought ones that cover the range are the range being nought.
fn covered_by_nought(held: &Held, at: &Varnode) -> bool {
    let end = at.offset.saturating_add(u64::from(at.size));
    let registers = held.iter().filter(|((register, _), _)| *register);
    let nought = registers.filter(|(_, word)| word.bits == 0);
    let mut next = at.offset;
    for ((_, start), word) in nought {
        let stop = start.saturating_add(u64::from(word.bytes));
        if *start <= next && stop > next {
            next = stop;
        }
    }
    next >= end
}

/// The constants temporaries and registers hold, by whether it is a register and where.
type Held = BTreeMap<(bool, u64), Word>;

/// Which bytes hold one value within an instruction: a byte is numbered by what last wrote it (or by
/// its place), and a copy or truncation hands its source's numbers on. Equal numbers are one value.
struct Numbers {
    written: BTreeMap<(bool, u64), u64>,
    fresh: u64,
    /// Bumped where an operation may write any register, so no place keeps the number it had.
    generation: u64,
    endian: Endianness,
    /// Whether the operations run in order, each once: else no two places are known to be one value.
    straight: bool,
}

impl Numbers {
    fn new(endian: Endianness, straight: bool) -> Self {
        Self {
            written: BTreeMap::new(),
            fresh: 0,
            generation: 0,
            endian,
            straight,
        }
    }

    /// The number of each byte of `at`, in storage order; none outside registers and temporaries.
    fn of(&self, at: &Varnode) -> Option<Vec<u64>> {
        if !self.straight {
            return None;
        }
        let register = match at.space {
            SpaceId::Register => true,
            SpaceId::Unique => false,
            _ => return None,
        };
        Some(
            (0..u64::from(at.size))
                .map(|byte| {
                    let place = (register, at.offset.saturating_add(byte));
                    let entry = 1 << 63 | self.generation << 48 | u64::from(register) << 47;
                    (self.written.get(&place).copied())
                        .unwrap_or(entry | (place.1 & ((1 << 47) - 1)))
                })
                .collect(),
        )
    }

    /// `at` holds `numbers`, or a value of its own where none are given.
    fn write(&mut self, at: &Varnode, numbers: Option<Vec<u64>>) {
        let register = match at.space {
            SpaceId::Register => true,
            SpaceId::Unique => false,
            _ => return,
        };
        for byte in 0..u64::from(at.size) {
            let number = match numbers.as_ref().and_then(|held| held.get(byte as usize)) {
                Some(number) => *number,
                None => {
                    self.fresh += 1;
                    self.fresh
                }
            };
            self.written
                .insert((register, at.offset.saturating_add(byte)), number);
        }
    }

    /// Move the numbers on past `op`.
    fn step(&mut self, op: &R2ILOp) {
        if op.reads_unstated() || op.is_control_flow() {
            self.written.clear();
            self.generation += 1;
            return;
        }
        match op {
            R2ILOp::Copy { dst, src } if dst.size == src.size => {
                let moved = self.of(src);
                self.write(dst, moved);
            }
            // The low bytes of a value are the first of a little-endian storage; no other order is known.
            R2ILOp::Subpiece { dst, src, offset } if self.endian == Endianness::Little => {
                let from = *offset as usize;
                let moved = self.of(src).and_then(|held| {
                    held.get(from..from + dst.size as usize)
                        .map(<[u64]>::to_vec)
                });
                self.write(dst, moved);
            }
            _ => {
                if let Some(output) = op.output() {
                    self.write(output, None);
                }
            }
        }
    }

    /// Whether `one` and `other` hold the same value in all their bytes.
    fn alike(&self, one: &Varnode, other: &Varnode) -> bool {
        match (self.of(one), self.of(other)) {
            (Some(one), Some(other)) => one == other,
            _ => one == other,
        }
    }
}

/// What each of `inputs` is known to be: a constant, a temporary or register holding one, or the
/// same value as an earlier input.
fn operands_of(inputs: &[&Varnode], held: &Held, numbers: &Numbers) -> Vec<Operand> {
    let mut operands = Vec::with_capacity(inputs.len());
    for (at, input) in inputs.iter().enumerate() {
        let value = match input.space {
            SpaceId::Const => Some(u128::from(input.offset) & mask(input.size)),
            SpaceId::Unique | SpaceId::Register => (held
                .get(&(input.space == SpaceId::Register, input.offset)))
            .filter(|word| word.bytes == input.size)
            .map(|word| word.bits),
            _ => None,
        };
        let known = match value {
            Some(bits) => Known::Value(bits),
            None => match (0..at).find(|before| numbers.alike(inputs[*before], input)) {
                Some(before) => Known::Same(before),
                None => Known::Nothing,
            },
        };
        operands.push(Operand {
            bytes: input.size,
            known,
        });
    }
    operands
}

/// A write to `output` leaves nothing overlapping it holding what it held.
fn forget(held: &mut Held, output: &Varnode) {
    let end = output.offset.saturating_add(u64::from(output.size));
    let register = output.space == SpaceId::Register;
    held.retain(|(held_register, start), word| {
        *held_register != register
            || *start >= end
            || start.saturating_add(u64::from(word.bytes)) <= output.offset
    });
}

/// Mark every operand of an operation whose result nothing reads as ignored: one that writes only a
/// temporary, which no later operation reads through an operand it does not ignore.
fn unused(ops: &[R2ILOp], ignored: &mut [u32]) {
    // An operation that reads registers its operands do not name may read any temporary before it.
    if ops.iter().any(R2ILOp::reads_unstated) {
        return;
    }
    // The byte ranges of temporaries some later, used operation reads.
    let mut live: Vec<(u64, u64)> = Vec::new();
    for (at, op) in ops.iter().enumerate().rev() {
        let output = op.output().filter(|output| output.space == SpaceId::Unique);
        let wanted = !op.writes_only_temporaries()
            || output.is_some_and(|output| {
                let end = output.offset.saturating_add(u64::from(output.size));
                live.iter()
                    .any(|(start, stop)| *start < end && *stop > output.offset)
            });
        if !wanted {
            ignored[at] = u32::MAX;
            continue;
        }
        if let Some(output) = output {
            let end = output.offset.saturating_add(u64::from(output.size));
            live.retain(|(start, stop)| !(*start >= output.offset && *stop <= end));
        }
        for (position, input) in op.inputs().into_iter().enumerate() {
            let skipped = position < 32 && ignored[at] >> position & 1 == 1;
            if input.space == SpaceId::Unique && !skipped {
                let end = input.offset.saturating_add(u64::from(input.size));
                live.push((input.offset, end));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const BINARY: &[Operation] = &[
        Operation::Add,
        Operation::Sub,
        Operation::Mult,
        Operation::Div,
        Operation::SDiv,
        Operation::Rem,
        Operation::SRem,
        Operation::And,
        Operation::Or,
        Operation::Xor,
        Operation::Left,
        Operation::Right,
        Operation::SRight,
        Operation::Equal,
        Operation::NotEqual,
        Operation::Less,
        Operation::SLess,
        Operation::LessEqual,
        Operation::SLessEqual,
        Operation::Carry,
        Operation::SCarry,
        Operation::SBorrow,
    ];

    fn word(bits: u128, bytes: u32) -> Word {
        Word::new(bits, bytes).expect("a width")
    }

    /// The values of `bytes` to try an operand at: the edges, the sign and a few patterns.
    fn samples(bytes: u32) -> Vec<u128> {
        let all = mask(bytes);
        let sign = 1u128 << (8 * bytes - 1);
        let mut values = vec![
            0,
            1,
            2,
            all,
            all - 1,
            sign,
            sign - 1,
            sign + 1,
            0x55 & all,
            0xaa & all,
            0x0123_4567_89ab_cdef & all,
            0xfedc_ba98_7654_3210 & all,
        ];
        values.sort_unstable();
        values.dedup();
        values
    }

    /// Both operands `bytes` wide, `fixed` at the position other than `at`.
    fn facts(at: usize, fixed: u128, bytes: u32) -> [Operand; 2] {
        let free = Operand {
            bytes,
            known: Known::Nothing,
        };
        let held = Operand {
            bytes,
            known: Known::Value(fixed),
        };
        if at == 0 { [free, held] } else { [held, free] }
    }

    /// What `operation` gives with `fixed` against the operand at `at` holding `x`, if it gives one.
    fn result(operation: Operation, at: usize, fixed: Word, x: u128) -> Option<u128> {
        let x = word(x, fixed.bytes);
        let operands = if at == 0 { [x, fixed] } else { [fixed, x] };
        apply(operation, &operands, fixed.bytes).ok()
    }

    /// An operand `ignored_operands` says is ignored never changes the result: every value of a byte
    /// is tried, and the edges and patterns of 2, 4 and 8 bytes.
    #[test]
    fn what_an_operation_ignores_it_gives_the_same_value_whatever_it_holds() {
        let cases = BINARY.iter().flat_map(|operation| {
            [1u32, 2, 4, 8]
                .into_iter()
                .map(move |bytes| (*operation, bytes))
        });
        for (operation, bytes) in cases {
            let tried = match bytes {
                1 => (0..=255).collect::<Vec<_>>(),
                _ => samples(bytes),
            };
            let positions = |constant: &u128| [(*constant, 0), (*constant, 1)];
            for (constant, at) in tried.iter().flat_map(positions) {
                assert_ignored_is_constant(operation, (constant, bytes), at, &tried);
            }
        }
    }

    /// Where the table says operand `at` is ignored against `constant`, no value of it changes the result.
    fn assert_ignored_is_constant(
        operation: Operation,
        (constant, bytes): (u128, u32),
        at: usize,
        tried: &[u128],
    ) {
        if ignored_operands(operation, &facts(at, constant, bytes)) >> at & 1 == 0 {
            return;
        }
        let seen = (tried.iter())
            .filter_map(|x| result(operation, at, word(constant, bytes), *x))
            .collect::<BTreeSet<_>>();
        assert!(
            seen.len() <= 1,
            "{operation:?} at {bytes} bytes with {constant:#x} against operand {at}: {seen:?}"
        );
    }

    /// A shift count is its own width: a byte shifted by a four byte count of 8 is gone.
    #[test]
    fn a_shift_by_the_width_of_the_value_or_more_ignores_the_value() {
        let shifted = |operation, count| {
            let operands = [
                Operand {
                    bytes: 1,
                    known: Known::Nothing,
                },
                Operand {
                    bytes: 4,
                    known: Known::Value(count),
                },
            ];
            ignored_operands(operation, &operands)
        };
        for operation in [Operation::Left, Operation::Right] {
            assert_eq!(shifted(operation, 8), 0b01, "{operation:?}");
            assert_eq!(shifted(operation, 7), 0, "{operation:?}");
        }
        // An arithmetic shift keeps the sign past the width: the value is read.
        assert_eq!(shifted(Operation::SRight, 8), 0);
    }

    /// Where a byte operation the table covers gives one value whatever one operand holds, the table
    /// says so: nothing it knows of a byte is left out.
    #[test]
    fn an_operation_constant_in_a_byte_operand_is_ignored() {
        let covered = [
            Operation::Mult,
            Operation::And,
            Operation::Or,
            Operation::Left,
            Operation::Right,
            Operation::SRight,
            Operation::Less,
            Operation::SLess,
            Operation::LessEqual,
            Operation::SLessEqual,
            Operation::Carry,
            Operation::SCarry,
            Operation::SBorrow,
            Operation::Rem,
            Operation::SRem,
        ];
        let cases = covered.into_iter().flat_map(|operation| {
            (0..=255u128).flat_map(move |constant| (0..2).map(move |at| (operation, constant, at)))
        });
        for (operation, constant, at) in cases {
            let fixed = word(constant, 1);
            let results = (0..=255u128)
                .map(|x| result(operation, at, fixed, x))
                .collect::<Vec<_>>();
            let seen = results.iter().flatten().collect::<BTreeSet<_>>();
            let said = ignored_operands(operation, &facts(at, constant, 1)) >> at & 1 == 1;
            if results.iter().all(Option::is_some) && seen.len() == 1 {
                assert!(said, "{operation:?}: {constant:#x} fixes operand {at}");
            }
        }
    }

    #[test]
    fn two_operands_of_one_storage_cancel_where_the_operation_does() {
        let alike = [
            Operand {
                bytes: 1,
                known: Known::Nothing,
            },
            Operand {
                bytes: 1,
                known: Known::Same(0),
            },
        ];
        for operation in [
            Operation::Xor,
            Operation::Sub,
            Operation::SBorrow,
            Operation::Equal,
            Operation::NotEqual,
            Operation::Less,
            Operation::SLess,
            Operation::LessEqual,
            Operation::SLessEqual,
        ] {
            assert_eq!(ignored_operands(operation, &alike), 0b11, "{operation:?}");
            // One storage holds one value, so every byte gives what a nought gives.
            let zero = apply(operation, &[word(0, 1), word(0, 1)], 1).expect("defined");
            for x in 0..=255u128 {
                let one = word(x, 1);
                assert_eq!(apply(operation, &[one, one], 1), Ok(zero), "{operation:?}");
            }
        }
        for operation in [
            Operation::And,
            Operation::Or,
            Operation::Add,
            Operation::Carry,
        ] {
            assert_eq!(ignored_operands(operation, &alike), 0, "{operation:?}");
        }
    }

    #[test]
    fn a_select_ignores_the_arm_its_condition_leaves() {
        let operand = |known| Operand { bytes: 1, known };
        let with = |cond| {
            [
                operand(cond),
                operand(Known::Nothing),
                operand(Known::Nothing),
            ]
        };
        assert_eq!(
            ignored_operands(Operation::Select, &with(Known::Value(1))),
            0b100
        );
        assert_eq!(
            ignored_operands(Operation::Select, &with(Known::Value(0))),
            0b010
        );
        let alike = [
            operand(Known::Nothing),
            operand(Known::Nothing),
            operand(Known::Same(1)),
        ];
        assert_eq!(ignored_operands(Operation::Select, &alike), 0b001);
    }

    /// A boolean that is false makes an `and` false, and one that is true makes an `or` true.
    #[test]
    fn a_boolean_fixed_by_its_other_operand_is_ignored() {
        let bit = |known| Operand { bytes: 1, known };
        let against = |fixed| [bit(Known::Nothing), bit(Known::Value(fixed))];
        for (operation, fixing) in [(Operation::BoolAnd, 0), (Operation::BoolOr, 1)] {
            assert_eq!(ignored_operands(operation, &against(fixing)), 0b01);
            assert_eq!(ignored_operands(operation, &against(1 - fixing)), 0);
            let fixed = word(fixing, 1);
            let seen = [0u128, 1]
                .map(|x| apply(operation, &[word(x, 1), fixed], 1))
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(seen[0], seen[1], "{operation:?}");
        }
        assert_eq!(ignored_operands(Operation::BoolXor, &against(0)), 0);
    }

    /// Whichever arm the condition leaves is not read: the other arm's value is what comes out.
    #[test]
    fn the_arm_a_select_leaves_changes_nothing() {
        for (cond, left) in [(0u128, 1usize), (1, 2)] {
            let arm = |kept: u128, dropped: u128| {
                let mut arms = [word(cond, 1), word(0, 1), word(0, 1)];
                arms[3 - left] = word(kept, 1);
                arms[left] = word(dropped, 1);
                apply(Operation::Select, &arms, 1)
            };
            for kept in [0u128, 7, 255] {
                let seen = (0..=255).map(|dropped| arm(kept, dropped).ok());
                let seen = seen.collect::<BTreeSet<_>>();
                assert_eq!(seen.len(), 1, "cond {cond}");
            }
        }
    }

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::register(offset, size)
    }

    fn reads_of(ops: &[R2ILOp], whole: bool) -> Reads {
        super::reads_of(ops, whole, Endianness::Little)
    }

    fn eax() -> Varnode {
        reg(0, 4)
    }

    /// `or eax, -1`: the register the result ignores is read by no operation.
    #[test]
    fn an_or_with_all_ones_ignores_its_other_operand() {
        let or = |size: u32, ones: u64| {
            vec![R2ILOp::IntOr {
                dst: reg(0, size),
                a: reg(0, size),
                b: Varnode::constant(ones, size),
            }]
        };
        assert_eq!(reads_of(&or(4, 0xffff_ffff), true).ignored, vec![0b01]);
        assert_eq!(reads_of(&or(8, u64::MAX), true).ignored, vec![0b01]);
        // One bit short of all ones is a read.
        assert_eq!(reads_of(&or(4, 0x7fff_ffff), true).ignored, vec![0]);
    }

    #[test]
    fn an_and_with_nought_and_a_product_with_nought_ignore_their_other_operand() {
        let and = |constant| R2ILOp::IntAnd {
            dst: eax(),
            a: eax(),
            b: Varnode::constant(constant, 4),
        };
        let mult = |constant| R2ILOp::IntMult {
            dst: eax(),
            a: eax(),
            b: Varnode::constant(constant, 4),
        };
        assert_eq!(reads_of(&[and(0)], true).ignored, vec![0b01]);
        assert_eq!(reads_of(&[and(0xff)], true).ignored, vec![0]);
        assert_eq!(reads_of(&[mult(0)], true).ignored, vec![0b01]);
        assert_eq!(reads_of(&[mult(1)], true).ignored, vec![0]);
    }

    /// `imul edx, edx, 0` as Sleigh lifts it: a product of sign extensions, the constant in a
    /// temporary, and the flags read the product.
    #[test]
    fn a_product_with_a_constant_held_in_a_temporary_ignores_the_register_it_extends() {
        let (wide, zero, product) = (
            Varnode::unique(0, 8),
            Varnode::unique(8, 8),
            Varnode::unique(0x10, 8),
        );
        let ops = vec![
            R2ILOp::IntSExt {
                dst: wide.clone(),
                src: eax(),
            },
            R2ILOp::IntSExt {
                dst: zero.clone(),
                src: Varnode::constant(0, 4),
            },
            R2ILOp::IntMult {
                dst: product.clone(),
                a: wide,
                b: zero,
            },
            R2ILOp::Subpiece {
                dst: eax(),
                src: product.clone(),
                offset: 0,
            },
            R2ILOp::IntSExt {
                dst: Varnode::unique(0x1c, 8),
                src: eax(),
            },
            R2ILOp::IntNotEqual {
                dst: reg(0x200, 1),
                a: Varnode::unique(0x1c, 8),
                b: product,
            },
        ];
        // The extension of EAX feeds only a product that ignores it, so it is dead; the extension
        // after the write reads the new EAX.
        let ignored = reads_of(&ops, true).ignored;
        assert_eq!(ignored[0], u32::MAX);
        assert_eq!(ignored[2], 0b01);
        assert_eq!(ignored[4], 0);
        // With a constant other than nought the extension is read.
        let mut live = ops;
        live[1] = R2ILOp::IntSExt {
            dst: Varnode::unique(8, 8),
            src: Varnode::constant(3, 4),
        };
        assert_eq!(reads_of(&live, true).ignored[0], 0);
    }

    /// AArch64's `orn x1, x1, xzr`: the all ones is built in two temporaries from constants.
    #[test]
    fn all_ones_built_in_temporaries_from_constants_is_all_ones() {
        let x1 = reg(8, 8);
        let ops = vec![
            R2ILOp::IntNegate {
                dst: Varnode::unique(0, 8),
                src: Varnode::constant(1, 8),
            },
            R2ILOp::IntXor {
                dst: Varnode::unique(8, 8),
                a: Varnode::constant(0, 8),
                b: Varnode::unique(0, 8),
            },
            R2ILOp::IntOr {
                dst: x1.clone(),
                a: x1,
                b: Varnode::unique(8, 8),
            },
        ];
        assert_eq!(reads_of(&ops, true).ignored[2], 0b01);
    }

    /// A register taken as both operands of an operation that cancels it is what a cancelling
    /// instruction does; a constant that fixes the result, or an address a `nop` drops, is not it.
    #[test]
    fn an_instruction_that_cancels_a_register_against_itself_says_so() {
        let xor = |a: Varnode, b: Varnode| R2ILOp::IntXor { dst: eax(), a, b };
        assert!(reads_of(&[xor(eax(), eax())], true).cancels_register);
        assert!(!reads_of(&[xor(eax(), reg(4, 4))], true).cancels_register);
        let or = R2ILOp::IntOr {
            dst: eax(),
            a: eax(),
            b: Varnode::constant(0xffff_ffff, 4),
        };
        assert!(!reads_of(&[or], true).cancels_register);
        // The address a multi-byte `nop` forms from a register twice is a dead temporary.
        let dropped = R2ILOp::IntAdd {
            dst: Varnode::unique(0, 8),
            a: reg(0, 8),
            b: reg(0, 8),
        };
        assert!(!reads_of(&[dropped], true).cancels_register);
        let temp = R2ILOp::IntSub {
            dst: Varnode::unique(0, 4),
            a: eax(),
            b: eax(),
        };
        assert!(!reads_of(&[temp], true).cancels_register);
    }

    /// AL is nought where the operations state it, however spelled; not for another value, a
    /// register's, or an operation that is not computed from its operands.
    #[test]
    fn an_instruction_leaves_a_register_nought_where_its_operations_state_it() {
        let al = reg(0, 1);
        let rax = reg(0, 8);
        let zext = || R2ILOp::IntZExt {
            dst: rax.clone(),
            src: eax(),
        };
        let copy = |dst: Varnode, bits: u64| R2ILOp::Copy {
            src: Varnode::constant(bits, dst.size),
            dst,
        };
        let binary =
            |dst: Varnode,
             a: Varnode,
             b: Varnode,
             make: fn(Varnode, Varnode, Varnode) -> R2ILOp| { make(dst, a, b) };
        let xor = |dst, a, b| R2ILOp::IntXor { dst, a, b };
        let sub = |dst, a, b| R2ILOp::IntSub { dst, a, b };
        let and = |dst, a, b| R2ILOp::IntAnd { dst, a, b };
        let nought = |ops: &[R2ILOp]| leaves_zero(ops, &al);
        assert!(nought(&[binary(eax(), eax(), eax(), xor), zext()]));
        assert!(nought(&[binary(eax(), eax(), eax(), sub), zext()]));
        assert!(nought(&[copy(eax(), 0), zext()]));
        assert!(nought(&[copy(al.clone(), 0)]));
        assert!(nought(&[binary(
            eax(),
            reg(0x30, 4),
            Varnode::constant(0, 4),
            and
        )]));
        // The flags beside it, computed from the register, change nothing.
        let flag = R2ILOp::IntEqual {
            dst: reg(0x200, 1),
            a: eax(),
            b: Varnode::constant(0, 4),
        };
        assert!(nought(&[binary(eax(), eax(), eax(), xor), flag, zext()]));
        // Any other value, or a register's, is not nought; nor is a byte beside it.
        assert!(!nought(&[copy(eax(), 1), zext()]));
        assert!(!nought(&[copy(eax(), 0x100), zext()]));
        assert!(!nought(&[
            R2ILOp::Copy {
                dst: eax(),
                src: reg(0x30, 4)
            },
            zext()
        ]));
        assert!(!nought(&[copy(reg(1, 1), 0)]));
        assert!(!nought(&[]));
        // A write to part of it after is not nought on the strength of the rest.
        let partial = R2ILOp::Copy {
            dst: al.clone(),
            src: reg(0x30, 1),
        };
        assert!(!nought(&[copy(eax(), 0), partial]));
        // A control transfer, or an operation the evaluator does not model, could have written it.
        assert!(!nought(&[copy(eax(), 0), R2ILOp::Unimplemented]));
        let call = R2ILOp::Call {
            target: Varnode::ram(0x1000, 8),
        };
        assert!(!nought(&[copy(eax(), 0), call]));
    }

    /// Operations not known to be a whole instruction prune no temporary: another may read it.
    #[test]
    fn operations_not_known_to_be_a_whole_instruction_prune_no_temporary() {
        let ops = vec![R2ILOp::IntSExt {
            dst: Varnode::unique(0, 8),
            src: eax(),
        }];
        assert_eq!(reads_of(&ops, true).ignored, vec![u32::MAX]);
        assert_eq!(reads_of(&ops, false).ignored, vec![0]);
    }

    /// `xor eax, eax` reads no value of the register, but a temporary cancelled against itself in
    /// the same instruction says nothing of the registers that instruction reads.
    #[test]
    fn only_a_register_cancelled_against_itself_blinds_the_instruction() {
        let xor = |operand: Varnode| R2ILOp::IntXor {
            dst: Varnode::unique(0x40, 4),
            a: operand.clone(),
            b: operand,
        };
        assert!(reads_of(&[xor(eax())], false).cancels_register);
        assert!(!reads_of(&[xor(Varnode::unique(0, 4))], false).cancels_register);
    }

    /// An operation whose reads the lift does not state (`cpuid` lifts to a copy of EAX and an
    /// operation naming no input) may read any temporary of its instruction: none is pruned.
    #[test]
    fn a_temporary_an_instruction_with_unstated_reads_computes_is_not_pruned() {
        let copy = || R2ILOp::Copy {
            dst: Varnode::unique(0, 4),
            src: eax(),
        };
        for unstated in [
            R2ILOp::Unimplemented,
            R2ILOp::CallOther {
                output: None,
                userop: 1,
                inputs: Vec::new(),
            },
            R2ILOp::CpuId { dst: reg(0x10, 4) },
        ] {
            assert_eq!(reads_of(&[copy(), unstated], true).ignored[0], 0);
        }
        assert_eq!(reads_of(&[copy(), R2ILOp::Nop], true).ignored[0], u32::MAX);
    }

    /// A temporary an effect reads keeps the operation that wrote it.
    #[test]
    fn a_temporary_an_effect_reads_keeps_its_producer_live() {
        let ops = vec![
            R2ILOp::IntAdd {
                dst: Varnode::unique(0, 8),
                a: reg(0, 8),
                b: reg(0x10, 8),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::unique(0, 8),
                val: Varnode::constant(1, 1),
            },
        ];
        assert_eq!(reads_of(&ops, true).ignored, vec![0, 0]);
    }

    /// `vxorps xmm1, xmm1, xmm1` as Sleigh lifts it: XMM1 copied whole to a temporary, and each dword
    /// xored with its own place in the copy. The cancel is the same as `xor eax, eax`'s.
    fn xor_with_a_copy(of: u64, lanes: u64) -> Vec<R2ILOp> {
        let copy = Varnode::unique(0, 16);
        let mut ops = vec![R2ILOp::Copy {
            dst: copy.clone(),
            src: reg(of, 16),
        }];
        for lane in 0..lanes {
            let piece = Varnode::unique(0x10 + 4 * lane, 4);
            ops.push(R2ILOp::Subpiece {
                dst: piece.clone(),
                src: copy.clone(),
                offset: 4 * lane as u32,
            });
            ops.push(R2ILOp::IntXor {
                dst: reg(0x1240 + 4 * lane, 4),
                a: reg(0x1240 + 4 * lane, 4),
                b: piece,
            });
        }
        ops
    }

    #[test]
    fn a_register_xored_by_a_copy_of_itself_is_cancelled() {
        let cancelled = reads_of(&xor_with_a_copy(0x1240, 4), true);
        assert!(cancelled.cancels_register);
        // Every operand of the copy and the pieces is a read the cancel makes dead.
        assert_eq!(cancelled.ignored[0], u32::MAX);
        assert_eq!(cancelled.ignored[2], 0b11);
        // Another register's copy is another value.
        assert!(!reads_of(&xor_with_a_copy(0x1280, 4), true).cancels_register);
        // A big-endian truncation takes the bytes from the other end: nothing is followed.
        let big = super::reads_of(&xor_with_a_copy(0x1240, 4), true, Endianness::Big);
        assert!(!big.cancels_register);
    }

    /// A local branch makes the operations after it run on some paths only: no copy is followed.
    #[test]
    fn an_instruction_that_branches_within_itself_follows_no_copy() {
        let mut branching = xor_with_a_copy(0x1240, 1);
        branching.insert(
            0,
            R2ILOp::Branch {
                target: Varnode::constant(1, 8),
            },
        );
        assert!(!reads_of(&branching, true).cancels_register);
    }

    /// The copy is the register's value as it was: written between the copy and the xor, the register
    /// holds another, and a piece taken from another place is another lane.
    #[test]
    fn a_copy_of_a_register_is_the_value_it_held() {
        let mut written = xor_with_a_copy(0x1240, 1);
        written.insert(
            1,
            R2ILOp::Copy {
                dst: reg(0x1240, 4),
                src: reg(0x1300, 4),
            },
        );
        assert!(!reads_of(&written, true).cancels_register);
        let mut shifted = xor_with_a_copy(0x1240, 2);
        if let R2ILOp::Subpiece { offset, .. } = &mut shifted[1] {
            *offset = 4;
        }
        let cancels = reads_of(&shifted, true);
        assert_eq!(
            cancels.ignored[2], 0,
            "lane 0 xored with lane 1 is no cancel"
        );
        assert_eq!(cancels.ignored[4], 0b11, "lane 1 xored with itself is");
        // An operation with unstated reads and effects between them may have written anything.
        let mut unstated = xor_with_a_copy(0x1240, 1);
        unstated.insert(
            1,
            R2ILOp::CallOther {
                output: None,
                userop: 1,
                inputs: Vec::new(),
            },
        );
        assert!(!reads_of(&unstated, true).cancels_register);
    }
}
