//! What each operation computes, run on one concrete byte state; a step it cannot take exactly stops the run.
//!
//! [`apply`] is the one statement of what a value operation computes from its
//! operands, and every constant fold in the engine answers through it.

use std::collections::BTreeMap;

use crate::{
    AtomicAccess, AtomicFetchOp, AtomicUpdate, BlockStop, BlockTransfer, BlockTransferKind,
    Endianness, R2ILOp, SpaceId, Varnode,
};

/// The bytes a value is carried in: a value of any width is exact while it fits them.
const CARRIED: u32 = u128::BITS / 8;

/// The bytes a run reads where it has written none.
pub trait Mapped {
    /// The byte at this address, or `None` where nothing is mapped.
    fn byte(&self, address: u64) -> Option<u8>;
}

impl<F: Fn(u64) -> Option<u8>> Mapped for F {
    fn byte(&self, address: u64) -> Option<u8> {
        self(address)
    }
}

/// Where control goes after one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// On to the next operation, or past the instruction after its last.
    Next,
    /// Out of the instruction.
    Transfer(Transfer),
    /// The run cannot go on, and says nothing about what follows.
    Stop(Stop),
}

/// A transfer of control, and where it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    pub kind: TransferKind,
    pub to: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
    Jump,
    Call,
    Return,
}

/// Why a run stopped, or why an operation has no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// An operation this evaluator does not execute, or not at these widths.
    Unmodelled,
    /// An access to a byte nothing maps.
    Unmapped { address: u64 },
    /// A read of a byte nothing wrote.
    Unwritten { space: SpaceId, offset: u64 },
    /// A division by zero, a signed quotient that does not fit, or a boolean that is neither.
    Undefined,
    /// The run has executed every operation and element its budget allows.
    Exhausted,
}

/// One access a run made to memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub kind: AccessKind,
    pub address: u64,
    pub width: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

/// Which way a multi-byte value lies in a space.
#[derive(Debug, Clone, Copy)]
enum Order {
    Little,
    Big,
}

/// A concrete machine: what each space holds, over the bytes the program maps.
pub struct State<M> {
    order: Order,
    registers: BTreeMap<u64, u8>,
    unique: BTreeMap<u64, u8>,
    /// Every memory byte the run has written; the rest read through `mapped`.
    written: BTreeMap<u64, u8>,
    mapped: M,
    accesses: Vec<Access>,
    /// The address and width the last linked load marked, until a conditional store or a clear.
    monitor: Option<(u64, u32)>,
    /// Operations and block elements the run may still execute.
    budget: u64,
}

impl<M: Mapped> State<M> {
    /// An empty machine over `mapped` that executes at most `budget` operations and block elements.
    ///
    /// `None` where the endianness does not say how a word lies.
    pub fn new(endian: Endianness, mapped: M, budget: u64) -> Option<Self> {
        let order = match endian {
            Endianness::Little => Order::Little,
            Endianness::Big => Order::Big,
            Endianness::Mixed | Endianness::Custom => return None,
        };
        Some(Self {
            order,
            registers: BTreeMap::new(),
            unique: BTreeMap::new(),
            written: BTreeMap::new(),
            mapped,
            accesses: Vec::new(),
            monitor: None,
            budget,
        })
    }

    /// What a register holds, where every byte of it has been written.
    pub fn register(&self, offset: u64, size: u32) -> Option<u128> {
        let bytes = (0..u64::from(size))
            .map(|at| self.registers.get(&offset.checked_add(at)?).copied())
            .collect::<Option<Vec<_>>>()?;
        width(size).ok()?;
        self.assembled(&bytes)
    }

    /// Give a register a value, as an entry state does.
    pub fn set_register(&mut self, offset: u64, size: u32, value: u128) -> Result<(), Stop> {
        self.write(&Varnode::register(offset, size), value)
    }

    /// Close one instruction: its temporaries die with it, so the next one's unwritten read stops.
    pub fn end_instruction(&mut self) {
        self.unique.clear();
    }

    /// The memory accesses since the last call, oldest first.
    pub fn take_accesses(&mut self) -> Vec<Access> {
        std::mem::take(&mut self.accesses)
    }

    /// The bytes a value of `size` bytes is in this machine's order, lowest address first.
    fn laid_out(&self, value: u128, size: u32) -> Vec<u8> {
        let little = (0..size).map(|at| value.checked_shr(8 * at).unwrap_or(0) as u8);
        match self.order {
            Order::Little => little.collect(),
            Order::Big => little.rev().collect(),
        }
    }

    /// Read `size` bytes of memory at `address` as one value, recording the access.
    pub fn load(&mut self, address: u64, size: u32) -> Result<u128, Stop> {
        let size = width(size)?;
        let bytes = (0..u64::from(size))
            .map(|at| {
                let at = address.wrapping_add(at);
                let held = self.written.get(&at).copied();
                held.or_else(|| self.mapped.byte(at))
                    .ok_or(Stop::Unmapped { address: at })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let value = self.assembled(&bytes).ok_or(Stop::Unmodelled)?;
        self.accesses.push(Access {
            kind: AccessKind::Read,
            address,
            width: size,
        });
        Ok(value)
    }

    /// What a storage holds at its own width; a read of memory is recorded as an access.
    pub fn value(&mut self, varnode: &Varnode) -> Result<u128, Stop> {
        self.read(varnode)
    }

    /// A value, read at its own width.
    fn read(&mut self, varnode: &Varnode) -> Result<u128, Stop> {
        let size = width(varnode.size)?;
        match varnode.space {
            SpaceId::Const => Ok(u128::from(varnode.offset) & mask(size)),
            SpaceId::Register | SpaceId::Unique => {
                let bytes = (0..u64::from(size))
                    .map(|at| self.byte(varnode.space, varnode.offset.wrapping_add(at)))
                    .collect::<Result<Vec<_>, _>>()?;
                self.assembled(&bytes).ok_or(Stop::Unmodelled)
            }
            SpaceId::Ram => self.load(varnode.offset, size),
            SpaceId::Custom(_) => Err(Stop::Unmodelled),
        }
    }

    fn word(&mut self, varnode: &Varnode) -> Result<Word, Stop> {
        Word::new(self.read(varnode)?, varnode.size)
    }

    /// A value read as an address.
    fn address(&mut self, varnode: &Varnode) -> Result<u64, Stop> {
        u64::try_from(self.read(varnode)?).map_err(|_| Stop::Unmodelled)
    }

    /// Write a value at a storage's width.
    fn write(&mut self, varnode: &Varnode, value: u128) -> Result<(), Stop> {
        let size = width(varnode.size)?;
        let bytes = self.laid_out(value, size);
        let space = match varnode.space {
            SpaceId::Register => &mut self.registers,
            SpaceId::Unique => &mut self.unique,
            SpaceId::Ram => return self.store(varnode.offset, size, value),
            SpaceId::Const | SpaceId::Custom(_) => return Err(Stop::Unmodelled),
        };
        for (at, byte) in (0..).zip(bytes) {
            space.insert(varnode.offset.wrapping_add(at), byte);
        }
        Ok(())
    }

    fn byte(&self, space: SpaceId, offset: u64) -> Result<u8, Stop> {
        let held = match space {
            SpaceId::Register => &self.registers,
            _ => &self.unique,
        };
        held.get(&offset)
            .copied()
            .ok_or(Stop::Unwritten { space, offset })
    }

    fn store(&mut self, address: u64, size: u32, value: u128) -> Result<(), Stop> {
        let size = width(size)?;
        let addresses = (0..u64::from(size)).map(|at| address.wrapping_add(at));
        if let Some(address) = addresses.clone().find(|at| self.mapped.byte(*at).is_none()) {
            return Err(Stop::Unmapped { address });
        }
        let bytes = self.laid_out(value, size);
        self.written.extend(addresses.zip(bytes));
        self.accesses.push(Access {
            kind: AccessKind::Write,
            address,
            width: size,
        });
        Ok(())
    }

    /// Spend one unit of the run's budget.
    fn spend(&mut self) -> Result<(), Stop> {
        self.budget = self.budget.checked_sub(1).ok_or(Stop::Exhausted)?;
        Ok(())
    }

    /// The value these bytes spell, first byte at the lowest offset, where it fits the bits carried.
    fn assembled(&self, bytes: &[u8]) -> Option<u128> {
        let mut significant = bytes.to_vec();
        if let Order::Little = self.order {
            significant.reverse();
        }
        let spare = significant.len().saturating_sub(CARRIED as usize);
        let (beyond, carried) = significant.split_at(spare);
        let fold = |value: u128, byte: &u8| (value << 8) | u128::from(*byte);
        beyond
            .iter()
            .all(|byte| *byte == 0)
            .then(|| carried.iter().fold(0, fold))
    }
}

/// A width a value can have: any but none.
fn width(bytes: u32) -> Result<u32, Stop> {
    match bytes {
        0 => Err(Stop::Unmodelled),
        _ => Ok(bytes),
    }
}

/// Every value a width holds, as far as the bits carried reach.
fn mask(bytes: u32) -> u128 {
    match bytes {
        0 => 0,
        _ if bytes < CARRIED => (1 << (8 * bytes)) - 1,
        _ => u128::MAX,
    }
}

/// A result modulo its width: past the bits carried it is exact, or refused.
fn modulo(bytes: u32, wrapped: u128, exact: Option<u128>) -> Result<u128, Stop> {
    match bytes > CARRIED {
        false => Ok(wrapped & mask(bytes)),
        true => exact.ok_or(Stop::Unmodelled),
    }
}

/// A value and the width it is read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Word {
    bits: u128,
    bytes: u32,
}

impl Word {
    /// `bits` read at `bytes`, or `Unmodelled` at no width at all.
    pub fn new(bits: u128, bytes: u32) -> Result<Self, Stop> {
        let bytes = width(bytes)?;
        Ok(Self {
            bits: bits & mask(bytes),
            bytes,
        })
    }

    /// The value read as two's complement at its width; wider than the bits carried, it is non-negative.
    fn signed(self) -> Result<i128, Stop> {
        if self.bytes > CARRIED {
            return i128::try_from(self.bits).map_err(|_| Stop::Unmodelled);
        }
        let spare = 128 - 8 * self.bytes;
        Ok(((self.bits << spare) as i128) >> spare)
    }

    /// The value as a p-code boolean, which is nought or one and nothing else.
    fn boolean(self) -> Result<u128, Stop> {
        (self.bits <= 1).then_some(self.bits).ok_or(Stop::Undefined)
    }

    /// Places to shift by, where fewer than the width.
    fn places(self, within: u32) -> Option<u32> {
        u32::try_from(self.bits)
            .ok()
            .filter(|places| *places < 8 * within)
    }
}

/// Whether a signed result overflows its width; past the bits carried, one they cannot hold is refused.
fn overflows(value: Option<i128>, bytes: u32) -> Result<bool, Stop> {
    if bytes > CARRIED {
        return value.map(|_| false).ok_or(Stop::Unmodelled);
    }
    let Some(value) = value else {
        return Ok(true);
    };
    let bound = 1i128.checked_shl(8 * bytes - 1).filter(|bound| *bound > 0);
    Ok(!bound.is_none_or(|bound| (-bound..bound).contains(&value)))
}

/// An operation whose value is a function of its operands alone, which are in p-code order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Copy,
    Add,
    Sub,
    Mult,
    Div,
    SDiv,
    Rem,
    SRem,
    And,
    Or,
    Xor,
    Left,
    Right,
    SRight,
    Equal,
    NotEqual,
    Less,
    SLess,
    LessEqual,
    SLessEqual,
    Carry,
    SCarry,
    SBorrow,
    BoolAnd,
    BoolOr,
    BoolXor,
    Negate,
    Not,
    BoolNot,
    ZExt,
    SExt,
    PopCount,
    Lzcount,
    /// The operand's bytes from `offset` up.
    Subpiece {
        offset: u32,
    },
    /// The first operand above the second.
    Piece,
    /// The first operand plus the second times `element_size`.
    PtrAdd {
        element_size: u32,
    },
    /// The first operand minus the second times `element_size`.
    PtrSub {
        element_size: u32,
    },
    /// The second operand where the first is non-zero, the third where it is zero.
    Select,
    /// The first operand with the second written over its bits from the third, a bit position, up.
    Insert,
}

impl Operation {
    /// The operation an r2il operation computes with, its result and its operands, where it computes from them alone.
    pub fn of(op: &R2ILOp) -> Option<(Self, &Varnode, Vec<&Varnode>)> {
        use Operation as O;
        let (operation, dst) = match op {
            R2ILOp::Copy { dst, .. } => (O::Copy, dst),
            R2ILOp::IntAdd { dst, .. } => (O::Add, dst),
            R2ILOp::IntSub { dst, .. } => (O::Sub, dst),
            R2ILOp::IntMult { dst, .. } => (O::Mult, dst),
            R2ILOp::IntDiv { dst, .. } => (O::Div, dst),
            R2ILOp::IntSDiv { dst, .. } => (O::SDiv, dst),
            R2ILOp::IntRem { dst, .. } => (O::Rem, dst),
            R2ILOp::IntSRem { dst, .. } => (O::SRem, dst),
            R2ILOp::IntAnd { dst, .. } => (O::And, dst),
            R2ILOp::IntOr { dst, .. } => (O::Or, dst),
            R2ILOp::IntXor { dst, .. } => (O::Xor, dst),
            R2ILOp::IntLeft { dst, .. } => (O::Left, dst),
            R2ILOp::IntRight { dst, .. } => (O::Right, dst),
            R2ILOp::IntSRight { dst, .. } => (O::SRight, dst),
            R2ILOp::IntEqual { dst, .. } => (O::Equal, dst),
            R2ILOp::IntNotEqual { dst, .. } => (O::NotEqual, dst),
            R2ILOp::IntLess { dst, .. } => (O::Less, dst),
            R2ILOp::IntSLess { dst, .. } => (O::SLess, dst),
            R2ILOp::IntLessEqual { dst, .. } => (O::LessEqual, dst),
            R2ILOp::IntSLessEqual { dst, .. } => (O::SLessEqual, dst),
            R2ILOp::IntCarry { dst, .. } => (O::Carry, dst),
            R2ILOp::IntSCarry { dst, .. } => (O::SCarry, dst),
            R2ILOp::IntSBorrow { dst, .. } => (O::SBorrow, dst),
            R2ILOp::BoolAnd { dst, .. } => (O::BoolAnd, dst),
            R2ILOp::BoolOr { dst, .. } => (O::BoolOr, dst),
            R2ILOp::BoolXor { dst, .. } => (O::BoolXor, dst),
            R2ILOp::IntNegate { dst, .. } => (O::Negate, dst),
            R2ILOp::IntNot { dst, .. } => (O::Not, dst),
            R2ILOp::BoolNot { dst, .. } => (O::BoolNot, dst),
            R2ILOp::IntZExt { dst, .. } => (O::ZExt, dst),
            R2ILOp::IntSExt { dst, .. } => (O::SExt, dst),
            R2ILOp::PopCount { dst, .. } => (O::PopCount, dst),
            R2ILOp::Lzcount { dst, .. } => (O::Lzcount, dst),
            R2ILOp::Subpiece { dst, offset, .. } => (O::Subpiece { offset: *offset }, dst),
            R2ILOp::Piece { dst, .. } => (O::Piece, dst),
            R2ILOp::PtrAdd {
                dst, element_size, ..
            } => (
                O::PtrAdd {
                    element_size: *element_size,
                },
                dst,
            ),
            R2ILOp::PtrSub {
                dst, element_size, ..
            } => (
                O::PtrSub {
                    element_size: *element_size,
                },
                dst,
            ),
            R2ILOp::Select { dst, .. } => (O::Select, dst),
            R2ILOp::Insert { dst, .. } => (O::Insert, dst),
            _ => return None,
        };
        Some((operation, dst, op.inputs()))
    }

    /// Whether the widths are the ones p-code requires of this operation.
    fn shaped(self, operands: &[Word], width: u32) -> bool {
        use Operation as O;
        let bytes = operands.iter().map(|operand| operand.bytes);
        match (self, bytes.collect::<Vec<_>>().as_slice()) {
            (O::Copy | O::Negate | O::Not, [a]) => *a == width,
            (O::ZExt | O::SExt, [a]) => *a <= width,
            (O::BoolNot | O::PopCount | O::Lzcount | O::Subpiece { .. }, [_]) => true,
            (O::Left | O::Right | O::SRight, [a, _]) => *a == width,
            (
                O::Equal
                | O::NotEqual
                | O::Less
                | O::SLess
                | O::LessEqual
                | O::SLessEqual
                | O::Carry
                | O::SCarry
                | O::SBorrow,
                [a, b],
            ) => a == b,
            (O::BoolAnd | O::BoolOr | O::BoolXor, [_, _]) => true,
            (O::Piece, [high, low]) => high.checked_add(*low) == Some(width),
            (O::PtrAdd { .. } | O::PtrSub { .. }, [base, _]) => *base == width,
            (O::Select, [_, a, b]) => *a == width && *b == width,
            (O::Insert, [root, value, _]) => *root == width && *value <= width,
            (
                O::Add
                | O::Sub
                | O::Mult
                | O::Div
                | O::SDiv
                | O::Rem
                | O::SRem
                | O::And
                | O::Or
                | O::Xor,
                [a, b],
            ) => *a == width && a == b,
            _ => false,
        }
    }
}

/// What `operation` computes from `operands` into `width` bytes, or why p-code gives it no value.
pub fn apply(operation: Operation, operands: &[Word], width: u32) -> Result<u128, Stop> {
    let width = self::width(width)?;
    if !operation.shaped(operands, width) {
        return Err(Stop::Unmodelled);
    }
    let value = match *operands {
        [a] => unary(operation, a, width)?,
        [a, b] => binary(operation, a, b)?,
        [root, value, position] if operation == Operation::Insert => {
            insert(root, value, position.bits, width)?
        }
        [cond, if_true, if_false] => match cond.bits {
            0 => if_false.bits,
            _ => if_true.bits,
        },
        _ => return Err(Stop::Unmodelled),
    };
    Ok(value & mask(width))
}

/// `root` with `value` written over its bits from `position` up; a value that runs past the width is unmodelled.
fn insert(root: Word, value: Word, position: u128, width: u32) -> Result<u128, Stop> {
    let position = u32::try_from(position).map_err(|_| Stop::Unmodelled)?;
    let bits = value.bytes.saturating_mul(8);
    if position
        .checked_add(bits)
        .is_none_or(|end| end > width.saturating_mul(8))
    {
        return Err(Stop::Unmodelled);
    }
    // A lane at or past bit 128 lies outside the carried word: a 256-bit register's upper half.
    let field = mask(value.bytes)
        .checked_shl(position)
        .ok_or(Stop::Unmodelled)?;
    let placed = value.bits.checked_shl(position).ok_or(Stop::Unmodelled)?;
    Ok((root.bits & !field) | placed)
}

fn unary(operation: Operation, src: Word, width: u32) -> Result<u128, Stop> {
    use Operation as O;
    let bits = src.bits;
    match operation {
        O::Copy | O::ZExt => Ok(bits),
        O::Negate => modulo(src.bytes, bits.wrapping_neg(), (bits == 0).then_some(0)),
        O::Not => modulo(src.bytes, !bits, None),
        O::BoolNot => Ok(src.boolean()? ^ 1),
        O::SExt => {
            let signed = src.signed()?;
            modulo(width, signed as u128, u128::try_from(signed).ok())
        }
        O::PopCount => Ok(u128::from(bits.count_ones())),
        // The bits carried are the width's low end, so what lies above them is zero.
        O::Lzcount => Ok(u128::from(bits.leading_zeros()) + 8 * u128::from(src.bytes) - 128),
        O::Subpiece { offset } => Ok(bits.checked_shr(offset.saturating_mul(8)).unwrap_or(0)),
        _ => Err(Stop::Unmodelled),
    }
}

fn binary(operation: Operation, a: Word, b: Word) -> Result<u128, Stop> {
    use Operation as O;
    let (x, y, bytes) = (a.bits, b.bits, a.bytes);
    let flag = |holds: bool| Ok(u128::from(holds));
    let scaled = |size: u32| {
        (
            y.wrapping_mul(u128::from(size)),
            y.checked_mul(u128::from(size)),
        )
    };
    match operation {
        O::Add => modulo(bytes, x.wrapping_add(y), x.checked_add(y)),
        O::Sub => modulo(bytes, x.wrapping_sub(y), x.checked_sub(y)),
        O::Mult => modulo(bytes, x.wrapping_mul(y), x.checked_mul(y)),
        O::Div => x.checked_div(y).ok_or(Stop::Undefined),
        O::Rem => x.checked_rem(y).ok_or(Stop::Undefined),
        O::SDiv => quotient(a, b),
        O::SRem => remainder(a, b),
        O::And => Ok(x & y),
        O::Or => Ok(x | y),
        O::Xor => Ok(x ^ y),
        // Past the width p-code states nought, or the sign for an arithmetic shift.
        O::Left => b.places(bytes).map_or(Ok(0), |at| {
            let shifted = x.checked_shl(at).unwrap_or(0);
            modulo(bytes, shifted, (x.leading_zeros() >= at).then_some(shifted))
        }),
        O::Right => Ok(b
            .places(bytes)
            .and_then(|at| x.checked_shr(at))
            .unwrap_or(0)),
        O::SRight => {
            let places = b.places(bytes).unwrap_or(127).min(127);
            Ok((a.signed()? >> places) as u128 & mask(bytes))
        }
        O::Equal => flag(x == y),
        O::NotEqual => flag(x != y),
        O::Less => flag(x < y),
        O::SLess => flag(a.signed()? < b.signed()?),
        O::LessEqual => flag(x <= y),
        O::SLessEqual => flag(a.signed()? <= b.signed()?),
        // Past the bits carried, two carried values cannot reach the width.
        O::Carry => flag(bytes <= CARRIED && x.wrapping_add(y) & mask(bytes) < x),
        O::SCarry => flag(overflows(a.signed()?.checked_add(b.signed()?), bytes)?),
        O::SBorrow => flag(overflows(a.signed()?.checked_sub(b.signed()?), bytes)?),
        O::BoolAnd => Ok(a.boolean()? & b.boolean()?),
        O::BoolOr => Ok(a.boolean()? | b.boolean()?),
        O::BoolXor => Ok(a.boolean()? ^ b.boolean()?),
        O::Piece => {
            let shift = 8 * b.bytes;
            let high = x.checked_shl(shift).filter(|_| x.leading_zeros() >= shift);
            let high = if x == 0 { Some(0) } else { high };
            high.map(|high| high | y).ok_or(Stop::Unmodelled)
        }
        O::PtrAdd { element_size } => {
            let (wrapped, exact) = scaled(element_size);
            modulo(
                bytes,
                x.wrapping_add(wrapped),
                exact.and_then(|by| x.checked_add(by)),
            )
        }
        O::PtrSub { element_size } => {
            let (wrapped, exact) = scaled(element_size);
            modulo(
                bytes,
                x.wrapping_sub(wrapped),
                exact.and_then(|by| x.checked_sub(by)),
            )
        }
        _ => Err(Stop::Unmodelled),
    }
}

/// A signed quotient, truncated toward zero, where the width holds it.
fn quotient(a: Word, b: Word) -> Result<u128, Stop> {
    let (dividend, divisor) = (a.signed()?, b.signed()?);
    if divisor == 0 {
        return Err(Stop::Undefined);
    }
    let exact = dividend.checked_div(divisor);
    match (overflows(exact, a.bytes)?, exact) {
        (false, Some(exact)) => Ok(exact as u128 & mask(a.bytes)),
        _ => Err(Stop::Undefined),
    }
}

/// A signed remainder, taking the dividend's sign.
fn remainder(a: Word, b: Word) -> Result<u128, Stop> {
    match b.signed()? {
        0 => Err(Stop::Undefined),
        -1 => Ok(0),
        divisor => Ok((a.signed()? % divisor) as u128 & mask(a.bytes)),
    }
}

/// Execute one operation.
pub fn step<M: Mapped>(op: &R2ILOp, state: &mut State<M>) -> Flow {
    executed(op, state).unwrap_or_else(Flow::Stop)
}

/// Execute one instruction's operations, following the local labels its branches name: `Flow::Next`
/// when control falls past the last, else the transfer or stop that ended the run.
pub fn run<M: Mapped>(ops: &[R2ILOp], state: &mut State<M>) -> Flow {
    let mut at = 0usize;
    while let Some(op) = ops.get(at) {
        at = match (step(op, state), op.local_offset()) {
            (Flow::Next, _) => at + 1,
            (Flow::Transfer(_), Some(offset)) => {
                let named = isize::try_from(offset)
                    .ok()
                    .and_then(|offset| at.checked_add_signed(offset));
                match named {
                    Some(named) if named <= ops.len() => named,
                    _ => return Flow::Stop(Stop::Unmodelled),
                }
            }
            (flow, _) => return flow,
        };
    }
    Flow::Next
}

fn executed<M: Mapped>(op: &R2ILOp, state: &mut State<M>) -> Result<Flow, Stop> {
    state.spend()?;
    if let Some(flow) = transfer(op, state)? {
        return Ok(flow);
    }
    match op {
        // Ordering constrains only what other observers see; one thread sees its own accesses in
        // program order (Arm ARM B2.3, internal visibility), so a fence changes no value it reads.
        R2ILOp::Nop | R2ILOp::Fence { .. } | R2ILOp::IndivisibleAccess => {}
        R2ILOp::Atomic(access) if access.space == SpaceId::Ram => atomic(access, state)?,
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr,
            val,
        } => {
            let address = state.address(addr)?;
            let value = state.read(val)?;
            state.store(address, val.size, value)?;
        }
        R2ILOp::Load {
            dst,
            space: SpaceId::Ram,
            addr,
        } => {
            let address = state.address(addr)?;
            let value = state.load(address, dst.size)?;
            state.write(dst, value)?;
        }
        // A guarded access happens where its guard holds and is no access at all where it fails;
        // one thread orders nothing, so the ordering it states changes no value.
        R2ILOp::StoreGuarded {
            space: SpaceId::Ram,
            addr,
            val,
            guard,
            ..
        } => {
            if state.word(guard)?.boolean()? == 1 {
                let address = state.address(addr)?;
                let value = state.read(val)?;
                state.store(address, val.size, value)?;
            }
        }
        R2ILOp::LoadGuarded {
            dst,
            space: SpaceId::Ram,
            addr,
            guard,
            ..
        } => {
            if state.word(guard)?.boolean()? == 1 {
                let address = state.address(addr)?;
                let value = state.load(address, dst.size)?;
                state.write(dst, value)?;
            }
        }
        R2ILOp::BlockTransfer(transfer) if transfer.space == SpaceId::Ram => {
            block(transfer, state)?;
        }
        _ if exclusive(op, state)? => {}
        _ if floating(op, state)? => {}
        _ => {
            let (operation, dst, operands) = Operation::of(op).ok_or(Stop::Unmodelled)?;
            let operands = operands
                .into_iter()
                .map(|operand| state.word(operand))
                .collect::<Result<Vec<_>, _>>()?;
            let value = apply(operation, &operands, dst.size)?;
            state.write(dst, value)?;
        }
    }
    Ok(Flow::Next)
}

/// One indivisible access as one thread runs it: read, compute from what was read, write back,
/// except where a compare-and-exchange finds another value; `dst` takes the value read.
fn atomic<M: Mapped>(access: &AtomicAccess, state: &mut State<M>) -> Result<(), Stop> {
    let bytes = access.dst.size;
    let address = state.address(&access.addr)?;
    let old = Word::new(state.load(address, bytes)?, bytes)?;
    let written = match &access.update {
        AtomicUpdate::Fetch { op, operand } => Some(fetched(*op, old, state.word(operand)?)?),
        AtomicUpdate::CompareExchange {
            expected,
            replacement,
        } => match state.word(expected)?.bits == old.bits {
            true => Some(state.read(replacement)?),
            false => None,
        },
    };
    if let Some(value) = written {
        state.store(address, bytes, value)?;
    }
    state.write(&access.dst, old.bits)
}

/// What a fetch operation writes back over `old`, at its width.
fn fetched(op: AtomicFetchOp, old: Word, operand: Word) -> Result<u128, Stop> {
    let (a, b) = (old.bits, operand.bits);
    let signed = || -> Result<bool, Stop> { Ok(old.signed()? >= operand.signed()?) };
    let value = match op {
        AtomicFetchOp::Add => a.wrapping_add(b),
        AtomicFetchOp::Sub => a.wrapping_sub(b),
        AtomicFetchOp::And => a & b,
        AtomicFetchOp::Or => a | b,
        AtomicFetchOp::Xor => a ^ b,
        AtomicFetchOp::Swap => b,
        AtomicFetchOp::SignedMax => {
            if signed()? {
                a
            } else {
                b
            }
        }
        AtomicFetchOp::SignedMin => {
            if signed()? {
                b
            } else {
                a
            }
        }
        AtomicFetchOp::UnsignedMax => a.max(b),
        AtomicFetchOp::UnsignedMin => a.min(b),
    };
    modulo(old.bytes, value & mask(old.bytes), None)
}

/// One thread's monitor (Arm ARM B2.9.2): a conditional store takes only after a linked load of
/// its address and width, and clears the mark whether or not it took; false for any other op.
fn exclusive<M: Mapped>(op: &R2ILOp, state: &mut State<M>) -> Result<bool, Stop> {
    match op {
        R2ILOp::LoadLinked {
            dst,
            space: SpaceId::Ram,
            addr,
            ..
        } => {
            let address = state.address(addr)?;
            let value = state.load(address, dst.size)?;
            state.write(dst, value)?;
            state.monitor = Some((address, dst.size));
        }
        R2ILOp::StoreConditional {
            result,
            space: SpaceId::Ram,
            addr,
            val,
            ..
        } => {
            let address = state.address(addr)?;
            let value = state.read(val)?;
            let took = state.monitor.take() == Some((address, val.size));
            if took {
                state.store(address, val.size, value)?;
            }
            if let Some(result) = result {
                state.write(result, u128::from(took))?;
            }
        }
        R2ILOp::ClearExclusive => state.monitor = None,
        _ => return Ok(false),
    }
    Ok(true)
}

/// An IEEE binary32 or binary64 value; p-code's other float widths are not modelled.
#[derive(Clone, Copy)]
enum Float {
    Single(f32),
    Double(f64),
}

/// The quiet NaN every arithmetic NaN result is: p-code leaves the payload open, and a
/// host's own payload would make the run depend on the host.
const SINGLE_NAN: u32 = 0x7fc0_0000;
const DOUBLE_NAN: u64 = 0x7ff8_0000_0000_0000;

impl Float {
    fn of(bits: u128, bytes: u32) -> Result<Self, Stop> {
        match bytes {
            4 => Ok(Self::Single(f32::from_bits(bits as u32))),
            8 => Ok(Self::Double(f64::from_bits(bits as u64))),
            _ => Err(Stop::Unmodelled),
        }
    }

    fn wide(self) -> f64 {
        match self {
            Self::Single(x) => f64::from(x),
            Self::Double(x) => x,
        }
    }

    /// The bits of an arithmetic result, its NaN the canonical one.
    fn bits(self) -> u128 {
        match self {
            Self::Single(x) if x.is_nan() => u128::from(SINGLE_NAN),
            Self::Double(x) if x.is_nan() => u128::from(DOUBLE_NAN),
            Self::Single(x) => u128::from(x.to_bits()),
            Self::Double(x) => u128::from(x.to_bits()),
        }
    }

    /// `x` rounded once at this value's format.
    fn at(self, x: f64) -> Self {
        match self {
            Self::Single(_) => Self::Single(x as f32),
            Self::Double(_) => Self::Double(x),
        }
    }

    fn binary(
        self,
        other: Self,
        single: fn(f32, f32) -> f32,
        double: fn(f64, f64) -> f64,
    ) -> Result<Self, Stop> {
        match (self, other) {
            (Self::Single(a), Self::Single(b)) => Ok(Self::Single(single(a, b))),
            (Self::Double(a), Self::Double(b)) => Ok(Self::Double(double(a, b))),
            _ => Err(Stop::Unmodelled),
        }
    }

    fn unary(self, single: fn(f32) -> f32, double: fn(f64) -> f64) -> Self {
        match self {
            Self::Single(x) => Self::Single(single(x)),
            Self::Double(x) => Self::Double(double(x)),
        }
    }
}

/// An IEEE binary16 value, exactly: only widening reads one, so no float16 rounding is modelled.
fn binary16(bits: u16) -> f64 {
    let magnitude = match (bits >> 10) & 0x1f {
        0 => f64::from(bits & 0x3ff) * 2f64.powi(-24),
        0x1f if bits & 0x3ff == 0 => f64::INFINITY,
        0x1f => f64::NAN,
        exponent => f64::from(0x400 | (bits & 0x3ff)) * 2f64.powi(i32::from(exponent) - 25),
    };
    if bits & 0x8000 == 0 {
        magnitude
    } else {
        -magnitude
    }
}

/// The sign bit of a float `bytes` wide.
fn sign(bytes: u32) -> Result<u128, Stop> {
    match width(bytes)? {
        bytes if bytes <= CARRIED => Ok(1u128 << (8 * bytes - 1)),
        _ => Err(Stop::Unmodelled),
    }
}

/// Executes a float operation in round-to-nearest-even, returning whether `op` is one; what p-code
/// leaves undefined (a `FLOAT_ROUND` tie, an integer the value does not fit) has no value.
fn floating<M: Mapped>(op: &R2ILOp, state: &mut State<M>) -> Result<bool, Stop> {
    let mut float = |varnode: &Varnode| -> Result<Float, Stop> {
        Float::of(state.read(varnode)?, varnode.size)
    };
    let (dst, value) = match op {
        R2ILOp::FloatAdd { dst, a, b } => (
            dst,
            float(a)?
                .binary(float(b)?, |a, b| a + b, |a, b| a + b)?
                .bits(),
        ),
        R2ILOp::FloatSub { dst, a, b } => (
            dst,
            float(a)?
                .binary(float(b)?, |a, b| a - b, |a, b| a - b)?
                .bits(),
        ),
        R2ILOp::FloatMult { dst, a, b } => (
            dst,
            float(a)?
                .binary(float(b)?, |a, b| a * b, |a, b| a * b)?
                .bits(),
        ),
        R2ILOp::FloatDiv { dst, a, b } => (
            dst,
            float(a)?
                .binary(float(b)?, |a, b| a / b, |a, b| a / b)?
                .bits(),
        ),
        // Sign operations are not arithmetic: a NaN keeps its payload.
        R2ILOp::FloatNeg { dst, src } => (dst, state.read(src)? ^ sign(src.size)?),
        R2ILOp::FloatAbs { dst, src } => (dst, state.read(src)? & !sign(src.size)?),
        R2ILOp::FloatSqrt { dst, src } => (dst, float(src)?.unary(f32::sqrt, f64::sqrt).bits()),
        R2ILOp::FloatCeil { dst, src } => (dst, float(src)?.unary(f32::ceil, f64::ceil).bits()),
        R2ILOp::FloatFloor { dst, src } => (dst, float(src)?.unary(f32::floor, f64::floor).bits()),
        R2ILOp::FloatRound { dst, src } => {
            let x = float(src)?;
            if (x.wide() - x.wide().trunc()).abs() == 0.5 {
                return Err(Stop::Undefined);
            }
            (dst, x.unary(f32::round, f64::round).bits())
        }
        R2ILOp::FloatNaN { dst, src } => (dst, u128::from(float(src)?.wide().is_nan())),
        R2ILOp::FloatEqual { dst, a, b } => (dst, u128::from(float(a)?.wide() == float(b)?.wide())),
        R2ILOp::FloatNotEqual { dst, a, b } => {
            (dst, u128::from(float(a)?.wide() != float(b)?.wide()))
        }
        R2ILOp::FloatLess { dst, a, b } => (dst, u128::from(float(a)?.wide() < float(b)?.wide())),
        R2ILOp::FloatLessEqual { dst, a, b } => {
            (dst, u128::from(float(a)?.wide() <= float(b)?.wide()))
        }
        R2ILOp::FloatFloat { dst, src } => {
            let x = match src.size {
                2 => binary16(state.read(src)? as u16),
                _ => float(src)?.wide(),
            };
            (dst, Float::of(0, dst.size)?.at(x).bits())
        }
        R2ILOp::Int2Float { dst, src } => {
            let integer = Word::new(state.read(src)?, src.size)?.signed()?;
            let value = match dst.size {
                4 => Float::Single(integer as f32),
                8 => Float::Double(integer as f64),
                _ => return Err(Stop::Unmodelled),
            };
            (dst, value.bits())
        }
        R2ILOp::Trunc { dst, src } | R2ILOp::Float2Int { dst, src } => {
            if !(1..=8).contains(&dst.size) {
                return Err(Stop::Unmodelled);
            }
            let x = float(src)?.wide().trunc();
            let bound = 2f64.powi(8 * dst.size as i32 - 1);
            if x.is_nan() || x < -bound || x >= bound {
                return Err(Stop::Undefined);
            }
            (dst, (x as i64) as u128 & mask(dst.size))
        }
        _ => return Ok(false),
    };
    state.write(dst, value)?;
    Ok(true)
}

/// Where a transfer goes, or `None` for an operation that is not one.
fn transfer<M: Mapped>(op: &R2ILOp, state: &mut State<M>) -> Result<Option<Flow>, Stop> {
    let (kind, to) = match op {
        R2ILOp::Branch { target } => (TransferKind::Jump, encoded(target)?),
        R2ILOp::CBranch { target, cond } => match state.read(cond)? {
            0 => return Ok(Some(Flow::Next)),
            _ => (TransferKind::Jump, encoded(target)?),
        },
        R2ILOp::BranchInd { target } => (TransferKind::Jump, state.address(target)?),
        R2ILOp::Call { target } => (TransferKind::Call, encoded(target)?),
        R2ILOp::CallInd { target } => (TransferKind::Call, state.address(target)?),
        R2ILOp::Return { target } => (TransferKind::Return, state.address(target)?),
        _ => return Ok(None),
    };
    Ok(Some(Flow::Transfer(Transfer { kind, to })))
}

/// A direct transfer's destination: the lift has already rewritten every instruction-local branch.
fn encoded(target: &Varnode) -> Result<u64, Stop> {
    match target.space {
        SpaceId::Const | SpaceId::Ram => Ok(target.offset),
        _ => Err(Stop::Unmodelled),
    }
}

/// A repeated string operation, one element at a time in its direction, each element one unit of budget.
fn block<M: Mapped>(transfer: &BlockTransfer, state: &mut State<M>) -> Result<(), Stop> {
    let size = width(transfer.element_size)?;
    let count = state.read(&transfer.count)?;
    // Ascending where the direction is zero, as the operation states.
    let descending = state.read(&transfer.direction)? != 0;
    let destination = state.address(&transfer.destination)?;
    let pointer = mask(width(transfer.destination.size)?);
    let at = |base: u64, index: u128| -> Result<u64, Stop> {
        let offset = index.wrapping_mul(u128::from(size));
        let moved = match descending {
            false => u128::from(base).wrapping_add(offset),
            true => u128::from(base).wrapping_sub(offset),
        };
        u64::try_from(moved & pointer).map_err(|_| Stop::Unmodelled)
    };
    // A fill's and a scan's source is a value, read once; a move's and a compare's is a pointer.
    let source = state.read(&transfer.source)?;
    let (mut reached, mut last) = (0u128, (0u128, 0u128));
    while reached < count {
        state.spend()?;
        let here = at(destination, reached)?;
        let there = || {
            at(
                u64::try_from(source).map_err(|_| Stop::Unmodelled)?,
                reached,
            )
        };
        let stop = match transfer.kind {
            BlockTransferKind::Move => {
                let moved = state.load(there()?, size)?;
                state.store(here, size, moved)?;
                None
            }
            BlockTransferKind::Fill => {
                state.store(here, size, source)?;
                None
            }
            BlockTransferKind::Scan(stop) => {
                last = (state.load(here, size)?, 0);
                Some((stop, last.0 == source & mask(size)))
            }
            BlockTransferKind::Compare(stop) => {
                last = (state.load(here, size)?, state.load(there()?, size)?);
                Some((stop, last.0 == last.1))
            }
        };
        reached += 1;
        if let Some((stop, equal)) = stop
            && equal == (stop == BlockStop::Equal)
        {
            break;
        }
    }
    let Some(answer) = &transfer.answer else {
        return Ok(());
    };
    // How far the walk reached, then the destination's element, then any source's.
    let counted = transfer.count.size;
    let elements = u32::from(matches!(transfer.kind, BlockTransferKind::Compare(_))) + 1;
    if counted + elements * size != answer.size {
        return Err(Stop::Unmodelled);
    }
    let above = |value: u128, bytes: u32| value.checked_shl(8 * bytes).unwrap_or(0);
    let value = reached | above(last.0, counted) | above(last.1, counted + size);
    state.write(answer, value)
}

#[cfg(test)]
mod tests {

    /// A guarded store writes and a guarded load reads only where the guard holds; a guard that is
    /// no boolean is undefined.
    #[test]
    fn a_guarded_access_happens_exactly_where_its_guard_holds() {
        let (guard, addr, val) = (
            Varnode::register(0x10, 1),
            Varnode::register(0x20, 8),
            Varnode::register(0x28, 4),
        );
        let ops = [
            R2ILOp::StoreGuarded {
                space: SpaceId::Ram,
                addr: addr.clone(),
                val: val.clone(),
                guard: guard.clone(),
                ordering: crate::MemoryOrdering::Relaxed,
            },
            R2ILOp::LoadGuarded {
                dst: val.clone(),
                space: SpaceId::Ram,
                addr: Varnode::constant(0x100, 8),
                guard: guard.clone(),
                ordering: crate::MemoryOrdering::Relaxed,
            },
        ];
        for (held, stored, loaded) in [(1, 0xdead_beef, 0x0303_0303), (0, 0x0101_0101, 0xdead_beef)]
        {
            let mut state = State::new(Endianness::Little, |_| Some(1u8), 64).expect("state");
            state.set_register(guard.offset, 1, held).expect("guard");
            state.set_register(addr.offset, 8, 0x200).expect("addr");
            state.set_register(val.offset, 4, 0xdead_beef).expect("val");
            state.store(0x100, 4, 0x0303_0303).expect("stored");
            for op in &ops {
                assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
            }
            assert_eq!(state.load(0x200, 4), Ok(stored), "guard {held}");
            assert_eq!(state.register(val.offset, 4), Some(loaded), "guard {held}");
        }
        let mut state = State::new(Endianness::Little, |_| Some(1u8), 64).expect("state");
        state.set_register(guard.offset, 1, 2).expect("guard");
        assert_eq!(step(&ops[0], &mut state), Flow::Stop(Stop::Undefined));
    }

    /// A conditional store takes, answering 1, only after a linked load of its address and width
    /// with no clear between; it clears the mark either way, so a second one fails and writes nothing.
    #[test]
    fn a_conditional_store_takes_only_after_a_linked_load_of_its_address() {
        let (addr, val, ok) = (
            Varnode::register(0x20, 8),
            Varnode::register(0x28, 4),
            Varnode::register(0x30, 1),
        );
        let linked = |at: u64| R2ILOp::LoadLinked {
            dst: Varnode::register(0x40, 4),
            space: SpaceId::Ram,
            addr: Varnode::constant(at, 8),
            ordering: crate::MemoryOrdering::Unknown,
        };
        let conditional = R2ILOp::StoreConditional {
            result: Some(ok.clone()),
            space: SpaceId::Ram,
            addr: addr.clone(),
            val: val.clone(),
            ordering: crate::MemoryOrdering::Unknown,
        };
        let wide_linked = R2ILOp::LoadLinked {
            dst: Varnode::register(0x40, 8),
            space: SpaceId::Ram,
            addr: Varnode::constant(0x200, 8),
            ordering: crate::MemoryOrdering::Unknown,
        };
        let (written, untouched) = (0xdead_beef, 0x0101_0101);
        for (ops, took, stored) in [
            (vec![linked(0x200), conditional.clone()], 1, written),
            (
                vec![linked(0x200), conditional.clone(), conditional.clone()],
                0,
                written,
            ),
            (vec![conditional.clone()], 0, untouched),
            (
                vec![linked(0x200), R2ILOp::ClearExclusive, conditional.clone()],
                0,
                untouched,
            ),
            (vec![linked(0x208), conditional.clone()], 0, untouched),
            (vec![wide_linked, conditional], 0, untouched),
        ] {
            let mut state = State::new(Endianness::Little, |_| Some(1u8), 64).expect("state");
            state.set_register(addr.offset, 8, 0x200).expect("addr");
            state.set_register(val.offset, 4, 0xdead_beef).expect("val");
            for op in &ops {
                assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
            }
            assert_eq!(state.register(ok.offset, 1), Some(took), "{ops:?}");
            assert_eq!(state.load(0x200, 4), Ok(stored), "{ops:?}");
        }
    }

    /// Each atomic update reads the cell, writes what it states back (a compare-and-exchange only
    /// where the cell held the expected value), and answers the value read, at the access's width.
    #[test]
    fn an_atomic_access_answers_the_old_value_and_writes_its_update() {
        use crate::{AtomicAccess, AtomicFetchOp as Op, AtomicUpdate};
        let (addr, operand, other, dst) = (
            Varnode::register(0x20, 8),
            Varnode::register(0x28, 2),
            Varnode::register(0x30, 2),
            Varnode::register(0x40, 2),
        );
        let fetch = |op| AtomicUpdate::Fetch {
            op,
            operand: operand.clone(),
        };
        // The cell holds 0x8001 (negative at 16 bits) and the operand 0x0203.
        let cas = |expected: &Varnode| AtomicUpdate::CompareExchange {
            expected: expected.clone(),
            replacement: operand.clone(),
        };
        for (update, stored) in [
            (fetch(Op::Add), 0x8204),
            (fetch(Op::Sub), 0x7dfe),
            (fetch(Op::And), 0x0001),
            (fetch(Op::Or), 0x8203),
            (fetch(Op::Xor), 0x8202),
            (fetch(Op::Swap), 0x0203),
            (fetch(Op::SignedMax), 0x0203),
            (fetch(Op::SignedMin), 0x8001),
            (fetch(Op::UnsignedMax), 0x8001),
            (fetch(Op::UnsignedMin), 0x0203),
            (cas(&other), 0x0203),
            (cas(&operand), 0x8001),
        ] {
            let op = R2ILOp::Atomic(Box::new(AtomicAccess {
                dst: dst.clone(),
                space: SpaceId::Ram,
                addr: addr.clone(),
                update: update.clone(),
                ordering: crate::MemoryOrdering::SeqCst,
            }));
            let cell = |at: u64| (0x200..0x210).contains(&at).then_some(0u8);
            let mut state = State::new(Endianness::Little, cell, 64).expect("state");
            state.set_register(addr.offset, 8, 0x200).expect("addr");
            state
                .set_register(operand.offset, 2, 0x0203)
                .expect("operand");
            state.set_register(other.offset, 2, 0x8001).expect("other");
            state.store(0x200, 2, 0x8001).expect("cell");
            state.store(0x202, 1, 0x77).expect("the byte after it");
            assert_eq!(step(&op, &mut state), Flow::Next, "{update:?}");
            assert_eq!(state.register(dst.offset, 2), Some(0x8001), "{update:?}");
            assert_eq!(state.load(0x200, 2), Ok(stored), "{update:?}");
            assert_eq!(state.load(0x202, 1), Ok(0x77), "{update:?}");
        }
    }

    /// A fence of any ordering runs and leaves registers, memory and the monitor as they were.
    #[test]
    fn a_fence_changes_nothing_one_thread_sees() {
        let (addr, val, ok) = (
            Varnode::register(0x20, 8),
            Varnode::register(0x28, 4),
            Varnode::register(0x30, 1),
        );
        for ordering in [
            crate::MemoryOrdering::Relaxed,
            crate::MemoryOrdering::Acquire,
            crate::MemoryOrdering::Release,
            crate::MemoryOrdering::AcqRel,
            crate::MemoryOrdering::SeqCst,
            crate::MemoryOrdering::Unknown,
        ] {
            let ops = [
                R2ILOp::LoadLinked {
                    dst: Varnode::register(0x40, 4),
                    space: SpaceId::Ram,
                    addr: addr.clone(),
                    ordering: crate::MemoryOrdering::Relaxed,
                },
                R2ILOp::Fence { ordering },
                R2ILOp::StoreConditional {
                    result: Some(ok.clone()),
                    space: SpaceId::Ram,
                    addr: addr.clone(),
                    val: val.clone(),
                    ordering: crate::MemoryOrdering::Relaxed,
                },
            ];
            let mut state = State::new(Endianness::Little, |_| Some(1u8), 64).expect("state");
            state.set_register(addr.offset, 8, 0x200).expect("addr");
            state.set_register(val.offset, 4, 0xdead_beef).expect("val");
            state.store(0x200, 4, 0x0101_0101).expect("memory");
            for op in &ops {
                assert_eq!(step(op, &mut state), Flow::Next, "{op:?}");
            }
            assert_eq!(state.register(0x40, 4), Some(0x0101_0101), "{ordering:?}");
            assert_eq!(state.register(ok.offset, 1), Some(1), "{ordering:?}");
            assert_eq!(state.load(0x200, 4), Ok(0xdead_beef), "{ordering:?}");
        }
    }

    /// A lane at bit 128 of a 256-bit register lies outside the carried word: unmodelled, not a panic.
    #[test]
    fn an_insert_past_the_carried_bits_is_unmodelled() {
        let word = |bits, bytes| Word::new(bits, bytes).expect("a width");
        let high = apply(
            Operation::Insert,
            &[word(0, 32), word(0xab, 4), word(128, 4)],
            32,
        );
        assert_eq!(high, Err(Stop::Unmodelled));
    }

    #[test]
    fn an_insert_writes_the_value_over_its_bits_and_keeps_the_rest() {
        let word = |bits, bytes| Word::new(bits, bytes).expect("a width");
        let inserted = apply(
            Operation::Insert,
            &[word(0x1234, 2), word(0xab, 1), word(8, 1)],
            2,
        );
        assert_eq!(inserted, Ok(0xab34));
        let low = apply(
            Operation::Insert,
            &[word(0x1234, 2), word(0xab, 1), word(0, 1)],
            2,
        );
        assert_eq!(low, Ok(0x12ab));
        let past = apply(
            Operation::Insert,
            &[word(0x1234, 2), word(0xab, 1), word(9, 1)],
            2,
        );
        assert_eq!(past, Err(Stop::Unmodelled));
    }

    use super::*;

    fn nothing_mapped(_: u64) -> Option<u8> {
        None
    }

    fn state() -> State<fn(u64) -> Option<u8>> {
        State::new(
            Endianness::Little,
            nothing_mapped as fn(u64) -> Option<u8>,
            u64::MAX,
        )
        .expect("little-endian")
    }

    fn register(offset: u64, size: u32) -> Varnode {
        Varnode::register(offset, size)
    }

    fn word(bits: u128, bytes: u32) -> Word {
        Word::new(bits, bytes).expect("a width")
    }

    #[test]
    fn the_flags_of_an_addition_are_its_carry_and_its_signed_overflows() {
        let byte = |operation, a, b| apply(operation, &[word(a, 1), word(b, 1)], 1);
        assert_eq!(byte(Operation::Carry, 0xff, 1), Ok(1));
        assert_eq!(byte(Operation::Carry, 0xfe, 1), Ok(0));
        assert_eq!(byte(Operation::SCarry, 0x7f, 1), Ok(1));
        assert_eq!(byte(Operation::SCarry, 0xff, 1), Ok(0));
        assert_eq!(byte(Operation::SBorrow, 0x80, 1), Ok(1));
        assert_eq!(byte(Operation::SBorrow, 0, 1), Ok(0));
    }

    #[test]
    fn a_shift_past_the_width_leaves_nought_or_the_sign() {
        let byte = |operation, a, b| apply(operation, &[word(a, 1), word(b, 1)], 1);
        assert_eq!(byte(Operation::Left, 0x81, 1), Ok(0x02));
        assert_eq!(byte(Operation::Left, 0x81, 8), Ok(0));
        assert_eq!(byte(Operation::SRight, 0x80, 9), Ok(0xff));
        assert_eq!(byte(Operation::SRight, 0x40, 9), Ok(0));
    }

    #[test]
    fn division_p_code_leaves_undefined_has_no_value() {
        let at =
            |operation, a, b, bytes| apply(operation, &[word(a, bytes), word(b, bytes)], bytes);
        assert_eq!(at(Operation::Div, 7, 0, 1), Err(Stop::Undefined));
        assert_eq!(at(Operation::SDiv, 0x80, 0xff, 1), Err(Stop::Undefined));
        assert_eq!(
            at(Operation::SDiv, 0x8000_0000_0000_0000, u128::MAX, 8),
            Err(Stop::Undefined)
        );
        assert_eq!(at(Operation::SDiv, 0xf9, 2, 1), Ok(0xfd));
        assert_eq!(at(Operation::SRem, 0xf9, 2, 1), Ok(0xff));
        assert_eq!(at(Operation::SRem, 0x80, 0xff, 1), Ok(0));
    }

    #[test]
    fn a_signed_comparison_reads_its_operands_at_their_own_width() {
        // A boolean result is one byte, and a four-byte 0x80 is positive at its own width.
        let wide = [word(0x80, 4), word(0, 4)];
        assert_eq!(apply(Operation::SLess, &wide, 1), Ok(0));
        assert_eq!(
            apply(Operation::SLess, &[word(0x80, 1), word(0, 1)], 1),
            Ok(1)
        );
        // A boolean operation over a value that is not one has no value.
        let (two, one) = (word(2, 1), word(1, 1));
        assert_eq!(
            apply(Operation::BoolAnd, &[two, one], 1),
            Err(Stop::Undefined)
        );
        // Operands of the wrong widths are not the operation p-code defines.
        let mixed = [word(1, 4), word(1, 8)];
        assert_eq!(apply(Operation::Add, &mixed, 8), Err(Stop::Unmodelled));
    }

    #[test]
    fn a_value_wider_than_the_bits_carried_is_exact_or_refused() {
        // A thirty-two byte register zero-extended from nothing is nothing, however wide.
        let zero = apply(Operation::ZExt, &[word(0, 4)], 32);
        assert_eq!(zero, Ok(0));
        let (small, large) = (word(5, 32), word(u128::MAX, 32));
        assert_eq!(apply(Operation::Add, &[small, small], 32), Ok(10));
        // Past 128 bits the sum is a number the carried bits cannot hold, so it is refused, not wrapped.
        assert_eq!(
            apply(Operation::Add, &[large, small], 32),
            Err(Stop::Unmodelled)
        );
        assert_eq!(apply(Operation::Not, &[small], 32), Err(Stop::Unmodelled));
        let negative = word(0xff, 1);
        assert_eq!(
            apply(Operation::SExt, &[negative], 32),
            Err(Stop::Unmodelled)
        );
        assert_eq!(apply(Operation::SExt, &[negative], 16), Ok(u128::MAX));
        // Five has 253 leading zeros in 256 bits, though only 128 of them are carried.
        assert_eq!(apply(Operation::Lzcount, &[small], 4), Ok(253));
        // A register wider than the bits carried reads back where its high bytes are clear.
        let mut machine = state();
        machine.set_register(0, 32, 7).expect("a wide register");
        assert_eq!(machine.register(0, 32), Some(7));
        machine.set_register(31, 1, 1).expect("its top byte");
        assert_eq!(machine.register(0, 32), None);
    }

    #[test]
    fn a_temporary_does_not_outlive_its_instruction() {
        let mut machine = state();
        let write = R2ILOp::Copy {
            dst: Varnode::unique(0, 8),
            src: Varnode::constant(5, 8),
        };
        let read = R2ILOp::Copy {
            dst: register(0, 8),
            src: Varnode::unique(0, 8),
        };
        assert_eq!(step(&write, &mut machine), Flow::Next);
        machine.end_instruction();
        let unwritten = Stop::Unwritten {
            space: SpaceId::Unique,
            offset: 0,
        };
        assert_eq!(step(&read, &mut machine), Flow::Stop(unwritten));
    }

    #[test]
    fn a_word_lies_in_the_order_the_endianness_says() {
        let mapped = |address: u64| (0x100..0x108).contains(&address).then_some(0);
        let mut big = State::new(Endianness::Big, mapped, u64::MAX).expect("big-endian");
        let (address, word) = (Varnode::constant(0x100, 8), register(0, 2));
        big.set_register(0, 2, 0x1122).expect("a word");
        let store = R2ILOp::Store {
            space: SpaceId::Ram,
            addr: address.clone(),
            val: word,
        };
        assert_eq!(step(&store, &mut big), Flow::Next);
        let high = R2ILOp::Load {
            dst: register(8, 1),
            space: SpaceId::Ram,
            addr: address,
        };
        assert_eq!(step(&high, &mut big), Flow::Next);
        assert_eq!(big.register(8, 1), Some(0x11));
        let accesses = big.take_accesses();
        assert_eq!(accesses[0].kind, AccessKind::Write);
        assert_eq!((accesses[1].kind, accesses[1].width), (AccessKind::Read, 1));
        // On a little-endian machine the low half of a register is its first bytes.
        let mut little = state();
        little
            .set_register(0, 8, 0x1122_3344_5566_7788)
            .expect("a word");
        assert_eq!(little.register(0, 4), Some(0x5566_7788));
        let unmapped = R2ILOp::Load {
            dst: register(8, 4),
            space: SpaceId::Ram,
            addr: Varnode::constant(0x100, 8),
        };
        let stopped = Flow::Stop(Stop::Unmapped { address: 0x100 });
        assert_eq!(step(&unmapped, &mut little), stopped);
    }

    #[test]
    fn a_scan_answers_how_far_it_reached_and_the_element_it_compared_last() {
        // "ab\0" at 0x100, then bytes nothing maps.
        let text = |address: u64| match address {
            0x100 => Some(b'a'),
            0x101 => Some(b'b'),
            0x102 => Some(0),
            _ => None,
        };
        let mut machine = State::new(Endianness::Little, text, u64::MAX).expect("little-endian");
        let (rdi, rcx, df, answer) = (
            register(0, 8),
            register(8, 8),
            register(16, 1),
            Varnode::unique(0, 9),
        );
        machine.set_register(0, 8, 0x100).expect("a pointer");
        machine
            .set_register(8, 8, u128::from(u64::MAX))
            .expect("a count");
        machine.set_register(16, 1, 0).expect("ascending");
        let scan = R2ILOp::BlockTransfer(Box::new(BlockTransfer {
            space: SpaceId::Ram,
            kind: BlockTransferKind::Scan(BlockStop::Equal),
            destination: rdi,
            source: Varnode::constant(0, 1),
            count: rcx,
            direction: df,
            element_size: 1,
            answer: Some(answer.clone()),
        }));
        assert_eq!(step(&scan, &mut machine), Flow::Next);
        // Three elements reached, and the last one compared is the terminator.
        let reached = R2ILOp::Subpiece {
            dst: register(24, 8),
            src: answer,
            offset: 0,
        };
        assert_eq!(step(&reached, &mut machine), Flow::Next);
        assert_eq!(machine.register(24, 8), Some(3));
        // Walking down from 0x102 finds no terminator before memory ends, and says so.
        machine.set_register(0, 8, 0x101).expect("a pointer");
        machine.set_register(16, 1, 1).expect("descending");
        let stopped = Flow::Stop(Stop::Unmapped { address: 0xff });
        assert_eq!(step(&scan, &mut machine), stopped);
    }

    /// Runs one float operation from `inputs` (offset, size, bits) and reads its result at offset 32.
    fn float_run(op: &R2ILOp, inputs: &[(u64, u32, u128)]) -> Result<u128, Stop> {
        let mut machine = state();
        for (offset, size, value) in inputs {
            machine
                .set_register(*offset, *size, *value)
                .expect("an input");
        }
        match step(op, &mut machine) {
            Flow::Next => Ok(machine
                .register(32, op.output().map_or(8, |dst| dst.size))
                .expect("a result")),
            Flow::Stop(stop) => Err(stop),
            flow => panic!("{flow:?}"),
        }
    }

    fn double(x: f64) -> u128 {
        u128::from(x.to_bits())
    }

    #[test]
    fn floats_round_to_nearest_even_with_one_nan_and_keep_a_sign_operations_payload() {
        let (a, b, out) = (register(0, 8), register(8, 8), register(32, 8));
        let divide = R2ILOp::FloatDiv {
            dst: out.clone(),
            a: a.clone(),
            b: b.clone(),
        };
        let thirds = [(0, 8, double(1.0)), (8, 8, double(3.0))];
        assert_eq!(float_run(&divide, &thirds), Ok(double(1.0 / 3.0)));
        // 0/0 is the canonical NaN whatever the host would produce.
        let zeros = [(0, 8, 0), (8, 8, 0)];
        assert_eq!(float_run(&divide, &zeros), Ok(u128::from(DOUBLE_NAN)));
        let signalling = 0x7ff4_0000_0000_0001u128;
        let negate = R2ILOp::FloatNeg {
            dst: out,
            src: a.clone(),
        };
        assert_eq!(
            float_run(&negate, &[(0, 8, signalling)]),
            Ok(signalling | 1 << 63)
        );
        let less = R2ILOp::FloatLess {
            dst: register(32, 1),
            a,
            b,
        };
        assert_eq!(
            float_run(&less, &[(0, 8, signalling), (8, 8, double(1.0))]),
            Ok(0)
        );
    }

    #[test]
    fn a_conversion_rounds_once_and_a_tie_or_an_overflow_has_no_value() {
        let (a, out) = (register(0, 8), register(32, 8));
        let round = R2ILOp::FloatRound {
            dst: out.clone(),
            src: a.clone(),
        };
        assert_eq!(
            float_run(&round, &[(0, 8, double(2.5))]),
            Err(Stop::Undefined)
        );
        assert_eq!(float_run(&round, &[(0, 8, double(2.75))]), Ok(double(3.0)));
        let truncate = R2ILOp::Trunc {
            dst: register(32, 4),
            src: a.clone(),
        };
        assert_eq!(
            float_run(&truncate, &[(0, 8, double(-2.9))]),
            Ok(0xffff_fffe)
        );
        let past = [(0, 8, double(2147483648.0))];
        assert_eq!(float_run(&truncate, &past), Err(Stop::Undefined));
        let widen = R2ILOp::Int2Float {
            dst: out,
            src: register(0, 4),
        };
        assert_eq!(float_run(&widen, &[(0, 4, 0xffff_ffff)]), Ok(double(-1.0)));
        let narrow = R2ILOp::FloatFloat {
            dst: register(32, 4),
            src: a,
        };
        let third = u128::from((1f32 / 3.0).to_bits());
        assert_eq!(float_run(&narrow, &[(0, 8, double(1.0 / 3.0))]), Ok(third));
    }

    #[test]
    fn a_half_widens_exactly_and_never_narrows() {
        let widen = R2ILOp::FloatFloat {
            dst: register(32, 4),
            src: register(0, 2),
        };
        let single = |x: f32| u128::from(x.to_bits());
        for (half, wide) in [
            (0x3800, 0.5),
            (0xbc00, -1.0),
            (0x7bff, 65504.0),
            (0x0001, 2f32.powi(-24)),
            (0x03ff, 1023.0 * 2f32.powi(-24)),
            (0x0400, 2f32.powi(-14)),
            (0x8000, -0.0),
            (0x7c00, f32::INFINITY),
            (0xfc00, f32::NEG_INFINITY),
        ] {
            assert_eq!(
                float_run(&widen, &[(0, 2, half)]),
                Ok(single(wide)),
                "{half:#x}"
            );
        }
        assert_eq!(
            float_run(&widen, &[(0, 2, 0x7e01)]),
            Ok(u128::from(SINGLE_NAN))
        );
        let narrow = R2ILOp::FloatFloat {
            dst: register(32, 2),
            src: register(0, 4),
        };
        assert_eq!(
            float_run(&narrow, &[(0, 4, single(0.5))]),
            Err(Stop::Unmodelled)
        );
    }

    #[test]
    fn an_unmodelled_width_stops_and_a_transfer_says_where() {
        let mut machine = state();
        machine.set_register(0, 2, 0x3c00).expect("a half");
        let half = R2ILOp::FloatAdd {
            dst: register(0, 2),
            a: register(0, 2),
            b: register(0, 2),
        };
        assert_eq!(step(&half, &mut machine), Flow::Stop(Stop::Unmodelled));
        let unwritten = Stop::Unwritten {
            space: SpaceId::Register,
            offset: 8,
        };
        let copy = R2ILOp::Copy {
            dst: register(0, 1),
            src: register(8, 1),
        };
        assert_eq!(step(&copy, &mut machine), Flow::Stop(unwritten));
        machine.set_register(8, 1, 0).expect("a flag");
        let skip = R2ILOp::CBranch {
            target: Varnode::ram(0x2000, 8),
            cond: register(8, 1),
        };
        assert_eq!(step(&skip, &mut machine), Flow::Next);
        machine.set_register(8, 1, 1).expect("a flag");
        let taken = Transfer {
            kind: TransferKind::Jump,
            to: 0x2000,
        };
        assert_eq!(step(&skip, &mut machine), Flow::Transfer(taken));
        machine.set_register(16, 8, 0x3000).expect("an address");
        let back = R2ILOp::Return {
            target: register(16, 8),
        };
        let returned = Transfer {
            kind: TransferKind::Return,
            to: 0x3000,
        };
        assert_eq!(step(&back, &mut machine), Flow::Transfer(returned));
        // A run spends its budget one operation at a time.
        let mut short = State::new(Endianness::Little, nothing_mapped, 1).expect("little-endian");
        assert_eq!(step(&R2ILOp::Nop, &mut short), Flow::Next);
        assert_eq!(step(&R2ILOp::Nop, &mut short), Flow::Stop(Stop::Exhausted));
    }

    /// A run follows the label a taken branch names and skips what it jumps over; a label outside
    /// the instruction stops it.
    #[test]
    fn a_run_follows_the_local_labels_its_branches_name() {
        let label = |offset: i64| Varnode::constant(offset as u64 & 0xffff_ffff, 4);
        let set = |at: u64, value: u64| R2ILOp::Copy {
            dst: register(at, 1),
            src: Varnode::constant(value, 1),
        };
        let ops = [
            R2ILOp::CBranch {
                target: label(3),
                cond: register(0, 1),
            },
            set(8, 1),
            R2ILOp::Branch { target: label(2) },
            set(8, 2),
            set(16, 3),
        ];
        for (cond, written) in [(0, 1), (1, 2)] {
            let mut machine = state();
            machine.set_register(0, 1, cond).expect("a flag");
            assert_eq!(run(&ops, &mut machine), Flow::Next);
            assert_eq!(machine.register(8, 1), Some(written));
            assert_eq!(machine.register(16, 1), Some(3));
        }
        let mut machine = state();
        for outside in [label(2), label(-1)] {
            let branch = [R2ILOp::Branch { target: outside }];
            assert_eq!(run(&branch, &mut machine), Flow::Stop(Stop::Unmodelled));
        }
        let end = [R2ILOp::Branch { target: label(1) }];
        assert_eq!(run(&end, &mut machine), Flow::Next);
    }
}
