//! What each operation computes, run on one concrete byte state; a step it cannot take exactly stops the run.
//!
//! [`apply`] is the one statement of what a value operation computes from its
//! operands, and every constant fold in the engine answers through it.

use std::collections::BTreeMap;

use crate::{BlockStop, BlockTransfer, BlockTransferKind, Endianness, R2ILOp, SpaceId, Varnode};

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
        [cond, if_true, if_false] => match cond.bits {
            0 => if_false.bits,
            _ => if_true.bits,
        },
        _ => return Err(Stop::Unmodelled),
    };
    Ok(value & mask(width))
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

fn executed<M: Mapped>(op: &R2ILOp, state: &mut State<M>) -> Result<Flow, Stop> {
    state.spend()?;
    if let Some(flow) = transfer(op, state)? {
        return Ok(flow);
    }
    match op {
        R2ILOp::Nop => {}
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
        R2ILOp::BlockTransfer(transfer) if transfer.space == SpaceId::Ram => {
            block(transfer, state)?;
        }
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

    #[test]
    fn only_the_integer_core_runs_and_a_transfer_says_where() {
        let mut machine = state();
        let float = R2ILOp::FloatAdd {
            dst: register(0, 8),
            a: register(0, 8),
            b: register(0, 8),
        };
        assert_eq!(step(&float, &mut machine), Flow::Stop(Stop::Unmodelled));
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
}
