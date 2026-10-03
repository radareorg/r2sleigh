//! Which bytes of each value an operation wrote as data
//! (doc/adr-written-lanes.md).
//!
//! A machine writes registers by lanes. `xor eax, eax` computes four bytes
//! and the 32-bit write zeroes the other four by convention; `setg al` computes
//! one byte and leaves seven as the caller left them; `movzx eax, byte` computes
//! one and zero-fills three. How wide a function's result is depends on which
//! bytes it *computed*, against which it filled or never touched, and that is
//! a fact about each operation's output, lost when an optimisation folds the
//! operation: `ZEXT(EAX ^ EAX)` becomes the constant `0:8`, whose bytes are
//! all literal.
//!
//! So the fact is recorded before any rewrite, in [`Lifted`](crate::Lifted),
//! for every operation and phi by [`OpId`]. Rewriting an operation in place
//! keeps its id, so the record of what the instruction wrote survives the
//! fold.
//!
//! Each byte is [`Data`](Byte::Data), or the set of the ways it was *not*
//! computed on the paths that reach it: zero-filled, sign-filled, or still
//! the byte some register was entered with. Joining paths unions the sets,
//! and `Data` absorbs. A literal's bytes are data, so `return 1` is as wide
//! as the instruction that wrote the one; widths never come from values.
//!
//! The record is one forward pass over the operations, repeated until the
//! phis settle: each byte only moves up a lattice of height
//! [`MOST_WAYS`] + 1, so the passes are bounded by that height times the loop
//! nesting, O(ops × W) each for width W in bytes.

use std::collections::BTreeMap;

use r2source::{CanonicalStorageId, CanonicalStorageSpace};

use crate::SSAFunction;
use crate::arena::OpId;
use crate::op::SSAOp;
use crate::var::SSAVar;

/// One byte of a register, by where it lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegisterByte {
    pub space: CanonicalStorageSpace,
    pub address: u64,
}

/// A way a byte came to hold what it holds without an operation computing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fill {
    /// The zero an unsigned extension writes above its source.
    Zero,
    /// The sign an extension copies above its source.
    Sign,
    /// The byte this register byte held when the function was entered.
    Entry(RegisterByte),
}

/// More ways than this and a byte is taken as data: it is computed on some
/// path in every case that matters, and the bound keeps the lattice short.
pub const MOST_WAYS: usize = 4;

/// One byte of a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Byte {
    /// Computed by an operation from its inputs or a literal, on some path.
    Data,
    /// Not computed on any path that reaches it; the ways, sorted. Empty
    /// only before the pass has reached it, which a settled record never is.
    Filled(Vec<Fill>),
}

impl Byte {
    const NONE: Self = Self::Filled(Vec::new());

    fn fill(fill: Fill) -> Self {
        Self::Filled(vec![fill])
    }

    /// The byte on either of two paths.
    fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Data, _) | (_, Self::Data) => Self::Data,
            (Self::Filled(a), Self::Filled(b)) => {
                let mut ways = a.iter().chain(b).copied().collect::<Vec<_>>();
                ways.sort_unstable();
                ways.dedup();
                match ways.len() > MOST_WAYS {
                    true => Self::Data,
                    false => Self::Filled(ways),
                }
            }
        }
    }

    /// Whether the byte holds something the function put there: data, or a
    /// byte it moved from anywhere but `home`, the place it now sits.
    pub fn written_at(&self, home: Option<RegisterByte>) -> bool {
        match self {
            Self::Data => true,
            Self::Filled(ways) => ways.iter().any(|way| match way {
                Fill::Entry(from) => Some(*from) != home,
                Fill::Zero | Fill::Sign => false,
            }),
        }
    }
}

/// Each byte of one operation's or phi's output, low byte first.
pub type Bytes = Vec<Byte>;

/// Two values' bytes on either of two paths, byte by byte.
pub fn join(a: &[Byte], b: &[Byte]) -> Bytes {
    a.iter().zip(b).map(|(a, b)| a.join(b)).collect()
}

/// What every operation and phi of a function wrote, by id, as lifted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Written {
    by_op: BTreeMap<OpId, Bytes>,
}

impl Written {
    /// What the operation or phi `id` wrote, where it was lifted.
    pub fn of(&self, id: OpId) -> Option<&Bytes> {
        self.by_op.get(&id)
    }

    /// Take the record of a function before anything rewrites it.
    pub fn capture(function: &SSAFunction) -> Self {
        let mut by_var = BTreeMap::<SSAVar, Bytes>::new();
        let mut by_op = BTreeMap::<OpId, Bytes>::new();
        // Until nothing changes: a loop's phi reads a value defined below it.
        while function.blocks().iter().fold(false, |changed, block| {
            changed | capture_block(function, block, &mut by_var, &mut by_op)
        }) {}
        Self { by_op }
    }
}

/// One pass over a block's phis and operations; whether any record moved.
fn capture_block(
    function: &SSAFunction,
    block: &crate::block::SSABlock,
    by_var: &mut BTreeMap<SSAVar, Bytes>,
    by_op: &mut BTreeMap<OpId, Bytes>,
) -> bool {
    let mut changed = false;
    for (id, phi) in block.sited_phis() {
        let bytes = phi
            .sources
            .iter()
            .map(|(_, source)| read(function, by_var, source))
            .fold(vec![Byte::NONE; phi.dst.size as usize], |held, source| {
                join(&held, &source)
            });
        changed |= settle(by_var, by_op, id, &phi.dst, bytes);
    }
    for (id, op) in block.sited() {
        if let Some(dst) = op.dst() {
            let bytes = transfer(op, |var| read(function, by_var, var));
            changed |= settle(by_var, by_op, id, dst, bytes);
        }
    }
    changed
}

/// Record what `id` wrote to `dst`, joined with what it was recorded as
/// writing before; whether that moved anything.
fn settle(
    by_var: &mut BTreeMap<SSAVar, Bytes>,
    by_op: &mut BTreeMap<OpId, Bytes>,
    id: OpId,
    dst: &SSAVar,
    bytes: Bytes,
) -> bool {
    let held = by_var.entry(dst.clone()).or_default();
    let joined = match held.len() == bytes.len() {
        true => held.iter().zip(&bytes).map(|(a, b)| a.join(b)).collect(),
        false => bytes,
    };
    if *held == joined {
        return false;
    }
    held.clone_from(&joined);
    by_op.insert(id, joined);
    true
}

/// The bytes of a variable an operation reads: a literal's are data, an entry
/// value's are the register bytes it was entered with, and anything else is
/// what its definition wrote, so far as the pass has reached it.
fn read(function: &SSAFunction, by_var: &BTreeMap<SSAVar, Bytes>, var: &SSAVar) -> Bytes {
    if var.constant_bits().is_some() {
        return vec![Byte::Data; var.size as usize];
    }
    if let Some(bytes) = by_var.get(var) {
        return bytes.clone();
    }
    if var.version == 0 {
        return entry_bytes(function.canonical_storage_for_var(var), var.size);
    }
    vec![Byte::NONE; var.size as usize]
}

/// The bytes of a value as the function was entered with it.
pub(crate) fn entry_bytes(storage: Option<CanonicalStorageId>, size: u32) -> Bytes {
    (0..u64::from(size))
        .map(|byte| match home(storage, byte) {
            Some(at) => Byte::fill(Fill::Entry(at)),
            None => Byte::Data,
        })
        .collect()
}

/// Where byte `byte` of a value in `storage` lives, where it is a register.
pub fn home(storage: Option<CanonicalStorageId>, byte: u64) -> Option<RegisterByte> {
    let storage = storage?;
    (storage.space == CanonicalStorageSpace::Register).then_some(RegisterByte {
        space: storage.space,
        address: storage.offset + byte,
    })
}

/// What an operation writes to each byte of its output, given what each of
/// its inputs holds. Only operations that move bytes without computing them
/// are modelled; every other result is data.
pub(crate) fn transfer(op: &SSAOp, input: impl Fn(&SSAVar) -> Bytes) -> Bytes {
    let size = op.dst().map_or(0, |dst| dst.size as usize);
    let mut out = match op {
        SSAOp::Copy { src, .. } => input(src),
        SSAOp::IntZExt { src, .. } => extended(input(src), size, Fill::Zero),
        SSAOp::IntSExt { src, .. } => extended(input(src), size, Fill::Sign),
        SSAOp::Subpiece { src, offset, .. } => {
            input(src).into_iter().skip(*offset as usize).collect()
        }
        SSAOp::Piece { hi, lo, .. } => {
            let mut bytes = input(lo);
            bytes.extend(input(hi));
            bytes
        }
        SSAOp::Insert(insert) => match lane(&insert.position) {
            Some(first) => {
                let mut bytes = input(&insert.src);
                for (at, byte) in input(&insert.value).into_iter().enumerate() {
                    if let Some(slot) = bytes.get_mut(first + at) {
                        *slot = byte;
                    }
                }
                bytes
            }
            None => Vec::new(),
        },
        _ => Vec::new(),
    };
    out.resize(size, Byte::Data);
    out
}

/// A value's bytes, with `fill` above them up to `size`.
fn extended(mut bytes: Bytes, size: usize, fill: Fill) -> Bytes {
    if bytes.len() < size {
        bytes.resize(size, Byte::fill(fill));
    }
    bytes
}

/// The first byte an INSERT writes, where its position is a byte-aligned
/// constant.
fn lane(position: &SSAVar) -> Option<usize> {
    let bits = position.constant_bits()?;
    (bits % 8 == 0)
        .then(|| usize::try_from(bits / 8).ok())
        .flatten()
}

/// How many bytes of a result carrier hold what the function put there: one
/// past the highest written byte, rounded up to a power of two no wider than
/// the carrier. `None` where the function wrote no byte of it.
pub fn written_width(bytes: &[Byte], storage: CanonicalStorageId) -> Option<u32> {
    let highest = (0..bytes.len())
        .rev()
        .find(|&at| bytes[at].written_at(home(Some(storage), at as u64)))?;
    let width = u32::try_from(highest + 1).ok()?.next_power_of_two();
    Some(width.min(storage.size))
}

/// Whether the byte just above a result of `width` bytes is the sign of the
/// result on every path, and nothing else: the function sign-extended what
/// it computed, so the value is signed at that width.
pub fn sign_filled_above(bytes: &[Byte], width: u32) -> bool {
    bytes
        .get(width as usize)
        .is_some_and(|byte| *byte == Byte::Filled(vec![Fill::Sign]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rax() -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: 0,
            size: 8,
        }
    }

    fn at(address: u64) -> Fill {
        Fill::Entry(RegisterByte {
            space: CanonicalStorageSpace::Register,
            address,
        })
    }

    /// The cases of doc/adr-written-lanes.md, as bytes.
    #[test]
    fn a_result_is_as_wide_as_the_bytes_the_function_computed() {
        let data = || Byte::Data;
        let zero = || Byte::fill(Fill::Zero);
        // `xor eax, eax`: four computed, four zero-filled.
        let xor = [
            data(),
            data(),
            data(),
            data(),
            zero(),
            zero(),
            zero(),
            zero(),
        ];
        assert_eq!(written_width(&xor, rax()), Some(4));
        // `setg al` over it: still the four bytes the xor computed.
        assert_eq!(written_width(&xor, rax()), Some(4));
        // `setg al` alone: seven bytes as the caller left them.
        let setg: Vec<Byte> = std::iter::once(data())
            .chain((1..8).map(|byte| Byte::fill(at(byte))))
            .collect();
        assert_eq!(written_width(&setg, rax()), Some(1));
        // `movzx eax, byte`: one computed, the rest zero.
        let movzx: Vec<Byte> = std::iter::once(data())
            .chain((1..8).map(|_| zero()))
            .collect();
        assert_eq!(written_width(&movzx, rax()), Some(1));
        // `mov eax, edi` moves another register's bytes, which is a write.
        let moved: Vec<Byte> = (0..4)
            .map(|byte| Byte::fill(at(0x38 + byte)))
            .chain((4..8).map(|_| zero()))
            .collect();
        assert_eq!(written_width(&moved, rax()), Some(4));
        // Three computed bytes are read as the four-byte lane holding them.
        let three = [
            data(),
            data(),
            data(),
            zero(),
            zero(),
            zero(),
            zero(),
            zero(),
        ];
        assert_eq!(written_width(&three, rax()), Some(4));
        // Nothing written: no width at all, rather than the carrier's.
        let untouched: Vec<Byte> = (0..8).map(|byte| Byte::fill(at(byte))).collect();
        assert_eq!(written_width(&untouched, rax()), None);
    }

    #[test]
    fn paths_join_by_the_ways_a_byte_was_not_computed() {
        let zero = Byte::fill(Fill::Zero);
        let kept = Byte::fill(at(5));
        // Zero-filled on one path and untouched on another: computed on none.
        let both = zero.join(&kept);
        assert_eq!(both, Byte::Filled(vec![Fill::Zero, at(5)]));
        assert!(!both.written_at(Some(RegisterByte {
            space: CanonicalStorageSpace::Register,
            address: 5
        })));
        assert_eq!(both.join(&Byte::Data), Byte::Data);
        assert_eq!(both.join(&both), both);
        let many = (0..=MOST_WAYS as u64)
            .map(|byte| Byte::fill(at(byte)))
            .fold(Byte::NONE, |held, byte| held.join(&byte));
        assert_eq!(many, Byte::Data);
    }
}
