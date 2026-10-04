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
    /// The zero the architecture writes above a narrower write of the same
    /// register: the upper half of `RAX` after a write of `EAX`.
    Zero,
    /// The sign the architecture copies above a narrower write.
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
    /// Written by an instruction that states the extension -- `movzx eax,
    /// al`, `movsx eax, al` -- as part of its destination: the zero or the
    /// sign above its source. A caller reads these bytes as the value.
    Widened { sign: bool },
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
            (Self::Widened { sign: a }, Self::Widened { sign: b }) if a == b => self.clone(),
            (Self::Widened { .. }, _) | (_, Self::Widened { .. }) => Self::Data,
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
            Self::Data | Self::Widened { .. } => true,
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

    /// Whether nothing was recorded: the function was never prepared.
    pub fn is_empty(&self) -> bool {
        self.by_op.is_empty()
    }

    /// Take the record of a function before anything rewrites it.
    pub fn capture(function: &SSAFunction) -> Self {
        let mut by_var = BTreeMap::<SSAVar, Bytes>::new();
        let mut by_op = BTreeMap::<OpId, Bytes>::new();
        let writes = Writes::of(function);
        // Until nothing changes: a loop's phi reads a value defined below it.
        while function
            .named_blocks()
            .iter()
            .fold(false, |changed, block| {
                changed | capture_block(function, &writes, block, &mut by_var, &mut by_op)
            })
        {}
        Self { by_op }
    }
}

/// One pass over a block's phis and operations; whether any record moved.
fn capture_block(
    function: &SSAFunction,
    writes: &Writes,
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
            let convention = by_convention(function, writes, op);
            let bytes = transfer(op, convention, crate::op::var_facts, |var| {
                read(function, by_var, var)
            });
            changed |= settle(by_var, by_op, id, dst, bytes);
        }
    }
    changed
}

/// Whether a zero extension is the architecture's rather than the
/// program's: it doubles a lane into the register that lane is the low half
/// of, and nothing later in the same instruction extends what it wrote.
///
/// The 64-bit machines this engine reads zero the upper half of a register
/// on a write of its lower half. `xor eax, eax` lifts to
/// `EAX = EAX ^ EAX; RAX = zext(EAX)`, a `cmovle eax, ecx` to
/// `RAX = zext(EAX); EAX = SELECT(..)`, and an arm64 `add w0, w0, #1` to
/// `tmp = W0 + 1; X0 = zext(tmp)`: each widening by half is the convention.
/// `movzx eax, al` lifts to `EAX = zext(AL); RAX = zext(EAX)` and
/// `movzx eax, word [m]` to `EAX = zext(tmp); RAX = zext(EAX)`: the first
/// extension of each is followed by the convention's, so it is the
/// instruction's own, writing its whole destination operand. Where one
/// operation does both -- arm64's `cset w0` is `X0 = zext(ZR)`, `ldrb` is
/// `X0 = zext(tmp)` -- the P-code cannot tell the stated part from the
/// conventional one, and the whole is taken as written: too wide is a
/// claim the caller can still check, too narrow drops bytes it reads. A
/// sign extension is always the program's.
fn by_convention(function: &SSAFunction, writes: &Writes, op: &SSAOp) -> bool {
    let SSAOp::IntZExt { dst, src } = op else {
        return false;
    };
    let register = function
        .canonical_storage_for_var(dst)
        .is_some_and(|storage| storage.space == CanonicalStorageSpace::Register);
    let halves = src.size.checked_mul(2) == Some(dst.size);
    let outermost = !writes.extended.contains(dst);
    register && halves && outermost
}

/// Every value an extension in the same instruction as its definition
/// widens again, as lifted.
struct Writes {
    extended: std::collections::BTreeSet<SSAVar>,
}

impl Writes {
    fn of(function: &SSAFunction) -> Self {
        let arena = function.arena();
        let mut definers = BTreeMap::new();
        let mut extended = std::collections::BTreeSet::new();
        for (id, op) in function
            .named_blocks()
            .iter()
            .flat_map(|block| block.sited())
        {
            if let SSAOp::IntZExt { src, .. } | SSAOp::IntSExt { src, .. } = op
                && let Some(definer) = definers.get(src)
                && arena.instruction(*definer).is_some()
                && arena.instruction(*definer) == arena.instruction(id)
            {
                extended.insert(src.clone());
            }
            if let Some(dst) = op.dst() {
                definers.insert(dst.clone(), id);
            }
        }
        Self { extended }
    }
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
///
/// `facts` gives an operand's width and constant bits (`op::var_facts` for a
/// function's operations); `input` gives the bytes of a source.
pub(crate) fn transfer<V>(
    op: &SSAOp<V>,
    convention: bool,
    facts: impl Fn(&V) -> (u32, Option<u64>),
    input: impl Fn(&V) -> Bytes,
) -> Bytes {
    let size = op.dst().map_or(0, |dst| facts(dst).0 as usize);
    let fill = |sign| match (convention, sign) {
        (true, false) => Byte::fill(Fill::Zero),
        (true, true) => Byte::fill(Fill::Sign),
        (false, sign) => Byte::Widened { sign },
    };
    let mut out = match op {
        SSAOp::Copy { src, .. } => input(src),
        SSAOp::IntZExt { src, .. } => extended(input(src), size, fill(false)),
        SSAOp::IntSExt { src, .. } => extended(input(src), size, fill(true)),
        SSAOp::Subpiece { src, offset, .. } => {
            input(src).into_iter().skip(*offset as usize).collect()
        }
        SSAOp::Piece { hi, lo, .. } => {
            let mut bytes = input(lo);
            bytes.extend(input(hi));
            bytes
        }
        SSAOp::Insert(insert) => match lane(facts(&insert.position).1) {
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
fn extended(mut bytes: Bytes, size: usize, fill: Byte) -> Bytes {
    if bytes.len() < size {
        bytes.resize(size, fill);
    }
    bytes
}

/// The first byte an INSERT writes, where its position is a byte-aligned
/// constant.
fn lane(position: Option<u64>) -> Option<usize> {
    let bits = position?;
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

/// Whether a result of `width` bytes is signed by what wrote it: its top
/// bytes are a sign extension the instruction stated (`movsx eax, al`), or
/// the byte above it is the architecture's sign fill on every path.
pub fn signed(bytes: &[Byte], width: u32) -> bool {
    let width = (width as usize).min(bytes.len());
    let top = &bytes[..width];
    let stated = top.last() == Some(&Byte::Widened { sign: true })
        && top
            .iter()
            .rev()
            .take_while(|byte| matches!(byte, Byte::Widened { .. }))
            .all(|byte| *byte == Byte::Widened { sign: true });
    stated || bytes.get(width) == Some(&Byte::Filled(vec![Fill::Sign]))
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

    /// An extension the instruction states writes its destination whole; a
    /// sign extension it states makes the value signed.
    #[test]
    fn a_stated_extension_writes_its_destination_and_says_its_sign() {
        let zero = || Byte::fill(Fill::Zero);
        let widened = |sign| Byte::Widened { sign };
        // `movzx eax, al` then the 32-bit write's convention.
        let movzx = [
            Byte::Data,
            widened(false),
            widened(false),
            widened(false),
            zero(),
            zero(),
            zero(),
            zero(),
        ];
        assert_eq!(written_width(&movzx, rax()), Some(4));
        assert!(!signed(&movzx, 4));
        // `movsx eax, al`: four bytes, signed.
        let movsx = [
            Byte::Data,
            widened(true),
            widened(true),
            widened(true),
            zero(),
            zero(),
            zero(),
            zero(),
        ];
        assert_eq!(written_width(&movsx, rax()), Some(4));
        assert!(signed(&movsx, 4));
        // A stated extension joined with data on another path is data.
        assert_eq!(widened(true).join(&Byte::Data), Byte::Data);
        assert_eq!(widened(true).join(&widened(false)), Byte::Data);
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
