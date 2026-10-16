//! Operand helpers for the canonical libsla P-code translator.
//!
//! Opcode dispatch lives in `disasm`; these helpers validate the common operand
//! shapes used by its translation arms.

use std::collections::BTreeMap;

use r2il::{R2ILOp, SpaceId, Varnode};

use crate::plan::Plan;

/// A validated view of operands from a libsla P-code instruction.
pub trait PcodeSource {
    /// Get the output varnode, if any.
    fn output(&self) -> Option<Varnode>;

    /// Get the input varnode at the given index, if any.
    fn input(&self, idx: usize) -> Option<Varnode>;

    /// Get a raw input value (for space IDs, constants) at the given index.
    fn input_raw_offset(&self, idx: usize) -> Option<u64>;

    /// Get the number of input operands.
    fn input_count(&self) -> usize;

    /// Get the space ID from a space index (for LOAD/STORE operations).
    fn space_from_index(&self, idx: u64) -> Option<SpaceId>;
}

/// Errors that can occur during translation.
#[derive(Debug, Clone)]
pub enum TranslateError {
    MissingOutput(&'static str),
    MissingInput(&'static str, usize),
    InvalidSpace(u64),
    /// A unique read or written across the bytes of more than one write.
    UniqueStraddles(Varnode),
}

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranslateError::MissingOutput(op) => write!(f, "{} requires an output", op),
            TranslateError::MissingInput(op, idx) => {
                write!(f, "{} requires input at index {}", op, idx)
            }
            TranslateError::InvalidSpace(idx) => write!(f, "Invalid space index: {}", idx),
            TranslateError::UniqueStraddles(node) => write!(
                f,
                "unique {:#x}:{} straddles the temporaries the instruction wrote",
                node.offset, node.size
            ),
        }
    }
}

impl std::error::Error for TranslateError {}

/// Result type for translation operations.
pub type Result<T> = std::result::Result<T, TranslateError>;

/// Helper to require an output varnode.
pub fn require_output<S: PcodeSource>(source: &S, name: &'static str) -> Result<Varnode> {
    source.output().ok_or(TranslateError::MissingOutput(name))
}

/// Helper to require an input varnode at the given index.
pub fn require_input<S: PcodeSource>(
    source: &S,
    idx: usize,
    name: &'static str,
) -> Result<Varnode> {
    source
        .input(idx)
        .ok_or(TranslateError::MissingInput(name, idx))
}

/// Helper for unary operations (one input, one output).
pub fn translate_unary<S: PcodeSource, F>(source: &S, name: &'static str, f: F) -> Result<R2ILOp>
where
    F: FnOnce(Varnode, Varnode) -> R2ILOp,
{
    let dst = require_output(source, name)?;
    let src = require_input(source, 0, name)?;
    Ok(f(dst, src))
}

/// Helper for binary operations (two inputs, one output).
pub fn translate_binary<S: PcodeSource, F>(source: &S, name: &'static str, f: F) -> Result<R2ILOp>
where
    F: FnOnce(Varnode, Varnode, Varnode) -> R2ILOp,
{
    let dst = require_output(source, name)?;
    let a = require_input(source, 0, name)?;
    let b = require_input(source, 1, name)?;
    Ok(f(dst, a, b))
}

/// Translate a LOAD operation.
pub fn translate_load<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let dst = require_output(source, "LOAD")?;
    let space_idx = source
        .input_raw_offset(0)
        .ok_or(TranslateError::MissingInput("LOAD", 0))?;
    let addr = require_input(source, 1, "LOAD")?;
    let space = source
        .space_from_index(space_idx)
        .ok_or(TranslateError::InvalidSpace(space_idx))?;
    Ok(R2ILOp::Load { dst, space, addr })
}

/// Translate a STORE operation.
pub fn translate_store<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let space_idx = source
        .input_raw_offset(0)
        .ok_or(TranslateError::MissingInput("STORE", 0))?;
    let addr = require_input(source, 1, "STORE")?;
    let val = require_input(source, 2, "STORE")?;
    let space = source
        .space_from_index(space_idx)
        .ok_or(TranslateError::InvalidSpace(space_idx))?;
    Ok(R2ILOp::Store { space, addr, val })
}

/// Translate a CBRANCH operation.
///
/// P-code spec: CBRANCH(dest, cond) - destination first, condition second.
pub fn translate_cbranch<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let target = require_input(source, 0, "CBRANCH")?;
    let cond = require_input(source, 1, "CBRANCH")?;
    Ok(R2ILOp::CBranch { target, cond })
}

/// Translate a SUBPIECE operation.
pub fn translate_subpiece<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let dst = require_output(source, "SUBPIECE")?;
    let src = require_input(source, 0, "SUBPIECE")?;
    let offset = source
        .input_raw_offset(1)
        .ok_or(TranslateError::MissingInput("SUBPIECE", 1))? as u32;
    Ok(R2ILOp::Subpiece { dst, src, offset })
}

/// Translate a PTRADD operation.
pub fn translate_ptradd<S: PcodeSource>(source: &S) -> Result<R2ILOp> {
    let dst = require_output(source, "PTRADD")?;
    let base = require_input(source, 0, "PTRADD")?;
    let index = require_input(source, 1, "PTRADD")?;
    let element_size = source
        .input_raw_offset(2)
        .ok_or(TranslateError::MissingInput("PTRADD", 2))? as u32;
    Ok(R2ILOp::PtrAdd {
        dst,
        base,
        index,
        element_size,
    })
}

/// A zero written to a register range no integer is as wide as (AArch64's `zext_zb` writes
/// `reg[8,56] = 0`) as the aligned power-of-two pieces it covers: the same bytes, the same zeros.
pub fn split_odd_register_zeroes(ops: Vec<R2ILOp>) -> Vec<R2ILOp> {
    let mut plan = Plan::new();
    for (index, op) in ops.iter().enumerate() {
        let R2ILOp::Copy { dst, src } = op else {
            continue;
        };
        if dst.space != SpaceId::Register
            || src.space != SpaceId::Const
            || src.offset != 0
            || dst.size.is_power_of_two()
        {
            continue;
        }
        let (mut at, end) = (dst.offset, dst.offset.saturating_add(u64::from(dst.size)));
        let mut pieces = Vec::new();
        while at < end {
            let aligned = 1u64 << at.trailing_zeros().min(3);
            let piece = aligned.min(1u64 << (end - at).ilog2());
            let size = u32::try_from(piece).expect("at most eight bytes");
            pieces.push(R2ILOp::Copy {
                dst: Varnode::register(at, size),
                src: Varnode::constant(0, size),
            });
            at += piece;
        }
        plan.expand(index, pieces);
    }
    plan.apply(ops)
}

/// Read each unique where it was written (gotcha 2), GP-5581's pieces in place: a piece read is its
/// `Subpiece`, one written is inserted into its holder, a straddle refuses, an unwritten read stays.
pub fn whole_unique_reads(
    ops: Vec<R2ILOp>,
    big_endian: bool,
    next_temp: &mut u64,
) -> Result<Vec<R2ILOp>> {
    // Live writes by first byte; they never overlap, so the one before a read is its only holder.
    let mut live: BTreeMap<u64, u32> = BTreeMap::new();
    let mut plan = Plan::new();
    for (index, op) in ops.iter().enumerate() {
        let mut pieces: Vec<(Varnode, Varnode, u32)> = Vec::new();
        for read in op
            .inputs()
            .into_iter()
            .filter(|v| v.space == SpaceId::Unique)
        {
            if let Some((holder, shift)) = holder_of(&live, read, big_endian)?
                && !pieces.iter().any(|(seen, ..)| seen == read)
            {
                pieces.push((read.clone(), holder, shift));
            }
        }
        let mut placed =
            (!pieces.is_empty()).then(|| take_pieces(&mut plan, index, op, pieces, next_temp));
        if let Some(output) = op.output().filter(|v| v.space == SpaceId::Unique) {
            match holder_of(&live, output, big_endian) {
                Ok(Some((holder, shift))) => {
                    let piece = Varnode::unique(*next_temp, output.size);
                    *next_temp += u64::from(output.size).max(1);
                    let mut op = placed.take().unwrap_or_else(|| op.clone());
                    *op.output_mut().expect("a unique output") = piece.clone();
                    placed = Some(op);
                    plan.insert_after(index, insert_piece(piece, holder, shift, next_temp));
                }
                _ => note_write(&mut live, output)?,
            }
        }
        if let Some(op) = placed {
            plan.replace(index, op);
        }
    }
    Ok(plan.apply(ops))
}

/// The live write holding `read` strictly inside it, and the piece's offset from its low end.
fn holder_of(
    live: &BTreeMap<u64, u32>,
    read: &Varnode,
    big_endian: bool,
) -> Result<Option<(Varnode, u32)>> {
    let read_end = read.offset + u64::from(read.size);
    let straddles = || Err(TranslateError::UniqueStraddles(read.clone()));
    let before = live.range(..=read.offset).next_back();
    let Some((&start, &size)) =
        before.filter(|(start, size)| **start + u64::from(**size) > read.offset)
    else {
        // Nothing holds its first byte; a write beginning inside it would be straddled.
        return match live.range(read.offset..read_end).next() {
            Some(_) => straddles(),
            None => Ok(None),
        };
    };
    let end = start + u64::from(size);
    if read_end > end {
        return straddles();
    }
    if (start, size) == (read.offset, read.size) {
        return Ok(None);
    }
    let shift = if big_endian {
        end - read_end
    } else {
        read.offset - start
    };
    let shift = u32::try_from(shift).expect("a piece lies inside a temporary");
    Ok(Some((Varnode::unique(start, size), shift)))
}

/// The operation reading pieces: a copy of one is the `SUBPIECE` GP-5581 folded, any other takes
/// its pieces first.
fn take_pieces(
    plan: &mut Plan,
    index: usize,
    op: &R2ILOp,
    pieces: Vec<(Varnode, Varnode, u32)>,
    next_temp: &mut u64,
) -> R2ILOp {
    if let (R2ILOp::Copy { dst, .. }, [(_, src, offset)]) = (op, pieces.as_slice()) {
        return R2ILOp::Subpiece {
            dst: dst.clone(),
            src: src.clone(),
            offset: *offset,
        };
    }
    let mut op = op.clone();
    for (read, src, offset) in pieces {
        let piece = Varnode::unique(*next_temp, read.size);
        *next_temp += u64::from(read.size).max(1);
        plan.insert_before(
            index,
            [R2ILOp::Subpiece {
                dst: piece.clone(),
                src,
                offset,
            }],
        );
        for input in op.inputs_mut().into_iter().filter(|input| **input == read) {
            *input = piece.clone();
        }
    }
    op
}

/// `holder` with its bytes from `shift` replaced by `piece`: a write GP-5581 made to a piece in
/// place, rebuilt as the holder's bytes above it, the piece and the bytes below it.
fn insert_piece(piece: Varnode, holder: Varnode, shift: u32, next_temp: &mut u64) -> Vec<R2ILOp> {
    let mut temp = |size: u32| {
        let node = Varnode::unique(*next_temp, size);
        *next_temp += u64::from(size);
        node
    };
    let mut ops = Vec::with_capacity(4);
    let above = holder.size - shift - piece.size;
    let mut value = piece;
    if above > 0 {
        let high = temp(above);
        ops.push(R2ILOp::Subpiece {
            dst: high.clone(),
            src: holder.clone(),
            offset: shift + value.size,
        });
        let joined = temp(above + value.size);
        ops.push(R2ILOp::Piece {
            dst: joined.clone(),
            hi: high,
            lo: value,
        });
        value = joined;
    }
    if shift > 0 {
        let low = temp(shift);
        ops.push(R2ILOp::Subpiece {
            dst: low.clone(),
            src: holder.clone(),
            offset: 0,
        });
        ops.push(R2ILOp::Piece {
            dst: holder,
            hi: value,
            lo: low,
        });
    } else {
        ops.push(R2ILOp::Copy {
            dst: holder,
            src: value,
        });
    }
    ops
}

/// Record a unique write; one overlapping a live write it does not replace exactly refuses.
fn note_write(live: &mut BTreeMap<u64, u32>, output: &Varnode) -> Result<()> {
    let end = output.offset + u64::from(output.size);
    let overlapped = live
        .range(..end)
        .next_back()
        .filter(|&(&start, &size)| start + u64::from(size) > output.offset);
    match overlapped {
        Some((&start, &size)) if (start, size) != (output.offset, output.size) => {
            Err(TranslateError::UniqueStraddles(output.clone()))
        }
        _ => {
            live.insert(output.offset, output.size);
            Ok(())
        }
    }
}

/// A copy between ram and anything else is one `Load` or `Store`, which needs no temporary.
fn copy_through_memory(op: &R2ILOp, address_size: u32) -> Option<R2ILOp> {
    let R2ILOp::Copy { dst, src } = op else {
        return None;
    };
    let at = |node: &Varnode| Varnode::constant(node.offset, address_size);
    match (src.space, dst.space) {
        (SpaceId::Ram, space) if space != SpaceId::Ram => Some(R2ILOp::Load {
            dst: dst.clone(),
            space: SpaceId::Ram,
            addr: at(src),
        }),
        (space, SpaceId::Ram) if space != SpaceId::Ram => Some(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: at(dst),
            val: src.clone(),
        }),
        _ => None,
    }
}

/// Each ram operand at a constant address as an explicit Load or Store, a direct transfer's target
/// excepted. Why: doc/adr-verified-layers.md D34.
pub fn canonicalize_memory_operands(
    ops: Vec<R2ILOp>,
    address_size: u32,
    next_temp: &mut u64,
) -> Vec<R2ILOp> {
    let mut plan = Plan::new();
    let mut temp = |size: u32| {
        let node = Varnode::unique(*next_temp, size);
        *next_temp += u64::from(size).max(1);
        node
    };
    let at = |node: u64| Varnode::constant(node, address_size);
    let in_ram = |node: &Varnode| node.space == SpaceId::Ram;
    for (index, op) in ops.iter().enumerate() {
        if let Some(access) = copy_through_memory(op, address_size) {
            plan.replace(index, access);
            continue;
        }
        if !op.output().is_some_and(in_ram) && !op.inputs().into_iter().any(in_ram) {
            continue;
        }
        let mut op = op.clone();
        let mut touched = false;
        let code_target = op
            .transfer()
            .filter(|transfer| transfer.direct)
            .map(|transfer| transfer.target.clone());
        for input in op.inputs_mut() {
            if !in_ram(input) || code_target.as_ref() == Some(&*input) {
                continue;
            }
            touched = true;
            let loaded = temp(input.size);
            plan.insert_before(
                index,
                [R2ILOp::Load {
                    dst: loaded.clone(),
                    space: SpaceId::Ram,
                    addr: at(input.offset),
                }],
            );
            *input = loaded;
        }
        if let Some(output) = op.output_mut().filter(|output| in_ram(output)) {
            touched = true;
            let address = output.offset;
            let val = temp(output.size);
            *output = val.clone();
            plan.insert_after(
                index,
                [R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: at(address),
                    val,
                }],
            );
        }
        if touched {
            plan.replace(index, op);
        }
    }
    plan.apply(ops)
}

/// A plain load of an address this instruction already loaded or stored, nothing written to the address,
/// value or memory between, reads the value held: one access Sleigh spells as several. O(n·k).
pub fn forward_repeated_loads(ops: Vec<R2ILOp>) -> Vec<R2ILOp> {
    let (mut loads, mut stores) = (0, 0);
    for op in &ops {
        loads += usize::from(matches!(op, R2ILOp::Load { .. }));
        stores += usize::from(matches!(op, R2ILOp::Store { .. }));
    }
    // Nothing to forward without a second load, or a load after a store.
    if loads == 0 || (loads == 1 && stores == 0) || ops.iter().any(R2ILOp::is_local_branch) {
        return ops;
    }
    // Each (space, address, size) whose value a varnode still holds.
    let mut held: Vec<(SpaceId, Varnode, Varnode)> = Vec::new();
    let mut plan = Plan::new();
    for (index, op) in ops.iter().enumerate() {
        match op {
            R2ILOp::Load { dst, space, addr } => {
                match forward_load(&mut held, dst.clone(), *space, addr.clone()) {
                    None => plan.remove(index),
                    Some(R2ILOp::Load { .. }) => {}
                    Some(copy) => plan.replace(index, copy),
                }
            }
            R2ILOp::Store { space, addr, val } => {
                // Another address may be the same bytes, so only this store's value stays known.
                held.clear();
                held.push((*space, addr.clone(), val.clone()));
            }
            op if op.is_speculatable_value() => {
                if let Some(written) = op.output() {
                    forget(&mut held, written);
                }
            }
            _ => held.clear(),
        }
    }
    plan.apply(ops)
}

/// One load where `held` may already know its value: the load, a copy of the value, or nothing.
fn forward_load(
    held: &mut Vec<(SpaceId, Varnode, Varnode)>,
    dst: Varnode,
    space: SpaceId,
    addr: Varnode,
) -> Option<R2ILOp> {
    let known = held
        .iter()
        .find(|(at, address, value)| *at == space && *address == addr && value.size == dst.size)
        .map(|(.., value)| value.clone());
    if known.as_ref() == Some(&dst) {
        return None;
    }
    forget(held, &dst);
    if let Some(value) = known {
        return Some(R2ILOp::Copy { dst, src: value });
    }
    if !overlaps(&dst, &addr) {
        held.push((space, addr.clone(), dst.clone()));
    }
    Some(R2ILOp::Load { dst, space, addr })
}

fn overlaps(a: &Varnode, b: &Varnode) -> bool {
    a.space == b.space
        && a.offset < b.offset.saturating_add(u64::from(b.size))
        && b.offset < a.offset.saturating_add(u64::from(a.size))
}

/// Drop what `written` overwrites: a held value, or the address it was read from.
fn forget(held: &mut Vec<(SpaceId, Varnode, Varnode)>, written: &Varnode) {
    held.retain(|(_, address, value)| !overlaps(address, written) && !overlaps(value, written));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `addv b0` zeroes Z0's bytes 1 to 31; the 7 bytes above B0 become one, two and four.
    #[test]
    fn a_zero_over_an_odd_register_range_is_aligned_pieces() {
        let split = split_odd_register_zeroes(vec![R2ILOp::Copy {
            dst: Varnode::register(0x5001, 7),
            src: Varnode::constant(0, 7),
        }]);
        let pieces = split
            .iter()
            .map(|op| match op {
                R2ILOp::Copy { dst, src } => (dst.offset, dst.size, src.offset, src.size),
                other => panic!("{other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            pieces,
            [(0x5001, 1, 0, 1), (0x5002, 2, 0, 2), (0x5004, 4, 0, 4)]
        );
        let wide = R2ILOp::Copy {
            dst: Varnode::register(0x5008, 8),
            src: Varnode::constant(0, 8),
        };
        assert_eq!(split_odd_register_zeroes(vec![wide]).len(), 1);
    }

    fn load(dst: Varnode, addr: Varnode) -> R2ILOp {
        R2ILOp::Load {
            dst,
            space: SpaceId::Ram,
            addr,
        }
    }

    /// `add dword [rbp - 0xdc], 0x1`: Sleigh loads the cell for CF, OF, AF, the sum, then SF, ZF
    /// and PF after the store; the machine reads it once and the flags read the stored value.
    #[test]
    fn a_repeated_load_of_one_address_reads_the_value_held() {
        let (address, cell) = (Varnode::unique(0x9000, 8), Varnode::unique(0xd300, 4));
        let flag = |offset| Varnode::register(offset, 1);
        let one = Varnode::constant(1, 4);
        let ops = forward_repeated_loads(vec![
            load(cell.clone(), address.clone()),
            R2ILOp::IntCarry {
                dst: flag(0x200),
                a: cell.clone(),
                b: one.clone(),
            },
            load(cell.clone(), address.clone()),
            R2ILOp::IntAdd {
                dst: cell.clone(),
                a: cell.clone(),
                b: one,
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: address.clone(),
                val: cell.clone(),
            },
            load(cell.clone(), address),
            R2ILOp::IntSLess {
                dst: flag(0x207),
                a: cell,
                b: Varnode::constant(0, 4),
            },
        ]);
        let loads = ops
            .iter()
            .filter(|op| matches!(op, R2ILOp::Load { .. }))
            .count();
        assert_eq!((ops.len(), loads), (5, 1), "{ops:?}");
    }

    /// A load into its own address register, a store elsewhere and a value overwritten between
    /// each leave the next load in place.
    #[test]
    fn a_load_after_its_address_value_or_memory_changed_stays() {
        let (address, value) = (Varnode::register(0x38, 8), Varnode::unique(0x100, 8));
        let other = Varnode::register(0x30, 8);
        for between in [
            R2ILOp::Copy {
                dst: address.clone(),
                src: other.clone(),
            },
            R2ILOp::Copy {
                dst: value.clone(),
                src: other.clone(),
            },
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: other.clone(),
                val: other,
            },
        ] {
            let ops = forward_repeated_loads(vec![
                load(value.clone(), address.clone()),
                between,
                load(value.clone(), address.clone()),
            ]);
            let loads = ops
                .iter()
                .filter(|op| matches!(op, R2ILOp::Load { .. }))
                .count();
            assert_eq!(loads, 2, "{ops:?}");
        }
        let chased = vec![
            load(address.clone(), address.clone()),
            load(address.clone(), address),
        ];
        assert_eq!(forward_repeated_loads(chased.clone()), chased);
    }

    fn pieces(ops: Vec<R2ILOp>, big_endian: bool) -> Result<Vec<R2ILOp>> {
        whole_unique_reads(ops, big_endian, &mut 0x1000)
    }

    /// `XMM0_Qb = COPY uniq:0x88[8]` of a 16-byte load at 0x80 is `SUBPIECE(uniq:0x80, 8)` again.
    #[test]
    fn a_copy_of_a_piece_is_a_subpiece_of_the_write() {
        let wide = Varnode::unique(0x80, 16);
        let ops = pieces(
            vec![
                R2ILOp::Copy {
                    dst: wide.clone(),
                    src: Varnode::register(0x1200, 16),
                },
                R2ILOp::Copy {
                    dst: Varnode::register(0x1100, 8),
                    src: Varnode::unique(0x80, 8),
                },
                R2ILOp::Copy {
                    dst: Varnode::register(0x1108, 8),
                    src: Varnode::unique(0x88, 8),
                },
            ],
            false,
        )
        .expect("pieces of one write");
        let offsets = ops[1..]
            .iter()
            .map(|op| match op {
                R2ILOp::Subpiece { src, offset, .. } => (src.clone(), *offset),
                other => panic!("{other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(offsets, [(wide.clone(), 0), (wide, 8)]);
    }

    /// Big-endian `result:4` of an 8-byte `result` at 0x80 is its bytes 0x84..0x88, the low half.
    #[test]
    fn a_big_endian_piece_counts_from_the_low_end() {
        let ops = pieces(
            vec![
                R2ILOp::Copy {
                    dst: Varnode::unique(0x80, 8),
                    src: Varnode::register(0x20, 8),
                },
                R2ILOp::IntSExt {
                    dst: Varnode::register(0x30, 8),
                    src: Varnode::unique(0x84, 4),
                },
            ],
            true,
        )
        .expect("a piece of one write");
        let [
            _,
            R2ILOp::Subpiece { dst, offset, .. },
            R2ILOp::IntSExt { src, .. },
        ] = ops.as_slice()
        else {
            panic!("{ops:?}");
        };
        assert_eq!((*offset, dst), (0, src));
    }

    /// `stxrb`'s skip over `*addr = tmp:1` still lands past the store once the piece is taken.
    #[test]
    fn a_skip_over_a_piece_lands_where_it_did() {
        let ops = pieces(
            vec![
                R2ILOp::Copy {
                    dst: Varnode::unique(0x80, 4),
                    src: Varnode::register(0x20, 4),
                },
                R2ILOp::CBranch {
                    target: Varnode::constant(2, 4),
                    cond: Varnode::unique(0x90, 1),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: Varnode::register(0x28, 8),
                    val: Varnode::unique(0x80, 1),
                },
                R2ILOp::Copy {
                    dst: Varnode::register(0x30, 1),
                    src: Varnode::constant(0, 1),
                },
            ],
            false,
        )
        .expect("a piece of one write");
        let R2ILOp::CBranch { target, .. } = &ops[1] else {
            panic!("{ops:?}");
        };
        assert!(matches!(ops[2], R2ILOp::Subpiece { .. }));
        assert_eq!(
            target.offset, 3,
            "the skip lands on the copy after the store"
        );
    }

    #[test]
    fn a_read_across_two_writes_refuses() {
        let write = |offset| R2ILOp::Copy {
            dst: Varnode::unique(offset, 4),
            src: Varnode::constant(0, 4),
        };
        let straddle = R2ILOp::Copy {
            dst: Varnode::register(0x20, 4),
            src: Varnode::unique(0x82, 4),
        };
        assert!(matches!(
            pieces(vec![write(0x80), write(0x84), straddle], false),
            Err(TranslateError::UniqueStraddles(_))
        ));
        assert!(matches!(
            pieces(vec![write(0x80), write(0x82)], false),
            Err(TranslateError::UniqueStraddles(_))
        ));
    }

    /// GP-7027's MOVBE: `dest[8,8] = ..` into a live `dest:4` rebuilds `dest` around the byte.
    #[test]
    fn a_piece_written_into_a_write_is_inserted_into_it() {
        let dest = Varnode::unique(0x80, 4);
        let writes = vec![
            R2ILOp::Copy {
                dst: dest.clone(),
                src: Varnode::constant(0x1122_3344, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x81, 1),
                src: Varnode::register(0, 1),
            },
            R2ILOp::Copy {
                dst: Varnode::register(0x20, 4),
                src: dest.clone(),
            },
        ];
        // Byte 0x81 is one above the low end little-endian, two above it big-endian.
        for (big_endian, shift) in [(false, 1), (true, 2)] {
            let ops = pieces(writes.clone(), big_endian).expect("a piece inside one write");
            let [
                _,
                R2ILOp::Copy { dst: piece, .. },
                R2ILOp::Subpiece {
                    src: above,
                    offset: high,
                    ..
                },
                R2ILOp::Piece { lo, .. },
                R2ILOp::Subpiece {
                    src: below,
                    offset: 0,
                    dst: low,
                },
                R2ILOp::Piece {
                    dst, lo: low_again, ..
                },
                R2ILOp::Copy { src: read, .. },
            ] = ops.as_slice()
            else {
                panic!("{ops:?}");
            };
            assert_eq!((*high, low.size), (shift + 1, shift));
            assert_eq!((lo, low_again), (piece, low));
            assert_eq!((above, below, dst, read), (&dest, &dest, &dest, &dest));
        }
        let overlapping = vec![
            R2ILOp::Copy {
                dst: dest,
                src: Varnode::constant(0, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::unique(0x83, 2),
                src: Varnode::constant(0, 2),
            },
        ];
        assert!(matches!(
            pieces(overlapping, false),
            Err(TranslateError::UniqueStraddles(_))
        ));
    }

    // Mock implementation for testing
    struct MockPcodeSource {
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    }

    impl PcodeSource for MockPcodeSource {
        fn output(&self) -> Option<Varnode> {
            self.output.clone()
        }

        fn input(&self, idx: usize) -> Option<Varnode> {
            self.inputs.get(idx).cloned()
        }

        fn input_raw_offset(&self, idx: usize) -> Option<u64> {
            self.inputs.get(idx).map(|v| v.offset)
        }

        fn input_count(&self) -> usize {
            self.inputs.len()
        }

        fn space_from_index(&self, idx: u64) -> Option<SpaceId> {
            Some(match idx {
                0 => SpaceId::Ram,
                1 => SpaceId::Register,
                2 => SpaceId::Unique,
                n => SpaceId::Custom(n as u32),
            })
        }
    }

    #[test]
    fn test_translate_unary() {
        let source = MockPcodeSource {
            output: Some(Varnode::register(0, 8)),
            inputs: vec![Varnode::constant(42, 8)],
        };

        let result = translate_unary(&source, "TEST", |dst, src| R2ILOp::Copy { dst, src });
        assert!(result.is_ok());
    }

    #[test]
    fn test_translate_binary() {
        let source = MockPcodeSource {
            output: Some(Varnode::register(0, 8)),
            inputs: vec![Varnode::register(8, 8), Varnode::constant(1, 8)],
        };

        let result = translate_binary(&source, "TEST", |dst, a, b| R2ILOp::IntAdd { dst, a, b });
        assert!(result.is_ok());
    }

    #[test]
    fn test_cbranch_order() {
        let target = Varnode::constant(0x1000, 8);
        let cond = Varnode::register(0, 1);

        let source = MockPcodeSource {
            output: None,
            inputs: vec![target, cond],
        };

        let result = translate_cbranch(&source).unwrap();
        match result {
            R2ILOp::CBranch { target: t, cond: c } => {
                assert_eq!(t.offset, 0x1000);
                assert!(c.is_register());
            }
            _ => panic!("Expected CBranch"),
        }
    }

    #[test]
    fn test_translate_ptradd() {
        // PTRADD(base, index, element_size)
        // r2il: base + (index * element_size)
        let base = Varnode::register(0, 8);
        let index = Varnode::register(8, 8);
        let element_size = Varnode::constant(4, 8); // 4-byte elements

        let source = MockPcodeSource {
            output: Some(Varnode::register(16, 8)),
            inputs: vec![base, index, element_size],
        };

        let result = translate_ptradd(&source).unwrap();
        match result {
            R2ILOp::PtrAdd {
                dst,
                base: b,
                index: i,
                element_size: sz,
            } => {
                assert_eq!(dst.offset, 16);
                assert_eq!(b.offset, 0);
                assert_eq!(i.offset, 8);
                assert_eq!(sz, 4);
            }
            _ => panic!("Expected PtrAdd"),
        }
    }

    /// `bsf ecx, [rip+d]` reads memory inside its own loop: a label still names its operation,
    /// and one naming a read names the load that now computes it.
    #[test]
    fn a_label_across_a_loaded_operand_keeps_naming_its_operation() {
        let flag = Varnode::register(0x206, 1);
        let label = |offset| Varnode::constant(offset, 4);
        let ops = vec![
            R2ILOp::CBranch {
                target: label(2),
                cond: flag.clone(),
            },
            R2ILOp::IntAdd {
                dst: Varnode::register(0, 4),
                a: Varnode::ram(0x2000, 4),
                b: Varnode::constant(1, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::register(8, 4),
                src: Varnode::register(0, 4),
            },
            R2ILOp::Branch {
                target: label(u64::from(u32::MAX) - 1),
            },
        ];
        let out = canonicalize_memory_operands(ops, 8, &mut 0x100);
        assert!(matches!(out[1], R2ILOp::Load { .. }), "{out:?}");
        assert_eq!(
            out[0],
            R2ILOp::CBranch {
                target: label(3),
                cond: flag
            }
        );
        assert_eq!(
            out[4],
            R2ILOp::Branch {
                target: label(u64::from(u32::MAX) - 2)
            }
        );
    }

    #[test]
    fn memory_operands_become_loads_and_stores() {
        let mut next = 0x100;
        let ops = vec![
            R2ILOp::IntZExt {
                dst: Varnode::register(0, 8),
                src: Varnode::ram(0x18da8, 1),
            },
            R2ILOp::IntAdd {
                dst: Varnode::ram(0x2000, 4),
                a: Varnode::ram(0x2000, 4),
                b: Varnode::constant(1, 4),
            },
            R2ILOp::Copy {
                dst: Varnode::register(8, 8),
                src: Varnode::ram(0x3000, 8),
            },
            R2ILOp::Copy {
                dst: Varnode::ram(0x3008, 8),
                src: Varnode::register(8, 8),
            },
            R2ILOp::Branch {
                target: Varnode::ram(0x4000, 8),
            },
        ];
        let out = canonicalize_memory_operands(ops, 8, &mut next);
        assert_eq!(
            out,
            vec![
                R2ILOp::Load {
                    dst: Varnode::unique(0x100, 1),
                    space: SpaceId::Ram,
                    addr: Varnode::constant(0x18da8, 8),
                },
                R2ILOp::IntZExt {
                    dst: Varnode::register(0, 8),
                    src: Varnode::unique(0x100, 1),
                },
                R2ILOp::Load {
                    dst: Varnode::unique(0x101, 4),
                    space: SpaceId::Ram,
                    addr: Varnode::constant(0x2000, 8),
                },
                R2ILOp::IntAdd {
                    dst: Varnode::unique(0x105, 4),
                    a: Varnode::unique(0x101, 4),
                    b: Varnode::constant(1, 4),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: Varnode::constant(0x2000, 8),
                    val: Varnode::unique(0x105, 4),
                },
                R2ILOp::Load {
                    dst: Varnode::register(8, 8),
                    space: SpaceId::Ram,
                    addr: Varnode::constant(0x3000, 8),
                },
                R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: Varnode::constant(0x3008, 8),
                    val: Varnode::register(8, 8),
                },
                R2ILOp::Branch {
                    target: Varnode::ram(0x4000, 8),
                },
            ]
        );
        assert_eq!(next, 0x109);
    }
}
