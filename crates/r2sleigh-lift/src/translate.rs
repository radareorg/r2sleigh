//! Operand helpers for the canonical libsla P-code translator.
//!
//! Opcode dispatch lives in `disasm`; these helpers validate the common operand
//! shapes used by its translation arms.

use r2il::{R2ILOp, SpaceId, Varnode};

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
}

impl std::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TranslateError::MissingOutput(op) => write!(f, "{} requires an output", op),
            TranslateError::MissingInput(op, idx) => {
                write!(f, "{} requires input at index {}", op, idx)
            }
            TranslateError::InvalidSpace(idx) => write!(f, "Invalid space index: {}", idx),
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
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        let R2ILOp::Copy { dst, src } = &op else {
            out.push(op);
            continue;
        };
        if dst.space != SpaceId::Register
            || src.space != SpaceId::Const
            || src.offset != 0
            || dst.size.is_power_of_two()
        {
            out.push(op);
            continue;
        }
        let (mut at, end) = (dst.offset, dst.offset.saturating_add(u64::from(dst.size)));
        while at < end {
            let aligned = 1u64 << at.trailing_zeros().min(3);
            let piece = aligned.min(1u64 << (end - at).ilog2());
            let size = u32::try_from(piece).expect("at most eight bytes");
            out.push(R2ILOp::Copy {
                dst: Varnode::register(at, size),
                src: Varnode::constant(0, size),
            });
            at += piece;
        }
    }
    out
}

/// Rewrite every direct-address memory operand into an explicit access.
///
/// Sleigh spells a memory operand with a constant address as a varnode in the
/// ram space, and SSA construction would rename that like a register: a read
/// became an undefined variable, and a write a local nothing else could see.
/// A read becomes a load into a fresh temporary, a written output becomes a
/// temporary the operation writes and a store carries out; a copy needs no
/// temporary at all. The code address a direct transfer names, as
/// [`R2ILOp::transfer`] states it, is not a memory operand; a slot an indirect
/// transfer reads its destination from is, and is loaded like any other.
pub fn canonicalize_memory_operands(
    ops: Vec<R2ILOp>,
    address_size: u32,
    next_temp: &mut u64,
) -> Vec<R2ILOp> {
    let mut out = Vec::with_capacity(ops.len());
    let mut temp = |size: u32| {
        let node = Varnode::unique(*next_temp, size);
        *next_temp += u64::from(size).max(1);
        node
    };
    for mut op in ops {
        match &op {
            R2ILOp::Copy { dst, src } if src.space == SpaceId::Ram && dst.space != SpaceId::Ram => {
                out.push(R2ILOp::Load {
                    dst: dst.clone(),
                    space: SpaceId::Ram,
                    addr: Varnode::constant(src.offset, address_size),
                });
                continue;
            }
            R2ILOp::Copy { dst, src } if dst.space == SpaceId::Ram && src.space != SpaceId::Ram => {
                out.push(R2ILOp::Store {
                    space: SpaceId::Ram,
                    addr: Varnode::constant(dst.offset, address_size),
                    val: src.clone(),
                });
                continue;
            }
            _ => {}
        }
        let code_target = op
            .transfer()
            .filter(|transfer| transfer.direct)
            .map(|transfer| transfer.target.clone());
        for input in op.inputs_mut() {
            if input.space != SpaceId::Ram || code_target.as_ref() == Some(&*input) {
                continue;
            }
            let loaded = temp(input.size);
            out.push(R2ILOp::Load {
                dst: loaded.clone(),
                space: SpaceId::Ram,
                addr: Varnode::constant(input.offset, address_size),
            });
            *input = loaded;
        }
        let written = op
            .output_mut()
            .filter(|output| output.space == SpaceId::Ram)
            .map(|output| {
                let address = output.offset;
                let value = temp(output.size);
                *output = value.clone();
                (address, value)
            });
        out.push(op);
        if let Some((address, val)) = written {
            out.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::constant(address, address_size),
                val,
            });
        }
    }
    out
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
