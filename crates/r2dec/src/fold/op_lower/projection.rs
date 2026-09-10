//! Pure lowering of source-owned per-use machine projections.
//!
//! This module does not decide which bits a use reads. It only translates the
//! exact [`r2ssa::MachineUseSlice`] selected upstream into a C expression.

use crate::ast::{BinaryOp, CExpr, CType};
use r2rewrite::CValue;
use r2ssa::{MachineCastKind, MachineUseSlice, MachineWriteProjection};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MachineUseProjectionError {
    UnsupportedIntegerWidth(u32),
    IntegerToAddressRequiresType(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MachineWriteProjectionError {
    UnsupportedIntegerWidth(u32),
}

const fn c_integer_width_is_spellable(width_bits: u32) -> bool {
    matches!(width_bits, 8 | 16 | 32 | 64 | 128)
}

pub(super) const fn c_bitvector_width_is_supported(width_bits: u32) -> bool {
    matches!(width_bits, 256 | 512)
}

fn bitvector_helper(name: String, args: Vec<CExpr>) -> CExpr {
    CExpr::call(
        CExpr::External {
            name,
            kind: crate::symbol::ExternalKind::Intrinsic,
        },
        args,
    )
}

fn checked_uint_type(width_bits: u32) -> Result<CType, MachineUseProjectionError> {
    c_integer_width_is_spellable(width_bits)
        .then_some(CType::Int {
            bits: width_bits,
            signedness: r2types::Signedness::Unsigned,
        })
        .ok_or(MachineUseProjectionError::UnsupportedIntegerWidth(
            width_bits,
        ))
}

fn checked_int_type(width_bits: u32) -> Result<CType, MachineUseProjectionError> {
    c_integer_width_is_spellable(width_bits)
        .then_some(CType::Int {
            bits: width_bits,
            signedness: r2types::Signedness::Signed,
        })
        .ok_or(MachineUseProjectionError::UnsupportedIntegerWidth(
            width_bits,
        ))
}

/// Translate one exact upstream slice, given what the base is spelled as.
///
/// A slice selects bits of the carrier: the base is brought to the carrier's
/// unsigned integer, so the shift is logical and a pointer takes its
/// address-width step, then shifted, then narrowed to the selected width;
/// and only then is the source-owned conversion applied. Every step says its
/// conversion through the one emitter, so a base already spelled at the
/// carrier is not converted to it, and reading the whole of a value is not a
/// projection at all: it is the base, with the type the base has.
///
/// The result carries its type, which is what the boundary reading the
/// operand converts from. Deriving it a second time from the text was how
/// the assignment conversion was spelled on top of the projection's own.
pub(super) fn project_machine_use_of(
    base: CExpr,
    base_type: Option<&CValue>,
    slice: MachineUseSlice,
    pointer_bits: u32,
) -> Result<(CExpr, CValue), MachineUseProjectionError> {
    let convert = |expr: CExpr, from: Option<&CValue>, to: &CType| match from {
        Some(from) => super::convert::convert(expr, from, to, pointer_bits),
        None if matches!(to, CType::Pointer(_)) => CExpr::cast(to.clone(), expr),
        None => expr,
    };
    let whole = slice.bit_offset() == 0 && slice.width_bits() == slice.carrier_width_bits();
    let (projected, projected_type) = if whole {
        let ty = base_type
            .cloned()
            .unwrap_or_else(|| CValue::Typed(CType::machine_bits(slice.carrier_width_bits())));
        (base, ty)
    } else if c_integer_width_is_spellable(slice.carrier_width_bits()) {
        let carrier_type = checked_uint_type(slice.carrier_width_bits())?;
        let selected_type = checked_uint_type(slice.width_bits())?;
        let mut projected = convert(base, base_type, &carrier_type);
        if slice.bit_offset() != 0 {
            projected = CExpr::binary(
                BinaryOp::Shr,
                projected,
                CExpr::UIntLit(u64::from(slice.bit_offset())),
            );
        }
        // The selection is a narrowing, and it is the operation: spelled
        // whatever the shifted carrier is, because the shift produces the
        // carrier's type and the slice is narrower than it.
        let projected = CExpr::cast(selected_type.clone(), projected);
        (projected, CValue::Typed(selected_type))
    } else if c_bitvector_width_is_supported(slice.carrier_width_bits()) {
        if c_integer_width_is_spellable(slice.width_bits()) {
            let selected_type = checked_uint_type(slice.width_bits())?;
            (
                bitvector_helper(
                    format!(
                        "r2sleigh_bits_extract_{}_{}",
                        slice.carrier_width_bits(),
                        slice.width_bits()
                    ),
                    vec![base, CExpr::UIntLit(u64::from(slice.bit_offset()))],
                ),
                CValue::Typed(selected_type),
            )
        } else {
            return Err(MachineUseProjectionError::UnsupportedIntegerWidth(
                slice.width_bits(),
            ));
        }
    } else {
        return Err(MachineUseProjectionError::UnsupportedIntegerWidth(
            slice.carrier_width_bits(),
        ));
    };

    let Some(conversion) = slice.conversion() else {
        return Ok((projected, projected_type));
    };
    let target_width = conversion.to_width_bits();
    let source_width = slice.width_bits();
    if c_bitvector_width_is_supported(source_width) || c_bitvector_width_is_supported(target_width)
    {
        // A width-changing wide conversion needs its own source-owned semantic
        // contract (especially for signed extension). The prelude currently
        // certifies only exact extraction/insertion and zero-extending writes.
        return Err(MachineUseProjectionError::UnsupportedIntegerWidth(
            target_width.max(source_width),
        ));
    }
    // The conversion is the use's own operation, and its operand has to be
    // the unsigned integer of the selected width -- an address takes its
    // step here, a signed spelling loses its sign -- so that a zero
    // extension zero-fills and a truncation keeps the low bits.
    let operand_type = checked_uint_type(source_width)?;
    let projected = convert(projected, Some(&projected_type), &operand_type);
    match conversion.kind() {
        MachineCastKind::ZeroExtend | MachineCastKind::Truncate => {
            let target = checked_uint_type(target_width)?;
            Ok((
                CExpr::cast(target.clone(), projected),
                CValue::Typed(target),
            ))
        }
        MachineCastKind::BitReinterpret | MachineCastKind::AddressToInteger => {
            let target = checked_uint_type(target_width)?;
            let converted = convert(projected, Some(&CValue::Typed(operand_type)), &target);
            Ok((converted, CValue::Typed(target)))
        }
        MachineCastKind::SignExtend => {
            let narrow = checked_int_type(source_width)?;
            let target = checked_int_type(target_width)?;
            Ok((
                CExpr::cast(target.clone(), CExpr::cast(narrow, projected)),
                CValue::Typed(target),
            ))
        }
        MachineCastKind::IntegerToAddress => Err(
            MachineUseProjectionError::IntegerToAddressRequiresType(target_width),
        ),
    }
}

fn checked_write_uint_type(width_bits: u32) -> Result<CType, MachineWriteProjectionError> {
    c_integer_width_is_spellable(width_bits)
        .then_some(CType::Int {
            bits: width_bits,
            signedness: r2types::Signedness::Unsigned,
        })
        .ok_or(MachineWriteProjectionError::UnsupportedIntegerWidth(
            width_bits,
        ))
}

/// Apply one exact source-owned carrier write to an assignment.
///
/// `lhs` is both the assignment target and, for an inserted slice, the source
/// of the bits that the machine definition preserves. No rendered occurrence
/// is attached to that preservation read: it is part of the write projection,
/// not an SSA `UseSite`.
///
/// `rhs_type` is what the right-hand side has. The projection converts it to
/// the width the machine writes -- a lane, or the narrow half of a zero
/// extension -- through the one emitter, so a value already at that width is
/// not converted to it, and the result carries the type the carrier is
/// written at, which the assignment to the declared object converts from.
pub(super) fn project_machine_write(
    lhs: CExpr,
    rhs: CExpr,
    rhs_type: Option<&CValue>,
    projection: MachineWriteProjection,
    pointer_bits: u32,
) -> Result<(CExpr, CExpr, Option<CValue>), MachineWriteProjectionError> {
    let convert = |expr: CExpr, from: Option<&CValue>, to: &CType| match from {
        Some(from) => super::convert::convert(expr, from, to, pointer_bits),
        None if matches!(to, CType::Pointer(_)) => CExpr::cast(to.clone(), expr),
        None => expr,
    };
    match projection {
        MachineWriteProjection::Full => Ok((lhs, rhs, rhs_type.cloned())),
        MachineWriteProjection::ZeroExtend {
            from_width_bits,
            to_width_bits,
        } => {
            if c_bitvector_width_is_supported(to_width_bits) {
                if !c_integer_width_is_spellable(from_width_bits) {
                    return Err(MachineWriteProjectionError::UnsupportedIntegerWidth(
                        from_width_bits,
                    ));
                }
                return Ok((
                    lhs,
                    bitvector_helper(
                        format!("r2sleigh_bits_zero_extend_{from_width_bits}_{to_width_bits}"),
                        vec![rhs],
                    ),
                    Some(CValue::Typed(CType::BitVector(to_width_bits))),
                ));
            }
            let from = checked_write_uint_type(from_width_bits)?;
            let to = checked_write_uint_type(to_width_bits)?;
            // The extension is the write's own operation, spelled whatever
            // the narrow value is; its operand is brought to the unsigned
            // narrow width so that it zero-fills.
            let rhs = convert(rhs, rhs_type, &from);
            Ok((lhs, CExpr::cast(to.clone(), rhs), Some(CValue::Typed(to))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbol::{SymbolRole, SymbolTable};

    fn binding_expr() -> CExpr {
        let mut symbols = SymbolTable::new();
        CExpr::Var(symbols.reserve_binding(
            "carrier".to_string(),
            CType::Int {
                bits: 64,
                signedness: r2types::Signedness::Unsigned,
            },
            SymbolRole::Carrier,
        ))
    }

    #[test]
    fn full_write_does_not_invent_a_conversion() {
        let lhs = binding_expr();
        let rhs = CExpr::UIntLit(7);
        let projected = project_machine_write(
            lhs.clone(),
            rhs.clone(),
            Some(&CValue::Constant),
            MachineWriteProjection::Full,
            64,
        )
        .expect("full write");
        assert!(projected.0.transparently_eq(&lhs));
        assert!(projected.1.transparently_eq(&rhs));
        assert_eq!(projected.2, Some(CValue::Constant));
    }

    #[test]
    fn zero_extending_write_uses_both_source_owned_widths() {
        let (_, rhs, ty) = project_machine_write(
            binding_expr(),
            CExpr::UIntLit(7),
            Some(&CValue::Typed(CType::u64())),
            MachineWriteProjection::ZeroExtend {
                from_width_bits: 32,
                to_width_bits: 64,
            },
            64,
        )
        .expect("zero-extending write");
        assert!(matches!(
            rhs,
            CExpr::Cast {
                ty: CType::Int { bits: 64, signedness: r2types::Signedness::Unsigned },
                expr,
                ..
            } if matches!(*expr, CExpr::Cast { ty: CType::Int { bits: 32, signedness: r2types::Signedness::Unsigned }, .. })
        ));
        assert_eq!(ty, Some(CValue::Typed(CType::u64())));
    }

    fn slice(offset: u32, width: u32, carrier: u32) -> MachineUseSlice {
        MachineUseSlice::for_test(offset, width, carrier, None)
    }

    #[test]
    fn reading_the_whole_of_a_value_is_the_value_with_its_own_type() {
        let base = binding_expr();
        let declared = CValue::Typed(CType::ptr(CType::u8()));
        let (projected, ty) =
            project_machine_use_of(base.clone(), Some(&declared), slice(0, 64, 64), 64)
                .expect("whole read");
        assert!(projected.transparently_eq(&base));
        assert_eq!(ty, declared);
    }

    #[test]
    fn a_slice_of_the_carrier_is_one_narrowing_of_a_base_already_at_the_carrier() {
        let base = binding_expr();
        let (projected, ty) = project_machine_use_of(
            base.clone(),
            Some(&CValue::Typed(CType::u64())),
            slice(0, 32, 64),
            64,
        )
        .expect("low half");
        let CExpr::Cast {
            ty: cast_ty, expr, ..
        } = projected
        else {
            panic!("a slice is a narrowing, got {projected:?}");
        };
        assert_eq!(cast_ty, CType::u32());
        assert!(
            expr.transparently_eq(&base),
            "no conversion to the carrier the base already is"
        );
        assert_eq!(ty, CValue::Typed(CType::u32()));
    }

    #[test]
    fn a_slice_of_a_pointer_takes_the_address_width_step_first() {
        let base = binding_expr();
        let (projected, _) = project_machine_use_of(
            base.clone(),
            Some(&CValue::Typed(CType::ptr(CType::u8()))),
            slice(0, 32, 64),
            64,
        )
        .expect("low half of a pointer");
        let CExpr::Cast { ty, expr, .. } = projected else {
            panic!("expected the narrowing");
        };
        assert_eq!(ty, CType::u32());
        assert!(matches!(
            *expr,
            CExpr::Cast {
                ty: CType::Int { bits: 64, .. },
                role: crate::ast::CastRole::PointerWidthStep,
                ..
            }
        ));
    }

    #[test]
    fn wide_machine_type_is_not_an_invented_integer_typedef() {
        assert_eq!(
            CType::machine_bits(256).to_string(),
            "struct r2sleigh_bits_256"
        );
        assert_eq!(
            CType::machine_bits(128),
            CType::Int {
                bits: 128,
                signedness: r2types::Signedness::Unsigned
            }
        );
    }
}
