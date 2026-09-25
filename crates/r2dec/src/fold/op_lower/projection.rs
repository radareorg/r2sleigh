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

fn checked_uint_type(width_bits: u32) -> Result<CType, MachineUseProjectionError> {
    CType::is_integer_width(width_bits)
        .then_some(CType::Int {
            bits: width_bits,
            signedness: r2types::Signedness::Unsigned,
        })
        .ok_or(MachineUseProjectionError::UnsupportedIntegerWidth(
            width_bits,
        ))
}

fn checked_int_type(width_bits: u32) -> Result<CType, MachineUseProjectionError> {
    CType::is_integer_width(width_bits)
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
    let convert = |expr: CExpr, from: Option<&CValue>, to: &CType| {
        super::convert::convert_optional(expr, from, to, pointer_bits)
    };
    // Whole against what is rendered, not against the machine carrier. A
    // binding is declared as wide as the widest read any member takes of it,
    // so a 64-bit register read only 32 bits at a time is declared
    // `uint32_t`; the slice still calls its carrier 64. Widening that name to
    // the carrier and narrowing it back selects the bits it already holds,
    // and the two conversions collapse into one that converts nothing, which
    // is where nearly every redundant cast in the output came from.
    let base_width_bits = base_type
        .and_then(CValue::as_type)
        .and_then(|ty| r2types::declaration_type_width_bits(ty, pointer_bits));
    let whole = slice.bit_offset() == 0
        && (slice.width_bits() == slice.carrier_width_bits()
            || base_width_bits == Some(slice.width_bits()));
    let (projected, projected_type) = if whole {
        let ty = base_type
            .cloned()
            .unwrap_or_else(|| CValue::Typed(CType::machine_bits(slice.carrier_width_bits())));
        (base, ty)
    } else if CType::is_integer_width(slice.carrier_width_bits()) {
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
    } else if crate::bitvector::is_supported(slice.carrier_width_bits()) {
        if CType::is_integer_width(slice.width_bits())
            && let Some(extract) = crate::bitvector::BitVectorHelper::extract(
                slice.carrier_width_bits(),
                slice.width_bits(),
            )
        {
            let selected_type = checked_uint_type(slice.width_bits())?;
            (
                extract.call(vec![base, CExpr::UIntLit(u64::from(slice.bit_offset()))]),
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

    // What each use slice selected and converted, so a cast in the output can
    // be traced to the slice that asked for it.
    r2il::refusal_evidence!(
        "use-slice-projection",
        "slice offset={} width={} carrier={} conversion={:?} base_type={:?} whole={whole}",
        slice.bit_offset(),
        slice.width_bits(),
        slice.carrier_width_bits(),
        slice.conversion().map(|conversion| conversion.kind()),
        base_type
    );
    let Some(conversion) = slice.conversion() else {
        return Ok((projected, projected_type));
    };
    let target_width = conversion.to_width_bits();
    let source_width = slice.width_bits();
    if crate::bitvector::is_supported(source_width) || crate::bitvector::is_supported(target_width)
    {
        // A width-changing wide conversion needs its own source-owned semantic
        // contract (especially for signed extension). The helpers
        // `crate::bitvector` defines are exact extraction, insertion and zero
        // extension, and none of them is a conversion a use slice states.
        return Err(MachineUseProjectionError::UnsupportedIntegerWidth(
            target_width.max(source_width),
        ));
    }
    // The conversion is the use's own operation, and its operand has to be
    // the integer of the selected width whose sign makes the conversion do
    // what the machine states: unsigned so a zero extension zero-fills and a
    // truncation keeps the low bits, signed so a sign extension sign-fills.
    // Bringing a sign extension's operand to the unsigned spelling first put
    // the sign back with a second cast, and over a name already declared at
    // the signed narrow type both of them converted nothing.
    let operand_type = if matches!(conversion.kind(), MachineCastKind::SignExtend) {
        checked_int_type(source_width)?
    } else {
        checked_uint_type(source_width)?
    };
    let projected = convert(projected, Some(&projected_type), &operand_type);
    match conversion.kind() {
        MachineCastKind::ZeroExtend => {
            // A name already exactly as wide as the selection needs no cast
            // to carry a zero extension: it is unsigned, so every consumer
            // that wants a wider type states so at its own boundary and the
            // conversion there zero-fills. Spelling it here instead widened
            // the name and let the next narrowing absorb the pair into one
            // cast that converts nothing, which is most of this output's
            // redundant casts.
            if base_width_bits == Some(source_width) {
                return Ok((projected, CValue::Typed(operand_type)));
            }
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
            let target = checked_int_type(target_width)?;
            Ok((
                CExpr::cast(target.clone(), projected),
                CValue::Typed(target),
            ))
        }
        // A floating conversion is an operation of its own, never a use slice.
        MachineCastKind::IntegerToFloat
        | MachineCastKind::FloatToInteger
        | MachineCastKind::FloatToFloat => Err(MachineUseProjectionError::UnsupportedIntegerWidth(
            target_width,
        )),
        MachineCastKind::IntegerToAddress => Err(
            MachineUseProjectionError::IntegerToAddressRequiresType(target_width),
        ),
    }
}

fn checked_write_uint_type(width_bits: u32) -> Result<CType, MachineWriteProjectionError> {
    CType::is_integer_width(width_bits)
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
    let convert = |expr: CExpr, from: Option<&CValue>, to: &CType| {
        super::convert::convert_optional(expr, from, to, pointer_bits)
    };
    match projection {
        MachineWriteProjection::Full => Ok((lhs, rhs, rhs_type.cloned())),
        MachineWriteProjection::ZeroExtend {
            from_width_bits,
            to_width_bits,
        } => {
            if crate::bitvector::is_supported(to_width_bits) {
                let Some(zero_extend) = CType::is_integer_width(from_width_bits)
                    .then(|| {
                        crate::bitvector::BitVectorHelper::zero_extend(
                            from_width_bits,
                            to_width_bits,
                        )
                    })
                    .flatten()
                else {
                    return Err(MachineWriteProjectionError::UnsupportedIntegerWidth(
                        from_width_bits,
                    ));
                };
                return Ok((
                    lhs,
                    zero_extend.call(vec![rhs]),
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
        // A name, not a literal: a literal needs no conversion at all, because
        // C reads it at whatever type holds it, so it could not show that both
        // widths were stated.
        let (_, rhs, ty) = project_machine_write(
            binding_expr(),
            binding_expr(),
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
            base,
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
