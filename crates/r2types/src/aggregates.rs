//! The structure a parameter's constant-offset accesses lay out (doc/adr-aggregates.md).

use std::collections::BTreeMap;

use r2ssa::{ParameterFieldAccess, ParameterFields};

use crate::{AggregateDefinition, CTypeLike, EvidenceTypes, Signedness};

/// A parameter's structure as its accesses lay it out: the tag it is spelled by, and its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredAggregate {
    pub tag: String,
    pub definition: AggregateDefinition,
    /// The member each accessed offset is, by its index in `definition.members`.
    pub fields: BTreeMap<i64, usize>,
}

/// Why a parameter's accesses lay out no structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayoutRefusal {
    /// Fields of one width are as much an array's elements as a structure's members.
    OneWidth,
    Overlap(i64),
    Unaligned(i64),
    /// Two accesses of one field whose solved types differ.
    Conflict(i64),
    BelowBase(i64),
}

/// Each parameter whose accesses lay out a structure, by slot.
pub(crate) fn parameter_aggregates(
    source: &r2ssa::SsaArtifact,
    evidence: &EvidenceTypes,
) -> BTreeMap<usize, InferredAggregate> {
    let entry = source.function().entry;
    let ptr_bits = source
        .machine_context()
        .memory_model()
        .default_address_bits();
    let mut out = BTreeMap::new();
    for (slot, fields) in &source.certificates().parameter_fields {
        let accesses = match fields {
            ParameterFields::Constant(accesses) => accesses,
            ParameterFields::Refused { inst, reason } => {
                r2il::refusal_evidence!(
                    "aggregate",
                    "{entry:#x} arg{slot}: {reason:?} at {inst:?}"
                );
                continue;
            }
        };
        let Ok(slot) = usize::try_from(*slot) else {
            continue;
        };
        match layout(accesses, evidence, ptr_bits) {
            Ok((definition, fields)) => {
                let tag = format!("fcn_{entry:x}_arg{slot}");
                out.insert(
                    slot,
                    InferredAggregate {
                        tag,
                        definition,
                        fields,
                    },
                );
            }
            Err(reason) => {
                r2il::refusal_evidence!("aggregate", "{entry:#x} arg{slot}: {reason:?}");
            }
        }
    }
    out
}

/// The members C lays out at the accessed offsets: each field at its offset, the bytes between
/// two fields an explicit pad. `accesses` is sorted by offset, then width.
fn layout(
    accesses: &[ParameterFieldAccess],
    evidence: &EvidenceTypes,
    ptr_bits: u32,
) -> Result<(AggregateDefinition, BTreeMap<i64, usize>), LayoutRefusal> {
    let mut fields = Vec::<(u64, u64, Option<CTypeLike>)>::new();
    for access in accesses {
        let offset =
            u64::try_from(access.offset).map_err(|_| LayoutRefusal::BelowBase(access.offset))?;
        let width = u64::from(access.width);
        let solved = (access.value)
            .and_then(|value| evidence.value_type(value))
            .filter(|ty| {
                field_type(ty)
                    && crate::function_facts::type_like_size_bytes(ty, ptr_bits) == Some(width)
            })
            .cloned();
        match fields.last_mut() {
            Some((at, bytes, ty)) if *at == offset => {
                if *bytes != width {
                    return Err(LayoutRefusal::Overlap(access.offset));
                }
                match (ty.as_ref(), solved) {
                    (Some(held), Some(solved)) if held != &solved => {
                        return Err(LayoutRefusal::Conflict(access.offset));
                    }
                    (None, solved @ Some(_)) => *ty = solved,
                    _ => {}
                }
            }
            Some((at, bytes, _)) if *at + *bytes > offset => {
                return Err(LayoutRefusal::Overlap(access.offset));
            }
            _ => fields.push((offset, width, solved)),
        }
    }
    let widths = fields
        .iter()
        .map(|(_, width, _)| *width)
        .collect::<std::collections::BTreeSet<_>>();
    if widths.len() < 2 {
        return Err(LayoutRefusal::OneWidth);
    }
    let mut members = Vec::new();
    let mut at = BTreeMap::new();
    let mut end = 0;
    for (offset, width, ty) in fields {
        // C aligns a scalar to its width, so an aligned field sits where the access says.
        if !matches!(width, 1 | 2 | 4 | 8) || offset % width != 0 {
            return Err(LayoutRefusal::Unaligned(offset as i64));
        }
        if offset > end {
            let pad = CTypeLike::Array(Box::new(byte()), usize::try_from(offset - end).ok());
            members.push((pad, format!("_pad_{end:x}")));
        }
        let ty = ty.unwrap_or(CTypeLike::Int {
            bits: (width * 8) as u32,
            signedness: Signedness::Unsigned,
        });
        at.insert(offset as i64, members.len());
        members.push((ty, format!("f_{offset:x}")));
        end = offset + width;
    }
    let definition = AggregateDefinition {
        is_union: false,
        members,
    };
    Ok((definition, at))
}

/// A scalar a field can be spelled at: C aligns it to its own width. A sign the solve left
/// unstated has no C spelling, so the field stays unsolved and the structure stays definable (D74).
fn field_type(ty: &CTypeLike) -> bool {
    match ty {
        CTypeLike::Int { signedness, .. } => *signedness != Signedness::Unknown,
        CTypeLike::Pointer(pointee) => !matches!(
            pointee.as_ref(),
            CTypeLike::Int {
                signedness: Signedness::Unknown,
                ..
            }
        ),
        CTypeLike::Float(_) | CTypeLike::Bool => true,
        _ => false,
    }
}

fn byte() -> CTypeLike {
    CTypeLike::Int {
        bits: 8,
        signedness: Signedness::Unsigned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pigz `free_pool` stripped: `f_8` solved as a pointer to an integer of no stated sign, which
    /// left `struct fcn_403da0_arg0` undefined and its parameter `uint64_t`.
    #[test]
    fn a_field_of_no_stated_sign_is_not_solved() {
        let int = |signedness| CTypeLike::Int {
            bits: 64,
            signedness,
        };
        assert!(!field_type(&int(Signedness::Unknown)));
        assert!(!field_type(&CTypeLike::Pointer(Box::new(int(
            Signedness::Unknown
        )))));
        assert!(field_type(&int(Signedness::Unsigned)));
        assert!(field_type(&CTypeLike::Pointer(Box::new(int(
            Signedness::Signed
        )))));
        assert!(field_type(&CTypeLike::Pointer(Box::new(CTypeLike::Void))));
    }
}
