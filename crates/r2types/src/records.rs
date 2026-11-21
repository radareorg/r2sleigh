//! The record a parameter's class's accesses lay out, span by span (doc/adr-memory-places.md,
//! invariants 2, 5 and 6; doc/adr-aggregates.md).

use std::collections::{BTreeMap, BTreeSet};

use crate::{AggregateDefinition, CTypeLike, EvidenceTypes, Signedness};

/// A parameter's record as its accesses lay it out: the tag, the members, the spans spelled at a
/// member's address, and the accesses refused one by one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredRecord {
    pub tag: String,
    pub definition: AggregateDefinition,
    /// The member at each accessed offset, by its index in `definition.members`.
    pub fields: BTreeMap<i64, usize>,
    /// Wider accesses that start at a member and end at a member's end or in padding: each is a
    /// byte copy at that member's address.
    pub spans: BTreeSet<(i64, u32)>,
    /// Accesses no member or span states, with why.
    pub refused: Vec<(i64, u32, SpanRefusal)>,
}

/// Why one access is neither a member nor a span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpanRefusal {
    /// It starts inside a member.
    Interior,
    /// It starts at a member and ends inside another, or overlaps one it does not contain.
    Straddle,
    /// A width C does not align to itself, or an offset not aligned to the width.
    Unaligned,
    /// It starts below the record's base.
    BelowBase,
}

/// Why a parameter's accesses lay out no record at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordRefusal {
    /// Members and refused accesses of one width are as much an array's elements as a record's
    /// members (doc/adr-aggregates.md, the `argv` measurement); a span adds no width.
    OneWidth,
    /// No access is a member.
    NoMember,
}

/// Each parameter whose class's accesses lay out a record, by slot.
pub(crate) fn parameter_records(
    source: &r2ssa::SsaArtifact,
    evidence: &EvidenceTypes,
) -> BTreeMap<usize, InferredRecord> {
    let entry = source.function().entry;
    let ptr_bits = source
        .machine_context()
        .memory_model()
        .default_address_bits();
    let mut out = BTreeMap::new();
    for slot in source.facts().boundaries.parameters.keys() {
        let Ok(slot) = usize::try_from(*slot) else {
            continue;
        };
        let accesses = (evidence.record(slot).iter())
            .map(|(offset, width, value)| {
                let solved = (value.and_then(|value| evidence.value_type(value)))
                    .filter(|ty| {
                        field_type(ty)
                            && crate::function_facts::type_like_size_bytes(ty, ptr_bits)
                                == Some(u64::from(*width))
                    })
                    .cloned();
                (*offset, *width, solved)
            })
            .collect::<Vec<_>>();
        if accesses.is_empty() {
            continue;
        }
        match layout(&accesses) {
            Ok((definition, fields, spans, refused)) => {
                for (offset, width, reason) in &refused {
                    r2il::refusal_evidence!(
                        "record-span",
                        "{entry:#x} arg{slot}: {width}@{offset}: {reason:?}"
                    );
                }
                let tag = format!("fcn_{entry:x}_arg{slot}");
                let record = InferredRecord {
                    tag,
                    definition,
                    fields,
                    spans,
                    refused,
                };
                out.insert(slot, record);
            }
            Err(reason) => {
                r2il::refusal_evidence!("record", "{entry:#x} arg{slot}: {reason:?}");
            }
        }
    }
    out
}

type Laid = (
    AggregateDefinition,
    BTreeMap<i64, usize>,
    BTreeSet<(i64, u32)>,
    Vec<(i64, u32, SpanRefusal)>,
);

/// The members, spans and refusals of `accesses`, sorted by offset then width. Members are the
/// accesses that contain no other; `O(A log A)`: one pass, and a search per wider access.
pub(crate) fn layout(accesses: &[(i64, u32, Option<CTypeLike>)]) -> Result<Laid, RecordRefusal> {
    let mut distinct = Vec::<(i64, u32, Option<CTypeLike>, bool)>::new();
    for (offset, width, ty) in accesses {
        match distinct.last_mut() {
            Some((at, bytes, held, agreed)) if *at == *offset && *bytes == *width => {
                // Two solved types of one member leave it untyped: its bytes are all it states.
                if *agreed && ty.is_some() && held.is_some() && held != ty {
                    *agreed = false;
                }
                if held.is_none() {
                    held.clone_from(ty);
                }
            }
            _ => distinct.push((*offset, *width, ty.clone(), true)),
        }
    }
    let end = |offset: i64, width: u32| offset.saturating_add(i64::from(width));
    // Sorted by offset then width, an access contains another exactly when the one before it
    // starts where it does, or some later one ends no later: a suffix minimum of ends, `O(A)`.
    let mut first_end_after = vec![i64::MAX; distinct.len() + 1];
    for index in (0..distinct.len()).rev() {
        let (offset, width, ..) = distinct[index];
        first_end_after[index] = first_end_after[index + 1].min(end(offset, width));
    }
    let contains_other = |index: usize| {
        let (offset, width, ..) = distinct[index];
        (index > 0 && distinct[index - 1].0 == offset)
            || first_end_after[index + 1] <= end(offset, width)
    };
    let mut members = Vec::<(i64, u32, Option<CTypeLike>)>::new();
    let mut wider = Vec::<(i64, u32)>::new();
    let mut refused = Vec::new();
    for (index, (offset, width, ty, agreed)) in distinct.iter().enumerate() {
        let (offset, width, agreed) = (*offset, *width, *agreed);
        if contains_other(index) {
            wider.push((offset, width));
            continue;
        }
        if offset < 0 {
            refused.push((offset, width, SpanRefusal::BelowBase));
            continue;
        }
        // C aligns a scalar to its width, so an aligned member sits where the access says.
        if !matches!(width, 1 | 2 | 4 | 8) || offset % i64::from(width) != 0 {
            refused.push((offset, width, SpanRefusal::Unaligned));
            continue;
        }
        if (members.last()).is_some_and(|(at, bytes, _)| end(*at, *bytes) > offset) {
            refused.push((offset, width, SpanRefusal::Straddle));
            continue;
        }
        members.push((offset, width, ty.clone().filter(|_| agreed)));
    }
    let mut widths = (members.iter().map(|(_, width, _)| *width))
        .chain(refused.iter().map(|(_, width, _)| *width))
        .collect::<BTreeSet<_>>();
    if members.is_empty() {
        return Err(RecordRefusal::NoMember);
    }
    let starts = (members.iter().map(|(offset, ..)| *offset)).collect::<BTreeSet<_>>();
    let mut spans = BTreeSet::new();
    for (offset, width) in wider {
        // The member that holds the access's last byte, if any, must end where the access ends.
        let last = end(offset, width) - 1;
        let after = members.partition_point(|(at, ..)| *at <= last);
        let inside = (after.checked_sub(1).and_then(|index| members.get(index)))
            .filter(|(at, bytes, _)| last < end(*at, *bytes));
        let ends_cleanly =
            inside.is_none_or(|(at, bytes, _)| end(*at, *bytes) == end(offset, width));
        if !starts.contains(&offset) {
            refused.push((offset, width, SpanRefusal::Interior));
        } else if !ends_cleanly {
            refused.push((offset, width, SpanRefusal::Straddle));
        } else {
            spans.insert((offset, width));
            continue;
        }
        widths.insert(width);
    }
    if widths.len() < 2 {
        return Err(RecordRefusal::OneWidth);
    }
    refused.sort();
    let mut definition = Vec::new();
    let mut fields = BTreeMap::new();
    let mut at = 0i64;
    for (offset, width, ty) in members {
        if offset > at {
            let bytes = usize::try_from(offset - at).ok();
            let pad = CTypeLike::Array(Box::new(byte()), bytes);
            definition.push((pad, format!("_pad_{at:x}")));
        }
        let ty = ty.unwrap_or(CTypeLike::Int {
            bits: width * 8,
            signedness: Signedness::Unsigned,
        });
        fields.insert(offset, definition.len());
        definition.push((ty, format!("f_{offset:x}")));
        at = end(offset, width);
    }
    let definition = AggregateDefinition {
        is_union: false,
        members: definition,
    };
    Ok((definition, fields, spans, refused))
}

/// A scalar a member can be spelled at: C aligns it to its own width. A sign the solve left
/// unstated has no C spelling, so the member stays unsolved and the record stays definable (D74).
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

    fn int(bits: u32) -> CTypeLike {
        CTypeLike::Int {
            bits,
            signedness: Signedness::Unsigned,
        }
    }

    fn laid(accesses: &[(i64, u32)]) -> Result<Laid, RecordRefusal> {
        let mut accesses = (accesses.iter())
            .map(|(offset, width)| (*offset, *width, None))
            .collect::<Vec<_>>();
        accesses.sort_by_key(|(offset, width, _)| (*offset, *width));
        layout(&accesses)
    }

    fn names(definition: &AggregateDefinition) -> Vec<&str> {
        (definition.members.iter())
            .map(|(_, name)| name.as_str())
            .collect()
    }

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

    /// ADR test 2: `{4@0, 8@8, 16@0}` lays out `f_0`, `f_8`, and the 16-byte copy is a span.
    #[test]
    fn a_wide_access_over_members_is_a_span() {
        let (definition, fields, spans, refused) =
            laid(&[(0, 4), (8, 8), (0, 16)]).expect("a record");
        assert_eq!(names(&definition), ["f_0", "_pad_4", "f_8"]);
        assert_eq!(fields.keys().copied().collect::<Vec<_>>(), [0, 8]);
        assert_eq!(spans.into_iter().collect::<Vec<_>>(), [(0, 16)]);
        assert!(refused.is_empty());
    }

    /// ADR test 2: `{8@0, 4@4}` refuses only the 8-byte access, which starts before the member.
    #[test]
    fn an_access_starting_before_a_member_refuses_only_itself() {
        let (definition, _, spans, refused) = laid(&[(0, 8), (4, 4)]).expect("a record");
        assert_eq!(names(&definition), ["_pad_0", "f_4"]);
        assert!(spans.is_empty());
        assert_eq!(refused, [(0, 8, SpanRefusal::Interior)]);
    }

    /// A vector copy over two pointer fields: one member width, so no record (ruling 4).
    #[test]
    fn two_pointers_and_their_copy_stay_one_width() {
        assert_eq!(
            laid(&[(0, 8), (8, 8), (0, 16)]).map(|_| ()),
            Err(RecordRefusal::OneWidth)
        );
    }

    /// ADR test 7: `argv[1..3]` is one width, no record.
    #[test]
    fn argv_stays_one_width() {
        assert_eq!(
            laid(&[(8, 8), (16, 8), (24, 8)]).map(|_| ()),
            Err(RecordRefusal::OneWidth)
        );
    }

    /// ADR test 3: a member read once as a pointer and once as an integer is left untyped.
    #[test]
    fn two_solved_types_leave_a_member_untyped() {
        let pointer = CTypeLike::Pointer(Box::new(CTypeLike::Void));
        let accesses = [
            (0, 1, None),
            (8, 8, Some(pointer)),
            (
                8,
                8,
                Some(CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Signed,
                }),
            ),
        ];
        let (definition, ..) = layout(&accesses).expect("a record");
        assert_eq!(definition.members[2], (int(64), "f_8".to_owned()));
    }

    /// An access that overlaps a member without containing it is unaligned and refused alone.
    #[test]
    fn an_overlapping_unaligned_access_refuses_only_itself() {
        let (definition, _, _, refused) = laid(&[(0, 4), (2, 4), (8, 8)]).expect("a record");
        assert_eq!(names(&definition), ["f_0", "_pad_4", "f_8"]);
        assert_eq!(refused, [(2, 4, SpanRefusal::Unaligned)]);
    }
}
