use std::collections::BTreeMap;

use r2source::{SourceTypeGraph, SourceTypeKind};

use crate::CTypeLike;

/// The owner that supplied a program data object's type.
///
/// This is deliberately not machine evidence. A renderer may trust it because
/// the source marked the analysis fact, but its proof line must say so.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum DataObjectTypeProvenance {
    /// The capture's own statement of the object's type: the binary's debug
    /// information, read at the object's address.
    Source,
}

/// One accepted type, keyed outside this value by the object's address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct DataObjectTypeFact {
    pub ty: CTypeLike,
    pub provenance: DataObjectTypeProvenance,
}

/// Why a source observation did not become a renderer type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum DataObjectTypeRefusal {
    /// The source named the object but stated no type at its address.
    MissingSourceType,
    /// The image graph's type has no layout the renderer can place (D345).
    UnplaceableSourceType(CTypeLike),
    /// Two source observations for one structural address disagreed. Neither
    /// is allowed to win by observation order.
    ConflictingSourceTypes { first: CTypeLike, second: CTypeLike },
}

/// Program-scope data object types and the refusals that prevented a type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramDataObjectTypeFacts {
    accepted: BTreeMap<u64, DataObjectTypeFact>,
    refused: BTreeMap<u64, DataObjectTypeRefusal>,
}

impl ProgramDataObjectTypeFacts {
    /// Each data symbol's type id in the image graph, kept where that graph lays it out (D345).
    /// O(objects x type depth).
    pub fn from_source(
        graph: Option<&SourceTypeGraph>,
        observations: impl IntoIterator<Item = (u64, Option<u32>)>,
    ) -> Self {
        let mut facts = Self::default();
        for (address, type_id) in observations {
            let typed = graph.zip(type_id);
            let ty = typed.and_then(|(graph, id)| crate::source_type_like(graph, id));
            match (typed, ty) {
                (None, _) => {
                    facts.observe_refused(address, DataObjectTypeRefusal::MissingSourceType)
                }
                (Some((graph, id)), Some(ty)) if placeable(graph, id, false) => {
                    facts.observe_accepted(address, ty);
                }
                (Some(_), ty) => facts.observe_refused(
                    address,
                    DataObjectTypeRefusal::UnplaceableSourceType(ty.unwrap_or(CTypeLike::Unknown)),
                ),
            }
        }
        facts
    }

    pub fn refused(&self) -> &BTreeMap<u64, DataObjectTypeRefusal> {
        &self.refused
    }

    pub fn get(&self, address: u64) -> Option<&DataObjectTypeFact> {
        self.accepted.get(&address)
    }

    /// Merge another function's observations into the program view.
    ///
    /// Absence and an unplaceable spelling cannot displace an accepted fact.
    /// Two different accepted types are a conflict and remove the type, so
    /// traversal order cannot decide rendered C.
    pub fn absorb(&mut self, other: &Self) {
        for (&address, refusal) in &other.refused {
            if !self.accepted.contains_key(&address) {
                self.observe_refused(address, refusal.clone());
            }
        }
        for (&address, fact) in &other.accepted {
            self.observe_accepted(address, fact.ty.clone());
        }
    }

    fn observe_accepted(&mut self, address: u64, ty: CTypeLike) {
        match self.accepted.get(&address) {
            Some(existing) if existing.ty == ty => {}
            Some(existing) => {
                let existing = existing.ty.clone();
                let (first, second) = if existing <= ty {
                    (existing, ty)
                } else {
                    (ty, existing)
                };
                self.accepted.remove(&address);
                self.refused.insert(
                    address,
                    DataObjectTypeRefusal::ConflictingSourceTypes { first, second },
                );
            }
            None if matches!(
                self.refused.get(&address),
                Some(DataObjectTypeRefusal::ConflictingSourceTypes { .. })
            ) => {}
            None => {
                self.refused.remove(&address);
                self.accepted.insert(
                    address,
                    DataObjectTypeFact {
                        ty,
                        provenance: DataObjectTypeProvenance::Source,
                    },
                );
            }
        }
    }

    fn observe_refused(&mut self, address: u64, refusal: DataObjectTypeRefusal) {
        if self.accepted.contains_key(&address) {
            return;
        }
        match self.refused.entry(address) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(refusal);
            }
            std::collections::btree_map::Entry::Occupied(mut entry)
                if refusal < *entry.get()
                    && !matches!(
                        entry.get(),
                        DataObjectTypeRefusal::ConflictingSourceTypes { .. }
                    ) =>
            {
                entry.insert(refusal);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }
}

/// Whether the graph lays a type out; an opaque tag, code, or a chain longer than the type count
/// (a cycle) refuses. O(chain).
fn placeable(graph: &SourceTypeGraph, type_id: u32, behind_pointer: bool) -> bool {
    let (mut type_id, mut behind_pointer) = (type_id, behind_pointer);
    for _ in 0..=graph.types().len() {
        let Some(node) = usize::try_from(type_id)
            .ok()
            .and_then(|index| graph.types().get(index))
        else {
            return false;
        };
        match node.kind() {
            SourceTypeKind::Void => return behind_pointer,
            SourceTypeKind::SignedInteger
            | SourceTypeKind::UnsignedInteger
            | SourceTypeKind::Char { .. }
            | SourceTypeKind::Float => return true,
            SourceTypeKind::Pointer { target_type_id, .. } => {
                (type_id, behind_pointer) = (target_type_id, true);
            }
            SourceTypeKind::Array {
                element_type_id, ..
            } => (type_id, behind_pointer) = (element_type_id, false),
            SourceTypeKind::Struct { aggregate_id } | SourceTypeKind::Union { aggregate_id } => {
                return usize::try_from(aggregate_id)
                    .ok()
                    .and_then(|index| graph.aggregates().get(index))
                    .is_some_and(|aggregate| aggregate.size_bits() > 0);
            }
            SourceTypeKind::Code { .. } | SourceTypeKind::Opaque { .. } => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use r2source::{SourceAggregateLayout, SourceAggregateMember, SourceType};

    use super::*;

    /// 0 `int`, 1 `unsigned`, 2 `struct cfg { int a; }`, 3 `struct cfg *`, 4 an opaque typedef.
    fn graph() -> SourceTypeGraph {
        SourceTypeGraph::from_parts(r2source::SourceTypeGraphParts {
            types: vec![
                SourceType::new(0, SourceTypeKind::SignedInteger, 32, 32),
                SourceType::new(1, SourceTypeKind::UnsignedInteger, 32, 32),
                SourceType::new(2, SourceTypeKind::Struct { aggregate_id: 0 }, 32, 32),
                SourceType::new(
                    3,
                    SourceTypeKind::Pointer {
                        target_type_id: 2,
                        const_target: false,
                    },
                    64,
                    64,
                ),
                SourceType::new(4, SourceTypeKind::Opaque { tag_id: 0 }, 0, 0),
            ],
            aggregates: vec![SourceAggregateLayout::new(
                0,
                2,
                32,
                32,
                "cfg",
                [SourceAggregateMember::new(0, 0, 0, 32, "a")],
            )],
            opaque_tags: vec![r2source::SourceOpaqueTag::new(
                0,
                r2source::SourceTagKeyword::Typedef,
                "looks_specific_t",
            )],
            ..r2source::SourceTypeGraphParts::default()
        })
        .expect("valid graph")
    }

    fn facts(id: Option<u32>) -> ProgramDataObjectTypeFacts {
        ProgramDataObjectTypeFacts::from_source(Some(&graph()), [(0x7000, id)])
    }

    #[test]
    fn a_builtin_type_is_accepted_and_marked() {
        let facts = facts(Some(0));
        assert_eq!(
            facts.get(0x7000).map(|fact| &fact.ty),
            Some(&CTypeLike::i32())
        );
        assert_eq!(
            facts.get(0x7000).map(|fact| fact.provenance),
            Some(DataObjectTypeProvenance::Source)
        );
    }

    /// D345 gate 3: a global struct places from the image graph alone, its pointer too.
    #[test]
    fn a_global_struct_places_from_the_image_graph() {
        assert_eq!(
            facts(Some(2)).get(0x7000).map(|fact| &fact.ty),
            Some(&CTypeLike::Struct("cfg".to_string()))
        );
        assert!(facts(Some(3)).get(0x7000).is_some());
    }

    #[test]
    fn an_undeclared_typedef_is_refused() {
        let facts = facts(Some(4));
        assert!(facts.get(0x7000).is_none());
        assert_eq!(
            facts.refused().get(&0x7000),
            Some(&DataObjectTypeRefusal::UnplaceableSourceType(
                CTypeLike::typedef("looks_specific_t")
            ))
        );
    }

    #[test]
    fn no_source_type_is_a_refusal_not_a_default_type() {
        let facts = facts(None);
        assert!(facts.get(0x7000).is_none());
        assert_eq!(
            facts.refused().get(&0x7000),
            Some(&DataObjectTypeRefusal::MissingSourceType)
        );
    }

    #[test]
    fn accepted_program_fact_survives_a_later_missing_observation() {
        let mut accepted = facts(Some(0));
        accepted.absorb(&facts(None));
        assert_eq!(
            accepted.get(0x7000).map(|fact| &fact.ty),
            Some(&CTypeLike::i32())
        );
    }

    #[test]
    fn conflicting_program_types_refuse_independent_of_order() {
        let (signed, unsigned) = (facts(Some(0)), facts(Some(1)));
        for (mut first, second) in [(signed.clone(), unsigned.clone()), (unsigned, signed)] {
            first.absorb(&second);
            assert!(first.get(0x7000).is_none());
            assert!(matches!(
                first.refused().get(&0x7000),
                Some(DataObjectTypeRefusal::ConflictingSourceTypes { .. })
            ));
        }
    }
}
