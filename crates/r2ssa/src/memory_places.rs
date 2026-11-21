//! Where each memory access lands: one base and one place, or a typed refusal
//! (doc/adr-memory-places.md, invariants 1 and 10).

use std::collections::BTreeMap;

use r2il::SpaceId;

use crate::graph::InstId;
use crate::semantic::{ObjectKind, ObjectModel, StructuredAccessId, StructuredDataflowFacts};
use crate::{AddressProvenanceFacts, AffineAddressTerm, SSAOp, SsaGraph, ValueId};

/// What an access's address is an offset of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlaceBase {
    /// The formal at this slot, as the function was entered with it.
    Parameter(u32),
    /// The pointer the read access with this id loaded.
    Loaded(StructuredAccessId),
    /// The entry stack pointer.
    Frame,
    /// The image global at this address.
    Global(u64),
    /// No base the address facts state.
    None,
}

/// Where an access lands relative to its base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {
    /// `base + offset`, `width` bytes.
    Field {
        offset: i64,
        width: u32,
    },
    /// `base + stride * index + inner`, the access inside one stride.
    Element {
        stride: u64,
        index: ValueId,
        inner: i64,
        width: u32,
    },
    Unplaced(Unplaced),
}

/// Why an access has no place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unplaced {
    /// The address adds more than one variable to its base, or a merge of two offsets.
    NotAffine,
    /// One scaled index whose constant does not fit inside one stride.
    IndexPastStride,
    /// A linked, guarded or atomic access, which no plain place models.
    Unmodelled,
    /// The address facts state no base.
    NoBase,
}

/// One access's base and place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessPlace {
    pub access: StructuredAccessId,
    pub base: PlaceBase,
    pub place: Place,
}

/// One field access a parameter's value reaches, from its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReachedField {
    pub offset: i64,
    pub width: u32,
    pub access: StructuredAccessId,
    pub value: Option<ValueId>,
}

/// What a parameter's value reaches: field places only, or the first operation that is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterReach {
    Fields(Vec<ReachedField>),
    /// `place` is the reached access's, `None` where the operation has no access.
    Refused {
        inst: InstId,
        base: PlaceBase,
        place: Option<Place>,
    },
}

/// Each access's place, a column in `StructuredDataflowFacts::memory_accesses` order, and what
/// each parameter's value reaches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryPlaces {
    places: Vec<AccessPlace>,
    parameters: BTreeMap<u32, ParameterReach>,
}

impl MemoryPlaces {
    /// The places of every access: one pass over the accesses and the values their roots pass,
    /// each value resolved once, `O(A + V)` (the accesses' map walked in order).
    pub(crate) fn collect(
        graph: &SsaGraph,
        addresses: &AddressProvenanceFacts,
        objects: &ObjectModel,
        structured: &StructuredDataflowFacts,
    ) -> Self {
        let mut roots = Roots::new(graph);
        let places = (structured.memory_accesses.values())
            .map(|access| {
                let (base, mut place) = if access.space != SpaceId::Ram {
                    (PlaceBase::None, Place::Unplaced(Unplaced::NoBase))
                } else {
                    let object = objects.object(access.object).map(|fact| &fact.kind);
                    locate(
                        addresses,
                        &mut roots,
                        structured,
                        object,
                        access.address,
                        access.object_offset,
                        access.width,
                    )
                };
                if !plain(graph, access.id.inst) {
                    place = Place::Unplaced(Unplaced::Unmodelled);
                }
                AccessPlace {
                    access: access.id,
                    base,
                    place,
                }
            })
            .collect::<Vec<_>>();
        Self {
            places,
            parameters: BTreeMap::new(),
        }
    }

    /// What each parameter reaches, from these places (`reach`).
    pub(crate) fn with_parameters(
        mut self,
        graph: &SsaGraph,
        boundaries: &crate::semantic::SourceBoundaryFacts,
        structured: &StructuredDataflowFacts,
        stack_reloads: &crate::dense::IdMap<ValueId, crate::semantic::StackReloadSourceCertificate>,
    ) -> Self {
        self.parameters = reach::parameters(&self, graph, boundaries, structured, stack_reloads);
        self
    }

    /// What the value of the parameter at `slot` reaches; `None` where it reaches no memory.
    pub fn parameter(&self, slot: u32) -> Option<&ParameterReach> {
        self.parameters.get(&slot)
    }

    /// Every parameter's reach, by slot.
    pub fn parameters(&self) -> impl Iterator<Item = (u32, &ParameterReach)> {
        self.parameters.iter().map(|(slot, reach)| (*slot, reach))
    }

    /// The access at `position` (`StructuredDataflowFacts::position`): `O(1)`.
    pub fn at(&self, position: usize) -> Option<&AccessPlace> {
        self.places.get(position)
    }

    /// Every access's place, in access id order.
    pub fn iter(&self) -> impl Iterator<Item = &AccessPlace> {
        self.places.iter()
    }
}

mod reach;

/// Whether the instruction is a plain load or store.
fn plain(graph: &SsaGraph, inst: InstId) -> bool {
    matches!(
        graph.op(inst),
        Some(SSAOp::Load { .. } | SSAOp::Store { .. })
    )
}

fn located(terms: &[AffineAddressTerm], offset: i64, width: u32) -> Place {
    match terms {
        [] => Place::Field { offset, width },
        [term] => match u64::try_from(term.coefficient) {
            Ok(stride)
                if stride > 0
                    && offset >= 0
                    && (offset as u64).saturating_add(u64::from(width)) <= stride =>
            {
                Place::Element {
                    stride,
                    index: term.value,
                    inner: offset,
                    width,
                }
            }
            Ok(stride) if stride > 0 => Place::Unplaced(Unplaced::IndexPastStride),
            _ => Place::Unplaced(Unplaced::NotAffine),
        },
        _ => Place::Unplaced(Unplaced::NotAffine),
    }
}

fn locate(
    addresses: &AddressProvenanceFacts,
    roots: &mut Roots<'_>,
    structured: &StructuredDataflowFacts,
    object: Option<&ObjectKind>,
    address: ValueId,
    object_offset: Option<i64>,
    width: u32,
) -> (PlaceBase, Place) {
    if let Some(expression) = addresses.parameter_expression(address) {
        let place = located(&expression.terms, expression.offset, width);
        return match u32::try_from(expression.parameter) {
            Ok(slot) => (PlaceBase::Parameter(slot), place),
            Err(_) => (PlaceBase::None, Place::Unplaced(Unplaced::NoBase)),
        };
    }
    if let Some(expression) = addresses.frame_expression(address) {
        return (
            PlaceBase::Frame,
            located(&expression.terms, expression.offset, width),
        );
    }
    // A load makes one read access, its ordinal 0: found by position, `O(1)`.
    let loaded = |load: InstId| {
        let id = StructuredAccessId {
            inst: load,
            ordinal: 0,
        };
        structured.position(id).map(|_| PlaceBase::Loaded(id))
    };
    if let Some(expression) = addresses.pointee_expression(address) {
        let base = match roots.of(address) {
            Root::Loaded { load, .. } => loaded(load),
            Root::Two => return (PlaceBase::None, Place::Unplaced(Unplaced::NotAffine)),
            Root::Unknown => None,
        };
        return match base {
            Some(base) => (base, located(&expression.terms, expression.offset, width)),
            None => (PlaceBase::None, Place::Unplaced(Unplaced::NoBase)),
        };
    }
    match roots.of(address) {
        Root::Loaded { load, offset } => match loaded(load) {
            Some(base) => (
                base,
                offset.map_or(Place::Unplaced(Unplaced::NotAffine), |offset| {
                    Place::Field { offset, width }
                }),
            ),
            None => (PlaceBase::None, Place::Unplaced(Unplaced::NoBase)),
        },
        Root::Two => (PlaceBase::None, Place::Unplaced(Unplaced::NotAffine)),
        Root::Unknown => match object {
            Some(ObjectKind::Global { address, .. }) => (
                PlaceBase::Global(*address),
                object_offset.map_or(Place::Unplaced(Unplaced::NotAffine), |offset| {
                    Place::Field { offset, width }
                }),
            ),
            _ => (PlaceBase::None, Place::Unplaced(Unplaced::NoBase)),
        },
    }
}

/// The loaded pointer a value is an offset of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    /// The output of the load at `load`, plus `offset` when only constants were added.
    Loaded {
        load: InstId,
        offset: Option<i64>,
    },
    /// Two loaded pointers, or one merged with another offset of itself.
    Two,
    Unknown,
}

/// Each value's root, a dense column filled once per value; a value on a cycle has none.
struct Roots<'a> {
    graph: &'a SsaGraph,
    column: crate::dense::IdMap<ValueId, Option<Root>>,
}

impl<'a> Roots<'a> {
    fn new(graph: &'a SsaGraph) -> Self {
        Self {
            graph,
            column: crate::dense::IdMap::default(),
        }
    }

    /// `value`'s root, resolving its operands first on an explicit stack: each value is pushed
    /// at most twice and resolved once, `O(V)` over all calls.
    fn of(&mut self, value: ValueId) -> Root {
        let mut stack = vec![value];
        while let Some(&top) = stack.last() {
            if let Some(Some(_)) = self.column.get(top) {
                stack.pop();
                continue;
            }
            let depth = stack.len();
            let column = &self.column;
            stack.extend(
                (self.operands(top).iter().copied())
                    .filter(|operand| column.get(*operand).is_none()),
            );
            if self.column.get(top).is_none() && stack.len() > depth {
                // In progress: a cycle back to `top` reads `None` and resolves to `Unknown`.
                self.column.insert(top, None);
                continue;
            }
            stack.truncate(depth);
            let root = self.resolve(top);
            self.column.insert(top, Some(root));
            stack.pop();
        }
        self.column
            .get(value)
            .copied()
            .flatten()
            .unwrap_or(Root::Unknown)
    }

    /// The values `value`'s root is read from, borrowed from the graph.
    fn operands(&self, value: ValueId) -> &'a [ValueId] {
        let graph = self.graph;
        let Some(inst) = graph.def_inst(value) else {
            return &[];
        };
        match graph.op(inst) {
            Some(SSAOp::Copy { src, .. }) => std::slice::from_ref(src),
            Some(SSAOp::IntSub { a, .. }) => std::slice::from_ref(a),
            Some(SSAOp::IntAdd { .. } | SSAOp::Phi { .. }) => graph.inputs(inst),
            _ => &[],
        }
    }

    fn root(&self, value: ValueId) -> Root {
        self.column
            .get(value)
            .copied()
            .flatten()
            .unwrap_or(Root::Unknown)
    }

    fn constant(&self, value: ValueId) -> Option<i64> {
        let var = self.graph.var(value);
        var.constant_bits().map(|bits| {
            let shift = 64u32.saturating_sub(var.size.saturating_mul(8)).min(63);
            ((bits << shift) as i64) >> shift
        })
    }

    fn resolve(&self, value: ValueId) -> Root {
        let Some(inst) = self.graph.def_inst(value) else {
            return Root::Unknown;
        };
        let shifted = |root: Root, by: Option<i64>| match root {
            Root::Loaded { load, offset } => Root::Loaded {
                load,
                offset: offset.zip(by).and_then(|(at, by)| at.checked_add(by)),
            },
            other => other,
        };
        match self.graph.op(inst) {
            Some(SSAOp::Load {
                space: SpaceId::Ram,
                dst,
                ..
            }) if *dst == value => Root::Loaded {
                load: inst,
                offset: Some(0),
            },
            Some(SSAOp::Copy { src, .. }) => self.root(*src),
            Some(SSAOp::IntAdd { a, b, .. }) => match (self.constant(*a), self.constant(*b)) {
                (None, Some(k)) => shifted(self.root(*a), Some(k)),
                (Some(k), None) => shifted(self.root(*b), Some(k)),
                (Some(_), Some(_)) => Root::Unknown,
                (None, None) => match (self.root(*a), self.root(*b)) {
                    (Root::Unknown, root) | (root, Root::Unknown) => shifted(root, None),
                    _ => Root::Two,
                },
            },
            Some(SSAOp::IntSub { a, b, .. }) => {
                shifted(self.root(*a), self.constant(*b).and_then(i64::checked_neg))
            }
            Some(SSAOp::Phi { sources, .. }) => {
                let mut roots = sources.iter().map(|source| self.root(*source));
                let first = roots.next().unwrap_or(Root::Unknown);
                if roots.all(|root| root == first) {
                    first
                } else if matches!(first, Root::Loaded { .. }) {
                    Root::Two
                } else {
                    Root::Unknown
                }
            }
            _ => Root::Unknown,
        }
    }
}
