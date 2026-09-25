//! The types one function interface names, as a closed graph.
//!
//! A source states a layout; this checks the statement is consistent and
//! carries it. It does not re-derive a natural layout and compare: a packed
//! struct, an i386 `double` aligned to four, and a record whose alignment the
//! producer raised are all layouts a compiler states, and refusing them cost
//! the function every type it had. What must hold is what makes a layout a
//! layout -- members inside their record, not overlapping one another, sizes
//! that are multiples of their alignment -- and nothing more.
//!
//! The graph holds exactly what its interface names. That is established by
//! [`SourceTypeGraph::closure`], never demanded of whoever built it: a
//! declaration interned per item may leave a node nothing names once one item
//! is dropped, and that is not a reason to lose the others.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

pub const SOURCE_TYPE_GRAPH_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceTypeKind {
    SignedInteger,
    UnsignedInteger,
    Pointer {
        target_type_id: u32,
    },
    Struct {
        aggregate_id: u32,
    },
    /// `void`: no size and no layout, and only ever a pointer's target or a
    /// signature's result.
    Void,
    /// Code, with the signature the graph states for it. Like `Void` it has
    /// no size and is only a pointer's target.
    Code {
        signature_id: u32,
    },
    /// An aggregate whose members all begin at its start.
    Union {
        aggregate_id: u32,
    },
    /// A run of elements of one type. `count` is stated, never inferred; an
    /// array whose bound the source does not give has none and no size, and
    /// is only a struct's last member or a pointer's target.
    Array {
        element_type_id: u32,
        count: Option<u64>,
    },
    /// An IEEE binary floating-point object.
    ///
    /// Not an integer of the same width: the bits mean something else, a cast
    /// between the two is a conversion rather than a reinterpretation, and the
    /// value travels in a different register class.
    Float,
    /// A tag the source declares and never completes: `FILE`, `struct x`.
    /// It has no size and is only a pointer's target, and it keeps its name,
    /// because a pointer to it has to say what it points at.
    Opaque {
        tag_id: u32,
    },
}

impl SourceTypeKind {
    /// Whether a value of this kind is an object with a size of its own.
    const fn is_sized(self) -> bool {
        !matches!(
            self,
            Self::Void | Self::Code { .. } | Self::Opaque { .. } | Self::Array { count: None, .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceType {
    id: u32,
    kind: SourceTypeKind,
    size_bits: u64,
    align_bits: u64,
}

impl SourceType {
    pub const fn new(id: u32, kind: SourceTypeKind, size_bits: u64, align_bits: u64) -> Self {
        Self {
            id,
            kind,
            size_bits,
            align_bits,
        }
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub const fn kind(&self) -> SourceTypeKind {
        self.kind
    }

    pub const fn size_bits(&self) -> u64 {
        self.size_bits
    }

    pub const fn align_bits(&self) -> u64 {
        self.align_bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceCarrierKind {
    Full,
    LowBits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceCarrierProjection {
    kind: SourceCarrierKind,
    offset_bits: u64,
    size_bits: u64,
}

impl SourceCarrierProjection {
    pub const fn new(kind: SourceCarrierKind, offset_bits: u64, size_bits: u64) -> Self {
        Self {
            kind,
            offset_bits,
            size_bits,
        }
    }

    pub const fn kind(&self) -> SourceCarrierKind {
        self.kind
    }

    pub const fn offset_bits(&self) -> u64 {
        self.offset_bits
    }

    pub const fn size_bits(&self) -> u64 {
        self.size_bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceLogicalValue {
    type_id: u32,
    carrier: SourceCarrierProjection,
}

impl SourceLogicalValue {
    pub const fn new(type_id: u32, carrier: SourceCarrierProjection) -> Self {
        Self { type_id, carrier }
    }

    pub const fn type_id(self) -> u32 {
        self.type_id
    }

    pub const fn carrier(&self) -> SourceCarrierProjection {
        self.carrier
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceAggregateMember {
    member_id: u32,
    type_id: u32,
    offset_bits: u64,
    size_bits: u64,
    name: String,
    bit_field: bool,
}

impl SourceAggregateMember {
    /// A member that holds whole elements of its type: one, or an array's
    /// worth where `size_bits` is a multiple of the type's.
    pub fn new(
        member_id: u32,
        type_id: u32,
        offset_bits: u64,
        size_bits: u64,
        name: impl Into<String>,
    ) -> Self {
        Self {
            member_id,
            type_id,
            offset_bits,
            size_bits,
            name: name.into(),
            bit_field: false,
        }
    }

    /// A bit-field: `size_bits` bits of an integer type, at any bit.
    pub fn new_bit_field(
        member_id: u32,
        type_id: u32,
        offset_bits: u64,
        size_bits: u64,
        name: impl Into<String>,
    ) -> Self {
        Self {
            bit_field: true,
            ..Self::new(member_id, type_id, offset_bits, size_bits, name)
        }
    }

    pub const fn member_id(&self) -> u32 {
        self.member_id
    }

    pub const fn type_id(&self) -> u32 {
        self.type_id
    }

    pub const fn offset_bits(&self) -> u64 {
        self.offset_bits
    }

    pub const fn size_bits(&self) -> u64 {
        self.size_bits
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn is_bit_field(&self) -> bool {
        self.bit_field
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceAggregateLayout {
    id: u32,
    type_id: u32,
    size_bits: u64,
    align_bits: u64,
    name: String,
    members: Box<[SourceAggregateMember]>,
}

impl SourceAggregateLayout {
    pub fn new(
        id: u32,
        type_id: u32,
        size_bits: u64,
        align_bits: u64,
        name: impl Into<String>,
        members: impl IntoIterator<Item = SourceAggregateMember>,
    ) -> Self {
        Self {
            id,
            type_id,
            size_bits,
            align_bits,
            name: name.into(),
            members: members.into_iter().collect::<Vec<_>>().into_boxed_slice(),
        }
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub const fn type_id(&self) -> u32 {
        self.type_id
    }

    pub const fn size_bits(&self) -> u64 {
        self.size_bits
    }

    pub const fn align_bits(&self) -> u64 {
        self.align_bits
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn members(&self) -> &[SourceAggregateMember] {
        &self.members
    }
}

/// What code of one type takes and returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCodeSignature {
    id: u32,
    return_type_id: u32,
    parameter_type_ids: Box<[u32]>,
    variadic: bool,
    /// Whether the parameters are stated. An unprototyped signature says
    /// nothing about them, which is not the same as saying there are none.
    prototyped: bool,
}

impl SourceCodeSignature {
    pub fn new(
        id: u32,
        return_type_id: u32,
        parameter_type_ids: impl IntoIterator<Item = u32>,
        variadic: bool,
        prototyped: bool,
    ) -> Self {
        Self {
            id,
            return_type_id,
            parameter_type_ids: parameter_type_ids.into_iter().collect(),
            variadic,
            prototyped,
        }
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub const fn return_type_id(&self) -> u32 {
        self.return_type_id
    }

    pub const fn parameter_type_ids(&self) -> &[u32] {
        &self.parameter_type_ids
    }

    pub const fn variadic(&self) -> bool {
        self.variadic
    }

    pub const fn prototyped(&self) -> bool {
        self.prototyped
    }
}

/// The keyword an incomplete tag is declared under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SourceTagKeyword {
    Struct,
    Union,
    Enum,
    /// A typedef name the source never says anything more about.
    Typedef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceOpaqueTag {
    id: u32,
    keyword: SourceTagKeyword,
    name: String,
}

impl SourceOpaqueTag {
    pub fn new(id: u32, keyword: SourceTagKeyword, name: impl Into<String>) -> Self {
        Self {
            id,
            keyword,
            name: name.into(),
        }
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub const fn keyword(&self) -> SourceTagKeyword {
        self.keyword
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A name the source gave one of this graph's types.
///
/// Compilation destroys the name but the producer's own type database keeps
/// it, and a rendering that writes `UInt16 *p` has to say what `UInt16` is --
/// a pointer to an undeclared tag is legal C, a pointer to an undeclared
/// typedef name is not. The binding is exact rather than inferred: the capture
/// resolved this spelling to this type while it was building the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceTypeAlias {
    name: String,
    type_id: u32,
}

impl SourceTypeAlias {
    pub const fn new(name: String, type_id: u32) -> Self {
        Self { name, type_id }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn type_id(&self) -> u32 {
        self.type_id
    }
}

/// Everything one graph is made of, by table.
#[derive(Debug, Clone, Default)]
pub struct SourceTypeGraphParts {
    pub types: Vec<SourceType>,
    pub aggregates: Vec<SourceAggregateLayout>,
    pub signatures: Vec<SourceCodeSignature>,
    pub opaque_tags: Vec<SourceOpaqueTag>,
    pub aliases: Vec<SourceTypeAlias>,
}

impl SourceTypeGraphParts {
    /// Whether one aggregate, as the next row of this table, is a layout the
    /// graph accepts: the check [`SourceTypeGraph::from_parts`] makes of it,
    /// asked of one record so a builder can give up that record alone.
    pub fn aggregate_is_consistent(&self, aggregate: &SourceAggregateLayout) -> bool {
        validate_aggregate(self.aggregates.len(), aggregate, self).is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceTypeGraph {
    schema_version: u32,
    types: Box<[SourceType]>,
    aggregates: Box<[SourceAggregateLayout]>,
    signatures: Box<[SourceCodeSignature]>,
    opaque_tags: Box<[SourceOpaqueTag]>,
    aliases: Box<[SourceTypeAlias]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceTypeGraphError {
    InvalidType,
    InvalidAggregate,
    InvalidMember,
    InvalidAlias,
    InvalidSignature,
    InvalidTag,
}

impl std::fmt::Display for SourceTypeGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid source type graph: {self:?}")
    }
}

impl std::error::Error for SourceTypeGraphError {}

/// A graph over only the nodes some roots reach, and where each went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTypeClosure {
    graph: SourceTypeGraph,
    renumbered: BTreeMap<u32, u32>,
}

impl SourceTypeClosure {
    pub const fn graph(&self) -> &SourceTypeGraph {
        &self.graph
    }

    pub fn into_graph(self) -> SourceTypeGraph {
        self.graph
    }

    /// The node an id of the graph it was taken from became.
    pub fn id(&self, original: u32) -> Option<u32> {
        self.renumbered.get(&original).copied()
    }
}

impl SourceTypeGraph {
    /// A graph that carries no source names for its types.
    pub fn new(
        types: impl IntoIterator<Item = SourceType>,
        aggregates: impl IntoIterator<Item = SourceAggregateLayout>,
    ) -> Result<Self, SourceTypeGraphError> {
        Self::new_with_aliases(types, aggregates, [])
    }

    pub fn new_with_aliases(
        types: impl IntoIterator<Item = SourceType>,
        aggregates: impl IntoIterator<Item = SourceAggregateLayout>,
        aliases: impl IntoIterator<Item = SourceTypeAlias>,
    ) -> Result<Self, SourceTypeGraphError> {
        Self::from_parts(SourceTypeGraphParts {
            types: types.into_iter().collect(),
            aggregates: aggregates.into_iter().collect(),
            aliases: aliases.into_iter().collect(),
            ..SourceTypeGraphParts::default()
        })
    }

    /// A graph from every table, once each is a consistent statement.
    ///
    /// A function that mentions no type has an empty graph. That is a
    /// complete account of the types it uses, not an absent one.
    pub fn from_parts(parts: SourceTypeGraphParts) -> Result<Self, SourceTypeGraphError> {
        validate(&parts)?;
        let SourceTypeGraphParts {
            types,
            aggregates,
            signatures,
            opaque_tags,
            aliases,
        } = parts;
        Ok(Self {
            schema_version: SOURCE_TYPE_GRAPH_SCHEMA_VERSION,
            types: types.into_boxed_slice(),
            aggregates: aggregates.into_boxed_slice(),
            signatures: signatures.into_boxed_slice(),
            opaque_tags: opaque_tags.into_boxed_slice(),
            aliases: aliases.into_boxed_slice(),
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn aliases(&self) -> &[SourceTypeAlias] {
        &self.aliases
    }

    pub const fn types(&self) -> &[SourceType] {
        &self.types
    }

    pub const fn aggregates(&self) -> &[SourceAggregateLayout] {
        &self.aggregates
    }

    pub const fn signatures(&self) -> &[SourceCodeSignature] {
        &self.signatures
    }

    pub const fn opaque_tags(&self) -> &[SourceOpaqueTag] {
        &self.opaque_tags
    }

    fn get(&self, id: u32) -> Option<&SourceType> {
        self.types.get(usize::try_from(id).ok()?)
    }

    /// Check source pointer types against the exact captured machine width.
    /// Structural type construction alone cannot grant this machine-specific
    /// fact because the type graph is also used by analysis-only callers.
    pub fn validates_pointer_width(&self, pointer_bits: u32) -> bool {
        self.types.iter().all(|source_type| {
            !matches!(source_type.kind, SourceTypeKind::Pointer { .. })
                || source_type.size_bits == u64::from(pointer_bits)
        })
    }

    pub(crate) fn validates_logical_value(
        &self,
        value: SourceLogicalValue,
        carrier_size_bytes: u32,
    ) -> bool {
        let Some(source_type) = self.get(value.type_id) else {
            return false;
        };
        let carrier_bits = u64::from(carrier_size_bytes) * 8;
        if !source_type.kind.is_sized()
            || value.carrier.offset_bits != 0
            || value.carrier.size_bits != source_type.size_bits
            || source_type.size_bits > carrier_bits
        {
            return false;
        }
        match value.carrier.kind {
            SourceCarrierKind::Full => source_type.size_bits == carrier_bits,
            // A scalar narrower than the register it travels in occupies that
            // register's low bits, and a floating-point value is such a scalar:
            // a `double` returned in a 128-bit vector register is the low half
            // of it, exactly as an `int` is the low half of a 64-bit register.
            SourceCarrierKind::LowBits => {
                source_type.size_bits < carrier_bits
                    && matches!(
                        source_type.kind,
                        SourceTypeKind::SignedInteger
                            | SourceTypeKind::UnsignedInteger
                            | SourceTypeKind::Float
                    )
            }
        }
    }

    /// The nodes one node names directly.
    fn successors(&self, id: u32) -> Vec<u32> {
        let Some(source_type) = self.get(id) else {
            return Vec::new();
        };
        match source_type.kind {
            SourceTypeKind::Pointer { target_type_id } => vec![target_type_id],
            SourceTypeKind::Array {
                element_type_id, ..
            } => vec![element_type_id],
            SourceTypeKind::Struct { aggregate_id } | SourceTypeKind::Union { aggregate_id } => {
                self.aggregates
                    .get(aggregate_id as usize)
                    .map(|aggregate| aggregate.members.iter().map(|m| m.type_id).collect())
                    .unwrap_or_default()
            }
            SourceTypeKind::Code { signature_id } => self
                .signatures
                .get(signature_id as usize)
                .map(|signature| {
                    std::iter::once(signature.return_type_id)
                        .chain(signature.parameter_type_ids.iter().copied())
                        .collect()
                })
                .unwrap_or_default(),
            SourceTypeKind::SignedInteger
            | SourceTypeKind::UnsignedInteger
            | SourceTypeKind::Float
            | SourceTypeKind::Void
            | SourceTypeKind::Opaque { .. } => Vec::new(),
        }
    }

    /// Every node the roots reach, in increasing id.
    fn reached(&self, roots: impl IntoIterator<Item = u32>) -> BTreeSet<u32> {
        let mut reached = BTreeSet::new();
        let mut pending = roots
            .into_iter()
            .filter(|root| self.get(*root).is_some())
            .collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if reached.insert(id) {
                pending.extend(self.successors(id));
            }
        }
        reached
    }

    /// The graph of what `roots` reach, renumbered in the order the nodes had.
    ///
    /// A valid graph's closure is valid: every node it keeps names only nodes
    /// it keeps, so this never refuses. A root that is not a node here is not
    /// one of the closure's either. Renumbering by the original order keeps a
    /// graph that was already closed exactly as it was.
    pub fn closure(&self, roots: impl IntoIterator<Item = u32>) -> SourceTypeClosure {
        let reached = self.reached(roots);
        let renumbered = reached
            .iter()
            .enumerate()
            .map(|(position, id)| (*id, position as u32))
            .collect::<BTreeMap<_, _>>();
        let kept = Renumbering::new(self, &reached);
        let graph = Self {
            schema_version: self.schema_version,
            types: kept.types(&renumbered).into_boxed_slice(),
            aggregates: kept.aggregates(&renumbered).into_boxed_slice(),
            signatures: kept.signatures(&renumbered).into_boxed_slice(),
            opaque_tags: kept.opaque_tags().into_boxed_slice(),
            aliases: self
                .aliases
                .iter()
                .filter_map(|alias| {
                    Some(SourceTypeAlias::new(
                        alias.name.clone(),
                        *renumbered.get(&alias.type_id)?,
                    ))
                })
                .collect(),
        };
        SourceTypeClosure { graph, renumbered }
    }

    /// Whether a node of this graph is an object something can be declared as.
    pub(crate) fn names_object(&self, id: u32) -> bool {
        self.get(id).is_some_and(|ty| ty.kind.is_sized())
    }
}

/// Which aggregate, signature and tag rows a closure keeps, and their new ids.
struct Renumbering<'a> {
    graph: &'a SourceTypeGraph,
    reached: &'a BTreeSet<u32>,
    aggregates: BTreeMap<u32, u32>,
    signatures: BTreeMap<u32, u32>,
    tags: BTreeMap<u32, u32>,
}

impl<'a> Renumbering<'a> {
    fn new(graph: &'a SourceTypeGraph, reached: &'a BTreeSet<u32>) -> Self {
        let mut aggregates = BTreeMap::new();
        let mut signatures = BTreeMap::new();
        let mut tags = BTreeMap::new();
        for id in reached {
            let Some(source_type) = graph.get(*id) else {
                continue;
            };
            let (table, row) = match source_type.kind {
                SourceTypeKind::Struct { aggregate_id }
                | SourceTypeKind::Union { aggregate_id } => (&mut aggregates, aggregate_id),
                SourceTypeKind::Code { signature_id } => (&mut signatures, signature_id),
                SourceTypeKind::Opaque { tag_id } => (&mut tags, tag_id),
                _ => continue,
            };
            let next = table.len() as u32;
            table.entry(row).or_insert(next);
        }
        Self {
            graph,
            reached,
            aggregates,
            signatures,
            tags,
        }
    }

    fn types(&self, renumbered: &BTreeMap<u32, u32>) -> Vec<SourceType> {
        let map = |id: u32| renumbered.get(&id).copied().unwrap_or(id);
        self.reached
            .iter()
            .filter_map(|id| self.graph.get(*id))
            .map(|source_type| {
                let kind = match source_type.kind {
                    SourceTypeKind::Pointer { target_type_id } => SourceTypeKind::Pointer {
                        target_type_id: map(target_type_id),
                    },
                    SourceTypeKind::Array {
                        element_type_id,
                        count,
                    } => SourceTypeKind::Array {
                        element_type_id: map(element_type_id),
                        count,
                    },
                    SourceTypeKind::Struct { aggregate_id } => SourceTypeKind::Struct {
                        aggregate_id: self.aggregates[&aggregate_id],
                    },
                    SourceTypeKind::Union { aggregate_id } => SourceTypeKind::Union {
                        aggregate_id: self.aggregates[&aggregate_id],
                    },
                    SourceTypeKind::Code { signature_id } => SourceTypeKind::Code {
                        signature_id: self.signatures[&signature_id],
                    },
                    SourceTypeKind::Opaque { tag_id } => SourceTypeKind::Opaque {
                        tag_id: self.tags[&tag_id],
                    },
                    other => other,
                };
                SourceType::new(
                    map(source_type.id),
                    kind,
                    source_type.size_bits,
                    source_type.align_bits,
                )
            })
            .collect()
    }

    fn aggregates(&self, renumbered: &BTreeMap<u32, u32>) -> Vec<SourceAggregateLayout> {
        let mut kept = self.rows(&self.aggregates, &self.graph.aggregates);
        for aggregate in &mut kept {
            aggregate.id = self.aggregates[&aggregate.id];
            aggregate.type_id = renumbered[&aggregate.type_id];
            for member in aggregate.members.iter_mut() {
                member.type_id = renumbered[&member.type_id];
            }
        }
        kept
    }

    fn signatures(&self, renumbered: &BTreeMap<u32, u32>) -> Vec<SourceCodeSignature> {
        let mut kept = self.rows(&self.signatures, &self.graph.signatures);
        for signature in &mut kept {
            signature.id = self.signatures[&signature.id];
            signature.return_type_id = renumbered[&signature.return_type_id];
            for parameter in signature.parameter_type_ids.iter_mut() {
                *parameter = renumbered[parameter];
            }
        }
        kept
    }

    fn opaque_tags(&self) -> Vec<SourceOpaqueTag> {
        let mut kept = self.rows(&self.tags, &self.graph.opaque_tags);
        for tag in &mut kept {
            tag.id = self.tags[&tag.id];
        }
        kept
    }

    /// The rows a table keeps, in their new order.
    fn rows<T: Clone>(&self, table: &BTreeMap<u32, u32>, rows: &[T]) -> Vec<T> {
        let mut ordered = table.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|(_, new)| **new);
        ordered
            .into_iter()
            .filter_map(|(old, _)| rows.get(*old as usize).cloned())
            .collect()
    }
}

fn validate(parts: &SourceTypeGraphParts) -> Result<(), SourceTypeGraphError> {
    for (position, source_type) in parts.types.iter().enumerate() {
        if u32::try_from(position) != Ok(source_type.id) {
            return Err(SourceTypeGraphError::InvalidType);
        }
        validate_type(source_type, parts)?;
    }
    let mut owners = BTreeSet::new();
    for (position, aggregate) in parts.aggregates.iter().enumerate() {
        validate_aggregate(position, aggregate, parts)?;
        if !owners.insert(aggregate.type_id) {
            return Err(SourceTypeGraphError::InvalidAggregate);
        }
    }
    // Every struct or union type owns exactly one aggregate.
    let owning_types = parts
        .types
        .iter()
        .filter(|ty| {
            matches!(
                ty.kind,
                SourceTypeKind::Struct { .. } | SourceTypeKind::Union { .. }
            )
        })
        .count();
    if owning_types != parts.aggregates.len() {
        return Err(SourceTypeGraphError::InvalidAggregate);
    }
    for (position, signature) in parts.signatures.iter().enumerate() {
        validate_signature(position, signature, parts)?;
    }
    for (position, tag) in parts.opaque_tags.iter().enumerate() {
        if u32::try_from(position) != Ok(tag.id) || !is_identifier(&tag.name) {
            return Err(SourceTypeGraphError::InvalidTag);
        }
    }
    validate_aliases(parts)
}

fn type_at(parts: &SourceTypeGraphParts, id: u32) -> Option<&SourceType> {
    parts.types.get(usize::try_from(id).ok()?)
}

/// Whether a size and an alignment are a consistent statement of an object:
/// whole bytes, a power-of-two alignment, and a size that is a multiple of
/// it. Nothing says the alignment is the size's.
fn sized_consistently(size_bits: u64, align_bits: u64) -> bool {
    size_bits > 0
        && size_bits.is_multiple_of(8)
        && align_bits >= 8
        && align_bits.is_power_of_two()
        && size_bits.is_multiple_of(align_bits)
}

fn validate_type(
    source_type: &SourceType,
    parts: &SourceTypeGraphParts,
) -> Result<(), SourceTypeGraphError> {
    let (size, align) = (source_type.size_bits, source_type.align_bits);
    let valid = match source_type.kind {
        SourceTypeKind::Void => size == 0 && align == 0,
        SourceTypeKind::Code { signature_id } => {
            size == 0 && align == 0 && (signature_id as usize) < parts.signatures.len()
        }
        SourceTypeKind::Opaque { tag_id } => {
            size == 0 && align == 0 && (tag_id as usize) < parts.opaque_tags.len()
        }
        SourceTypeKind::SignedInteger | SourceTypeKind::UnsignedInteger => {
            sized_consistently(size, align) && matches!(size, 8 | 16 | 32 | 64 | 128)
        }
        // binary16 through binary128, and the x87 extended format in the
        // ten bytes it is, or the twelve or sixteen a target stores it in.
        SourceTypeKind::Float => {
            sized_consistently(size, align) && matches!(size, 16 | 32 | 64 | 80 | 96 | 128)
        }
        SourceTypeKind::Pointer { target_type_id } => {
            sized_consistently(size, align)
                && matches!(size, 32 | 64)
                && type_at(parts, target_type_id).is_some()
        }
        SourceTypeKind::Struct { aggregate_id } | SourceTypeKind::Union { aggregate_id } => {
            sized_consistently(size, align) && (aggregate_id as usize) < parts.aggregates.len()
        }
        SourceTypeKind::Array {
            element_type_id,
            count,
        } => array_is_consistent(size, align, element_type_id, count, parts),
    };
    match valid {
        true => Ok(()),
        false => Err(SourceTypeGraphError::InvalidType),
    }
}

/// An array is its element, `count` times; one with no count has no size and
/// the element's alignment.
fn array_is_consistent(
    size: u64,
    align: u64,
    element: u32,
    count: Option<u64>,
    parts: &SourceTypeGraphParts,
) -> bool {
    let Some(element) = type_at(parts, element).filter(|element| element.kind.is_sized()) else {
        return false;
    };
    if align != element.align_bits {
        return false;
    }
    match count {
        None => size == 0,
        Some(count) => count > 0 && element.size_bits.checked_mul(count) == Some(size),
    }
}

fn validate_aggregate(
    position: usize,
    aggregate: &SourceAggregateLayout,
    parts: &SourceTypeGraphParts,
) -> Result<(), SourceTypeGraphError> {
    let owner = type_at(parts, aggregate.type_id).filter(|owner| {
        owner.size_bits == aggregate.size_bits && owner.align_bits == aggregate.align_bits
    });
    let is_union = match owner.map(SourceType::kind) {
        Some(SourceTypeKind::Struct { aggregate_id }) if aggregate_id == aggregate.id => false,
        Some(SourceTypeKind::Union { aggregate_id }) if aggregate_id == aggregate.id => true,
        _ => {
            r2il::refusal_evidence!(
                "type-graph",
                "aggregate {} ({}) has no owning type of its kind, size and alignment",
                aggregate.id,
                aggregate.name
            );
            return Err(SourceTypeGraphError::InvalidAggregate);
        }
    };
    if u32::try_from(position) != Ok(aggregate.id) {
        return Err(SourceTypeGraphError::InvalidAggregate);
    }
    let mut end = 0u64;
    let last = aggregate.members.len().saturating_sub(1);
    for (index, member) in aggregate.members.iter().enumerate() {
        let flexible_allowed = !is_union && index == last;
        let extent = member_extent(index, member, flexible_allowed, parts)?;
        let (start, stop) = (member.offset_bits, member.offset_bits + extent);
        // A struct lays its members out in turn, none over another; a union
        // lays every one at its start.
        let placed = match is_union {
            true => start == 0,
            false => start >= end,
        };
        if !placed || stop > aggregate.size_bits {
            r2il::refusal_evidence!(
                "type-graph",
                "aggregate {} ({}) member {} spans [{start}, {stop}) after {end} in {} bits",
                aggregate.id,
                aggregate.name,
                member.name,
                aggregate.size_bits
            );
            return Err(SourceTypeGraphError::InvalidMember);
        }
        end = end.max(stop);
    }
    Ok(())
}

/// The bits one member occupies, where it is a member its record can have.
fn member_extent(
    index: usize,
    member: &SourceAggregateMember,
    flexible_allowed: bool,
    parts: &SourceTypeGraphParts,
) -> Result<u64, SourceTypeGraphError> {
    let member_type = type_at(parts, member.type_id).ok_or(SourceTypeGraphError::InvalidMember)?;
    if u32::try_from(index) != Ok(member.member_id)
        || member.offset_bits.checked_add(member.size_bits).is_none()
    {
        return Err(SourceTypeGraphError::InvalidMember);
    }
    let valid = match (member.bit_field, member_type.kind) {
        (true, SourceTypeKind::SignedInteger | SourceTypeKind::UnsignedInteger) => {
            member.size_bits > 0 && member.size_bits <= member_type.size_bits
        }
        (true, _) => false,
        (false, SourceTypeKind::Array { count: None, .. }) => {
            flexible_allowed && member.size_bits == 0 && member.offset_bits.is_multiple_of(8)
        }
        (false, kind) => {
            kind.is_sized()
                && member.size_bits > 0
                && member.size_bits.is_multiple_of(member_type.size_bits)
                && member.offset_bits.is_multiple_of(8)
        }
    };
    match valid {
        true => Ok(member.size_bits),
        false => Err(SourceTypeGraphError::InvalidMember),
    }
}

fn validate_signature(
    position: usize,
    signature: &SourceCodeSignature,
    parts: &SourceTypeGraphParts,
) -> Result<(), SourceTypeGraphError> {
    let returns = type_at(parts, signature.return_type_id);
    let returns_ok =
        returns.is_some_and(|ty| ty.kind == SourceTypeKind::Void || ty.kind.is_sized());
    let parameters_ok = signature
        .parameter_type_ids
        .iter()
        .all(|id| type_at(parts, *id).is_some_and(|ty| ty.kind.is_sized()));
    let stated_only_if_prototyped =
        signature.prototyped || (signature.parameter_type_ids.is_empty() && !signature.variadic);
    match u32::try_from(position) == Ok(signature.id)
        && returns_ok
        && parameters_ok
        && stated_only_if_prototyped
    {
        true => Ok(()),
        false => Err(SourceTypeGraphError::InvalidSignature),
    }
}

fn is_identifier(name: &str) -> bool {
    name.starts_with(|ch: char| ch == '_' || ch.is_ascii_alphabetic())
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// A name binds one of this graph's types and binds it once. A name that
/// resolved to two types would make the rendering's declaration of it a coin
/// toss, which is worse than not spelling the name at all.
fn validate_aliases(parts: &SourceTypeGraphParts) -> Result<(), SourceTypeGraphError> {
    let mut named = BTreeSet::new();
    for alias in &parts.aliases {
        if !is_identifier(&alias.name)
            || type_at(parts, alias.type_id).is_none()
            || !named.insert(alias.name.as_str())
        {
            return Err(SourceTypeGraphError::InvalidAlias);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
