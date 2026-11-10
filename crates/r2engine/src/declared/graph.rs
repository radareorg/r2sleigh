//! A declaration's types, as the graph an interface carries (the one conversion, D168).
//!
//! Each node is placed on its own. A node the interface contract cannot state
//! -- a record with no name to define it by, a signature that names such a
//! record, a scalar whose width the target leaves open -- costs what reaches
//! it and nothing else: a member of it is left out of its record as padding, a
//! pointer to it points at `void`, and a parameter or local of it carries no
//! type. The graph is interned per item, and the interface closes it over
//! what it names, so an item that is dropped later strands nothing.

use std::collections::{BTreeMap, BTreeSet};

use r2abi::{CDataModel, Keyword, Member, Qualifiers, Record, RecordKind, Scalar, ScalarKind};
use r2abi::{Signature, Type, TypeGraph, TypeId};
use r2source::{
    SourceAggregateLayout, SourceAggregateMember, SourceCarrierKind, SourceCarrierProjection,
    SourceCodeSignature, SourceLogicalValue, SourceOpaqueTag, SourceTagKeyword, SourceType,
    SourceTypeAlias, SourceTypeGraph, SourceTypeGraphParts, SourceTypeKind,
};

/// The interface's graph, built one declared node at a time.
pub(crate) struct Interned<'a> {
    graph: &'a TypeGraph,
    model: CDataModel,
    parts: SourceTypeGraphParts,
    /// Each declared node's place, or nothing where it has none.
    nodes: BTreeMap<TypeId, Option<u32>>,
    /// One node per scalar shape, and one `void`.
    leaves: BTreeMap<(u8, u64), u32>,
    /// One row per incomplete tag.
    tags: BTreeMap<(u8, String), u32>,
    /// Which declared record each aggregate name stands for: a consumer finds
    /// a layout by its name, so one name has one layout.
    names: BTreeMap<String, TypeId>,
    /// The node each typedef or scalar name stands at: the first binding of a name wins.
    named: BTreeMap<String, u32>,
    /// Nodes carrying an alias, so a record keeps its first name.
    aliased: BTreeSet<u32>,
    /// A named copy of a pointer still being placed, resynced at `finish`.
    copies: Vec<(u32, u32)>,
    /// Every record's node, which a name binds to even while its layout is placed.
    records: BTreeSet<u32>,
}

impl<'a> Interned<'a> {
    pub(crate) fn new(graph: &'a TypeGraph, model: CDataModel) -> Self {
        Self {
            graph,
            model,
            parts: SourceTypeGraphParts::default(),
            nodes: BTreeMap::new(),
            leaves: BTreeMap::new(),
            tags: BTreeMap::new(),
            names: BTreeMap::new(),
            named: BTreeMap::new(),
            aliased: BTreeSet::new(),
            copies: Vec::new(),
            records: BTreeSet::new(),
        }
    }

    /// A value of this type in a carrier of `carrier_bytes`: the carrier's
    /// low bits where the type is narrower.
    ///
    /// A declared type narrower than its carrier occupies the carrier's low
    /// bits and says so, which is what `int` in a 64-bit register is.
    pub(crate) fn value(&mut self, ty: TypeId, carrier_bytes: u32) -> Option<SourceLogicalValue> {
        let id = self.object(ty)?;
        let bits = self.parts.types[id as usize].size_bits();
        let kind = match bits == u64::from(carrier_bytes) * 8 {
            true => SourceCarrierKind::Full,
            false => SourceCarrierKind::LowBits,
        };
        Some(SourceLogicalValue::new(
            id,
            SourceCarrierProjection::new(kind, 0, bits),
        ))
    }

    /// A prototype's parameter or result: sized, `void`, or a tag or name the
    /// declaration leaves incomplete.
    pub(crate) fn declared(&mut self, ty: TypeId) -> Option<u32> {
        let id = self.node(ty)?;
        let source = &self.parts.types[id as usize];
        let stated = source.size_bits() > 0
            || matches!(source.kind(), SourceTypeKind::Opaque { .. })
            || self.graph.peel(ty).0 == TypeId::VOID;
        stated.then_some(id)
    }

    /// The node of a type something can be declared as: one with a size.
    pub(crate) fn object(&mut self, ty: TypeId) -> Option<u32> {
        let id = self.node(ty)?;
        let sized = self.parts.types[id as usize].size_bits() > 0;
        sized.then_some(id)
    }

    /// Every node interned so far, as a graph.
    pub(crate) fn finish(mut self) -> Option<SourceTypeGraph> {
        for (copy, structure) in std::mem::take(&mut self.copies) {
            let kind = self.parts.types[structure as usize].kind();
            let (size, align) = (
                self.size(copy),
                self.parts.types[copy as usize].align_bits(),
            );
            self.set(copy, kind, size, align);
        }
        SourceTypeGraph::from_parts(self.parts)
            .inspect_err(|error| {
                r2il::refusal_evidence!("declared-types", "the interned graph refused: {error:?}");
            })
            .ok()
    }

    /// One declared node's place: its structure, under the name it is declared by.
    pub(crate) fn node(&mut self, ty: TypeId) -> Option<u32> {
        let structure = self.structure(ty)?;
        match self.alias(ty) {
            Some(name) => Some(self.named(name, structure)),
            None => Some(structure),
        }
    }

    /// The outermost typedef name `ty` is declared by, or a scalar's own name (`size_t`); C's
    /// keywords and the `<stdint.h>` names the structure already spells are none.
    fn alias(&self, ty: TypeId) -> Option<String> {
        let mut at = ty;
        for _ in 0..self.graph.len() {
            match self.graph.get(at)? {
                Type::Qualified { target, .. } => at = *target,
                Type::Typedef { name, .. } => {
                    let named = is_identifier(name) && !r2types::spells_its_structure(name);
                    return named.then(|| name.clone());
                }
                Type::Scalar(Scalar {
                    name: Some(name), ..
                }) => {
                    let named = r2types::spelling_names_a_type(name)
                        && !r2types::spells_its_structure(name);
                    return named.then(|| name.clone());
                }
                _ => return None,
            }
        }
        None
    }

    /// The node `name` stands at over `structure`. A record carries the name
    /// itself; any other node is copied, so its structure stays unnamed.
    fn named(&mut self, name: String, structure: u32) -> u32 {
        if let Some(found) = self.named.get(&name) {
            return *found;
        }
        let source = &self.parts.types[structure as usize];
        let (kind, size, align) = (source.kind(), source.size_bits(), source.align_bits());
        let id = match kind {
            // A name the target's model leaves unstated is already its own tag.
            SourceTypeKind::Opaque { tag_id }
                if self.parts.opaque_tags[tag_id as usize].keyword()
                    == SourceTagKeyword::Typedef =>
            {
                return structure;
            }
            _ if self.records.contains(&structure) => {
                if !self.aliased.insert(structure) {
                    return structure;
                }
                structure
            }
            SourceTypeKind::Struct { .. } | SourceTypeKind::Union { .. } => {
                if !self.aliased.insert(structure) {
                    return structure;
                }
                structure
            }
            _ => {
                let copy = self.push(kind, size, align);
                self.copies.push((copy, structure));
                self.aliased.insert(copy);
                copy
            }
        };
        self.parts
            .aliases
            .push(SourceTypeAlias::new(name.clone(), id));
        self.named.insert(name, id);
        id
    }

    fn size(&self, id: u32) -> u64 {
        self.parts.types[id as usize].size_bits()
    }

    /// One declared node's structure, read through its names and qualifiers:
    /// neither changes a layout or a register class.
    fn structure(&mut self, ty: TypeId) -> Option<u32> {
        let (id, _) = self.graph.peel(ty);
        if let Some(found) = self.nodes.get(&id) {
            return *found;
        }
        let graph = self.graph;
        let placed = match graph.get(id)? {
            Type::Void => Some(self.leaf(SourceTypeKind::Void, 0, 0)),
            // A name over a scalar the target's model leaves unstated is that name alone.
            Type::Scalar(scalar) => (self.scalar(scalar)).or_else(|| {
                self.name_of(ty)
                    .map(|name| self.opaque(Keyword::Typedef, &name))
            }),
            Type::Enum { underlying, .. } => self.node(*underlying),
            Type::Pointer { target } => Some(self.pointer(id, *target)),
            Type::Array { element, count } => self.array(*element, *count),
            Type::Record(record) => Some(self.record(id, record)),
            Type::Code(signature) => self.code(signature),
            Type::Opaque { keyword, tag } => Some(self.opaque(*keyword, tag)),
            Type::Typedef { .. } | Type::Qualified { .. } | Type::Refused(_) => None,
        };
        self.nodes.insert(id, placed);
        placed
    }

    /// The innermost typedef name `ty` reaches through names and qualifiers.
    fn name_of(&self, ty: TypeId) -> Option<String> {
        let (mut at, mut name) = (ty, None);
        for _ in 0..self.graph.len() {
            match self.graph.get(at)? {
                Type::Typedef {
                    name: named,
                    target,
                } => (name, at) = (Some(named.clone()), *target),
                Type::Qualified { target, .. } => at = *target,
                _ => break,
            }
        }
        name
    }

    fn push(&mut self, kind: SourceTypeKind, size: u64, align: u64) -> u32 {
        let id = self.parts.types.len() as u32;
        self.parts
            .types
            .push(SourceType::new(id, kind, size, align));
        id
    }

    fn set(&mut self, id: u32, kind: SourceTypeKind, size: u64, align: u64) {
        self.parts.types[id as usize] = SourceType::new(id, kind, size, align);
    }

    fn leaf(&mut self, kind: SourceTypeKind, size: u64, align: u64) -> u32 {
        let shape = match kind {
            SourceTypeKind::SignedInteger => 0,
            SourceTypeKind::UnsignedInteger => 1,
            SourceTypeKind::Float => 2,
            SourceTypeKind::Char { signed: Some(true) } => 4,
            SourceTypeKind::Char {
                signed: Some(false),
            } => 5,
            SourceTypeKind::Char { signed: None } => 6,
            _ => 3,
        };
        if let Some(found) = self.leaves.get(&(shape, size)) {
            return *found;
        }
        let id = self.push(kind, size, align);
        self.leaves.insert((shape, size), id);
        id
    }

    fn scalar(&mut self, scalar: &Scalar) -> Option<u32> {
        let bits = u64::from(self.model.bits(scalar.width)?);
        if let Some(signed) = super::plain_char(scalar, &self.model) {
            return Some(self.leaf(
                SourceTypeKind::Char { signed },
                bits,
                natural_alignment(bits),
            ));
        }
        let (kind, stated) = match self.model.kind(scalar.kind)? {
            ScalarKind::Signed => (SourceTypeKind::SignedInteger, integer_width(bits)),
            ScalarKind::Unsigned | ScalarKind::Bool => {
                (SourceTypeKind::UnsignedInteger, integer_width(bits))
            }
            ScalarKind::Float => (
                SourceTypeKind::Float,
                matches!(bits, 16 | 32 | 64 | 80 | 96 | 128),
            ),
            // The model resolves both to a sign.
            ScalarKind::PlainChar | ScalarKind::WideChar => return None,
        };
        stated.then(|| self.leaf(kind, bits, natural_alignment(bits)))
    }

    /// A pointer, placed before its target so a record reaching itself
    /// through one closes on it. What it points at that has no place is
    /// `void`: the pointer is still a pointer.
    fn pointer(&mut self, id: TypeId, target: TypeId) -> u32 {
        let bits = u64::from(self.model.pointer_bits);
        let const_target = self.graph.peel(target).1.contains(Qualifiers::CONST);
        let placeholder = SourceTypeKind::Pointer {
            target_type_id: 0,
            const_target,
        };
        let pointer = self.push(placeholder, bits, bits);
        self.nodes.insert(id, Some(pointer));
        let target = match self.node(target) {
            Some(target) => target,
            None => self.leaf(SourceTypeKind::Void, 0, 0),
        };
        let kind = SourceTypeKind::Pointer {
            target_type_id: target,
            const_target,
        };
        self.set(pointer, kind, bits, bits);
        pointer
    }

    /// An array of a sized element. One with no bound, or GNU's zero-length
    /// one, has no size and is only a record's last member or a pointer's
    /// target, which the graph checks where it is used.
    fn array(&mut self, element: TypeId, count: Option<u64>) -> Option<u32> {
        let element = self.object(element)?;
        let element_type = &self.parts.types[element as usize];
        let (element_bits, align) = (element_type.size_bits(), element_type.align_bits());
        let count = count.filter(|count| *count > 0);
        let size = match count {
            Some(count) => element_bits.checked_mul(count)?,
            None => 0,
        };
        let kind = SourceTypeKind::Array {
            element_type_id: element,
            count,
        };
        Some(self.push(kind, size, align))
    }

    fn opaque(&mut self, keyword: Keyword, tag: &str) -> u32 {
        let (key, keyword) = match keyword {
            Keyword::Struct => (0, SourceTagKeyword::Struct),
            Keyword::Union => (1, SourceTagKeyword::Union),
            Keyword::Enum => (2, SourceTagKeyword::Enum),
            Keyword::Typedef => (3, SourceTagKeyword::Typedef),
        };
        let row = match self.tags.get(&(key, tag.to_owned())) {
            Some(row) => *row,
            None => {
                let row = self.parts.opaque_tags.len() as u32;
                self.parts
                    .opaque_tags
                    .push(SourceOpaqueTag::new(row, keyword, tag));
                self.tags.insert((key, tag.to_owned()), row);
                row
            }
        };
        self.push(SourceTypeKind::Opaque { tag_id: row }, 0, 0)
    }

    /// Code whose every stated part has a place. Anything less is code this
    /// graph cannot describe, and a pointer to it points at `void`.
    fn code(&mut self, signature: &Signature) -> Option<u32> {
        let returns = match self.graph.peel(signature.returns).0 {
            TypeId::VOID => self.leaf(SourceTypeKind::Void, 0, 0),
            returns => self.object(returns)?,
        };
        let parameters = signature
            .parameters
            .iter()
            .map(|parameter| self.object(*parameter))
            .collect::<Option<Vec<_>>>()?;
        let row = self.parts.signatures.len() as u32;
        self.parts.signatures.push(SourceCodeSignature::new(
            row,
            returns,
            parameters,
            signature.variadic,
            signature.prototyped,
        ));
        Some(self.push(SourceTypeKind::Code { signature_id: row }, 0, 0))
    }
}

/// Records, whose members may reach the record itself.
impl Interned<'_> {
    /// A record with the layout it states, placed before its members so a
    /// member pointing back at it names it. One the contract cannot state is
    /// its tag, incomplete, and one with no tag is nothing the graph
    /// describes.
    fn record(&mut self, id: TypeId, record: &Record) -> u32 {
        let slot = self.push(SourceTypeKind::Void, 0, 0);
        self.nodes.insert(id, Some(slot));
        self.records.insert(slot);
        let Some(tag) = record.tag.clone().filter(|tag| is_identifier(tag)) else {
            r2il::refusal_evidence!(
                "declared-types",
                "a record with no name of its own to define it by is left undescribed"
            );
            return slot;
        };
        // A consumer finds a layout by its name, so a second record of one
        // name is that tag and no layout.
        let own_name = self.names.get(&tag).is_none_or(|own| *own == id);
        if own_name && self.layout(slot, &tag, record).is_some() {
            self.names.insert(tag, id);
            return slot;
        }
        let keyword = match record.kind {
            RecordKind::Struct => Keyword::Struct,
            RecordKind::Union => Keyword::Union,
        };
        let opaque = self.opaque(keyword, &tag);
        let kind = self.parts.types[opaque as usize].kind();
        // The slot stands for the record; the node just pushed is the same
        // tag, and nothing names it.
        self.parts.types.pop();
        self.set(slot, kind, 0, 0);
        slot
    }

    /// The record's layout as the next aggregate row, where it is one.
    fn layout(&mut self, slot: u32, tag: &str, record: &Record) -> Option<()> {
        let size = record.size_bytes.checked_mul(8).filter(|size| *size > 0)?;
        let last = record.members.len().saturating_sub(1);
        let mut members = Vec::new();
        for (index, member) in record.members.iter().enumerate() {
            let flexible = record.kind == RecordKind::Struct && index == last;
            if let Some(placed) = self.member(members.len() as u32, member, flexible) {
                members.push(placed);
            }
        }
        let align = self.alignment(size, &members);
        let row = self.parts.aggregates.len() as u32;
        let kind = match record.kind {
            RecordKind::Struct => SourceTypeKind::Struct { aggregate_id: row },
            RecordKind::Union => SourceTypeKind::Union { aggregate_id: row },
        };
        self.set(slot, kind, size, align);
        let aggregate = SourceAggregateLayout::new(row, slot, size, align, tag, members);
        if !self.parts.aggregate_is_consistent(&aggregate) {
            r2il::refusal_evidence!(
                "declared-types",
                "{tag}: the layout it states is not one a record can have"
            );
            return None;
        }
        self.parts.aggregates.push(aggregate);
        Some(())
    }

    /// One member at the place the declaration gives it. A member with no
    /// name is padding to everything else, and so is one whose type has no
    /// place.
    fn member(
        &mut self,
        id: u32,
        member: &Member,
        flexible: bool,
    ) -> Option<SourceAggregateMember> {
        let name = member.name.as_deref()?;
        let ty = self.node(member.ty)?;
        let source = &self.parts.types[ty as usize];
        let integer = matches!(
            source.kind(),
            SourceTypeKind::SignedInteger
                | SourceTypeKind::UnsignedInteger
                | SourceTypeKind::Char { .. }
        );
        match (member.bit_size, source.kind()) {
            (Some(bits), _) => integer.then(|| {
                SourceAggregateMember::new_bit_field(id, ty, member.offset_bits, bits, name)
            }),
            (None, SourceTypeKind::Array { count: None, .. }) => {
                flexible.then(|| SourceAggregateMember::new(id, ty, member.offset_bits, 0, name))
            }
            (None, _) => (source.size_bits() > 0).then(|| {
                SourceAggregateMember::new(id, ty, member.offset_bits, source.size_bits(), name)
            }),
        }
    }

    /// The alignment the stated layout shows: the widest member's own, no
    /// more than every member offset and the size agree with. A packed
    /// record's members sit at offsets that pull it down to what they allow,
    /// and an i386 `double` at four bytes does the same; the layout is the
    /// evidence, not the members' natural alignment.
    fn alignment(&self, size: u64, members: &[SourceAggregateMember]) -> u64 {
        let natural = members
            .iter()
            .map(|member| self.parts.types[member.type_id() as usize].align_bits())
            .max()
            .unwrap_or(8)
            .max(8);
        let mut align = natural;
        while align > 8
            && (!size.is_multiple_of(align)
                || members.iter().any(|member| {
                    !member.is_bit_field() && !member.offset_bits().is_multiple_of(align)
                }))
        {
            align /= 2;
        }
        align
    }
}

const fn integer_width(bits: u64) -> bool {
    matches!(bits, 8 | 16 | 32 | 64 | 128)
}

/// The largest power of two dividing a scalar's width, and at least a byte.
const fn natural_alignment(bits: u64) -> u64 {
    let lowest = bits.isolate_lowest_one();
    if lowest < 8 { 8 } else { lowest }
}

fn is_identifier(name: &str) -> bool {
    name.starts_with(|ch: char| ch == '_' || ch.is_ascii_alphabetic())
        && name
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2abi::{Qualifiers, Width};

    fn int(graph: &mut TypeGraph) -> TypeId {
        graph.add(Type::Scalar(Scalar {
            kind: ScalarKind::Signed,
            width: Width::Bits(32),
            name: Some("int".to_owned()),
        }))
    }

    /// `const struct node *` where `struct node { int key; struct node *next;
    /// char tag[8]; }`: the pointer, the record and the cycle through `next`
    /// each have a place, and the record's layout is the one it states.
    #[test]
    fn a_pointer_to_a_record_that_reaches_itself_is_placed_whole() {
        let mut graph = TypeGraph::new();
        let int = int(&mut graph);
        let char_ = graph.add(Type::Scalar(Scalar {
            kind: ScalarKind::Signed,
            width: Width::Bits(8),
            name: Some("char".to_owned()),
        }));
        let tag = graph.add(Type::Array {
            element: char_,
            count: Some(8),
        });
        let node = graph.reserve();
        let next = graph.add(Type::Pointer { target: node });
        let member = |name: &str, ty, offset_bits| Member {
            name: Some(name.to_owned()),
            ty,
            offset_bits,
            bit_size: None,
        };
        graph.define(
            node,
            Type::Record(Record {
                kind: RecordKind::Struct,
                tag: Some("node".to_owned()),
                size_bytes: 24,
                members: vec![
                    member("key", int, 0),
                    member("next", next, 64),
                    member("tag", tag, 128),
                ],
            }),
        );
        let constant = graph.add(Type::Qualified {
            qualifiers: Qualifiers::CONST,
            target: node,
        });
        let parameter = graph.add(Type::Pointer { target: constant });

        let mut interned = Interned::new(&graph, CDataModel::unix(64));
        let value = interned.value(parameter, 8).expect("a pointer is placed");
        let local = interned.object(int).expect("an int is placed");
        let placed = interned.finish().expect("the graph states");
        let SourceTypeKind::Pointer { target_type_id, .. } =
            placed.types()[value.type_id() as usize].kind()
        else {
            panic!("{placed:?}");
        };
        let SourceTypeKind::Struct { aggregate_id } =
            placed.types()[target_type_id as usize].kind()
        else {
            panic!("{placed:?}");
        };
        let layout = &placed.aggregates()[aggregate_id as usize];
        assert_eq!(layout.name(), "node");
        assert_eq!(layout.size_bits(), 192);
        let offsets = layout
            .members()
            .iter()
            .map(|member| (member.name(), member.offset_bits()))
            .collect::<Vec<_>>();
        assert_eq!(offsets, [("key", 0), ("next", 64), ("tag", 128)]);
        // `next` points back at the node the parameter points at.
        assert_eq!(
            placed.types()[layout.members()[1].type_id() as usize].kind(),
            SourceTypeKind::Pointer {
                target_type_id,
                const_target: false
            }
        );
        // The parameter's pointee is `const`; `next`'s is not.
        assert!(matches!(
            placed.types()[value.type_id() as usize].kind(),
            SourceTypeKind::Pointer {
                const_target: true,
                ..
            }
        ));
        assert_eq!(
            placed.types()[local as usize].kind(),
            SourceTypeKind::SignedInteger
        );
    }

    /// A record this contract cannot define -- it has no name -- costs the
    /// pointer to it its pointee, and nothing else: the `int` beside it keeps
    /// its type.
    #[test]
    fn an_unplaceable_node_degrades_only_what_reaches_it() {
        let mut graph = TypeGraph::new();
        let int = int(&mut graph);
        let anonymous = graph.add(Type::Record(Record {
            kind: RecordKind::Struct,
            tag: None,
            size_bytes: 4,
            members: vec![],
        }));
        let pointer = graph.add(Type::Pointer { target: anonymous });
        let mut interned = Interned::new(&graph, CDataModel::unix(64));
        let pointer = interned.value(pointer, 8).expect("the pointer is placed");
        assert!(interned.object(anonymous).is_none());
        let int = interned.value(int, 8).expect("the int is placed");
        let placed = interned.finish().expect("the graph states");
        let SourceTypeKind::Pointer { target_type_id, .. } =
            placed.types()[pointer.type_id() as usize].kind()
        else {
            panic!("{placed:?}");
        };
        assert_eq!(
            placed.types()[target_type_id as usize].kind(),
            SourceTypeKind::Void
        );
        assert_eq!(int.carrier().kind(), SourceCarrierKind::LowBits);
    }

    /// One declared node through the graph and the one converter.
    fn converted(graph: &TypeGraph, ty: TypeId, model: CDataModel) -> r2types::CTypeLike {
        let mut interned = Interned::new(graph, model);
        let id = interned.node(ty).expect("the node is placed");
        let placed = interned.finish().expect("the graph states");
        r2types::source_type_like(&placed, id).expect("the type converts")
    }

    fn char_pointer(signedness: r2types::Signedness) -> r2types::CTypeLike {
        use r2types::CTypeLike;
        let char_ = CTypeLike::named(
            "char",
            CTypeLike::Int {
                bits: 8,
                signedness,
            },
        );
        CTypeLike::Pointer(Box::new(CTypeLike::Const(Box::new(char_))))
    }

    /// `strlen`'s `const char *`: the byte's sign is the model's, or none; DWARF's own `char`
    /// states its sign, which no model overrides.
    #[test]
    fn a_rows_plain_char_takes_the_models_sign_and_debug_information_keeps_its_own() {
        use r2abi::{CLibrary, LibraryRows};
        use r2types::Signedness;
        let rows = LibraryRows::embedded(CLibrary::Glibc);
        let strlen = rows
            .find(CLibrary::Glibc.scope(), "strlen")
            .expect("strlen");
        let parameter = rows.prototype(strlen).parameters[0].ty;
        let aarch64 = *CDataModel::of("aarch64", 64, CLibrary::Glibc).expect("AAPCS64 glibc");
        let x86_64 = *CDataModel::of("x86-64", 64, CLibrary::Glibc).expect("SysV glibc");
        let unix = CDataModel::unix(64);
        let of = |model| converted(rows.graph(), parameter, model);
        assert_eq!(of(aarch64), char_pointer(Signedness::Unsigned));
        assert_eq!(of(x86_64), char_pointer(Signedness::Signed));
        assert_eq!(of(unix), char_pointer(Signedness::Unknown));
        let mut graph = TypeGraph::new();
        let stated = graph.add(Type::Scalar(Scalar {
            kind: ScalarKind::Signed,
            width: Width::Bits(8),
            name: Some("char".to_owned()),
        }));
        assert_eq!(
            converted(&graph, stated, aarch64),
            r2types::CTypeLike::plain_char(Some(true))
        );
    }

    /// glibc's `FILE` keeps its name over its tag, `size_t` over its width, and `va_list` over
    /// the pointer it is passed as.
    #[test]
    fn a_name_stands_over_its_structure() {
        use r2abi::{CLibrary, LibraryRows};
        use r2types::{CTypeLike, Signedness};
        let rows = LibraryRows::embedded(CLibrary::Glibc);
        let model = *CDataModel::of("x86-64", 64, CLibrary::Glibc).expect("SysV glibc");
        let parameter = |name: &str, index: usize| {
            let row = rows.find(CLibrary::Glibc.scope(), name).expect("a row");
            converted(
                rows.graph(),
                rows.prototype(row).parameters[index].ty,
                model,
            )
        };
        let file = CTypeLike::named("FILE", CTypeLike::Struct("_IO_FILE".to_owned()));
        assert_eq!(parameter("fclose", 0), CTypeLike::Pointer(Box::new(file)));
        let size = CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Unsigned,
        };
        assert_eq!(parameter("malloc", 0), CTypeLike::named("size_t", size));
        let list = parameter("vfprintf", 2);
        assert!(
            matches!(&list, CTypeLike::Typedef { name, ty } if name == "va_list" && ty.is_pointer()),
            "{list:?}"
        );
    }

    /// `typedef struct node node; struct node { node *next; };`: the alias reached while the
    /// record is still being placed names the record, and the graph states.
    #[test]
    fn a_typedef_a_record_reaches_through_itself_names_the_record() {
        use r2types::CTypeLike;
        let mut graph = TypeGraph::new();
        let record = graph.reserve();
        let node = graph.add(Type::Typedef {
            name: "node".to_owned(),
            target: record,
        });
        let next = graph.add(Type::Pointer { target: node });
        graph.define(
            record,
            Type::Record(Record {
                kind: RecordKind::Struct,
                tag: Some("node".to_owned()),
                size_bytes: 8,
                members: vec![Member {
                    name: Some("next".to_owned()),
                    ty: next,
                    offset_bits: 0,
                    bit_size: None,
                }],
            }),
        );
        // `struct node *` reaches the record first, and `next` names it while it is placed.
        let parameter = graph.add(Type::Pointer { target: record });
        let named = CTypeLike::named("node", CTypeLike::Struct("node".to_owned()));
        assert_eq!(
            converted(&graph, parameter, CDataModel::unix(64)),
            CTypeLike::Pointer(Box::new(named))
        );
    }
}
