//! What the binary's own debug information declares.
//!
//! Every type the entries describe becomes one node of an
//! [`r2abi::TypeGraph`], read once and remembered by the entry it came from,
//! so a type that reaches itself through a pointer closes on its own node
//! rather than being spelled until something gives up. Every attribute is read
//! through the entry's origins: a concrete function states its code and its
//! frame and leaves its name and its types to the abstract instance or the
//! declaration it completes, and reading only the entry in hand lost every
//! clone and every out-of-line definition.
//!
//! A function is declared at the address its body begins, an object at the
//! address it occupies. Nothing here is keyed by name, because nothing a name
//! reaches is unique.
//!
//! It refuses one node at a time. A type the entries do not complete is
//! opaque, a type this reading cannot state is refused, and either costs only
//! what reaches it: a member of that type, a parameter, a local. The rest of
//! the declaration stands.

use std::collections::{BTreeMap, BTreeSet};

use gimli::{AttributeValue, DwAt};
use r2abi::{
    Arrival, DataModel, DataObject, Declarations, FrameBase, Keyword, Local, Member, Parameter,
    Prototype, Qualifiers, Record, RecordKind, Scalar, ScalarKind, Signature, Type, TypeGraph,
    TypeId, Width,
};

type Slice<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;
type Entry<'a> = gimli::DebuggingInformationEntry<Slice<'a>>;
type Value<'a> = AttributeValue<Slice<'a>>;

/// Read every declaration the debug information states.
///
/// A binary with no debug information answers with nothing, which is the same
/// answer as one whose debug information the walk could not read: neither
/// states a declaration, and the engine renders machine types as it did
/// before.
pub(crate) fn read(file: &object::File<'_>) -> Declarations {
    use object::{Object as _, ObjectSection as _};
    let endian = match file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };
    let load = |id: gimli::SectionId| -> Result<Slice<'_>, ()> {
        let data = file
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, endian))
    };
    let Ok(dwarf) = gimli::Dwarf::load(load) else {
        return Declarations::default();
    };
    let units = Units::load(&dwarf);
    Reader::new(&units, endian).read()
}

/// One entry, by the unit it is in and its offset there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Die {
    unit: usize,
    offset: usize,
}

/// Every unit, and what a reference from one to another needs.
struct Units<'d, 'a> {
    dwarf: &'d gimli::Dwarf<Slice<'a>>,
    units: Vec<gimli::Unit<Slice<'a>>>,
    /// Where each `.debug_info` unit begins, in order, for `DW_FORM_ref_addr`.
    info: Vec<(usize, usize)>,
    /// The type each type unit defines, by its signature, for
    /// `DW_FORM_ref_sig8`.
    signatures: BTreeMap<u64, Die>,
}

impl<'d, 'a> Units<'d, 'a> {
    fn load(dwarf: &'d gimli::Dwarf<Slice<'a>>) -> Self {
        let mut loaded = Self {
            dwarf,
            units: Vec::new(),
            info: Vec::new(),
            signatures: BTreeMap::new(),
        };
        let mut headers = dwarf.units();
        while let Ok(Some(header)) = headers.next() {
            loaded.add(header);
        }
        let mut types = dwarf.type_units();
        while let Ok(Some(header)) = types.next() {
            loaded.add(header);
        }
        loaded.info.sort_unstable();
        loaded
    }

    fn add(&mut self, header: gimli::UnitHeader<Slice<'a>>) {
        let start = header.debug_info_offset().map(|offset| offset.0);
        let Ok(unit) = self.dwarf.unit(header) else {
            return;
        };
        let index = self.units.len();
        if let Some(start) = start {
            self.info.push((start, index));
        }
        if let gimli::UnitType::Type {
            type_signature,
            type_offset,
        }
        | gimli::UnitType::SplitType {
            type_signature,
            type_offset,
        } = unit.header.type_()
        {
            self.signatures.insert(
                type_signature.0,
                Die {
                    unit: index,
                    offset: type_offset.0,
                },
            );
        }
        self.units.push(unit);
    }

    fn entry(&self, die: Die) -> Option<Entry<'a>> {
        self.units
            .get(die.unit)?
            .entry(gimli::UnitOffset(die.offset))
            .ok()
    }

    /// The entry a reference names, in whichever unit it is in.
    fn resolve(&self, owner: Die, value: Value<'a>) -> Option<Die> {
        match value {
            AttributeValue::UnitRef(offset) => Some(Die {
                unit: owner.unit,
                offset: offset.0,
            }),
            AttributeValue::DebugInfoRef(offset) => {
                let position = self.info.partition_point(|(start, _)| *start <= offset.0);
                let (_, unit) = *self.info.get(position.checked_sub(1)?)?;
                let local = offset.to_unit_offset(&self.units[unit].header)?;
                Some(Die {
                    unit,
                    offset: local.0,
                })
            }
            AttributeValue::DebugTypesRef(signature) => self.signatures.get(&signature.0).copied(),
            _ => None,
        }
    }

    /// An entry's children, in order, with their tags.
    fn children(&self, die: Die) -> Vec<(Die, gimli::DwTag)> {
        let mut found = Vec::new();
        let Some(unit) = self.units.get(die.unit) else {
            return found;
        };
        let Ok(mut tree) = unit.entries_tree(Some(gimli::UnitOffset(die.offset))) else {
            return found;
        };
        let Ok(root) = tree.root() else {
            return found;
        };
        let mut children = root.children();
        while let Ok(Some(child)) = children.next() {
            let entry = child.entry();
            found.push((
                Die {
                    unit: die.unit,
                    offset: entry.offset().0,
                },
                entry.tag(),
            ));
        }
        found
    }

    fn string(&self, owner: Die, value: Value<'a>) -> Option<String> {
        let unit = self.units.get(owner.unit)?;
        let slice = self.dwarf.attr_string(unit, value).ok()?;
        gimli::Reader::to_string(&slice)
            .ok()
            .map(|text| text.to_string())
    }

    fn address(&self, owner: Die, value: Value<'a>) -> Option<u64> {
        let unit = self.units.get(owner.unit)?;
        self.dwarf.attr_address(unit, value).ok().flatten()
    }

    /// The address ranges an entry covers, in the order it lists them.
    fn ranges(&self, die: Die) -> Vec<std::ops::Range<u64>> {
        let (Some(unit), Some(entry)) = (self.units.get(die.unit), self.entry(die)) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        if let Ok(mut ranges) = self.dwarf.die_ranges(unit, &entry) {
            while let Ok(Some(range)) = ranges.next() {
                if range.begin < range.end {
                    found.push(range.begin..range.end);
                }
            }
        }
        found
    }

    /// What pointers are in this unit: its address size.
    fn model(&self, unit: usize) -> DataModel {
        let bits = self
            .units
            .get(unit)
            .map_or(64, |unit| u32::from(unit.header.address_size()) * 8);
        DataModel::unix(bits)
    }
}

/// The declaration being read, and every node read so far.
struct Reader<'u, 'd, 'a> {
    units: &'u Units<'d, 'a>,
    endian: gimli::RunTimeEndian,
    graph: TypeGraph,
    /// Each type entry's node, so an entry is read once however often it is
    /// named and a cycle closes on the node it started from.
    nodes: BTreeMap<Die, TypeId>,
    /// Each entry followed by its origins, nearest first, read once.
    origins: BTreeMap<Die, Vec<Die>>,
}

impl<'u, 'd, 'a> Reader<'u, 'd, 'a> {
    fn new(units: &'u Units<'d, 'a>, endian: gimli::RunTimeEndian) -> Self {
        Self {
            units,
            endian,
            graph: TypeGraph::new(),
            nodes: BTreeMap::new(),
            origins: BTreeMap::new(),
        }
    }

    fn read(mut self) -> Declarations {
        let mut found = Found::default();
        for unit in 0..self.units.units.len() {
            self.read_unit(unit, &mut found);
        }
        let mut declarations = Declarations::new(self.graph);
        for (entry, prototype) in found.functions {
            declarations.declare_function(entry, prototype);
        }
        for (address, object) in found.objects {
            declarations.declare_object(address, object);
        }
        declarations
    }

    /// Every subprogram with a body, and every object at a fixed address
    /// outside one.
    fn read_unit(&mut self, unit: usize, found: &mut Found) {
        let root = self.units.units[unit].header.root_offset().0;
        let mut pending = vec![Die { unit, offset: root }];
        while let Some(scope) = pending.pop() {
            for (die, tag) in self.units.children(scope) {
                match tag {
                    gimli::DW_TAG_subprogram => {
                        let function = self.subprogram(die, &mut found.objects);
                        found.functions.extend(function);
                    }
                    gimli::DW_TAG_variable => found.objects.extend(self.static_object(die)),
                    // A namespace or a class holds declarations of its own.
                    gimli::DW_TAG_namespace
                    | gimli::DW_TAG_structure_type
                    | gimli::DW_TAG_class_type => pending.push(die),
                    _ => {}
                }
            }
        }
    }
}

/// What the walk over every unit finds, before it is declared.
#[derive(Default)]
struct Found {
    functions: Vec<(u64, Prototype)>,
    objects: Vec<(u64, DataObject)>,
}

/// The merged view: an attribute is the entry's own, or its origin's.
impl<'a> Reader<'_, '_, 'a> {
    /// This entry, then what it is a concrete instance of, then what it is the
    /// definition of, transitively.
    fn chain(&mut self, die: Die) -> Vec<Die> {
        if let Some(chain) = self.origins.get(&die) {
            return chain.clone();
        }
        let mut chain = vec![die];
        let mut seen = BTreeSet::from([die]);
        let mut at = 0;
        while let Some(current) = chain.get(at).copied() {
            at += 1;
            let Some(entry) = self.units.entry(current) else {
                continue;
            };
            for link in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
                let next = entry
                    .attr_value(link)
                    .and_then(|value| self.units.resolve(current, value));
                if let Some(next) = next
                    && seen.insert(next)
                {
                    chain.push(next);
                }
            }
        }
        self.origins.insert(die, chain.clone());
        chain
    }

    /// An attribute through the merged view, with the entry that states it:
    /// a reference is relative to that entry's unit, not the one asked about.
    fn attr(&mut self, die: Die, name: DwAt) -> Option<(Die, Value<'a>)> {
        self.chain(die).into_iter().find_map(|owner| {
            let value = self.units.entry(owner)?.attr_value(name)?;
            Some((owner, value))
        })
    }

    fn own_attr(&self, die: Die, name: DwAt) -> Option<Value<'a>> {
        self.units.entry(die)?.attr_value(name)
    }

    fn name(&mut self, die: Die) -> Option<String> {
        let (owner, value) = self.attr(die, gimli::DW_AT_name)?;
        self.units.string(owner, value)
    }

    fn flag(&mut self, die: Die, name: DwAt) -> bool {
        matches!(self.attr(die, name), Some((_, AttributeValue::Flag(true))))
    }

    fn udata(&mut self, die: Die, name: DwAt) -> Option<u64> {
        self.attr(die, name)?.1.udata_value()
    }

    /// The node `DW_AT_type` names; `void` where the entry names none, which
    /// is how DWARF writes `void *` and a function returning nothing.
    fn type_of(&mut self, die: Die) -> TypeId {
        match self.attr(die, gimli::DW_AT_type) {
            None => TypeId::VOID,
            Some((owner, value)) => match self.units.resolve(owner, value) {
                Some(target) => self.node(target),
                None => self.graph.refused("a type reference no unit holds"),
            },
        }
    }
}

/// Type entries, one node each.
impl Reader<'_, '_, '_> {
    fn node(&mut self, die: Die) -> TypeId {
        if let Some(found) = self.nodes.get(&die) {
            return *found;
        }
        let Some(tag) = self.units.entry(die).map(|entry| entry.tag()) else {
            return self.graph.refused("a type entry that does not read");
        };
        // A scalar cannot reach itself, and one node stands for each.
        if tag == gimli::DW_TAG_base_type {
            let ty = self.base(die);
            let id = self.graph.add(ty);
            self.nodes.insert(die, id);
            return id;
        }
        let id = self.graph.reserve();
        self.nodes.insert(die, id);
        let ty = self.build(die, tag);
        self.graph.define(id, ty);
        id
    }

    fn build(&mut self, die: Die, tag: gimli::DwTag) -> Type {
        match tag {
            gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type => self.pointer(die),
            gimli::DW_TAG_const_type => self.qualified(die, Qualifiers::CONST),
            gimli::DW_TAG_volatile_type => self.qualified(die, Qualifiers::VOLATILE),
            gimli::DW_TAG_restrict_type => self.qualified(die, Qualifiers::RESTRICT),
            gimli::DW_TAG_atomic_type => self.qualified(die, Qualifiers::ATOMIC),
            gimli::DW_TAG_typedef => self.typedef(die),
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                self.record(die, RecordKind::Struct)
            }
            gimli::DW_TAG_union_type => self.record(die, RecordKind::Union),
            gimli::DW_TAG_enumeration_type => self.enumeration(die),
            gimli::DW_TAG_array_type => self.array(die),
            gimli::DW_TAG_subroutine_type => self.code(die),
            other => refused(format!("a {other} is not a type this reads")),
        }
    }

    fn base(&mut self, die: Die) -> Type {
        let encoding = self
            .attr(die, gimli::DW_AT_encoding)
            .and_then(|(_, value)| match value {
                AttributeValue::Encoding(encoding) => Some(encoding),
                _ => None,
            });
        let kind = match encoding {
            Some(gimli::DW_ATE_signed | gimli::DW_ATE_signed_char) => ScalarKind::Signed,
            Some(gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char | gimli::DW_ATE_UTF) => {
                ScalarKind::Unsigned
            }
            Some(gimli::DW_ATE_boolean) => ScalarKind::Bool,
            Some(gimli::DW_ATE_float) => ScalarKind::Float,
            other => return refused(format!("a base type encoded {other:?}")),
        };
        let Some(bits) = self
            .udata(die, gimli::DW_AT_byte_size)
            .and_then(|bytes| u32::try_from(bytes.checked_mul(8)?).ok())
            .filter(|bits| *bits > 0)
        else {
            return refused("a base type with no size");
        };
        Type::Scalar(Scalar {
            kind,
            width: Width::Bits(bits),
            name: self.name(die),
        })
    }

    fn pointer(&mut self, die: Die) -> Type {
        let address_bits = u64::from(self.units.model(die.unit).pointer_bits);
        // A pointer of another size than the unit's addresses is a based or
        // segmented pointer, which this model does not describe.
        if let Some(bytes) = self.udata(die, gimli::DW_AT_byte_size)
            && bytes.checked_mul(8) != Some(address_bits)
        {
            return refused(format!(
                "a {bytes}-byte pointer in a {address_bits}-bit unit"
            ));
        }
        Type::Pointer {
            target: self.type_of(die),
        }
    }

    fn qualified(&mut self, die: Die, qualifiers: Qualifiers) -> Type {
        Type::Qualified {
            qualifiers,
            target: self.type_of(die),
        }
    }

    fn typedef(&mut self, die: Die) -> Type {
        let Some(name) = self.name(die) else {
            return refused("a typedef with no name");
        };
        let target = self.type_of(die);
        // `typedef struct { ... } foo_t;` names the record only through the
        // typedef, and a rendering has to call it something to define it.
        if let Some(Type::Record(record)) = self.graph.get(target)
            && record.tag.is_none()
        {
            let mut named = record.clone();
            named.tag = Some(name.clone());
            self.graph.define(target, Type::Record(named));
        }
        Type::Typedef { name, target }
    }

    fn enumeration(&mut self, die: Die) -> Type {
        let tag = self.name(die);
        if self.flag(die, gimli::DW_AT_declaration) {
            return match tag {
                Some(tag) => Type::Opaque {
                    keyword: Keyword::Enum,
                    tag,
                },
                None => refused("an anonymous enumeration never completed"),
            };
        }
        let underlying = match self.attr(die, gimli::DW_AT_type) {
            Some(_) => self.type_of(die),
            None => match self.udata(die, gimli::DW_AT_byte_size) {
                // Older producers state only the size; every enumerator of a
                // C enumeration fits an `int` of that size.
                Some(bytes) => self.graph.add(Type::Scalar(Scalar {
                    kind: ScalarKind::Signed,
                    width: Width::Bits(u32::try_from(bytes * 8).unwrap_or(0)),
                    name: None,
                })),
                None => return refused("an enumeration with no size"),
            },
        };
        Type::Enum { tag, underlying }
    }

    fn array(&mut self, die: Die) -> Type {
        let element = self.type_of(die);
        let bounds = self
            .units
            .children(die)
            .into_iter()
            .filter(|(_, tag)| *tag == gimli::DW_TAG_subrange_type)
            .map(|(subrange, _)| self.count(subrange))
            .collect::<Vec<_>>();
        let Some((outermost, inner)) = bounds.split_first() else {
            return refused("an array with no dimension");
        };
        // `int a[2][3]` is one entry with two dimensions, the first outermost.
        let mut ty = element;
        for count in inner.iter().rev() {
            ty = self.graph.add(Type::Array {
                element: ty,
                count: *count,
            });
        }
        Type::Array {
            element: ty,
            count: *outermost,
        }
    }

    /// A dimension's element count, where it is a constant.
    fn count(&mut self, subrange: Die) -> Option<u64> {
        if let Some(count) = self.udata(subrange, gimli::DW_AT_count) {
            return Some(count);
        }
        let upper = self.attr(subrange, gimli::DW_AT_upper_bound)?.1;
        let lower = self.udata(subrange, gimli::DW_AT_lower_bound).unwrap_or(0);
        // A GNU zero-length array states its upper bound as minus one.
        let upper = match upper {
            AttributeValue::Sdata(value) => value,
            other => i64::try_from(other.udata_value()?).ok()?,
        };
        u64::try_from(
            upper
                .checked_add(1)?
                .checked_sub(i64::try_from(lower).ok()?)?,
        )
        .ok()
    }

    fn code(&mut self, die: Die) -> Type {
        let mut parameters = Vec::new();
        let mut variadic = false;
        for (child, tag) in self.units.children(die) {
            match tag {
                gimli::DW_TAG_formal_parameter => parameters.push(self.type_of(child)),
                gimli::DW_TAG_unspecified_parameters => variadic = true,
                _ => {}
            }
        }
        let prototyped =
            self.flag(die, gimli::DW_AT_prototyped) || !parameters.is_empty() || variadic;
        Type::Code(Signature {
            returns: self.type_of(die),
            parameters,
            variadic,
            prototyped,
        })
    }
}

fn refused(reason: impl Into<String>) -> Type {
    Type::Refused(r2abi::Refusal(reason.into()))
}

/// Records, member by member.
impl Reader<'_, '_, '_> {
    fn record(&mut self, die: Die, kind: RecordKind) -> Type {
        let tag = self.name(die);
        let keyword = match kind {
            RecordKind::Struct => Keyword::Struct,
            RecordKind::Union => Keyword::Union,
        };
        let size_bytes = self.udata(die, gimli::DW_AT_byte_size);
        let (true, Some(size_bytes)) = (!self.flag(die, gimli::DW_AT_declaration), size_bytes)
        else {
            // A tag declared and never completed here: `FILE`, and every
            // `struct x;` a header only points at.
            return match tag {
                Some(tag) => Type::Opaque { keyword, tag },
                None => refused("an anonymous record never completed"),
            };
        };
        let mut members = Vec::new();
        for (child, child_tag) in self.units.children(die) {
            match child_tag {
                gimli::DW_TAG_member => {
                    if let Some(member) = self.member(child, kind) {
                        members.push(member);
                    }
                }
                // A base class is layout the model does not state.
                gimli::DW_TAG_inheritance => {
                    return refused("a record with a base class");
                }
                _ => {}
            }
        }
        Type::Record(Record {
            kind,
            tag,
            size_bytes,
            members,
        })
    }

    /// One member at the offset the declaration gives it, or nothing where it
    /// gives none: a member it does not place is padding to everything else.
    fn member(&mut self, die: Die, kind: RecordKind) -> Option<Member> {
        // A static member is a declaration of an object elsewhere.
        if self.flag(die, gimli::DW_AT_external) || self.flag(die, gimli::DW_AT_declaration) {
            return None;
        }
        let ty = self.type_of(die);
        let bit_size = self.udata(die, gimli::DW_AT_bit_size);
        let offset_bits = match (self.member_offset(die, bit_size), kind) {
            (Some(offset), _) => offset,
            // A union places every member at its start, and says so by
            // saying nothing.
            (None, RecordKind::Union) => 0,
            (None, RecordKind::Struct) => return None,
        };
        Some(Member {
            name: self.name(die),
            ty,
            offset_bits,
            bit_size,
        })
    }

    /// Bits from the record's start to one member.
    fn member_offset(&mut self, die: Die, bit_size: Option<u64>) -> Option<u64> {
        if let Some(bits) = self.udata(die, gimli::DW_AT_data_bit_offset) {
            return Some(bits);
        }
        let bytes = match self.attr(die, gimli::DW_AT_data_member_location) {
            None => 0,
            Some((_, AttributeValue::Exprloc(expression))) => plus_uconst(expression)?,
            Some((_, value)) => value.udata_value()?,
        };
        let base = bytes.checked_mul(8)?;
        // DWARF 2 and 3 place a bit-field by its storage unit and counting
        // from that unit's most significant bit.
        let (Some(bit_size), Some(from_top)) = (bit_size, self.udata(die, gimli::DW_AT_bit_offset))
        else {
            return Some(base);
        };
        match self.endian {
            gimli::RunTimeEndian::Big => base.checked_add(from_top),
            gimli::RunTimeEndian::Little => {
                let unit = self.udata(die, gimli::DW_AT_byte_size)?.checked_mul(8)?;
                base.checked_add(unit.checked_sub(from_top)?.checked_sub(bit_size)?)
            }
        }
    }
}

/// `DW_OP_plus_uconst n`, the only location expression a member offset is.
fn plus_uconst(expression: gimli::Expression<Slice<'_>>) -> Option<u64> {
    use gimli::Reader as _;
    let mut reader = expression.0;
    if reader.read_u8().ok()? != gimli::DW_OP_plus_uconst.0 {
        return None;
    }
    let offset = reader.read_uleb128().ok()?;
    reader.is_empty().then_some(offset)
}

/// Functions: where each begins, what it takes, and its frame.
impl Reader<'_, '_, '_> {
    /// One subprogram with a body, at the address its body begins.
    fn subprogram(
        &mut self,
        die: Die,
        objects: &mut Vec<(u64, DataObject)>,
    ) -> Option<(u64, Prototype)> {
        let entry = self.entry_address(die)?;
        let name = self.name(die)?;
        let return_type = self.type_of(die);
        let returns = self.spelled(return_type);
        let frame_base = self
            .own_attr(die, gimli::DW_AT_frame_base)
            .and_then(frame_base_of);
        let (parameters, variadic) = self.parameters(die, entry);
        let mut locals = Vec::new();
        self.frame(die, &[], &mut locals, objects);
        let prototype = Prototype {
            name,
            parameters,
            returns,
            return_type,
            variadic,
            // The source said so, which is stronger than any table: a call to
            // one of these ends the block, because the bytes after it are the
            // next function's rather than this one's.
            noreturn: self.flag(die, gimli::DW_AT_noreturn),
            frame_base,
            locals,
        };
        Some((entry, prototype))
    }

    /// Where the body begins, as the entry states it.
    ///
    /// `DW_AT_entry_pc` where there is one, then the low address. A body in
    /// several ranges states neither when it is split into hot and cold
    /// parts, and the producers that split one -- GCC and Clang -- list the
    /// range holding the entry first; the rest are the cold code a branch
    /// reaches, never an entry.
    fn entry_address(&self, die: Die) -> Option<u64> {
        for attribute in [gimli::DW_AT_entry_pc, gimli::DW_AT_low_pc] {
            if let Some(value) = self.own_attr(die, attribute)
                && let Some(address) = self.units.address(die, value)
            {
                return Some(address);
            }
        }
        self.own_attr(die, gimli::DW_AT_ranges)?;
        self.units.ranges(die).first().map(|range| range.start)
    }

    fn spelled(&self, ty: TypeId) -> r2abi::Spelled {
        self.graph
            .spelled(ty)
            .unwrap_or_else(|| r2abi::Spelled::from("/* unspellable */"))
    }

    /// The parameters in the order the source declares them.
    ///
    /// A concrete instance of an abstract function lists its parameters as
    /// it has them, which for a clone is not the source's order and may
    /// leave one out; each is placed by the source parameter it is an
    /// instance of, and one it leaves out is said to arrive nowhere.
    fn parameters(&mut self, die: Die, entry: u64) -> (Vec<Parameter>, bool) {
        // Only an abstract origin lists what its instances are instances of.
        // A definition completing a declaration lists its own parameters in
        // full, and they refer to nothing.
        let source = self
            .own_attr(die, gimli::DW_AT_abstract_origin)
            .and_then(|value| self.units.resolve(die, value))
            .filter(|origin| !self.formals(*origin).0.is_empty())
            .unwrap_or(die);
        let variadic = self.chain(die).into_iter().any(|link| self.formals(link).1);
        let (formals, _) = self.formals(source);
        let (concrete, _) = self.formals(die);
        let mut instances = BTreeMap::new();
        for instance in &concrete {
            let origin = self
                .own_attr(*instance, gimli::DW_AT_abstract_origin)
                .and_then(|value| self.units.resolve(*instance, value))
                .unwrap_or(*instance);
            instances.insert(origin, *instance);
        }
        let described = source != die;
        let parameters = formals
            .into_iter()
            .map(|formal| {
                let instance = instances.get(&formal).copied();
                self.parameter(formal, instance, described, entry)
            })
            .collect();
        (parameters, variadic)
    }

    /// An entry's formal parameters, and whether it takes more.
    fn formals(&self, die: Die) -> (Vec<Die>, bool) {
        let children = self.units.children(die);
        let variadic = children
            .iter()
            .any(|(_, tag)| *tag == gimli::DW_TAG_unspecified_parameters);
        let formals = children
            .into_iter()
            .filter(|(_, tag)| *tag == gimli::DW_TAG_formal_parameter)
            .map(|(child, _)| child)
            .collect();
        (formals, variadic)
    }

    fn parameter(
        &mut self,
        formal: Die,
        instance: Option<Die>,
        described: bool,
        entry: u64,
    ) -> Parameter {
        let ty = self.type_of(formal);
        let spelling = self.spelled(ty);
        let located = instance.unwrap_or(formal);
        let location = self.own_attr(located, gimli::DW_AT_location);
        let frame_offset = location.and_then(frame_offset_of);
        let arrival = match (instance, location) {
            (None, _) if described => Some(Arrival::Unpassed),
            _ if self.own_attr(located, gimli::DW_AT_const_value).is_some() => {
                Some(Arrival::Unpassed)
            }
            (_, Some(value)) => self.arrival(located, value, entry),
            (_, None) => None,
        };
        let mut parameter =
            Parameter::new(ty, spelling, self.name(formal)).at_frame_offset(frame_offset);
        parameter.arrival = arrival;
        parameter
    }

    /// The register a location puts a parameter in at the first instruction.
    fn arrival(&self, die: Die, value: Value<'_>, entry: u64) -> Option<Arrival> {
        let expression = match value {
            AttributeValue::Exprloc(expression) => expression,
            other => {
                let unit = self.units.units.get(die.unit)?;
                let mut list = self.units.dwarf.attr_locations(unit, other).ok()??;
                let mut found = None;
                while let Ok(Some(located)) = list.next() {
                    if (located.range.begin..located.range.end).contains(&entry) {
                        found = Some(located.data);
                        break;
                    }
                }
                found?
            }
        };
        register_of(expression).map(Arrival::Register)
    }
}

/// Frame variables and the objects a function scope holds at fixed addresses.
impl Reader<'_, '_, '_> {
    /// Every variable at or below one scope. A nested function is a function
    /// of its own, and its variables are not this frame's.
    fn frame(
        &mut self,
        scope: Die,
        ranges: &[std::ops::Range<u64>],
        locals: &mut Vec<Local>,
        objects: &mut Vec<(u64, DataObject)>,
    ) {
        for (child, tag) in self.units.children(scope) {
            match tag {
                gimli::DW_TAG_variable => match self.static_object(child) {
                    Some(object) => objects.push(object),
                    None => locals.extend(self.local(child, ranges)),
                },
                // A block names its variables over its own code, which is
                // inside every block around it.
                gimli::DW_TAG_lexical_block | gimli::DW_TAG_inlined_subroutine => {
                    let inner = self.units.ranges(child);
                    let inner = match inner.is_empty() {
                        true => ranges.to_vec(),
                        false => inner,
                    };
                    self.frame(child, &inner, locals, objects);
                }
                _ => {}
            }
        }
    }

    fn local(&mut self, die: Die, scopes: &[std::ops::Range<u64>]) -> Option<Local> {
        let frame_offset = self
            .own_attr(die, gimli::DW_AT_location)
            .and_then(frame_offset_of)?;
        let name = self.name(die)?;
        let ty = self.type_of(die);
        let size_bytes = self
            .graph
            .size_bits(ty, &self.units.model(die.unit))
            .and_then(|bits| u32::try_from(bits / 8).ok())
            .filter(|bytes| *bytes > 0);
        Some(Local {
            name,
            spelling: self.graph.spelled(ty),
            frame_offset,
            size_bytes,
            ty,
            scopes: scopes.to_vec(),
        })
    }

    /// A variable at a fixed address: a global, or a function's `static`.
    fn static_object(&mut self, die: Die) -> Option<(u64, DataObject)> {
        let AttributeValue::Exprloc(expression) = self.own_attr(die, gimli::DW_AT_location)? else {
            return None;
        };
        let address = self.static_address(die, expression)?;
        let name = self.name(die)?;
        let ty = self.type_of(die);
        let size_bytes = self
            .graph
            .size_bits(ty, &self.units.model(die.unit))
            .map(|bits| bits / 8);
        Some((
            address,
            DataObject {
                name,
                ty,
                size_bytes,
            },
        ))
    }

    /// `DW_OP_addr a` or `DW_OP_addrx i`, and nothing after it.
    fn static_address(&self, die: Die, expression: gimli::Expression<Slice<'_>>) -> Option<u64> {
        let unit = self.units.units.get(die.unit)?;
        let mut operations = expression.operations(unit.encoding());
        let address = match operations.next().ok()?? {
            gimli::Operation::Address { address } => address,
            gimli::Operation::AddressIndex { index } => {
                self.units.dwarf.address(unit, index).ok()?
            }
            _ => return None,
        };
        operations.next().ok()?.is_none().then_some(address)
    }
}

/// `DW_OP_call_frame_cfa` or `DW_OP_reg<n>`, and nothing else.
fn frame_base_of(value: Value<'_>) -> Option<FrameBase> {
    use gimli::Reader as _;
    let AttributeValue::Exprloc(expression) = value else {
        return None;
    };
    let mut reader = expression.0;
    let op = reader.read_u8().ok()?;
    // A base with anything after it is computed rather than stated.
    if !reader.is_empty() {
        return None;
    }
    match op {
        op if op == gimli::DW_OP_call_frame_cfa.0 => Some(FrameBase::CallFrameCfa),
        op if (gimli::DW_OP_reg0.0..=gimli::DW_OP_reg31.0).contains(&op) => {
            Some(FrameBase::Register(u16::from(op - gimli::DW_OP_reg0.0)))
        }
        _ => None,
    }
}

/// The frame offset a `DW_OP_fbreg` location states, where it states one.
///
/// A variable the compiler kept in a register, or moved between places as the
/// body ran, occupies no frame slot and so answers with nothing.
fn frame_offset_of(value: Value<'_>) -> Option<i64> {
    use gimli::Reader as _;
    let AttributeValue::Exprloc(expression) = value else {
        return None;
    };
    let mut reader = expression.0;
    if reader.read_u8().ok()? != gimli::DW_OP_fbreg.0 {
        return None;
    }
    let offset = reader.read_sleb128().ok()?;
    // An offset with arithmetic after it is not a slot at that offset.
    reader.is_empty().then_some(offset)
}

/// The register a location is, where it is exactly one whole register.
fn register_of(expression: gimli::Expression<Slice<'_>>) -> Option<u16> {
    use gimli::Reader as _;
    let mut reader = expression.0;
    let op = reader.read_u8().ok()?;
    let register = match op {
        op if (gimli::DW_OP_reg0.0..=gimli::DW_OP_reg31.0).contains(&op) => {
            u16::from(op - gimli::DW_OP_reg0.0)
        }
        op if op == gimli::DW_OP_regx.0 => u16::try_from(reader.read_uleb128().ok()?).ok()?,
        _ => return None,
    };
    reader.is_empty().then_some(register)
}

#[cfg(test)]
mod tests;
