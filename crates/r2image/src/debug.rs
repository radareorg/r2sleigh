//! What the binary's own debug information says a function takes and returns.
//!
//! The engine reached debug information through radare2 until now: radare2's
//! importer turned DWARF into its analysis model, the capture read that model,
//! and the result crossed the bridge. The native route reads no debug
//! information at all, so it has never had an exact type for anything -- every
//! parameter is the width of the register it arrived in.
//!
//! This reads the entries directly. What it produces is an `r2abi::Prototype`,
//! the same shape the calling-convention data already hands the engine, so a
//! signature read from DWARF and one read from a declaration reach the
//! renderer by the same path and neither becomes a second type model.
//!
//! It fails closed. A parameter whose type the walk cannot spell in C refuses
//! the whole prototype rather than leaving a hole in the middle of a
//! signature, because a signature with a guessed parameter is worse than no
//! signature: the caller renders arguments against it.

use std::collections::BTreeMap;

use gimli::AttributeValue;

/// Every function the debug information states, by the address it states it
/// at and by name.
#[derive(Debug, Clone, Default)]
pub struct DebugPrototypes {
    by_address: BTreeMap<u64, r2abi::Prototype>,
    by_name: BTreeMap<String, r2abi::Prototype>,
}

impl DebugPrototypes {
    /// What the debug information says about the function at this address.
    pub fn at(&self, address: u64) -> Option<&r2abi::Prototype> {
        self.by_address.get(&address)
    }

    /// The same, by the name a call site spells.
    pub fn named(&self, name: &str) -> Option<&r2abi::Prototype> {
        self.by_name.get(name)
    }

    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Every address the debug information describes a function at.
    pub fn addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.by_address.keys().copied()
    }

    /// Every prototype it states, for layering over the shipped declarations.
    pub fn prototypes(&self) -> impl Iterator<Item = r2abi::Prototype> + '_ {
        self.by_name.values().cloned()
    }
}

/// Read every subprogram the debug information describes.
///
/// A binary with no debug information answers with nothing, which is the same
/// answer as one whose debug information the walk could not read: neither
/// states a prototype, and the engine renders machine types as it did before.
pub(crate) fn read(file: &object::File<'_>) -> DebugPrototypes {
    use object::Object as _;
    let endian = match file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };
    let load = |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, _>, ()> {
        use object::ObjectSection as _;
        let data = file
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, endian))
    };
    let Ok(dwarf) = gimli::Dwarf::load(load) else {
        return DebugPrototypes::default();
    };
    let mut found = DebugPrototypes::default();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        read_unit(&dwarf, &unit, &mut found);
    }
    found
}

type Slice<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

fn read_unit<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    found: &mut DebugPrototypes,
) {
    // The offsets first, because reading one subprogram's children needs a
    // cursor of its own and the walk cannot hold two.
    let mut subprograms = Vec::new();
    let mut entries = unit.entries();
    while let Ok(Some(entry)) = entries.next_dfs() {
        if entry.tag() == gimli::DW_TAG_subprogram
            && let Some(low_pc) = low_pc(dwarf, unit, entry)
        {
            subprograms.push((entry.offset(), low_pc));
        }
    }
    for (offset, low_pc) in subprograms {
        let Some(prototype) = subprogram(dwarf, unit, offset) else {
            continue;
        };
        found
            .by_name
            .insert(prototype.name.clone(), prototype.clone());
        found.by_address.insert(low_pc, prototype);
    }
}

/// The address a subprogram begins at, where it states one plainly.
///
/// A declaration without a body states none, and an entry whose low address is
/// an index into the address table is read through that table.
fn low_pc<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>>,
) -> Option<u64> {
    match entry.attr_value(gimli::DW_AT_low_pc)? {
        AttributeValue::Addr(address) => Some(address),
        AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        _ => None,
    }
}

/// One subprogram, or nothing where any part of its prototype is unspellable.
fn subprogram<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    at: gimli::UnitOffset,
) -> Option<r2abi::Prototype> {
    let mut tree = unit.entries_tree(Some(at)).ok()?;
    let root = tree.root().ok()?;
    let entry = root.entry();
    let name = string(dwarf, unit, entry, gimli::DW_AT_name)?;
    let returns = match entry.attr_value(gimli::DW_AT_type) {
        Some(value) => spell(dwarf, unit, value)?,
        // A subprogram with no type returns nothing, which C spells `void`.
        None => "void".to_owned(),
    };
    let frame_base = entry
        .attr_value(gimli::DW_AT_frame_base)
        .and_then(frame_base_of);
    let mut parameters = Vec::new();
    let mut variadic = false;
    let mut locals = Vec::new();
    // Parameters are its own children: a nested scope's variables are not
    // parameters, and a nested subprogram is a function of its own. Frame
    // variables are collected from every scope inside it, because a variable
    // declared in an inner block still occupies one slot of one frame.
    let mut children = root.children();
    while let Ok(Some(child)) = children.next() {
        let entry = child.entry();
        match entry.tag() {
            gimli::DW_TAG_formal_parameter => {
                let value = entry.attr_value(gimli::DW_AT_type)?;
                let spelling = spell(dwarf, unit, value)?;
                let called = string(dwarf, unit, entry, gimli::DW_AT_name);
                parameters.push(
                    r2abi::Parameter::new(spelling, called).at_frame_offset(
                        entry
                            .attr_value(gimli::DW_AT_location)
                            .and_then(frame_offset_of),
                    ),
                );
            }
            gimli::DW_TAG_unspecified_parameters => variadic = true,
            _ => {}
        }
        collect_locals(dwarf, unit, child, &mut locals);
    }
    Some(r2abi::Prototype {
        name,
        parameters,
        returns,
        variadic,
        frame_base,
        locals,
    })
}

/// Every frame variable at or below one entry.
fn collect_locals<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    node: gimli::EntriesTreeNode<'_, '_, Slice<'a>>,
    into: &mut Vec<r2abi::Local>,
) {
    let entry = node.entry();
    if entry.tag() == gimli::DW_TAG_variable
        && let Some(name) = string(dwarf, unit, entry, gimli::DW_AT_name)
        && let Some(frame_offset) = entry
            .attr_value(gimli::DW_AT_location)
            .and_then(frame_offset_of)
    {
        let declared = entry.attr_value(gimli::DW_AT_type);
        into.push(r2abi::Local {
            name,
            spelling: declared.and_then(|value| spell(dwarf, unit, value)),
            frame_offset,
            size_bytes: declared.and_then(|value| extent(unit, value, 0)),
        });
    }
    let mut children = node.children();
    while let Ok(Some(child)) = children.next() {
        collect_locals(dwarf, unit, child, into);
    }
}

/// `DW_OP_call_frame_cfa` or `DW_OP_reg<n>`, and nothing else.
fn frame_base_of(value: AttributeValue<Slice<'_>>) -> Option<r2abi::FrameBase> {
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
        op if op == gimli::constants::DW_OP_call_frame_cfa.0 => {
            Some(r2abi::FrameBase::CallFrameCfa)
        }
        op if (gimli::constants::DW_OP_reg0.0..=gimli::constants::DW_OP_reg31.0).contains(&op) => {
            Some(r2abi::FrameBase::Register(u16::from(
                op - gimli::constants::DW_OP_reg0.0,
            )))
        }
        _ => None,
    }
}

/// The frame offset a `DW_OP_fbreg` location states, where it states one.
///
/// A variable the compiler kept in a register, or moved between places as the
/// body ran, occupies no frame slot and so answers with nothing.
fn frame_offset_of(value: AttributeValue<Slice<'_>>) -> Option<i64> {
    use gimli::Reader as _;
    let AttributeValue::Exprloc(expression) = value else {
        return None;
    };
    let mut reader = expression.0;
    if reader.read_u8().ok()? != gimli::constants::DW_OP_fbreg.0 {
        return None;
    }
    let offset = reader.read_sleb128().ok()?;
    // An offset with arithmetic after it is not a slot at that offset.
    reader.is_empty().then_some(offset)
}

/// The C spelling of one type entry.
///
/// Every shape C has a spelling for is spelled; anything else answers with
/// nothing, and the prototype that needed it is refused.
fn spell<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    value: AttributeValue<Slice<'a>>,
) -> Option<String> {
    spell_at(dwarf, unit, value, 0)
}

/// The type graph is a graph, and a type that refers to itself through a
/// pointer is ordinary C. The walk stops where a spelling would have to name
/// the type it is spelling, which is the only place a name is enough.
const SPELLING_DEPTH: usize = 16;

fn spell_at<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    value: AttributeValue<Slice<'a>>,
    depth: usize,
) -> Option<String> {
    if depth >= SPELLING_DEPTH {
        return None;
    }
    let AttributeValue::UnitRef(offset) = value else {
        return None;
    };
    let mut cursor = unit.entries_at_offset(offset).ok()?;
    let entry = cursor.next_dfs().ok()??;
    let inner = |tag: gimli::DwAt| entry.attr_value(tag);
    let named = |prefix: &str| {
        string(dwarf, unit, entry, gimli::DW_AT_name).map(|name| format!("{prefix}{name}"))
    };
    match entry.tag() {
        gimli::DW_TAG_base_type => string(dwarf, unit, entry, gimli::DW_AT_name),
        gimli::DW_TAG_typedef => named(""),
        gimli::DW_TAG_structure_type => named("struct "),
        gimli::DW_TAG_union_type => named("union "),
        gimli::DW_TAG_enumeration_type => named("enum "),
        gimli::DW_TAG_pointer_type => match inner(gimli::DW_AT_type) {
            // `void *` is a pointer entry with no target.
            None => Some("void *".to_owned()),
            Some(target) => spell_at(dwarf, unit, target, depth + 1).map(pointer_to),
        },
        gimli::DW_TAG_const_type => match inner(gimli::DW_AT_type) {
            None => Some("const void".to_owned()),
            Some(target) => {
                spell_at(dwarf, unit, target, depth + 1).map(|to| format!("const {to}"))
            }
        },
        // `volatile` and `restrict` change no layout and no argument passing,
        // so the spelling is the type they qualify.
        gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type => {
            spell_at(dwarf, unit, inner(gimli::DW_AT_type)?, depth + 1)
        }
        // An array decays to a pointer wherever a parameter can hold one, and
        // a parameter is the only place this walk spells a type.
        gimli::DW_TAG_array_type => {
            spell_at(dwarf, unit, inner(gimli::DW_AT_type)?, depth + 1).map(pointer_to)
        }
        _ => None,
    }
}

/// How many bytes one type entry occupies.
///
/// A qualifier occupies what it qualifies. Anything whose extent the entry
/// does not state answers with nothing -- an array is usually such an entry,
/// since its extent is its element's size times a count stated by a child --
/// and the variable that needed it declares no slot rather than one of a
/// guessed width.
fn extent<'a>(
    unit: &gimli::Unit<Slice<'a>>,
    value: AttributeValue<Slice<'a>>,
    depth: usize,
) -> Option<u32> {
    if depth >= SPELLING_DEPTH {
        return None;
    }
    let AttributeValue::UnitRef(offset) = value else {
        return None;
    };
    let mut cursor = unit.entries_at_offset(offset).ok()?;
    let entry = cursor.next_dfs().ok()??;
    if let Some(size) = entry
        .attr_value(gimli::DW_AT_byte_size)
        .and_then(|value| value.udata_value())
    {
        return u32::try_from(size).ok();
    }
    match entry.tag() {
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type => {
            extent(unit, entry.attr_value(gimli::DW_AT_type)?, depth + 1)
        }
        _ => None,
    }
}

/// A pointer to this type, spelled as C spells it: `char **`, not `char * *`.
fn pointer_to(target: String) -> String {
    match target.ends_with('*') {
        true => format!("{target}*"),
        false => format!("{target} *"),
    }
}

fn string<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>>,
    attribute: gimli::DwAt,
) -> Option<String> {
    let value = entry.attr_value(attribute)?;
    let slice = dwarf.attr_string(unit, value).ok()?;
    slice.to_string().ok().map(|text| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Built from `tests/data/dwarf_prototypes.c` with
    /// `clang -target x86_64-unknown-linux-gnu -fuse-ld=lld -nostdlib -g -O1`.
    /// It is linked rather than an object file because an object's debug
    /// section offsets are relocations nothing has applied yet, so every name
    /// in one reads as whatever sits at offset zero.
    const FIXTURE: &[u8] = include_bytes!("../tests/data/dwarf_prototypes.elf");

    fn prototypes() -> DebugPrototypes {
        read(&object::File::parse(FIXTURE).expect("the fixture parses"))
    }

    fn spelled(found: &DebugPrototypes, name: &str) -> String {
        let prototype = found.named(name).expect(name);
        let parameters = prototype
            .parameters
            .iter()
            .map(|parameter| match &parameter.name {
                Some(called) => format!("{} {called}", parameter.spelling),
                None => parameter.spelling.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("{} {name}({parameters})", prototype.returns)
    }

    #[test]
    fn a_declared_signature_is_read_with_its_own_spellings() {
        let found = prototypes();
        assert_eq!(spelled(&found, "add"), "int add(int a, int b)");
        assert_eq!(
            spelled(&found, "scale"),
            "ulong_t scale(ulong_t v, size_t n)"
        );
    }

    #[test]
    fn an_aggregate_and_a_pointer_keep_the_shape_c_spells() {
        let found = prototypes();
        assert_eq!(
            spelled(&found, "sum_point"),
            "int sum_point(const struct point * p)"
        );
        assert_eq!(
            spelled(&found, "pick"),
            "char * pick(char ** names, int index)"
        );
        assert_eq!(
            spelled(&found, "mean"),
            "double mean(const double * xs, int n)"
        );
    }

    #[test]
    fn a_frame_variable_is_read_with_its_offset_from_the_frame_base() {
        let found = prototypes();
        let shifted = found.named("shifted").expect("shifted");
        assert_eq!(shifted.frame_base, Some(r2abi::FrameBase::Register(6)));
        let moved = shifted
            .locals
            .iter()
            .find(|local| local.name == "moved")
            .expect("moved");
        assert_eq!(moved.spelling.as_deref(), Some("struct point"));
        assert!(moved.frame_offset < 0, "{moved:?}");
    }

    #[test]
    fn a_variable_declared_inside_a_block_is_still_a_frame_variable() {
        let found = prototypes();
        let mean = found.named("mean").expect("mean");
        let names = mean
            .locals
            .iter()
            .map(|local| local.name.as_str())
            .collect::<Vec<_>>();
        // `i` is declared in the loop's own scope and `t` in the body's.
        assert!(names.contains(&"t"), "{names:?}");
        assert!(names.contains(&"i"), "{names:?}");
    }

    #[test]
    fn a_declaration_without_a_body_states_no_prototype() {
        // `counted` is declared and never defined, so it has no low address
        // and nothing here is about it.
        assert!(prototypes().named("counted").is_none());
    }

    #[test]
    fn a_binary_with_no_debug_information_states_nothing() {
        // The same translation unit compiled without `-g`.
        const STRIPPED: &[u8] = include_bytes!("../tests/data/dwarf_prototypes_stripped.elf");
        let found = read(&object::File::parse(STRIPPED).expect("the fixture parses"));
        assert!(found.is_empty());
    }
}
