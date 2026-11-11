//! What a Sleigh language's compiler specification states about the machine
//! (doc/adr-machine-profile.md, M0; doc/adr-call-boundary.md, "What the cspec states").
//!
//! Every element under `compiler_spec` is read into a field or refused by name
//! ([`LanguageProfile::refused`]); one this reading does not know is listed in
//! [`LanguageProfile::unknown`], which the every-element test holds empty for each
//! specification a convention selects.

use std::collections::BTreeSet;
use std::ops::RangeInclusive;

pub use r2abi::{Extension, SlotClass};

/// Which way the stack grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackGrowth {
    /// Towards lower addresses: Ghidra's default.
    Lower,
    /// Towards higher addresses.
    Higher,
}

/// One storage location a specification names, as Sleigh spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecStorage {
    /// A register, by its Sleigh name.
    Register(String),
    /// Bytes at an offset in an address space: `stack` for an argument the
    /// caller pushes, `ram` for a range of memory.
    Address {
        space: String,
        offset: i64,
        size: Option<u32>,
    },
}

/// One `pentry`: where a prototype puts one argument or result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamEntry {
    pub class: SlotClass,
    pub at: SpecStorage,
    /// `minsize` to `maxsize`, in bytes.
    pub size: RangeInclusive<u32>,
    pub align: Option<u32>,
    /// How a narrower value fills the location; `Unspecified` where the entry states none.
    pub extension: Extension,
    /// The argument position the entry fills: entries of one `<group>` share it.
    pub group: u16,
}

/// `extrapop`: the bytes the callee pops on return beyond the call's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraPop {
    Bytes(u32),
    Unknown,
}

/// An inclusive range of stack offsets from the stack pointer at the callee's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackRange {
    pub first: i64,
    pub last: i64,
}

/// One `<prototype>` model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoModel {
    /// The model's name in the specification (`__stdcall`, `abi-internal`).
    pub name: Box<str>,
    /// In `pentry` order.
    pub input: Box<[ParamEntry]>,
    pub output: Box<[ParamEntry]>,
    pub unaffected: Box<[SpecStorage]>,
    pub killed_by_call: Box<[SpecStorage]>,
    pub likely_trash: Box<[SpecStorage]>,
    /// `localrange`: where the callee's own stack data may lie (Win64's home area 8..39).
    pub local_range: Box<[StackRange]>,
    pub param_range: Box<[StackRange]>,
    /// The bytes the transfer spends on the return address before the callee's first instruction.
    pub stack_shift: u32,
    pub extrapop: ExtraPop,
    /// `<varargs first="0">` with `<goto_stack>`: every variadic argument on the stack (Apple arm64).
    pub variadic_on_stack: bool,
}

impl ProtoModel {
    /// Whether every register input position holds one integer and one float alternative, so
    /// the nth argument of either class takes position n, as Microsoft x64 has it.
    pub fn shares_positions(&self) -> bool {
        let registers =
            || (self.input.iter()).filter(|entry| matches!(entry.at, SpecStorage::Register(_)));
        let count = |group, class| {
            registers()
                .filter(|entry| entry.group == group && entry.class == class)
                .count()
        };
        registers().next().is_some()
            && registers().all(|entry| {
                count(entry.group, SlotClass::Integer) == 1
                    && count(entry.group, SlotClass::Float) == 1
            })
    }

    /// Where the first stack argument sits, from the stack pointer entering the call, and the
    /// step to the next: the stack entry's address less the `stackshift` the transfer spent.
    pub fn stack_arguments(&self) -> Option<(i64, u32)> {
        self.input.iter().find_map(|entry| match &entry.at {
            SpecStorage::Address { space, offset, .. } if space == "stack" => Some((
                offset.checked_sub(i64::from(self.stack_shift))?,
                entry.align?,
            )),
            _ => None,
        })
    }
}

/// The machine facts one compiler specification declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageProfile {
    /// The register the stack pointer lives in, spelled as Sleigh spells it.
    pub stack_pointer: Option<String>,
    pub stack_growth: StackGrowth,
    /// The register a call leaves the return address in, where the machine
    /// uses one. A machine that pushes it names a stack location instead,
    /// and this is then `None`.
    pub return_address: Option<String>,
    /// Where a machine that pushes the return address leaves it: the offset
    /// from the stack pointer entering the function, and its size.
    pub return_address_slot: Option<(i64, u32)>,
    /// `data_organization`'s pointer size in bytes, where stated.
    pub pointer_size: Option<u32>,
    /// The default prototype first, then the others in document order.
    pub prototypes: Vec<ProtoModel>,
    /// Storage every function of the program shares (`global`).
    pub global: Vec<SpecStorage>,
    /// What the specification states that this reading names and does not read, as paths
    /// (`prototype/input/rule/join_dual_class`, `data_organization/wchar_size`).
    pub refused: BTreeSet<Box<str>>,
    /// What it states that this reading does not know.
    pub unknown: BTreeSet<Box<str>>,
}

/// A specification that does not parse as XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

/// Top-level elements no field reads: fix-ups, pointer and split hints, aliases.
const REFUSED_TOP: &[&str] = &[
    "callfixup",
    "callotherfixup",
    "funcptr",
    "prefersplit",
    "modelalias",
    "spacebase",
    "context_data",
    "nohighptr",
    "readonly",
    "aggressivetrim",
    "deadcodedelay",
    "segmentop",
    "resolveprototype",
    "eval_current_prototype",
    "eval_called_prototype",
    "properties",
    "inferptrbounds",
];

/// What one reading of a specification read, refused and did not know.
#[derive(Default)]
struct Audit {
    refused: BTreeSet<Box<str>>,
    unknown: BTreeSet<Box<str>>,
}

type Node<'a, 'input> = roxmltree::Node<'a, 'input>;

impl Audit {
    fn refuse(&mut self, path: impl Into<Box<str>>) {
        self.refused.insert(path.into());
    }

    fn unknown(&mut self, path: impl Into<Box<str>>) {
        self.unknown.insert(path.into());
    }

    /// Every attribute of `node` is one it reads or refuses by name; any other is unknown.
    fn attributes(&mut self, node: Node<'_, '_>, path: &str, read: &[&str], refused: &[&str]) {
        for attribute in node.attributes() {
            let name = attribute.name();
            if refused.contains(&name) {
                self.refuse(format!("{path}@{name}"));
            } else if !read.contains(&name) {
                self.unknown(format!("{path}@{name}"));
            }
        }
    }
}

fn elements<'a, 'input>(node: Node<'a, 'input>) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(Node::is_element)
}

impl LanguageProfile {
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        // A whole specification has one root; a fragment is read as the
        // children of one.
        let wrapped;
        let document = match roxmltree::Document::parse(text) {
            Ok(document) => document,
            Err(_) => {
                wrapped = format!("<spec>{text}</spec>");
                roxmltree::Document::parse(&wrapped)
                    .map_err(|error| ProfileError(error.to_string()))?
            }
        };
        let mut audit = Audit::default();
        let mut profile = Self {
            stack_pointer: None,
            stack_growth: StackGrowth::Lower,
            return_address: None,
            return_address_slot: None,
            pointer_size: None,
            prototypes: Vec::new(),
            global: Vec::new(),
            refused: BTreeSet::new(),
            unknown: BTreeSet::new(),
        };
        let mut default = None;
        let mut others = Vec::new();
        // A fragment of one element parses as a document whose root is that element.
        let root = document.root_element();
        let tops = match root.tag_name().name() {
            "compiler_spec" | "spec" => elements(root).collect::<Vec<_>>(),
            _ => vec![root],
        };
        for child in tops {
            match child.tag_name().name() {
                "stackpointer" => {
                    audit.attributes(child, "stackpointer", &["register", "growth"], &["space"]);
                    profile.stack_pointer = child.attribute("register").map(str::to_owned);
                    profile.stack_growth = match child.attribute("growth") {
                        Some("positive") => StackGrowth::Higher,
                        _ => StackGrowth::Lower,
                    };
                }
                "returnaddress" => profile.read_return_address(child, &mut audit),
                "data_organization" => profile.read_data_organization(child, &mut audit),
                "default_proto" => default = default_prototype(child, &mut audit),
                "prototype" => others.push(prototype(child, &mut audit)),
                "global" => profile.global = storage_list(child, "global", &mut audit),
                name if REFUSED_TOP.contains(&name) => audit.refuse(name),
                name => audit.unknown(name),
            }
        }
        profile.prototypes = default.into_iter().chain(others).collect();
        profile.refused = audit.refused;
        profile.unknown = audit.unknown;
        Ok(profile)
    }

    /// The pointer size; the rest of the data model is S14's (`CDataModel`), refused here.
    fn read_data_organization(&mut self, node: Node<'_, '_>, audit: &mut Audit) {
        for item in elements(node) {
            match item.tag_name().name() {
                "pointer_size" => {
                    self.pointer_size = item.attribute("value").and_then(|v| v.parse().ok());
                }
                name => audit.refuse(format!("data_organization/{name}")),
            }
        }
    }

    fn read_return_address(&mut self, node: Node<'_, '_>, audit: &mut Audit) {
        for item in elements(node) {
            match item.tag_name().name() {
                "register" => self.return_address = item.attribute("name").map(str::to_owned),
                "varnode" if item.attribute("space") == Some("stack") => {
                    let offset = item.attribute("offset").and_then(|v| v.parse().ok());
                    let size = item.attribute("size").and_then(|v| v.parse().ok());
                    self.return_address_slot = offset.zip(size);
                }
                name => audit.unknown(format!("returnaddress/{name}")),
            }
        }
    }

    /// The default prototype, where the specification states one.
    pub fn default_prototype(&self) -> Option<&ProtoModel> {
        self.prototypes.first()
    }

    /// Where the default prototype puts its first stack argument, and the step to the next.
    pub fn stack_arguments(&self) -> Option<(i64, u32)> {
        self.default_prototype()?.stack_arguments()
    }

    /// The same specification with the named prototype as its default: a program whose
    /// functions use one of its other models, as Go's ABI0 is beside its ABIInternal.
    pub fn under(&self, prototype: &str) -> Option<Self> {
        let at = self.prototypes.iter().position(|p| &*p.name == prototype)?;
        let mut profile = self.clone();
        let chosen = profile.prototypes.remove(at);
        profile.prototypes.insert(0, chosen);
        Some(profile)
    }
}

/// One `<language>` of a `.ldefs` file: the files that make it up, by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageDefinition {
    pub id: String,
    pub sla: String,
    pub pspec: String,
    /// Each compiler's id and specification file, in the order stated.
    pub compilers: Vec<(String, String)>,
    pub dwarf: Option<String>,
}

impl LanguageDefinition {
    /// Every language a `.ldefs` file defines; an unreadable file defines none.
    pub fn parse_all(text: &str) -> Vec<Self> {
        let Ok(document) = roxmltree::Document::parse(text) else {
            return Vec::new();
        };
        let languages = document
            .descendants()
            .filter(|node| node.has_tag_name("language"));
        languages.filter_map(language).collect()
    }

    /// The specification a compiler id names.
    pub fn compiler(&self, id: &str) -> Option<&str> {
        self.compilers
            .iter()
            .find(|(compiler, _)| compiler == id)
            .map(|(_, spec)| spec.as_str())
    }
}

fn language(node: roxmltree::Node<'_, '_>) -> Option<LanguageDefinition> {
    let compilers = node
        .children()
        .filter(|child| child.has_tag_name("compiler"))
        .filter_map(|child| {
            Some((
                child.attribute("id")?.into(),
                child.attribute("spec")?.into(),
            ))
        })
        .collect();
    let dwarf = node
        .children()
        .filter(|child| child.has_tag_name("external_name"))
        .find(|child| child.attribute("tool") == Some("DWARF.register.mapping.file"))
        .and_then(|child| child.attribute("name"))
        .map(str::to_string);
    Some(LanguageDefinition {
        id: node.attribute("id")?.into(),
        sla: node.attribute("slafile")?.into(),
        pspec: node.attribute("processorspec")?.into(),
        compilers,
        dwarf,
    })
}

/// A language's DWARF register numbering, as its `.dwarf` file states it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DwarfRegisters {
    names: std::collections::BTreeMap<u16, String>,
    stack_pointer: Option<u16>,
}

impl DwarfRegisters {
    /// Read `register_mapping` entries; `auto_count` numbers a run by the name's trailing digits.
    pub fn parse(text: &str) -> Self {
        let mut registers = Self::default();
        let Ok(document) = roxmltree::Document::parse(text) else {
            return registers;
        };
        let mappings = document
            .descendants()
            .filter(|node| node.has_tag_name("register_mapping"));
        for node in mappings {
            let number = node
                .attribute("dwarf")
                .and_then(|text| text.parse::<u16>().ok());
            let (Some(number), Some(name)) = (number, node.attribute("ghidra")) else {
                continue;
            };
            if node.attribute("stackpointer") == Some("true") {
                registers.stack_pointer = Some(number);
            }
            let count = node
                .attribute("auto_count")
                .and_then(|text| text.parse().ok());
            registers.names.extend(run(number, name, count));
        }
        registers
    }

    /// The register a DWARF number names.
    pub fn name_of(&self, number: u16) -> Option<&str> {
        self.names.get(&number).map(String::as_str)
    }

    /// The number the stack pointer has.
    pub const fn stack_pointer(&self) -> Option<u16> {
        self.stack_pointer
    }
}

/// The registers one mapping numbers: itself, or a run counted on from its trailing digits.
fn run(number: u16, name: &str, count: Option<u16>) -> Vec<(u16, String)> {
    let Some(count) = count else {
        return vec![(number, name.to_string())];
    };
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
    let first = name[base.len()..].parse::<u16>().unwrap_or(0);
    (0..count)
        .filter_map(|step| Some((number.checked_add(step)?, first.checked_add(step)?)))
        .map(|(numbered, index)| (numbered, format!("{base}{index}")))
        .collect()
}

fn default_prototype(node: Node<'_, '_>, audit: &mut Audit) -> Option<ProtoModel> {
    let mut default = None;
    for item in elements(node) {
        match item.tag_name().name() {
            "prototype" => default = Some(prototype(item, audit)),
            name => audit.unknown(format!("default_proto/{name}")),
        }
    }
    default
}

fn prototype(node: Node<'_, '_>, audit: &mut Audit) -> ProtoModel {
    audit.attributes(node, "prototype", &["name", "extrapop", "stackshift"], &[]);
    let mut model = ProtoModel {
        name: node.attribute("name").unwrap_or_default().into(),
        input: Box::default(),
        output: Box::default(),
        unaffected: Box::default(),
        killed_by_call: Box::default(),
        likely_trash: Box::default(),
        local_range: Box::default(),
        param_range: Box::default(),
        stack_shift: node
            .attribute("stackshift")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        extrapop: match node.attribute("extrapop").map(str::parse) {
            Some(Ok(bytes)) => ExtraPop::Bytes(bytes),
            _ => ExtraPop::Unknown,
        },
        variadic_on_stack: false,
    };
    for child in elements(node) {
        let name = child.tag_name().name();
        let path = format!("prototype/{name}");
        match name {
            "input" => {
                audit.attributes(child, &path, &[], &["pointermax", "thisbeforeretpointer"]);
                let (entries, on_stack) = entries(child, &path, true, audit);
                model.input = entries;
                model.variadic_on_stack = on_stack;
            }
            "output" => {
                audit.attributes(child, &path, &[], &["killedbycall"]);
                model.output = entries(child, &path, false, audit).0;
            }
            "unaffected" => model.unaffected = storage_list(child, &path, audit).into(),
            "killedbycall" => model.killed_by_call = storage_list(child, &path, audit).into(),
            "likelytrash" => model.likely_trash = storage_list(child, &path, audit).into(),
            "localrange" => model.local_range = ranges(child, &path, audit),
            "paramrange" => model.param_range = ranges(child, &path, audit),
            "returnaddress" | "pcode" | "sharestack" => audit.refuse(path),
            _ => audit.unknown(path),
        }
    }
    model
}

/// An `<input>` or `<output>`: each direct `pentry` or `group` is one position, a group's entries
/// sharing it; and whether a rule sends every variadic argument to the stack.
fn entries(
    list: Node<'_, '_>,
    path: &str,
    input: bool,
    audit: &mut Audit,
) -> (Box<[ParamEntry]>, bool) {
    let mut entries = Vec::new();
    let mut on_stack = false;
    let mut group = 0u16;
    for child in elements(list) {
        let name = child.tag_name().name();
        match name {
            "pentry" => {
                entries.extend(pentry(child, group, path, audit));
                group += 1;
            }
            "group" => {
                for alternative in elements(child) {
                    match alternative.tag_name().name() {
                        "pentry" => entries.extend(pentry(alternative, group, path, audit)),
                        other => audit.unknown(format!("{path}/group/{other}")),
                    }
                }
                group += 1;
            }
            "rule" => on_stack |= rule(child, path, input, audit),
            "sharestack" => audit.refuse(format!("{path}/{name}")),
            _ => audit.unknown(format!("{path}/{name}")),
        }
    }
    (entries.into(), on_stack)
}

/// Whether a `<rule>` is `<varargs first="0">` with `<goto_stack>`, the one rule read (Apple's
/// variadic tail on the stack); every other rule's actions are refused by name.
fn rule(node: Node<'_, '_>, path: &str, input: bool, audit: &mut Audit) -> bool {
    let has = |name: &str| elements(node).any(|child| child.has_tag_name(name));
    let from_first = elements(node)
        .any(|child| child.has_tag_name("varargs") && child.attribute("first") == Some("0"));
    if input && from_first && has("goto_stack") {
        return true;
    }
    for child in elements(node) {
        audit.refuse(format!("{path}/rule/{}", child.tag_name().name()));
    }
    false
}

fn pentry(node: Node<'_, '_>, group: u16, path: &str, audit: &mut Audit) -> Option<ParamEntry> {
    let path = format!("{path}/pentry");
    let read = [
        "minsize",
        "maxsize",
        "align",
        "metatype",
        "storage",
        "extension",
    ];
    audit.attributes(node, &path, &read, &[]);
    let number = |name: &str| node.attribute(name).and_then(|value| value.parse().ok());
    // Older specifications class an entry with `metatype`, newer ones with `storage`.
    let class = match node
        .attribute("metatype")
        .or_else(|| node.attribute("storage"))
    {
        None | Some("general") => SlotClass::Integer,
        Some("float") => SlotClass::Float,
        Some("hiddenret") => SlotClass::HiddenReturn,
        Some(other) => {
            audit.refuse(format!("{path}@storage={other}"));
            return None;
        }
    };
    let extension = match node.attribute("extension") {
        None => Extension::Unspecified,
        Some("zero") => Extension::Zero,
        Some("sign") => Extension::Sign,
        Some("inttype") => Extension::IntType,
        Some("float") => Extension::Float,
        Some(other) => {
            audit.unknown(format!("{path}@extension={other}"));
            Extension::Unspecified
        }
    };
    let at = elements(node).find_map(|child| located(child, &path, audit))?;
    let (Some(min), Some(max)) = (number("minsize"), number("maxsize")) else {
        audit.unknown(format!("{path} without a size"));
        return None;
    };
    let on_stack = matches!(&at, SpecStorage::Address { space, .. } if space == "stack");
    Some(ParamEntry {
        class: if on_stack { SlotClass::Stack } else { class },
        at,
        size: min..=max,
        align: number("align"),
        extension,
        group,
    })
}

/// A `pentry`'s location; a `join` of pieces is refused by name.
fn located(node: Node<'_, '_>, path: &str, audit: &mut Audit) -> Option<SpecStorage> {
    let pieces = node.attributes().any(|a| a.name().starts_with("piece"));
    if pieces {
        audit.refuse(format!("{path}/{}@piece", node.tag_name().name()));
        return None;
    }
    let located = storage(node);
    if located.is_none() {
        audit.unknown(format!("{path}/{}", node.tag_name().name()));
    }
    located
}

fn ranges(node: Node<'_, '_>, path: &str, audit: &mut Audit) -> Box<[StackRange]> {
    let number = |range: Node<'_, '_>, name: &str| {
        let text = range.attribute(name)?;
        let value = match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok()?,
            None => text.parse::<u64>().ok()?,
        };
        // Ghidra spells a negative stack offset as its 64-bit two's complement.
        Some(value as i64)
    };
    let mut ranges = Vec::new();
    for range in elements(node) {
        let stack = range.has_tag_name("range") && range.attribute("space") == Some("stack");
        match (stack, number(range, "first"), number(range, "last")) {
            (true, Some(first), Some(last)) => ranges.push(StackRange { first, last }),
            _ => audit.unknown(format!("{path}/{}", range.tag_name().name())),
        }
    }
    ranges.into()
}

fn storage_list(node: Node<'_, '_>, path: &str, audit: &mut Audit) -> Vec<SpecStorage> {
    let mut list = Vec::new();
    for child in elements(node) {
        match storage(child) {
            Some(storage) => list.push(storage),
            None => audit.unknown(format!("{path}/{}", child.tag_name().name())),
        }
    }
    list
}

/// One `register`, `addr`, `varnode` or `range` element as storage.
fn storage(node: Node<'_, '_>) -> Option<SpecStorage> {
    let offset = |name: &str| {
        node.attribute(name)
            .and_then(|value| value.parse::<i64>().ok())
    };
    match node.tag_name().name() {
        "register" => Some(SpecStorage::Register(node.attribute("name")?.to_owned())),
        "addr" | "varnode" => Some(SpecStorage::Address {
            space: node.attribute("space")?.to_owned(),
            offset: offset("offset")?,
            size: node.attribute("size").and_then(|value| value.parse().ok()),
        }),
        "range" => Some(SpecStorage::Address {
            space: node.attribute("space")?.to_owned(),
            offset: offset("first").unwrap_or(0),
            size: None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> LanguageProfile {
        LanguageProfile::parse(text).expect("parses")
    }

    #[test]
    fn a_language_definition_names_its_files() {
        let languages = LanguageDefinition::parse_all(
            r#"<language_definitions>
              <language processor="x86" id="x86:LE:64:default" slafile="x86-64.sla" processorspec="x86-64.pspec">
                <compiler name="Visual Studio" spec="x86-64-win.cspec" id="windows"/>
                <compiler name="gcc" spec="x86-64-gcc.cspec" id="gcc"/>
                <external_name tool="DWARF.register.mapping.file" name="x86-64.dwarf"/>
              </language>
            </language_definitions>"#,
        );
        let [x86_64] = languages.as_slice() else {
            panic!("one language: {languages:?}");
        };
        assert_eq!(x86_64.sla, "x86-64.sla");
        assert_eq!(x86_64.compiler("gcc"), Some("x86-64-gcc.cspec"));
        assert_eq!(x86_64.compiler("windows"), Some("x86-64-win.cspec"));
        assert_eq!(x86_64.dwarf.as_deref(), Some("x86-64.dwarf"));
    }

    #[test]
    fn a_dwarf_numbering_expands_its_runs_and_names_the_stack_pointer() {
        let registers = DwarfRegisters::parse(
            r#"<dwarf><register_mappings>
                <register_mapping dwarf="0" ghidra="x0" auto_count="31"/>
                <register_mapping dwarf="31" ghidra="sp" stackpointer="true"/>
                <register_mapping dwarf="8" ghidra="R8" auto_count="8"/>
            </register_mappings></dwarf>"#,
        );
        assert_eq!(registers.name_of(29), Some("x29"));
        assert_eq!(registers.name_of(31), Some("sp"));
        assert_eq!(registers.stack_pointer(), Some(31));
        // A later run overwrites what an earlier one numbered, as Ghidra's does.
        assert_eq!(registers.name_of(15), Some("R15"));
        assert_eq!(registers.name_of(40), None);
    }

    #[test]
    fn a_machine_that_pushes_the_return_address_states_the_slot() {
        let spec = parse(
            r#"<returnaddress>
    <varnode space="stack" offset="0" size="4"/>
  </returnaddress>"#,
        );
        assert_eq!(spec.return_address, None);
        assert_eq!(spec.return_address_slot, Some((0, 4)));
    }

    #[test]
    fn a_stack_only_convention_states_where_its_arguments_are() {
        let spec = parse(
            r#"<default_proto>
    <prototype name="__cdecl" extrapop="4" stackshift="4">
      <input>
        <pentry minsize="1" maxsize="500" align="4">
          <addr offset="4" space="stack"/>
        </pentry>
      </input>
    </prototype>
  </default_proto>"#,
        );
        assert_eq!(spec.stack_arguments(), Some((0, 4)));
    }

    #[test]
    fn a_register_convention_reaches_its_stack_entry_past_the_registers() {
        let spec = parse(
            r#"<default_proto>
    <prototype name="__stdcall" extrapop="8" stackshift="8">
      <input>
        <pentry minsize="1" maxsize="8"><register name="RDI"/></pentry>
        <pentry minsize="1" maxsize="500" align="8">
          <addr offset="8" space="stack"/>
        </pentry>
      </input>
    </prototype>
  </default_proto>"#,
        );
        assert_eq!(spec.stack_arguments(), Some((0, 8)));
    }

    /// Every compiler specification the trusted languages use parses, states
    /// a stack pointer, a return address and a default prototype with inputs
    /// and outputs; and x86-64's SysV model is the one its ABI documents.
    #[cfg(feature = "x86")]
    #[test]
    fn the_x86_64_gcc_specification_states_the_sysv_model() {
        let spec = parse(sleigh_config::processor_x86::CSPEC_X86_64_GCC);
        assert_eq!(spec.stack_pointer.as_deref(), Some("RSP"));
        assert_eq!(spec.return_address, None);
        assert_eq!(spec.return_address_slot, Some((0, 8)));
        assert_eq!(spec.pointer_size, Some(8));
        let default = spec.default_prototype().expect("a default prototype");
        let general = default
            .input
            .iter()
            .filter(|entry| entry.class == SlotClass::Integer)
            .filter_map(|entry| match &entry.at {
                SpecStorage::Register(name) => Some(name.as_str()),
                SpecStorage::Address { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(general, ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]);
        let unaffected = default
            .unaffected
            .iter()
            .filter_map(|storage| match storage {
                SpecStorage::Register(name) => Some(name.as_str()),
                SpecStorage::Address { .. } => None,
            })
            .collect::<Vec<_>>();
        assert!(!default.shares_positions());
        for register in ["RBX", "RSP", "RBP", "R12", "R13", "R14", "R15"] {
            assert!(
                unaffected.contains(&register),
                "{register} in {unaffected:?}"
            );
        }
    }

    #[cfg(feature = "arm")]
    #[test]
    fn the_aarch64_specification_states_the_aapcs64_model() {
        let spec = parse(sleigh_config::processor_aarch64::CSPEC_AARCH64);
        assert_eq!(spec.stack_pointer.as_deref(), Some("sp"));
        assert_eq!(spec.return_address.as_deref(), Some("x30"));
        let default = spec.default_prototype().expect("a default prototype");
        let general = default
            .input
            .iter()
            .filter(|entry| entry.class == SlotClass::Integer)
            .filter_map(|entry| match &entry.at {
                SpecStorage::Register(name) => Some(name.as_str()),
                SpecStorage::Address { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            &general[..8],
            ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        );
        assert!(!default.shares_positions());
    }

    /// Apple's arm64 sends every variadic argument to the stack; the usual AAPCS64 does not.
    #[cfg(feature = "arm")]
    #[test]
    fn the_apple_aarch64_specification_sends_variadic_arguments_to_the_stack() {
        let apple = parse(sleigh_config::processor_aarch64::CSPEC_AARCH64_APPLE);
        let usual = parse(sleigh_config::processor_aarch64::CSPEC_AARCH64);
        assert!(apple.default_prototype().unwrap().variadic_on_stack);
        assert!(!usual.default_prototype().unwrap().variadic_on_stack);
        // Both name x30 the return address: Ghidra's Apple text left it out.
        assert_eq!(apple.return_address.as_deref(), Some("x30"));
        assert_eq!(apple.stack_arguments(), usual.stack_arguments());
    }

    /// Microsoft x64 states its four register positions as `<group>`s: the nth integer and
    /// the nth float argument share one position.
    #[cfg(feature = "x86")]
    #[test]
    fn the_x86_64_windows_specification_states_positional_pairs() {
        let spec = parse(sleigh_config::processor_x86::CSPEC_X86_64_WIN);
        let default = spec.default_prototype().expect("a default prototype");
        let registers = |class| {
            default
                .input
                .iter()
                .filter(|entry| entry.class == class)
                .filter_map(|entry| match &entry.at {
                    SpecStorage::Register(name) => Some((entry.group, name.as_str())),
                    SpecStorage::Address { .. } => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            registers(SlotClass::Integer),
            [(0, "RCX"), (1, "RDX"), (2, "R8"), (3, "R9")]
        );
        assert_eq!(
            registers(SlotClass::Float),
            [
                (0, "XMM0_Qa"),
                (1, "XMM1_Qa"),
                (2, "XMM2_Qa"),
                (3, "XMM3_Qa")
            ]
        );
        assert!(default.shares_positions());
        // The stack entry is the fifth position, past the 32-byte home area.
        assert_eq!(default.input.last().map(|entry| entry.group), Some(4));
        assert_eq!(spec.stack_arguments(), Some((32, 8)));
    }
    /// The vendored specifications of the graded processors, by file name.
    #[cfg(all(feature = "x86", feature = "arm"))]
    fn vendored() -> impl Iterator<Item = (&'static str, &'static str)> {
        (sleigh_config::processor_x86::FILES.iter())
            .chain(sleigh_config::processor_aarch64::FILES)
            .filter(|(name, _)| name.ends_with(".cspec"))
            .copied()
    }

    /// Every element and attribute of each specification a convention selects is read or
    /// refused by name; one no convention selects is named here, so a new one fails.
    #[cfg(all(feature = "x86", feature = "arm"))]
    #[test]
    fn every_element_of_a_selected_specification_is_read_or_refused_by_name() {
        // The four the ADR grades, then those r2abi's other ids select (i386, Go, a PE's).
        let selected = [
            "AARCH64.cspec",
            "AARCH64_apple.cspec",
            "x86-64-gcc.cspec",
            "x86-64-win.cspec",
            "AARCH64_golang.cspec",
            "AARCH64_win.cspec",
            "x86-64-golang.cspec",
            "x86gcc.cspec",
            "x86win.cspec",
        ];
        let unselected = [
            "AARCH64_ilp32.cspec",
            "x86-16.cspec",
            "x86-32-golang.cspec",
            "x86borland.cspec",
            "x86delphi.cspec",
        ];
        let mut seen = Vec::new();
        for (name, text) in vendored() {
            seen.push(name);
            let profile = parse(text);
            if selected.contains(&name) {
                assert!(profile.unknown.is_empty(), "{name}: {:?}", profile.unknown);
            } else {
                assert!(
                    unselected.contains(&name),
                    "{name} is neither selected nor named"
                );
            }
        }
        seen.sort_unstable();
        let mut named = selected
            .iter()
            .chain(&unselected)
            .copied()
            .collect::<Vec<_>>();
        named.sort_unstable();
        assert_eq!(seen, named);
    }

    /// The `<rule>` actions no slice reads yet are refused by name, not dropped unseen.
    #[cfg(feature = "arm")]
    #[test]
    fn the_aarch64_rules_no_slice_reads_are_refused_by_name() {
        let spec = parse(sleigh_config::processor_aarch64::CSPEC_AARCH64);
        for path in [
            "prototype/output/rule/join_per_primitive",
            "prototype/output/rule/hidden_return",
            "prototype/input/rule/convert_to_ptr",
            "prototype/input/rule/join",
            "callfixup",
        ] {
            assert!(spec.refused.contains(path), "{path} in {:?}", spec.refused);
        }
        let default = spec.default_prototype().expect("a default prototype");
        let hidden = default
            .input
            .iter()
            .find(|e| e.class == SlotClass::HiddenReturn);
        assert_eq!(
            hidden.map(|entry| &entry.at),
            Some(&SpecStorage::Register("x8".into()))
        );
        // The specification's own claim; r2abi's AAPCS64 row overrides it (C.16).
        let x0 = default.input.iter().find(|e| e.class == SlotClass::Integer);
        assert_eq!(x0.map(|entry| entry.extension), Some(Extension::Zero));
    }

    /// Microsoft x64's callee owns the 32-byte home area above the return address.
    #[cfg(feature = "x86")]
    #[test]
    fn the_x86_64_windows_specification_states_the_home_area() {
        let spec = parse(sleigh_config::processor_x86::CSPEC_X86_64_WIN);
        let default = spec.default_prototype().expect("a default prototype");
        assert!(
            default
                .local_range
                .contains(&StackRange { first: 8, last: 39 })
        );
        assert_eq!(default.extrapop, ExtraPop::Bytes(8));
        assert_eq!(default.stack_shift, 8);
        assert!(spec.refused.contains("prototype/input@pointermax"));
    }

    /// i386 gcc states EAX likely trash, and a joined EDX:EAX result it does not place.
    #[cfg(feature = "x86")]
    #[test]
    fn the_i386_gcc_specification_states_likely_trash() {
        let spec = parse(sleigh_config::processor_x86::CSPEC_X86GCC);
        let default = spec.default_prototype().expect("a default prototype");
        assert_eq!(
            &*default.likely_trash,
            [SpecStorage::Register("EAX".into())]
        );
        assert!(spec.refused.iter().any(|path| path.ends_with("@piece")));
    }
}
