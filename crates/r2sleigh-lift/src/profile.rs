//! What a Sleigh language's compiler specification states about the machine
//! (doc/adr-machine-profile.md, M0).
//!
//! The `.cspec` names the stack pointer and which way it grows, where a call
//! leaves the return address, the pointer size, and the prototype models: the
//! storage each argument and result takes, what a call kills and what it
//! leaves as it found it, and the storage the whole program shares. The
//! lifter owns the specification bundle, so it owns this reading of it, and
//! no crate below it names an architecture to answer these questions.

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

/// How an entry's value is classed by the prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryClass {
    /// No class stated: an integer or pointer.
    General,
    /// `float`.
    Float,
    /// Any other class, such as the hidden return pointer.
    Other,
}

/// One `pentry`: where a prototype puts one argument or result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrototypeEntry {
    pub class: EntryClass,
    pub storage: SpecStorage,
    pub min_size: Option<u32>,
    pub max_size: Option<u32>,
    pub align: Option<u32>,
    /// `extension`: how a narrower value fills the storage (`zero`, `sign`,
    /// `inttype`), where the specification says.
    pub extension: Option<String>,
}

/// One prototype model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prototype {
    pub name: String,
    /// The bytes the transfer spends on the return address before the
    /// callee's first instruction.
    pub stack_shift: Option<i64>,
    /// The bytes the callee pops on return, beyond what the call pushed.
    pub extra_pop: Option<String>,
    pub inputs: Vec<PrototypeEntry>,
    pub outputs: Vec<PrototypeEntry>,
    /// Storage a call to a function of this model leaves undefined.
    pub killed_by_call: Vec<SpecStorage>,
    /// Storage a call leaves as it found it.
    pub unaffected: Vec<SpecStorage>,
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
    /// Where the default prototype puts its first stack argument, from the
    /// stack pointer entering the call, and the step to the next.
    pub stack_arguments: Option<(i64, u32)>,
    /// `data_organization`'s pointer size in bytes, where stated.
    pub pointer_size: Option<u32>,
    /// The default prototype first, then the others in document order.
    pub prototypes: Vec<Prototype>,
    /// Storage every function of the program shares (`global`).
    pub global: Vec<SpecStorage>,
}

/// A specification that does not parse as XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError(pub String);

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
        let root = document.root_element();
        let first = |name: &str| root.descendants().find(|node| node.has_tag_name(name));
        let pointer = first("stackpointer");
        let returns = first("returnaddress");
        let default = first("default_proto").and_then(|default| {
            default
                .children()
                .find(|node| node.has_tag_name("prototype"))
        });
        let mut prototypes = default.into_iter().map(prototype).collect::<Vec<_>>();
        prototypes.extend(
            root.descendants()
                .filter(|node| {
                    node.has_tag_name("prototype")
                        && !node
                            .parent_element()
                            .is_some_and(|parent| parent.has_tag_name("default_proto"))
                })
                .map(prototype),
        );
        Ok(Self {
            stack_pointer: pointer
                .and_then(|node| node.attribute("register"))
                .map(str::to_owned),
            stack_growth: match pointer.and_then(|node| node.attribute("growth")) {
                Some("positive") => StackGrowth::Higher,
                _ => StackGrowth::Lower,
            },
            return_address: returns
                .and_then(|node| {
                    node.descendants()
                        .find(|node| node.has_tag_name("register"))
                })
                .and_then(|node| node.attribute("name"))
                .map(str::to_owned),
            return_address_slot: returns
                .and_then(|node| node.descendants().find(|node| node.has_tag_name("varnode")))
                .filter(|node| node.attribute("space") == Some("stack"))
                .and_then(|node| {
                    Some((
                        node.attribute("offset")?.parse().ok()?,
                        node.attribute("size")?.parse().ok()?,
                    ))
                }),
            stack_arguments: default.and_then(stack_arguments),
            pointer_size: first("pointer_size")
                .and_then(|node| node.attribute("value"))
                .and_then(|value| value.parse().ok()),
            prototypes,
            global: first("global").map(storage_list).unwrap_or_default(),
        })
    }

    /// The default prototype, where the specification states one.
    pub fn default_prototype(&self) -> Option<&Prototype> {
        self.prototypes.first()
    }
}

/// Where the default prototype's first stack argument sits, and the step to
/// the next.
///
/// A stack `pentry` states its own address and alignment, so a convention
/// that passes everything on the stack -- x86 cdecl -- describes its
/// arguments as exactly as a register convention does. The address is in the
/// callee's own coordinates, where the transfer has already spent
/// `stackshift` bytes on the return address, so that much is taken off to
/// name the slot from the stack pointer entering the call.
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

fn stack_arguments(prototype: roxmltree::Node<'_, '_>) -> Option<(i64, u32)> {
    let shift = prototype.attribute("stackshift")?.parse::<i64>().ok()?;
    let input = prototype
        .children()
        .find(|node| node.has_tag_name("input"))?;
    let entry = input
        .children()
        .filter(|node| node.has_tag_name("pentry"))
        .find(|entry| {
            entry
                .children()
                .find(|node| node.has_tag_name("addr"))
                .is_some_and(|addr| addr.attribute("space") == Some("stack"))
        })?;
    let addr = entry.children().find(|node| node.has_tag_name("addr"))?;
    let offset = addr.attribute("offset")?.parse::<i64>().ok()?;
    let align = entry.attribute("align")?.parse().ok()?;
    Some((offset.checked_sub(shift)?, align))
}

fn prototype(node: roxmltree::Node<'_, '_>) -> Prototype {
    let entries = |name: &str| {
        node.children()
            .find(|child| child.has_tag_name(name))
            .map(|list| {
                list.children()
                    .filter(|child| child.has_tag_name("pentry"))
                    .filter_map(pentry)
                    .collect()
            })
            .unwrap_or_default()
    };
    let storages = |name: &str| {
        node.children()
            .find(|child| child.has_tag_name(name))
            .map(storage_list)
            .unwrap_or_default()
    };
    Prototype {
        name: node.attribute("name").unwrap_or_default().to_owned(),
        stack_shift: node
            .attribute("stackshift")
            .and_then(|value| value.parse().ok()),
        extra_pop: node.attribute("extrapop").map(str::to_owned),
        inputs: entries("input"),
        outputs: entries("output"),
        killed_by_call: storages("killedbycall"),
        unaffected: storages("unaffected"),
    }
}

fn pentry(node: roxmltree::Node<'_, '_>) -> Option<PrototypeEntry> {
    let number = |name: &str| node.attribute(name).and_then(|value| value.parse().ok());
    Some(PrototypeEntry {
        // Older specifications class an entry with `metatype`, newer ones
        // with `storage`; both say `float`, and `hiddenret` is the latter's
        // hidden return pointer.
        class: match node
            .attribute("metatype")
            .or_else(|| node.attribute("storage"))
        {
            None | Some("general") => EntryClass::General,
            Some("float") => EntryClass::Float,
            Some(_) => EntryClass::Other,
        },
        storage: node.children().find_map(storage)?,
        min_size: number("minsize"),
        max_size: number("maxsize"),
        align: number("align"),
        extension: node.attribute("extension").map(str::to_owned),
    })
}

fn storage_list(node: roxmltree::Node<'_, '_>) -> Vec<SpecStorage> {
    node.children().filter_map(storage).collect()
}

/// One `register`, `addr`, `varnode` or `range` element as storage.
fn storage(node: roxmltree::Node<'_, '_>) -> Option<SpecStorage> {
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
        assert_eq!(spec.stack_arguments, Some((0, 4)));
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
        assert_eq!(spec.stack_arguments, Some((0, 8)));
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
            .inputs
            .iter()
            .filter(|entry| entry.class == EntryClass::General)
            .filter_map(|entry| match &entry.storage {
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
            .inputs
            .iter()
            .filter(|entry| entry.class == EntryClass::General)
            .filter_map(|entry| match &entry.storage {
                SpecStorage::Register(name) => Some(name.as_str()),
                SpecStorage::Address { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            &general[..8],
            ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        );
    }
}
