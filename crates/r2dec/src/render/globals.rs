//! D4: an access at the exact address of an object the program names, spelled by that name and
//! at the type its declaration states (doc/adr-decompiler-rewrite.md); any other stays an address.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use r2ssa::MachineType;
use r2types::{DataObjectTypeFact, ProgramDataObjectTypeFacts};

use super::RenderInput;
use super::calls;
use crate::ast::{CExpr, CExternObject, CType};

/// The object an access names: its address, and the object itself where its declared type holds
/// exactly the bits the access moves.
pub(super) struct Named {
    pub(super) address: CExpr,
    pub(super) object: Option<(CExpr, CType)>,
}

/// The named objects of one function, each declared once, in address order.
pub(super) struct Globals<'a> {
    /// The container's name at each address the function refers to.
    symbols: &'a BTreeMap<u64, String>,
    functions: &'a BTreeMap<u64, String>,
    types: &'a ProgramDataObjectTypeFacts,
    ptr_bits: u32,
    used: RefCell<BTreeMap<u64, CExternObject>>,
    /// The address each spelled name stands for: two objects never share one identifier.
    names: RefCell<BTreeMap<String, u64>>,
}

impl<'a> Globals<'a> {
    pub(super) fn of(input: &RenderInput<'a>) -> Self {
        Self {
            symbols: input.data_symbols(),
            functions: input.function_names(),
            types: input.data_object_types(),
            ptr_bits: input.ptr_bits(),
            used: RefCell::new(BTreeMap::new()),
            names: RefCell::new(BTreeMap::new()),
        }
    }

    /// The object named at exactly `address`, read or (`store`) written as `class`. `taken` says
    /// whether an identifier already names something else in the function.
    pub(super) fn at(
        &self,
        address: u64,
        class: &MachineType,
        store: bool,
        taken: impl Fn(&str) -> bool,
    ) -> Option<Named> {
        let symbol = self.symbols.get(&address)?;
        // Code is a function, no object; r2engine `data_symbols` drops relocation slots (D489).
        if self.functions.contains_key(&address) {
            return None;
        }
        let name = c_identifier_for_data_symbol(symbol);
        let fact = self.types.get(address);
        // A stated type C cannot spell without its definition declares nothing, and is no `char[]`.
        let declared = match fact {
            Some(fact) => Some(declarable(&fact.ty)?),
            None => None,
        };
        match self.names.borrow_mut().entry(name.clone()) {
            Entry::Occupied(held) if *held.get() != address => return None,
            Entry::Occupied(_) => {}
            Entry::Vacant(free) => {
                if taken(&name) {
                    return None;
                }
                free.insert(address);
            }
        }
        self.used
            .borrow_mut()
            .entry(address)
            .or_insert_with(|| CExternObject {
                name: name.clone(),
                address,
                type_fact: fact
                    .zip(declared.clone())
                    .map(|(fact, ty)| DataObjectTypeFact {
                        ty,
                        provenance: fact.provenance.clone(),
                    }),
                type_refusal: self.types.refused().get(&address).cloned(),
            });
        let object = CExpr::DataObject { address, name };
        let whole = declared.filter(|ty| {
            // A `_Bool` store converts any nonzero byte to 1, which the machine does not.
            calls::held_as(ty, class, self.ptr_bits)
                && !(store
                    && (matches!(ty, CType::Const(_)) || matches!(ty.unaliased(), CType::Bool)))
        });
        Some(Named {
            address: CExpr::addr_of(object.clone()),
            object: whole.map(|ty| (object, ty)),
        })
    }

    pub(super) fn objects(&self) -> Vec<CExternObject> {
        self.used.borrow().values().cloned().collect()
    }
}

/// `ty` as an object's declaration spells it: a type C spells with no definition, or an array of
/// stated length of one.
fn declarable(ty: &CType) -> Option<CType> {
    match ty {
        CType::Array(element, Some(length)) => Some(CType::Array(
            Box::new(calls::spellable(element, &|_, _| false).filter(|ty| *ty != CType::Void)?),
            Some(*length),
        )),
        CType::Const(inner) if matches!(&**inner, CType::Array(..)) => {
            Some(CType::Const(Box::new(declarable(inner)?)))
        }
        ty => calls::spellable(ty, &|_, _| false),
    }
}

/// Whether a string literal can stand where `required` is wanted: only a pointer to `char`, the
/// C string convention, since a literal ends at its NUL and other readers may read past it.
pub(crate) fn string_literal_serves(required: &CType, _ptr_bits: u32) -> bool {
    let CType::Pointer(inner) = required else {
        return false;
    };
    let pointee = match &**inner {
        CType::Const(inner) => &**inner,
        other => other,
    };
    matches!(pointee, CType::Typedef { name, .. } if name == "char")
}

/// The C name for a radare2 data flag.
///
/// The fact is kept as radare2 stated it -- `obj.progName`, `reloc.stderr` --
/// because that is what the analysis said and what the proof line answers for.
/// What C can take is the name without the flag space that qualifies it, and
/// with anything left that is not an identifier character replaced, so the
/// rendered program declares `progName` rather than a dotted spelling no
/// compiler accepts.
pub(crate) fn c_identifier_for_data_symbol(flag: &str) -> String {
    const SPACES: [&str; 6] = ["obj.", "reloc.", "segment.", "section.", "str.", "sym."];
    let mut name = flag;
    while let Some(stripped) = SPACES.iter().find_map(|space| name.strip_prefix(space)) {
        name = stripped;
    }
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.starts_with(|c: char| c.is_ascii_digit()) {
        format!("g_{cleaned}")
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name proves nothing (AGENTS.md rule 6): r2engine `data_symbols` drops relocation slots
    /// (D489), so a data symbol that arrives is an object whatever its flag space.
    #[test]
    fn a_reloc_spelled_data_symbol_is_an_object() {
        let symbols = BTreeMap::from([(0x4010, "reloc.x".to_owned())]);
        let functions = BTreeMap::new();
        let types = ProgramDataObjectTypeFacts::default();
        let globals = Globals {
            symbols: &symbols,
            functions: &functions,
            types: &types,
            ptr_bits: 64,
            used: RefCell::new(BTreeMap::new()),
            names: RefCell::new(BTreeMap::new()),
        };
        let word = MachineType::Integer {
            width_bits: 64,
            signedness: r2ssa::MachineSignedness::Unsigned,
        };
        assert!(globals.at(0x4010, &word, false, |_| false).is_some());
        let objects = globals.objects();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].name, "x");
    }
}
