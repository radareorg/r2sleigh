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
    /// The container's name at each address the function refers to (legacy's one table).
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
        // radare2's `reloc.` names a slot holding the object's address (r2engine's `data_symbols`
        // drops the slots it states), and code is a function: neither is the object.
        if symbol.starts_with("reloc.") || self.functions.contains_key(&address) {
            return None;
        }
        let name = crate::c_identifier_for_data_symbol(symbol);
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
                        provenance: fact.provenance,
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
            Box::new(calls::spellable(element).filter(|ty| *ty != CType::Void)?),
            Some(*length),
        )),
        CType::Const(inner) if matches!(&**inner, CType::Array(..)) => {
            Some(CType::Const(Box::new(declarable(inner)?)))
        }
        ty => calls::spellable(ty),
    }
}
