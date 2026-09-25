//! What a binary's own debug information declares, by address.
//!
//! A declaration read from the binary is about the code and data at the
//! addresses it states, and only those. Two `static` functions in two units
//! may share a name, and one function body may be every function the linker
//! folded into it; a name reaches neither. So the functions here are keyed by
//! the address the body begins at, the objects by the address they occupy,
//! and nothing is looked up by what it is called. The library table, which
//! declares what an import is expected to be, is keyed by name and kept apart
//! in [`crate::Prototypes`].

use std::collections::{BTreeMap, BTreeSet};

use crate::Prototype;
use crate::types::{Type, TypeGraph, TypeId};

/// One object the debug information places at a fixed address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataObject {
    pub name: String,
    pub ty: TypeId,
    /// Its type's size, where the type has one.
    pub size_bytes: Option<u64>,
}

/// Every function and object a binary's debug information declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declarations {
    graph: TypeGraph,
    functions: BTreeMap<u64, Prototype>,
    /// Entries two declarations claim with prototypes that are not the same
    /// type: which one the body is cannot be told, so neither is stated.
    contested: BTreeSet<u64>,
    objects: BTreeMap<u64, DataObject>,
}

impl Declarations {
    /// An empty set whose declarations will name nodes of `graph`.
    pub fn new(graph: TypeGraph) -> Self {
        Self {
            graph,
            ..Self::default()
        }
    }

    pub fn graph(&self) -> &TypeGraph {
        &self.graph
    }

    /// State the function whose body begins at `entry`.
    ///
    /// Identical code folded into one body is declared once per function the
    /// source had. The declarations agree about the body only where their
    /// prototypes are the same type, and then either is the body's; where
    /// they are not, the entry is contested and states nothing, however many
    /// more declarations arrive.
    pub fn declare_function(&mut self, entry: u64, prototype: Prototype) {
        if self.contested.contains(&entry) {
            return;
        }
        let Some(existing) = self.functions.get(&entry) else {
            self.functions.insert(entry, prototype);
            return;
        };
        if !same_interface(&self.graph, existing, &prototype) {
            self.functions.remove(&entry);
            self.contested.insert(entry);
        }
    }

    /// State the object at `address`. A second, different statement of one
    /// address leaves it unstated, for the same reason.
    pub fn declare_object(&mut self, address: u64, object: DataObject) {
        match self.objects.get(&address) {
            None => {
                self.objects.insert(address, object);
            }
            Some(existing) if Equivalence::new(&self.graph).same(existing.ty, object.ty) => {}
            Some(_) => {
                self.objects.remove(&address);
            }
        }
    }

    /// The function whose body begins at `entry`.
    pub fn function_at(&self, entry: u64) -> Option<&Prototype> {
        self.functions.get(&entry)
    }

    /// Whether two declarations claim `entry` and disagree about it.
    pub fn is_contested(&self, entry: u64) -> bool {
        self.contested.contains(&entry)
    }

    pub fn functions(&self) -> impl Iterator<Item = (u64, &Prototype)> {
        self.functions
            .iter()
            .map(|(entry, prototype)| (*entry, prototype))
    }

    pub fn object_at(&self, address: u64) -> Option<&DataObject> {
        self.objects.get(&address)
    }

    pub fn objects(&self) -> impl Iterator<Item = (u64, &DataObject)> {
        self.objects
            .iter()
            .map(|(address, object)| (*address, object))
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.objects.is_empty() && self.contested.is_empty()
    }
}

/// Whether two prototypes take and return the same types, whatever they call
/// them.
fn same_interface(graph: &TypeGraph, left: &Prototype, right: &Prototype) -> bool {
    let mut equivalence = Equivalence::new(graph);
    left.variadic == right.variadic
        && left.parameters.len() == right.parameters.len()
        && equivalence.same(left.return_type, right.return_type)
        && left
            .parameters
            .iter()
            .zip(&right.parameters)
            .all(|(left, right)| equivalence.same(left.ty, right.ty))
}

/// Structural equality of two nodes of one graph.
///
/// Names and qualifiers are read through: they change neither a layout nor a
/// calling convention. A record reaching itself through a pointer is compared
/// coinductively -- a pair already being compared is assumed equal, which is
/// the greatest fixed point and exactly when two recursive layouts agree.
struct Equivalence<'a> {
    graph: &'a TypeGraph,
    assumed: BTreeSet<(TypeId, TypeId)>,
}

impl<'a> Equivalence<'a> {
    fn new(graph: &'a TypeGraph) -> Self {
        Self {
            graph,
            assumed: BTreeSet::new(),
        }
    }

    fn same(&mut self, left: TypeId, right: TypeId) -> bool {
        let (left, _) = self.graph.peel(left);
        let (right, _) = self.graph.peel(right);
        if left == right || !self.assumed.insert((left, right)) {
            return true;
        }
        let (Some(a), Some(b)) = (self.graph.get(left), self.graph.get(right)) else {
            return false;
        };
        self.same_node(a, b)
    }

    fn same_node(&mut self, left: &Type, right: &Type) -> bool {
        match (left, right) {
            (Type::Void, Type::Void) => true,
            (Type::Scalar(a), Type::Scalar(b)) => a.kind == b.kind && a.width == b.width,
            (Type::Pointer { target: a }, Type::Pointer { target: b }) => self.same(*a, *b),
            (
                Type::Array {
                    element: a,
                    count: m,
                },
                Type::Array {
                    element: b,
                    count: n,
                },
            ) => m == n && self.same(*a, *b),
            (Type::Enum { underlying: a, .. }, Type::Enum { underlying: b, .. }) => {
                self.same(*a, *b)
            }
            (Type::Record(a), Type::Record(b)) => {
                a.kind == b.kind
                    && a.size_bytes == b.size_bytes
                    && a.members.len() == b.members.len()
                    && a.members.iter().zip(&b.members).all(|(m, n)| {
                        m.offset_bits == n.offset_bits
                            && m.bit_size == n.bit_size
                            && self.same(m.ty, n.ty)
                    })
            }
            (Type::Code(a), Type::Code(b)) => {
                a.variadic == b.variadic
                    && a.prototyped == b.prototyped
                    && a.parameters.len() == b.parameters.len()
                    && self.same(a.returns, b.returns)
                    && a.parameters
                        .iter()
                        .zip(&b.parameters)
                        .all(|(m, n)| self.same(*m, *n))
            }
            (Type::Opaque { keyword: k, tag: t }, Type::Opaque { keyword: l, tag: u }) => {
                k == l && t == u
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parameter;
    use crate::types::{Scalar, ScalarKind, Width};

    fn scalar(graph: &mut TypeGraph, kind: ScalarKind, bits: u32, name: &str) -> TypeId {
        graph.add(Type::Scalar(Scalar {
            kind,
            width: Width::Bits(bits),
            name: Some(name.to_owned()),
        }))
    }

    fn taking(name: &str, ty: TypeId) -> Prototype {
        Prototype {
            name: name.to_owned(),
            parameters: vec![Parameter::new(ty, "", Some("x"))],
            ..Prototype::default()
        }
    }

    #[test]
    fn a_folded_body_keeps_a_declaration_only_its_functions_agree_on() {
        let mut graph = TypeGraph::new();
        let int = scalar(&mut graph, ScalarKind::Signed, 32, "int");
        let also_int = scalar(&mut graph, ScalarKind::Signed, 32, "int32_t");
        let long = scalar(&mut graph, ScalarKind::Signed, 64, "long");
        let mut declarations = Declarations::new(graph);

        declarations.declare_function(0x1000, taking("f", int));
        declarations.declare_function(0x1000, taking("g", also_int));
        assert_eq!(
            declarations.function_at(0x1000).map(|p| p.name.as_str()),
            Some("f"),
            "the same type under another name is the same interface"
        );

        declarations.declare_function(0x2000, taking("h", int));
        declarations.declare_function(0x2000, taking("k", long));
        declarations.declare_function(0x2000, taking("m", int));
        assert!(declarations.function_at(0x2000).is_none());
        assert!(declarations.is_contested(0x2000));
    }
}
