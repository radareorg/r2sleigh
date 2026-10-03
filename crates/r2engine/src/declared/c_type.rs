//! A declared type as the type layer states it.
//!
//! The type layer's model names an aggregate by its tag and reaches no
//! further, so a record is its name here and a pointer to one ends at it.

use std::collections::BTreeSet;

use r2abi::{DataModel, Keyword, Qualifiers, RecordKind, ScalarKind, Type, TypeGraph, TypeId};
use r2types::{CTypeLike, Signedness};

/// One declared node, or `Unknown` where the declaration states nothing the
/// type layer can hold.
pub(crate) fn c_type(graph: &TypeGraph, ty: TypeId, model: &DataModel) -> CTypeLike {
    Conversion {
        graph,
        model,
        visiting: BTreeSet::new(),
    }
    .convert(ty, false)
}

struct Conversion<'a> {
    graph: &'a TypeGraph,
    model: &'a DataModel,
    /// Nodes being converted. A type reaches itself only through a record,
    /// which ends at its name; reaching one of these again is a declaration
    /// that describes a type through itself, which states nothing.
    visiting: BTreeSet<TypeId>,
}

impl Conversion<'_> {
    fn convert(&mut self, ty: TypeId, pointee: bool) -> CTypeLike {
        if !self.visiting.insert(ty) {
            return CTypeLike::Unknown;
        }
        let converted = self.node(ty, pointee);
        self.visiting.remove(&ty);
        converted
    }

    fn node(&mut self, ty: TypeId, pointee: bool) -> CTypeLike {
        let graph = self.graph;
        let Some(node) = graph.get(ty) else {
            return CTypeLike::Unknown;
        };
        match node {
            Type::Void => CTypeLike::Void,
            Type::Scalar(scalar) => match (scalar.kind, self.model.bits(scalar.width)) {
                (_, None) => CTypeLike::Unknown,
                (ScalarKind::Bool, Some(_)) => CTypeLike::Bool,
                (ScalarKind::Float, Some(bits)) => CTypeLike::Float(bits),
                (ScalarKind::Signed, Some(bits)) => CTypeLike::Int {
                    bits,
                    signedness: Signedness::Signed,
                },
                (ScalarKind::Unsigned, Some(bits)) => CTypeLike::Int {
                    bits,
                    signedness: Signedness::Unsigned,
                },
            },
            Type::Pointer { target } => match self.convert(*target, true) {
                // The type layer spells a function type as a pointer to one.
                code @ CTypeLike::Function { .. } => code,
                target => CTypeLike::Pointer(Box::new(target)),
            },
            Type::Array { element, count } => CTypeLike::Array(
                Box::new(self.convert(*element, false)),
                count.and_then(|count| usize::try_from(count).ok()),
            ),
            Type::Record(record) => match (&record.tag, record.kind) {
                (Some(tag), RecordKind::Struct) => CTypeLike::Struct(tag.clone()),
                (Some(tag), RecordKind::Union) => CTypeLike::Union(tag.clone()),
                (None, _) => CTypeLike::Unknown,
            },
            // An enumeration is its underlying integer to everything that
            // reads a value of it.
            Type::Enum { underlying, .. } => self.convert(*underlying, pointee),
            Type::Code(signature) if signature.prototyped && !signature.variadic => {
                CTypeLike::Function {
                    ret: Box::new(self.convert(signature.returns, false)),
                    params: signature
                        .parameters
                        .iter()
                        .map(|parameter| self.convert(*parameter, false))
                        .collect(),
                }
            }
            Type::Opaque { keyword, tag } => match keyword {
                Keyword::Struct => CTypeLike::Struct(tag.clone()),
                Keyword::Union => CTypeLike::Union(tag.clone()),
                Keyword::Enum => CTypeLike::Enum(tag.clone()),
                Keyword::Typedef => CTypeLike::typedef(tag.clone()),
            },
            // A pointee's `const` is part of the pointer's type; a qualifier
            // anywhere else is not part of a prototype's.
            Type::Qualified { qualifiers, target } => {
                let target = self.convert(*target, pointee);
                match pointee && qualifiers.contains(Qualifiers::CONST) {
                    true => CTypeLike::Const(Box::new(target)),
                    false => target,
                }
            }
            // What a name stands for, which is what the call is read with;
            // the spelling that keeps the name travels beside the signature.
            Type::Typedef { target, .. } => self.convert(*target, pointee),
            Type::Code(_) | Type::Refused(_) => CTypeLike::Unknown,
        }
    }
}
