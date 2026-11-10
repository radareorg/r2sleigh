//! A declared type as the type layer states it.
//!
//! The type layer's model names an aggregate by its tag and reaches no
//! further, so a record is its name here and a pointer to one ends at it.

use std::collections::BTreeSet;

use r2abi::{
    CDataModel, Keyword, Qualifiers, RecordKind, Scalar, ScalarKind, Type, TypeGraph, TypeId,
};
use r2types::{CTypeLike, Signedness};

/// One declared node, or `Unknown` where the declaration states nothing the
/// type layer can hold.
pub(crate) fn c_type(graph: &TypeGraph, ty: TypeId, model: &CDataModel) -> CTypeLike {
    Conversion {
        graph,
        model,
        visiting: BTreeSet::new(),
    }
    .convert(ty, false)
}

struct Conversion<'a> {
    graph: &'a TypeGraph,
    model: &'a CDataModel,
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
            Type::Scalar(scalar) => self.scalar(scalar),
            Type::Pointer { target } => match self.convert(*target, true) {
                // The type layer spells a function type as a pointer to one.
                code @ (CTypeLike::Function { .. } | CTypeLike::UnprototypedFunction(_)) => code,
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
            // What a name stands for (its spelling travels beside the signature);
            // a scalar the target's model leaves unstated is its name alone.
            Type::Typedef { name, target } => match self.convert(*target, pointee) {
                CTypeLike::Unknown if matches!(graph.get(*target), Some(Type::Scalar(_))) => {
                    CTypeLike::typedef(name.clone())
                }
                // A name over a tag nothing completes is how C spells a handle (`FILE`), and one
                // over a pointer to such a tag a pointer-passed state (`va_list`).
                converted
                @ (CTypeLike::Struct(_) | CTypeLike::Union(_) | CTypeLike::Pointer(_))
                    if opaque_behind(graph, *target) =>
                {
                    CTypeLike::named(name.clone(), converted)
                }
                target => target,
            },
            // A code type the declaration gives no parameters for (r2abi's `func`).
            Type::Code(signature) if !signature.prototyped => {
                CTypeLike::UnprototypedFunction(Box::new(self.convert(signature.returns, false)))
            }
            Type::Code(_) | Type::Refused(_) => CTypeLike::Unknown,
        }
    }

    fn scalar(&self, scalar: &Scalar) -> CTypeLike {
        let bits = self.model.bits(scalar.width);
        if let Some(signed) = super::plain_char(scalar, self.model) {
            return CTypeLike::plain_char(signed);
        }
        match (self.model.kind(scalar.kind), bits) {
            (_, None) | (None, _) => CTypeLike::Unknown,
            (Some(ScalarKind::Bool), Some(_)) => CTypeLike::Bool,
            (Some(ScalarKind::Float), Some(bits)) => CTypeLike::Float(bits),
            (Some(ScalarKind::Signed), Some(bits)) => CTypeLike::Int {
                bits,
                signedness: Signedness::Signed,
            },
            (Some(ScalarKind::Unsigned), Some(bits)) => CTypeLike::Int {
                bits,
                signedness: Signedness::Unsigned,
            },
            // The model resolves both to a sign.
            (Some(ScalarKind::PlainChar | ScalarKind::WideChar), Some(_)) => CTypeLike::Unknown,
        }
    }
}

/// Whether `ty` is a tag nothing completes, or a pointer to one.
fn opaque_behind(graph: &TypeGraph, ty: TypeId) -> bool {
    match graph.resolved(ty) {
        Some(Type::Opaque { .. }) => true,
        Some(Type::Pointer { target }) => {
            matches!(graph.resolved(*target), Some(Type::Opaque { .. }))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2abi::{CLibrary, LibraryRows, Width};

    /// `strlen`'s `const char *` under a model: the byte's sign is the model's, or none.
    fn strlen_char(model: &CDataModel) -> CTypeLike {
        let rows = LibraryRows::embedded(CLibrary::Glibc);
        let strlen = rows
            .find(CLibrary::Glibc.scope(), "strlen")
            .expect("strlen is declared");
        c_type(rows.graph(), rows.prototype(strlen).parameters[0].ty, model)
    }

    fn char_of(signedness: Signedness) -> CTypeLike {
        let char_ = CTypeLike::named(
            "char",
            CTypeLike::Int {
                bits: 8,
                signedness,
            },
        );
        CTypeLike::Pointer(Box::new(CTypeLike::Const(Box::new(char_))))
    }

    #[test]
    fn a_rows_plain_char_takes_the_models_sign_and_debug_information_keeps_its_own() {
        let aarch64 = CDataModel::of("aarch64", 64, CLibrary::Glibc).expect("AAPCS64 glibc");
        let x86_64 = CDataModel::of("x86-64", 64, CLibrary::Glibc).expect("SysV glibc");
        assert_eq!(strlen_char(aarch64), char_of(Signedness::Unsigned));
        assert_eq!(strlen_char(x86_64), char_of(Signedness::Signed));
        assert_eq!(
            strlen_char(&CDataModel::unix(64)),
            char_of(Signedness::Unknown)
        );
        // DWARF's `char` states DW_ATE_signed_char, which no model overrides.
        let mut graph = TypeGraph::new();
        let stated = graph.add(Type::Scalar(r2abi::Scalar {
            kind: ScalarKind::Signed,
            width: Width::Bits(8),
            name: Some("char".to_owned()),
        }));
        assert_eq!(
            c_type(&graph, stated, aarch64),
            CTypeLike::named(
                "char",
                CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Signed
                }
            )
        );
    }

    /// glibc's `FILE` keeps its name over the tag its header gives it.
    #[test]
    fn a_handle_keeps_its_name_over_its_tag() {
        let rows = LibraryRows::embedded(CLibrary::Glibc);
        let fclose = rows
            .find(CLibrary::Glibc.scope(), "fclose")
            .expect("fclose");
        let model = CDataModel::of("x86-64", 64, CLibrary::Glibc).expect("SysV glibc");
        let stream = c_type(rows.graph(), rows.prototype(fclose).parameters[0].ty, model);
        let file = CTypeLike::named("FILE", CTypeLike::Struct("_IO_FILE".to_owned()));
        assert_eq!(stream, CTypeLike::Pointer(Box::new(file)));
        // `va_list` is passed as a pointer and spelled by its name.
        let vfprintf = rows
            .find(CLibrary::Glibc.scope(), "vfprintf")
            .expect("vfprintf");
        let list = c_type(
            rows.graph(),
            rows.prototype(vfprintf).parameters[2].ty,
            model,
        );
        assert!(
            matches!(&list, CTypeLike::Typedef { name, .. } if name == "va_list"),
            "{list:?}"
        );
    }
}
