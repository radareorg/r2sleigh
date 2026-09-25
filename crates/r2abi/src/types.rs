//! What a declaration says a type is.
//!
//! One model for every declaration the engine reads: a binary's own debug
//! information and the shipped library table both become nodes of a
//! [`TypeGraph`], and a prototype names its parameters, its result and its
//! frame variables by node. A C spelling is derived from the graph for
//! presentation; nothing downstream reads a type back out of text.
//!
//! The graph states what the declaration states and no more. A member sits at
//! the offset the declaration gives it and a record is as large as it says,
//! whatever a natural layout would have made of it. A tag the declaration
//! never completes is [`Type::Opaque`], which is a type a pointer may name and
//! nothing may hold. A node the reader could not state is [`Type::Refused`]
//! with the reason, and only what reaches it through that node loses anything:
//! a refusal never spreads to its neighbours.

use std::collections::{BTreeMap, BTreeSet};

/// One node of one [`TypeGraph`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(u32);

impl TypeId {
    /// `void`, which every graph holds at its first node.
    pub const VOID: TypeId = TypeId(0);

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// How many bits a scalar is, as the declaration says it.
///
/// Debug information states a width in bytes. The shipped table spells C
/// types, and how wide `long` is belongs to the target rather than to the
/// spelling, so it stays a question the [`DataModel`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Width {
    Bits(u32),
    /// `long`.
    Long,
    /// An integer as wide as an address: `size_t`, `intptr_t`, `ptrdiff_t`.
    Pointer,
    /// `long double`, whose storage the target decides.
    LongDouble,
}

/// What one scalar's bits mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScalarKind {
    Signed,
    Unsigned,
    Bool,
    /// An IEEE binary floating-point value.
    Float,
}

/// A value the language operates on directly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scalar {
    pub kind: ScalarKind,
    pub width: Width,
    /// What the declaration calls it, such as `long unsigned int`; presentation
    /// only.
    pub name: Option<String>,
}

/// Whether a record lays its members out in turn or all at its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    Struct,
    Union,
}

/// The keyword a tag is declared under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Keyword {
    Struct,
    Union,
    Enum,
    /// A name for a type the declaration never says anything more about.
    Typedef,
}

/// One member, where the declaration places it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Member {
    pub name: Option<String>,
    pub ty: TypeId,
    /// Bits from the record's start, as stated.
    pub offset_bits: u64,
    /// The width of a bit-field; `None` for a member that occupies its type.
    pub bit_size: Option<u64>,
}

/// A struct or union with the layout the declaration states.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Record {
    pub kind: RecordKind,
    /// The tag, or the name of the typedef that is the record's only name.
    pub tag: Option<String>,
    pub size_bytes: u64,
    /// In the order the declaration lists them.
    pub members: Vec<Member>,
}

/// What code takes and returns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature {
    pub returns: TypeId,
    pub parameters: Vec<TypeId>,
    pub variadic: bool,
    /// Whether the parameters are stated at all. `int f()` in C, or a
    /// declaration that says only that something is a function, states none.
    pub prototyped: bool,
}

/// The qualifiers on one type: which never change its layout, and which a
/// redeclaration must still repeat.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Qualifiers(u8);

impl Qualifiers {
    pub const CONST: Qualifiers = Qualifiers(1);
    pub const VOLATILE: Qualifiers = Qualifiers(2);
    pub const RESTRICT: Qualifiers = Qualifiers(4);
    pub const ATOMIC: Qualifiers = Qualifiers(8);

    pub const fn union(self, other: Qualifiers) -> Qualifiers {
        Qualifiers(self.0 | other.0)
    }

    pub const fn contains(self, other: Qualifiers) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// As C spells them, in the order a declaration writes them.
    fn words(self) -> impl Iterator<Item = &'static str> {
        [
            (Self::CONST, "const"),
            (Self::VOLATILE, "volatile"),
            (Self::RESTRICT, "restrict"),
            (Self::ATOMIC, "_Atomic"),
        ]
        .into_iter()
        .filter(move |(bit, _)| self.contains(*bit))
        .map(|(_, word)| word)
    }
}

/// Why one node states nothing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Refusal(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    Void,
    Scalar(Scalar),
    Pointer {
        target: TypeId,
    },
    /// `count` elements of one type; `None` where the declaration states no
    /// bound, which is a flexible array member or an incomplete array.
    Array {
        element: TypeId,
        count: Option<u64>,
    },
    Record(Record),
    /// An enumeration, which is its underlying integer everywhere but in name.
    Enum {
        tag: Option<String>,
        underlying: TypeId,
    },
    Code(Signature),
    /// A tag the declaration never completes: `FILE`, or any `struct x;`.
    Opaque {
        keyword: Keyword,
        tag: String,
    },
    Qualified {
        qualifiers: Qualifiers,
        target: TypeId,
    },
    Typedef {
        name: String,
        target: TypeId,
    },
    Refused(Refusal),
}

/// How wide the target makes the widths a C spelling leaves to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataModel {
    pub pointer_bits: u32,
    pub long_bits: u32,
    /// The storage a `long double` occupies, where this model states it.
    pub long_double_bits: Option<u32>,
}

impl DataModel {
    /// `long` and pointers as wide as each other, which is every Unix target
    /// this engine lifts. Nothing here states `long double`: its format and
    /// its class are the convention's to say.
    pub const fn unix(pointer_bits: u32) -> Self {
        Self {
            pointer_bits,
            long_bits: pointer_bits,
            long_double_bits: None,
        }
    }

    pub fn bits(&self, width: Width) -> Option<u32> {
        match width {
            Width::Bits(bits) => Some(bits),
            Width::Long => Some(self.long_bits),
            Width::Pointer => Some(self.pointer_bits),
            Width::LongDouble => self.long_double_bits,
        }
    }
}

/// Every type one source declares, by node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeGraph {
    types: Vec<Type>,
    /// Scalars and `void` are values, so one node stands for each.
    leaves: BTreeMap<Type, TypeId>,
}

impl Default for TypeGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeGraph {
    pub fn new() -> Self {
        let mut leaves = BTreeMap::new();
        leaves.insert(Type::Void, TypeId::VOID);
        Self {
            types: vec![Type::Void],
            leaves,
        }
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    pub fn get(&self, id: TypeId) -> Option<&Type> {
        self.types.get(id.index())
    }

    /// Every node, in the order it was added.
    pub fn iter(&self) -> impl Iterator<Item = (TypeId, &Type)> {
        self.types
            .iter()
            .enumerate()
            .map(|(index, ty)| (TypeId(index as u32), ty))
    }

    /// Add one node. A scalar or `void` already present is that node.
    pub fn add(&mut self, ty: Type) -> TypeId {
        if matches!(ty, Type::Void | Type::Scalar(_)) {
            if let Some(found) = self.leaves.get(&ty) {
                return *found;
            }
            let id = self.push(ty.clone());
            self.leaves.insert(ty, id);
            return id;
        }
        self.push(ty)
    }

    /// A node whose content is stated later, so that a type reaching itself
    /// through a pointer names this node rather than a copy of it.
    pub fn reserve(&mut self) -> TypeId {
        self.push(Type::Refused(Refusal("never completed".to_owned())))
    }

    /// State what a reserved node is.
    pub fn define(&mut self, id: TypeId, ty: Type) {
        if let Some(slot) = self.types.get_mut(id.index()) {
            *slot = ty;
        }
    }

    pub fn refused(&mut self, reason: impl Into<String>) -> TypeId {
        self.push(Type::Refused(Refusal(reason.into())))
    }

    fn push(&mut self, ty: Type) -> TypeId {
        let id = TypeId(u32::try_from(self.types.len()).unwrap_or(u32::MAX));
        self.types.push(ty);
        id
    }

    /// The type a name or a qualifier stands for, with every one of them read
    /// through, and the qualifiers met on the way.
    pub fn peel(&self, id: TypeId) -> (TypeId, Qualifiers) {
        let mut at = id;
        let mut qualifiers = Qualifiers::default();
        let mut seen = BTreeSet::new();
        while seen.insert(at) {
            match self.get(at) {
                Some(Type::Typedef { target, .. }) => at = *target,
                Some(Type::Qualified {
                    qualifiers: more,
                    target,
                }) => {
                    qualifiers = qualifiers.union(*more);
                    at = *target;
                }
                _ => return (at, qualifiers),
            }
        }
        // A name that stands for itself is no type.
        (at, qualifiers)
    }

    /// The node itself, read through names and qualifiers.
    pub fn resolved(&self, id: TypeId) -> Option<&Type> {
        self.get(self.peel(id).0)
    }

    /// How many bits an object of this type occupies, where that is stated.
    ///
    /// An object has a size only if the declaration completes it: `void`,
    /// code, an opaque tag, an array with no bound and a refused node have
    /// none.
    pub fn size_bits(&self, id: TypeId, model: &DataModel) -> Option<u64> {
        self.size_through(id, model, &mut BTreeSet::new())
    }

    fn size_through(
        &self,
        id: TypeId,
        model: &DataModel,
        visiting: &mut BTreeSet<TypeId>,
    ) -> Option<u64> {
        // A record holding itself by value has no size in any language.
        if !visiting.insert(id) {
            return None;
        }
        let size = match self.get(id)? {
            Type::Scalar(scalar) => model.bits(scalar.width).map(u64::from),
            Type::Pointer { .. } => Some(u64::from(model.pointer_bits)),
            Type::Array {
                element,
                count: Some(count),
            } => self
                .size_through(*element, model, visiting)?
                .checked_mul(*count),
            Type::Record(record) => record.size_bytes.checked_mul(8),
            Type::Enum { underlying, .. }
            | Type::Qualified {
                target: underlying, ..
            }
            | Type::Typedef {
                target: underlying, ..
            } => self.size_through(*underlying, model, visiting),
            Type::Void
            | Type::Array { count: None, .. }
            | Type::Code(_)
            | Type::Opaque { .. }
            | Type::Refused(_) => None,
        };
        visiting.remove(&id);
        size
    }

    /// What a record is called, where anything calls it.
    pub fn tag(&self, id: TypeId) -> Option<&str> {
        match self.get(id)? {
            Type::Record(record) => record.tag.as_deref(),
            Type::Enum { tag, .. } => tag.as_deref(),
            Type::Opaque { tag, .. } => Some(tag),
            _ => None,
        }
    }

    /// The type as the declaration writes it and as the language reads it,
    /// for presentation.
    pub fn spelled(&self, id: TypeId) -> Option<crate::Spelled> {
        let declared = self.spelling(id, "", Names::Keep)?;
        let resolved = self.spelling(id, "", Names::Resolve);
        Some(crate::Spelled::new(declared, resolved))
    }

    /// One declaration of `name` at this type, as C writes it: `int v[4]`,
    /// `int (*fn)(int, int)`.
    pub fn declaration(&self, id: TypeId, name: &str) -> Option<String> {
        self.spelling(id, name, Names::Keep)
    }

    fn spelling(&self, id: TypeId, inner: &str, names: Names) -> Option<String> {
        Spelling {
            graph: self,
            names,
            visiting: BTreeSet::new(),
        }
        .declare(id, inner.to_owned())
    }
}

/// Whether a spelling keeps a typedef's name or writes what it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Names {
    Keep,
    Resolve,
}

/// One C declarator being written inside out.
struct Spelling<'a> {
    graph: &'a TypeGraph,
    names: Names,
    /// Nodes being spelled. Reaching one again means the graph describes a
    /// type through itself without a name to stop at, which C cannot write.
    visiting: BTreeSet<TypeId>,
}

impl Spelling<'_> {
    fn declare(&mut self, id: TypeId, inner: String) -> Option<String> {
        if !self.visiting.insert(id) {
            return None;
        }
        let spelled = self.declare_node(id, inner);
        self.visiting.remove(&id);
        spelled
    }

    fn declare_node(&mut self, id: TypeId, inner: String) -> Option<String> {
        let graph = self.graph;
        match graph.get(id)? {
            Type::Void => Some(joined("void", &inner)),
            Type::Scalar(scalar) => Some(joined(&scalar_spelling(scalar), &inner)),
            Type::Record(record) => {
                let keyword = match record.kind {
                    RecordKind::Struct => "struct",
                    RecordKind::Union => "union",
                };
                Some(joined(
                    &format!("{keyword} {}", record.tag.as_ref()?),
                    &inner,
                ))
            }
            Type::Enum { tag, underlying } => match tag {
                Some(tag) => Some(joined(&format!("enum {tag}"), &inner)),
                None => self.declare(*underlying, inner),
            },
            Type::Opaque { keyword, tag } => Some(joined(&opaque_spelling(*keyword, tag), &inner)),
            Type::Typedef { name, target } => match self.names {
                Names::Keep => Some(joined(name, &inner)),
                Names::Resolve => self.declare(*target, inner),
            },
            Type::Qualified { qualifiers, target } => self.qualified(*qualifiers, *target, inner),
            Type::Pointer { target } => self.declare(*target, format!("*{inner}")),
            Type::Array { element, count } => {
                let bound = count.map(|count| count.to_string()).unwrap_or_default();
                self.declare(*element, format!("{}[{bound}]", grouped(&inner)))
            }
            Type::Code(signature) => self.code(signature, inner),
            Type::Refused(_) => None,
        }
    }

    /// A qualifier on a pointer follows the star; on anything else it leads.
    fn qualified(
        &mut self,
        qualifiers: Qualifiers,
        target: TypeId,
        inner: String,
    ) -> Option<String> {
        let words = qualifiers.words().collect::<Vec<_>>().join(" ");
        let pointer = matches!(self.graph.get(target), Some(Type::Pointer { .. }));
        match pointer {
            true => self.declare(target, format!(" {words}{}", spaced(&inner))),
            false => self
                .declare(target, inner)
                .map(|spelled| format!("{words} {spelled}")),
        }
    }

    fn code(&mut self, signature: &Signature, inner: String) -> Option<String> {
        let mut parameters = signature
            .parameters
            .iter()
            .map(|parameter| self.declare(*parameter, String::new()))
            .collect::<Option<Vec<_>>>()?;
        if signature.variadic {
            parameters.push("...".to_owned());
        }
        let list = match (signature.prototyped, parameters.is_empty()) {
            (false, _) => String::new(),
            (true, true) => "void".to_owned(),
            (true, false) => parameters.join(", "),
        };
        self.declare(signature.returns, format!("{}({list})", grouped(&inner)))
    }
}

/// A declarator that binds looser than a suffix is parenthesised before one.
fn grouped(inner: &str) -> String {
    match inner.trim_start().starts_with('*') {
        true => format!("({})", inner.trim()),
        false => inner.to_owned(),
    }
}

fn spaced(inner: &str) -> String {
    match inner.is_empty() || inner.starts_with('*') || inner.starts_with('[') {
        true => inner.to_owned(),
        false => format!(" {inner}"),
    }
}

/// A specifier and the declarator it applies to: `char *`, `int v[4]`,
/// `int[4]`.
fn joined(specifier: &str, inner: &str) -> String {
    let inner = inner.trim();
    match inner.is_empty() || inner.starts_with('[') {
        true => format!("{specifier}{inner}"),
        false => format!("{specifier} {inner}"),
    }
}

fn opaque_spelling(keyword: Keyword, tag: &str) -> String {
    match keyword {
        Keyword::Struct => format!("struct {tag}"),
        Keyword::Union => format!("union {tag}"),
        Keyword::Enum => format!("enum {tag}"),
        Keyword::Typedef => tag.to_owned(),
    }
}

/// What C calls a scalar the declaration gave no name.
fn scalar_spelling(scalar: &Scalar) -> String {
    if let Some(name) = &scalar.name {
        return name.clone();
    }
    match (scalar.kind, scalar.width) {
        (ScalarKind::Bool, _) => "_Bool".to_owned(),
        (ScalarKind::Float, Width::Bits(32)) => "float".to_owned(),
        (ScalarKind::Float, Width::Bits(64)) => "double".to_owned(),
        (ScalarKind::Float, _) => "long double".to_owned(),
        (ScalarKind::Signed, Width::Long) => "long".to_owned(),
        (ScalarKind::Unsigned, Width::Long) => "unsigned long".to_owned(),
        (ScalarKind::Signed, Width::Pointer) => "intptr_t".to_owned(),
        (ScalarKind::Unsigned, Width::Pointer) => "uintptr_t".to_owned(),
        (ScalarKind::Signed, width) => format!("int{}_t", bits_of(width)),
        (ScalarKind::Unsigned, width) => format!("uint{}_t", bits_of(width)),
    }
}

fn bits_of(width: Width) -> u32 {
    match width {
        Width::Bits(bits) => bits,
        Width::Long | Width::Pointer | Width::LongDouble => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(graph: &mut TypeGraph) -> TypeId {
        graph.add(Type::Scalar(Scalar {
            kind: ScalarKind::Signed,
            width: Width::Bits(32),
            name: Some("int".to_owned()),
        }))
    }

    #[test]
    fn a_declarator_is_written_inside_out() {
        let mut graph = TypeGraph::new();
        let int = int(&mut graph);
        let array = graph.add(Type::Array {
            element: int,
            count: Some(4),
        });
        assert_eq!(graph.declaration(array, "v").as_deref(), Some("int v[4]"));
        let code = graph.add(Type::Code(Signature {
            returns: int,
            parameters: vec![int, int],
            variadic: false,
            prototyped: true,
        }));
        let pointer = graph.add(Type::Pointer { target: code });
        assert_eq!(
            graph.declaration(pointer, "fn").as_deref(),
            Some("int (*fn)(int, int)")
        );
        assert_eq!(
            graph.spelled(pointer).map(|s| s.declared),
            Some("int (*)(int, int)".to_owned())
        );
        let constant = graph.add(Type::Qualified {
            qualifiers: Qualifiers::CONST,
            target: int,
        });
        let to_constant = graph.add(Type::Pointer { target: constant });
        assert_eq!(
            graph.spelled(to_constant).map(|s| s.declared),
            Some("const int *".to_owned())
        );
    }

    #[test]
    fn a_record_reaching_itself_through_a_pointer_is_one_node() {
        let mut graph = TypeGraph::new();
        let int = int(&mut graph);
        let node = graph.reserve();
        let next = graph.add(Type::Pointer { target: node });
        graph.define(
            node,
            Type::Record(Record {
                kind: RecordKind::Struct,
                tag: Some("node".to_owned()),
                size_bytes: 16,
                members: vec![
                    Member {
                        name: Some("key".to_owned()),
                        ty: int,
                        offset_bits: 0,
                        bit_size: None,
                    },
                    Member {
                        name: Some("next".to_owned()),
                        ty: next,
                        offset_bits: 64,
                        bit_size: None,
                    },
                ],
            }),
        );
        let model = DataModel::unix(64);
        assert_eq!(graph.size_bits(node, &model), Some(128));
        assert_eq!(graph.size_bits(next, &model), Some(64));
        assert_eq!(
            graph.spelled(next).map(|s| s.declared),
            Some("struct node *".to_owned())
        );
    }

    #[test]
    fn an_incomplete_type_has_no_size_and_a_name() {
        let mut graph = TypeGraph::new();
        let file = graph.add(Type::Opaque {
            keyword: Keyword::Typedef,
            tag: "FILE".to_owned(),
        });
        let pointer = graph.add(Type::Pointer { target: file });
        let model = DataModel::unix(64);
        assert_eq!(graph.size_bits(file, &model), None);
        assert_eq!(graph.size_bits(pointer, &model), Some(64));
        assert_eq!(
            graph.spelled(pointer).map(|s| s.declared),
            Some("FILE *".to_owned())
        );
    }

    #[test]
    fn a_name_that_stands_for_itself_states_nothing() {
        let mut graph = TypeGraph::new();
        let loop_ = graph.reserve();
        graph.define(
            loop_,
            Type::Typedef {
                name: "t".to_owned(),
                target: loop_,
            },
        );
        assert_eq!(graph.size_bits(loop_, &DataModel::unix(64)), None);
        assert_eq!(
            graph.spelled(loop_).map(|s| s.resolved),
            Some(None),
            "the kept name spells; what it names does not"
        );
    }
}
