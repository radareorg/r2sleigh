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

use crate::CDataModel;

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
/// spelling, so it stays a question the [`CDataModel`] answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Width {
    Bits(u32),
    /// `long`.
    Long,
    /// An integer as wide as an address: `size_t`, `intptr_t`, `ptrdiff_t`.
    Pointer,
    /// `long double`, whose storage the target decides.
    LongDouble,
    /// `wchar_t`'s, which the target's [`CDataModel`] states.
    WideChar,
    /// The Linux kernel's `__kernel_mode_t`, bionic's `mode_t`: the target's [`CDataModel`] states it.
    KernelMode,
}

/// What one scalar's bits mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScalarKind {
    Signed,
    Unsigned,
    Bool,
    /// An IEEE binary floating-point value.
    Float,
    /// Plain `char`, whose sign the target's [`CDataModel`] states.
    PlainChar,
    /// `wchar_t`, whose sign the target's [`CDataModel`] states.
    WideChar,
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
    /// The convention the type states (`DW_AT_calling_convention` on a subroutine type).
    pub convention: crate::StatedConvention,
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
    pub fn size_bits(&self, id: TypeId, model: &CDataModel) -> Option<u64> {
        self.size_through(id, model, &mut BTreeSet::new())
    }

    fn size_through(
        &self,
        id: TypeId,
        model: &CDataModel,
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

/// Record identity across units (D491, C17 6.2.7p1): nodes with equal labelled unfoldings are one.
impl TypeGraph {
    /// The quotient: each class at its lowest id, in first-occurrence order; each old node's new id.
    /// Hopcroft refinement, O((N + E) log N); each split raises the class count, which N bounds.
    pub fn quotient(&mut self) -> Vec<TypeId> {
        let classes = Refinement::of(&self.types).coarsest();
        let mut renumbered = vec![u32::MAX; classes.count];
        let mut kept = Vec::new();
        let mut index = Vec::with_capacity(self.types.len());
        for (node, class) in classes.class.iter().enumerate() {
            let slot = &mut renumbered[*class as usize];
            if *slot == u32::MAX {
                *slot = u32::try_from(kept.len()).unwrap_or(u32::MAX);
                kept.push(node);
            }
            index.push(TypeId(*slot));
        }
        let types = kept.iter().map(|node| {
            let mut ty = self.types[*node].clone();
            map_children(&mut ty, |child| index[child.index()]);
            ty
        });
        self.types = types.collect();
        self.leaves = (self.iter())
            .filter(|(_, ty)| matches!(ty, Type::Void | Type::Scalar(_)))
            .map(|(id, ty)| (ty.clone(), id))
            .collect();
        index
    }
}

/// Each child a node names, in declared order: its edges, by position.
fn each_child(ty: &Type, mut child: impl FnMut(TypeId)) {
    match ty {
        Type::Pointer { target }
        | Type::Array {
            element: target, ..
        }
        | Type::Enum {
            underlying: target, ..
        }
        | Type::Qualified { target, .. }
        | Type::Typedef { target, .. } => child(*target),
        Type::Record(record) => record.members.iter().for_each(|member| child(member.ty)),
        Type::Code(signature) => {
            child(signature.returns);
            signature.parameters.iter().copied().for_each(child);
        }
        Type::Void | Type::Scalar(_) | Type::Opaque { .. } | Type::Refused(_) => {}
    }
}

/// The same node naming `map(child)` for each child.
fn map_children(ty: &mut Type, mut map: impl FnMut(TypeId) -> TypeId) {
    match ty {
        Type::Pointer { target }
        | Type::Array {
            element: target, ..
        }
        | Type::Enum {
            underlying: target, ..
        }
        | Type::Qualified { target, .. }
        | Type::Typedef { target, .. } => *target = map(*target),
        Type::Record(record) => (record.members.iter_mut()).for_each(|m| m.ty = map(m.ty)),
        Type::Code(signature) => {
            signature.returns = map(signature.returns);
            (signature.parameters.iter_mut()).for_each(|p| *p = map(*p));
        }
        Type::Void | Type::Scalar(_) | Type::Opaque { .. } | Type::Refused(_) => {}
    }
}

/// A node's label: the node with every child `void`; variant, tags, names, sizes, offsets,
/// qualifiers, counts and signature flags compare.
fn label(ty: &Type) -> Type {
    let mut label = ty.clone();
    map_children(&mut label, |_| TypeId::VOID);
    label
}

/// The coarsest partition where one class has one label and, per child position, children of one
/// class (Valmari and Lehtinen's refinable partition).
struct Refinement {
    /// Nodes grouped by class: each class is one range of it.
    order: Vec<u32>,
    /// Each node's index in `order`.
    at: Vec<u32>,
    class: Vec<u32>,
    start: Vec<u32>,
    end: Vec<u32>,
    /// One past each class's marked prefix.
    marked: Vec<u32>,
    touched: Vec<u32>,
    /// Each node's parents, as `(parent, position)`, from `parents_from[node]` to the next node's.
    parents_from: Vec<u32>,
    parents: Vec<(u32, u32)>,
    arity: usize,
}

/// The finished partition: each node's class, and how many classes there are.
struct Classes {
    class: Vec<u32>,
    count: usize,
}

impl Refinement {
    /// Classes by label, in label order, and every node's parents.
    fn of(types: &[Type]) -> Self {
        let labels = types.iter().map(label).collect::<Vec<_>>();
        let mut order = (0..types.len() as u32).collect::<Vec<_>>();
        order.sort_by(|a, b| labels[*a as usize].cmp(&labels[*b as usize]).then(a.cmp(b)));
        let (mut class, mut at) = (vec![0; types.len()], vec![0; types.len()]);
        let (mut start, mut end) = (Vec::new(), Vec::new());
        for (index, node) in order.iter().enumerate() {
            let fresh = index == 0 || labels[order[index - 1] as usize] != labels[*node as usize];
            if fresh {
                start.push(index as u32);
                end.push(index as u32);
            }
            let last = start.len() - 1;
            end[last] += 1;
            class[*node as usize] = last as u32;
            at[*node as usize] = index as u32;
        }
        let mut counts = vec![0u32; types.len() + 1];
        let mut arity = 0;
        for ty in types {
            let mut position = 0;
            each_child(ty, |child| {
                counts[child.index() + 1] += 1;
                position += 1;
            });
            arity = arity.max(position);
        }
        for node in 0..types.len() {
            counts[node + 1] += counts[node];
        }
        let mut filled = counts.clone();
        let mut parents = vec![(0, 0); counts[types.len()] as usize];
        for (parent, ty) in types.iter().enumerate() {
            let mut position = 0;
            each_child(ty, |child| {
                let slot = &mut filled[child.index()];
                parents[*slot as usize] = (parent as u32, position);
                *slot += 1;
                position += 1;
            });
        }
        Self {
            order,
            at,
            class,
            marked: start.clone(),
            start,
            end,
            touched: Vec::new(),
            parents_from: counts,
            parents,
            arity,
        }
    }

    /// Refine until every class is stable against every class. A class split after its turn queues
    /// its smaller half; the other half is then stable, since a node has one child per position.
    fn coarsest(mut self) -> Classes {
        let mut waiting = (0..self.start.len() as u32).collect::<Vec<_>>();
        let mut queued = vec![true; self.start.len()];
        let (mut by_position, mut used) = (vec![Vec::new(); self.arity], Vec::new());
        while let Some(splitter) = waiting.pop() {
            queued[splitter as usize] = false;
            let (from, to) = (self.start[splitter as usize], self.end[splitter as usize]);
            let members = self.order[from as usize..to as usize].to_vec();
            for node in members {
                let parents =
                    self.parents_from[node as usize]..self.parents_from[node as usize + 1];
                for (parent, position) in
                    &self.parents[parents.start as usize..parents.end as usize]
                {
                    let parents = &mut by_position[*position as usize];
                    if parents.is_empty() {
                        used.push(*position as usize);
                    }
                    parents.push(*parent);
                }
            }
            for position in used.drain(..) {
                for parent in std::mem::take(&mut by_position[position]) {
                    self.mark(parent);
                }
                self.split(&mut waiting, &mut queued);
            }
        }
        Classes {
            class: self.class,
            count: self.start.len(),
        }
    }

    fn mark(&mut self, node: u32) {
        let class = self.class[node as usize] as usize;
        let (index, boundary) = (self.at[node as usize], self.marked[class]);
        if index < boundary {
            return;
        }
        let other = self.order[boundary as usize];
        self.order.swap(index as usize, boundary as usize);
        self.at[other as usize] = index;
        self.at[node as usize] = boundary;
        if boundary == self.start[class] {
            self.touched.push(class as u32);
        }
        self.marked[class] = boundary + 1;
    }

    /// Split each touched class into its marked prefix, a new class, and the rest.
    fn split(&mut self, waiting: &mut Vec<u32>, queued: &mut Vec<bool>) {
        for class in std::mem::take(&mut self.touched) {
            let class = class as usize;
            let (from, middle, to) = (self.start[class], self.marked[class], self.end[class]);
            self.marked[class] = from;
            if middle == to {
                continue;
            }
            let fresh = self.start.len() as u32;
            for index in from..middle {
                self.class[self.order[index as usize] as usize] = fresh;
            }
            self.start.push(from);
            self.end.push(middle);
            self.marked.push(from);
            self.start[class] = middle;
            self.marked[class] = middle;
            let smaller = match queued[class] || middle - from <= to - middle {
                true => fresh,
                false => class as u32,
            };
            queued.push(false);
            for queue in [smaller].into_iter().chain(queued[class].then_some(fresh)) {
                if !queued[queue as usize] {
                    queued[queue as usize] = true;
                    waiting.push(queue);
                }
            }
        }
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
        (ScalarKind::PlainChar, _) => "char".to_owned(),
        (ScalarKind::WideChar, _) => "wchar_t".to_owned(),
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
        Width::Long | Width::Pointer | Width::LongDouble | Width::WideChar | Width::KernelMode => 0,
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
            convention: crate::StatedConvention::Normal,
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
        let model = CDataModel::unix(64);
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
        let model = CDataModel::unix(64);
        assert_eq!(graph.size_bits(file, &model), None);
        assert_eq!(graph.size_bits(pointer, &model), Some(64));
        assert_eq!(
            graph.spelled(pointer).map(|s| s.declared),
            Some("FILE *".to_owned())
        );
    }

    /// One unit's `typedef struct _IO_FILE { int _flags; struct _IO_FILE *_chain; } FILE`, with
    /// `chain` naming the second member.
    fn io_file(graph: &mut TypeGraph, chain: &str) -> (TypeId, TypeId, TypeId) {
        let int = int(graph);
        let record = graph.reserve();
        let pointer = graph.add(Type::Pointer { target: record });
        let member = |name: &str, ty, offset_bits| Member {
            name: Some(name.to_owned()),
            ty,
            offset_bits,
            bit_size: None,
        };
        let members = vec![member("_flags", int, 0), member(chain, pointer, 64)];
        let tag = Some("_IO_FILE".to_owned());
        let (kind, size_bytes) = (RecordKind::Struct, 16);
        graph.define(
            record,
            Type::Record(Record {
                kind,
                tag,
                size_bytes,
                members,
            }),
        );
        let name = "FILE".to_owned();
        let file = graph.add(Type::Typedef {
            name,
            target: record,
        });
        (record, pointer, file)
    }

    /// Two units' `FILE` over `struct _IO_FILE`, reaching itself through `_chain`, is one node; a
    /// record differing in one member name stays its own (D491, C17 6.2.7p1).
    #[test]
    fn equal_unfoldings_of_two_units_are_one_node() {
        let mut graph = TypeGraph::new();
        let first = io_file(&mut graph, "_chain");
        let second = io_file(&mut graph, "_chain");
        let other = io_file(&mut graph, "_next");
        let before = graph.len();
        let index = graph.quotient();
        let class = |id: TypeId| index[id.index()];
        assert_eq!(class(first.0), class(second.0));
        assert_eq!(class(first.1), class(second.1));
        assert_eq!(class(first.2), class(second.2));
        assert_ne!(class(first.0), class(other.0));
        assert_ne!(class(first.2), class(other.2));
        assert_eq!(graph.len(), before - 3);
        assert_eq!(class(TypeId::VOID), TypeId::VOID);
        let spelled = graph.spelled(class(first.1)).map(|s| s.declared);
        assert_eq!(spelled.as_deref(), Some("struct _IO_FILE *"));
    }

    /// The refinement equals the naive fixpoint (relabel by children's classes until the count
    /// holds) on generated graphs with cycles and records of mixed arity.
    #[test]
    fn the_quotient_is_the_naive_fixpoint() {
        let (mut seed, mut merged) = (0x2545_f491_4f6c_dd1d_u64, 0);
        for _ in 0..300 {
            let mut graph = TypeGraph::new();
            let int = int(&mut graph);
            let size = 2 + draw(&mut seed, 40);
            let nodes = (0..size).map(|_| graph.reserve()).collect::<Vec<_>>();
            let pick = |seed: &mut u64| match draw(seed, 5) {
                0 => int,
                _ => nodes[draw(seed, size)],
            };
            for node in &nodes {
                let name = ["a", "b"][draw(&mut seed, 2)].to_owned();
                let ty = match draw(&mut seed, 5) {
                    0 => Type::Pointer {
                        target: pick(&mut seed),
                    },
                    1 => Type::Typedef {
                        name,
                        target: pick(&mut seed),
                    },
                    2 => Type::Opaque {
                        keyword: Keyword::Struct,
                        tag: name,
                    },
                    _ => {
                        let mut members = Vec::new();
                        for at in 0..draw(&mut seed, 3) {
                            members.push(Member {
                                name: Some(["x", "y"][draw(&mut seed, 2)].to_owned()),
                                ty: pick(&mut seed),
                                offset_bits: 64 * at as u64,
                                bit_size: None,
                            });
                        }
                        let (kind, tag) = (RecordKind::Struct, Some(name));
                        Type::Record(Record {
                            kind,
                            tag,
                            size_bytes: 24,
                            members,
                        })
                    }
                };
                graph.define(*node, ty);
            }
            let naive = naive_classes(&graph);
            let index = graph.clone().quotient();
            merged += naive.len() - naive.iter().collect::<BTreeSet<_>>().len();
            for a in 0..naive.len() {
                for b in 0..naive.len() {
                    assert_eq!(naive[a] == naive[b], index[a] == index[b], "{graph:?}");
                }
            }
        }
        assert!(
            merged > 300,
            "{merged} nodes merged: the graphs exercise merging"
        );
    }

    /// A xorshift draw below `bound`: the generated graphs are the same on every run.
    fn draw(seed: &mut u64, bound: usize) -> usize {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        (*seed % bound as u64) as usize
    }

    /// Classes by label, then by label and children's classes, until the count holds.
    fn naive_classes(graph: &TypeGraph) -> Vec<usize> {
        let rank = |keys: Vec<(Type, Vec<usize>)>| {
            let sorted = keys.iter().cloned().collect::<BTreeSet<_>>();
            let order = sorted.into_iter().collect::<Vec<_>>();
            (keys.iter())
                .map(|key| order.binary_search(key).unwrap_or(0))
                .collect::<Vec<_>>()
        };
        let labels = graph
            .types
            .iter()
            .map(|ty| (label(ty), Vec::new()))
            .collect();
        let mut classes = rank(labels);
        loop {
            let keys = (graph.types.iter().enumerate())
                .map(|(node, ty)| {
                    let mut children = vec![classes[node]];
                    each_child(ty, |child| children.push(classes[child.index()]));
                    (label(ty), children)
                })
                .collect();
            let refined = rank(keys);
            let count = |c: &[usize]| c.iter().collect::<BTreeSet<_>>().len();
            if count(&refined) == count(&classes) {
                return refined;
            }
            classes = refined;
        }
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
        assert_eq!(graph.size_bits(loop_, &CDataModel::unix(64)), None);
        assert_eq!(
            graph.spelled(loop_).map(|s| s.resolved),
            Some(None),
            "the kept name spells; what it names does not"
        );
    }
}
