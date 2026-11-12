//! D4: each struct and union tag a staged rendering spells, defined once at the layout the declared
//! graph states, else declared incomplete behind a pointer (doc/adr-decompiler-rewrite.md).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::{RenderInput, calls};
use crate::ast::{CAggregateDef, CFunction, CType};

/// The tags one function's declared types let the unit define, with each one's members as spelled.
pub(super) struct Tags {
    /// Each definable tag as r2types states it, which a callee's own graph must state alike.
    stated: BTreeMap<String, r2types::AggregateDefinition>,
    defined: BTreeMap<String, (bool, Vec<(CType, String)>)>,
    /// Each tag the declared graph states, laid out or not, as a union or not: a pointer may name it.
    declarable: BTreeMap<String, bool>,
    /// Each tag any graph of the unit states, as a union or not; `None` where two disagree.
    kinds: BTreeMap<String, Option<bool>>,
    /// The tags a pointer asked for whose kinds disagree, so it was spelled at its class.
    refused: RefCell<BTreeSet<String>>,
}

impl Tags {
    pub(super) fn of(input: &RenderInput<'_>) -> Self {
        let callees = input.callee_type_graphs().collect::<Vec<_>>();
        Self::of_parts(input.type_graph(), input.inferred_aggregates(), &callees)
    }

    #[cfg(test)]
    fn of_graph(graph: Option<&r2ssa::SourceTypeGraph>) -> Self {
        Self::of_parts(graph, &BTreeMap::new(), &[])
    }

    /// The greatest set of laid-out aggregates whose members name only tags in the set or, behind a
    /// pointer, tags the graph states (doc/adr-aggregates.md); one round per aggregate at most.
    fn of_parts(
        graph: Option<&r2ssa::SourceTypeGraph>,
        inferred: &BTreeMap<String, r2types::AggregateDefinition>,
        callees: &[&r2ssa::SourceTypeGraph],
    ) -> Self {
        let declared = (graph.iter())
            .flat_map(|graph| graph.aggregates().iter().map(move |layout| (graph, layout)))
            .filter_map(|(graph, layout)| {
                let definition = r2types::aggregate_members(graph, layout.name())?;
                Some((layout.name().to_owned(), definition))
            });
        // A declared tag of the same name wins: it comes last.
        let stated = (inferred.iter())
            .map(|(name, definition)| (name.clone(), definition.clone()))
            .chain(declared)
            .collect::<BTreeMap<_, _>>();
        let laid = (stated.iter()).map(|(name, definition)| (name.as_str(), definition.is_union));
        let kinds = unit_kinds(
            (graph.iter().chain(callees))
                .flat_map(|graph| stated_tags(graph))
                .chain(laid),
        );
        let declarable = (graph.iter().flat_map(|graph| stated_tags(graph)))
            .filter(|(name, is_union)| kinds.get(*name) == Some(&Some(*is_union)))
            .map(|(name, is_union)| (name.to_owned(), is_union))
            .collect::<BTreeMap<_, _>>();
        let mut candidates = (stated.iter())
            .map(|(name, definition)| (name.clone(), definition.is_union))
            .collect::<BTreeMap<_, _>>();
        loop {
            let defined = (stated.iter())
                .filter(|(name, _)| candidates.contains_key(*name))
                .filter_map(|(name, definition)| {
                    let members = spelled_members(&definition.members, &candidates, &declarable)?;
                    Some((name.clone(), (definition.is_union, members)))
                })
                .collect::<BTreeMap<_, _>>();
            if defined.len() == candidates.len() {
                return Self {
                    stated,
                    defined,
                    declarable,
                    kinds,
                    refused: RefCell::default(),
                };
            }
            candidates = (defined.iter())
                .map(|(name, (is_union, _))| (name.clone(), *is_union))
                .collect();
        }
    }

    /// Whether the unit defines tag `name` as a union (`is_union`) or a struct.
    pub(super) fn defines(&self, name: &str, is_union: bool) -> bool {
        (self.defined.get(name)).is_some_and(|(defined, _)| *defined == is_union)
    }

    /// Whether a pointer in this unit may name tag `name`: the unit defines it so, or defines no
    /// tag of that name and the declared graph states it, so [`Self::definitions`] declares it.
    pub(super) fn names(&self, name: &str, is_union: bool) -> bool {
        match self.defined.get(name) {
            Some((defined, _)) => *defined == is_union,
            None => self.one_kind(name, is_union) && self.declarable.get(name) == Some(&is_union),
        }
    }

    /// Whether a callee's declaration may name tag `name` behind a pointer: the unit lays it out
    /// as `graph` does, or defines no tag of that name and `graph` states it. O(`graph`'s tags).
    pub(super) fn declares(
        &self,
        name: &str,
        is_union: bool,
        graph: Option<&r2ssa::SourceTypeGraph>,
    ) -> bool {
        self.agrees(name, is_union, graph)
            || (!self.defined.contains_key(name)
                && self.one_kind(name, is_union)
                && graph.is_some_and(|graph| {
                    stated_tags(graph).any(|stated| stated == (name, is_union))
                }))
    }

    /// Whether a callee's projection may name tag `name` behind a pointer: the unit lays it out as
    /// `graph` does, or defines no tag of that name, so a declaration of it names the callee's (W46).
    pub(super) fn admits(
        &self,
        name: &str,
        is_union: bool,
        graph: Option<&r2ssa::SourceTypeGraph>,
    ) -> bool {
        self.agrees(name, is_union, graph)
            || (!self.defined.contains_key(name) && self.one_kind(name, is_union))
    }

    /// Whether every graph of the unit that states tag `name` states it as `is_union`; a tag two
    /// state as different kinds is recorded, since no one declaration of it is C.
    fn one_kind(&self, name: &str, is_union: bool) -> bool {
        match self.kinds.get(name) {
            None => true,
            Some(Some(kind)) => *kind == is_union,
            Some(None) => {
                self.refused.borrow_mut().insert(name.to_owned());
                false
            }
        }
    }

    /// The tags a pointer named whose kinds the unit's graphs disagree on, by name.
    pub(super) fn conflicting(&self) -> Vec<String> {
        self.refused.borrow().iter().cloned().collect()
    }

    /// Whether `graph`, a callee's own, lays tag `name` out as the unit defines it.
    fn agrees(&self, name: &str, is_union: bool, graph: Option<&r2ssa::SourceTypeGraph>) -> bool {
        self.defines(name, is_union)
            && graph
                .and_then(|graph| r2types::aggregate_members(graph, name))
                .as_ref()
                == self.stated.get(name)
    }

    /// The definitions `c` needs: every tag it spells and every tag those hold, each once; a tag
    /// a member holds by value stands before its holder, and ties go by name.
    pub(super) fn definitions(&self, c: &CFunction) -> Vec<CAggregateDef> {
        let mut spelled = BTreeMap::new();
        // A tag only a callee's projection names, behind a pointer: declared, never laid out.
        let mut declared = BTreeMap::new();
        let mut pending = Vec::new();
        c.visit_types(&mut |ty| pending.push(ty.clone()));
        pending.extend(
            c.extern_objects
                .iter()
                .filter_map(|object| (object.type_fact.as_ref()).map(|fact| fact.ty.clone())),
        );
        while let Some(ty) = pending.pop() {
            let Some((name, is_union)) = tag_of(&ty, &mut pending) else {
                continue;
            };
            if self.defines(&name, is_union)
                && let Some((_, members)) = self.defined.get(&name)
                && spelled.insert(name.clone(), is_union).is_none()
            {
                pending.extend(members.iter().map(|(ty, _)| ty.clone()));
            } else if !self.defined.contains_key(&name) {
                declared.insert(name, is_union);
            }
        }
        let mut placed = BTreeSet::new();
        let mut ordered = (declared.into_iter())
            .map(|(name, is_union)| CAggregateDef {
                is_union,
                name,
                members: Vec::new(),
            })
            .collect::<Vec<_>>();
        for name in spelled.keys() {
            self.place(name, &spelled, &mut placed, &mut ordered);
        }
        ordered
    }

    /// `name` after every tag its members hold by value; a by-value cycle has no layout, so the
    /// walk ends.
    fn place(
        &self,
        name: &str,
        spelled: &BTreeMap<String, bool>,
        placed: &mut BTreeSet<String>,
        ordered: &mut Vec<CAggregateDef>,
    ) {
        if !placed.insert(name.to_owned()) {
            return;
        }
        let (_, members) = &self.defined[name];
        for (ty, _) in members {
            if let Some(held) = held_by_value(ty) {
                self.place(held, spelled, placed, ordered);
            }
        }
        ordered.push(CAggregateDef {
            is_union: spelled[name],
            name: name.to_owned(),
            members: members.clone(),
        });
    }
}

/// Each of `members` as the definition spells it, where every one is spelled.
fn spelled_members(
    members: &[(CType, String)],
    defined: &BTreeMap<String, bool>,
    declarable: &BTreeMap<String, bool>,
) -> Option<Vec<(CType, String)>> {
    (members.iter())
        .map(|(ty, member)| Some((spelled_member(ty, defined, declarable)?, member.clone())))
        .collect()
}

/// A member's type as the definition spells it: an array of a spelled element, a defined tag held
/// by value, or a type naming behind pointers tags defined or `declarable`.
fn spelled_member(
    ty: &CType,
    defined: &BTreeMap<String, bool>,
    declarable: &BTreeMap<String, bool>,
) -> Option<CType> {
    match ty {
        CType::Array(element, Some(length)) => Some(CType::Array(
            Box::new(spelled_member(element, defined, declarable)?),
            Some(*length),
        )),
        CType::Struct(tag) => (defined.get(tag) == Some(&false)).then(|| ty.clone()),
        CType::Union(tag) => (defined.get(tag) == Some(&true)).then(|| ty.clone()),
        _ => calls::spellable(ty, &|tag, is_union| match defined.get(tag) {
            Some(defined) => *defined == is_union,
            None => declarable.get(tag) == Some(&is_union),
        }),
    }
}

/// The struct and union tags `graph` states, laid out or not, whose name C spells, each as a union
/// or not. O(types + tags).
fn stated_tags(graph: &r2ssa::SourceTypeGraph) -> impl Iterator<Item = (&str, bool)> {
    let laid_out = graph.aggregates().iter().filter_map(|layout| {
        let ty = (graph.types().get(usize::try_from(layout.type_id()).ok()?))
            .filter(|ty| ty.id() == layout.type_id())?;
        match ty.kind() {
            r2ssa::SourceTypeKind::Struct { .. } => Some((layout.name(), false)),
            r2ssa::SourceTypeKind::Union { .. } => Some((layout.name(), true)),
            _ => None,
        }
    });
    let opaque = (graph.opaque_tags().iter()).filter_map(|tag| match tag.keyword() {
        r2ssa::SourceTagKeyword::Struct => Some((tag.name(), false)),
        r2ssa::SourceTagKeyword::Union => Some((tag.name(), true)),
        _ => None,
    });
    (laid_out.chain(opaque)).filter(|(name, _)| spells_a_tag(name))
}

/// Each tag `stated` names, as a union or not; `None` where two statements disagree.
fn unit_kinds<'g>(stated: impl Iterator<Item = (&'g str, bool)>) -> BTreeMap<String, Option<bool>> {
    let mut kinds = BTreeMap::<String, Option<bool>>::new();
    for (name, is_union) in stated {
        let kind = kinds.entry(name.to_owned()).or_insert(Some(is_union));
        if *kind != Some(is_union) {
            *kind = None;
        }
    }
    kinds
}

/// Whether `name` is a C identifier: letters, digits and `_`, not led by a digit.
fn spells_a_tag(name: &str) -> bool {
    !name.starts_with(|c: char| c.is_ascii_digit())
        && !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The tag `ty` names, if it is one; a type around one queues what it wraps.
fn tag_of(ty: &CType, pending: &mut Vec<CType>) -> Option<(String, bool)> {
    match ty {
        CType::Struct(name) => Some((name.clone(), false)),
        CType::Union(name) => Some((name.clone(), true)),
        CType::Array(inner, _)
        | CType::Pointer(inner)
        | CType::Const(inner)
        | CType::UnprototypedFunction(inner)
        | CType::Typedef { ty: inner, .. } => {
            pending.push(inner.as_ref().clone());
            None
        }
        CType::Function { ret, params } => {
            pending.push(ret.as_ref().clone());
            pending.extend(params.iter().cloned());
            None
        }
        _ => None,
    }
}

/// The tag a member of type `ty` holds by value, through arrays of it.
fn held_by_value(ty: &CType) -> Option<&str> {
    match ty {
        CType::Struct(name) | CType::Union(name) => Some(name),
        CType::Array(element, _) => held_by_value(element),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::Tags;
    use crate::ast::CType;

    /// `struct node` laid out as `{int32_t a; int32_t b;}` and, where `twice`, also as `{int64_t x;}`.
    fn nodes(twice: bool) -> r2ssa::SourceTypeGraph {
        let node = |id| r2ssa::SourceTypeKind::Struct { aggregate_id: id };
        let mut types = vec![
            r2ssa::SourceType::new(0, node(0), 64, 32),
            r2ssa::SourceType::new(1, r2ssa::SourceTypeKind::SignedInteger, 32, 32),
            r2ssa::SourceType::new(2, r2ssa::SourceTypeKind::SignedInteger, 64, 64),
        ];
        let mut layouts = vec![r2ssa::SourceAggregateLayout::new(
            0,
            0,
            64,
            32,
            "node",
            [
                r2ssa::SourceAggregateMember::new(0, 1, 0, 32, "a"),
                r2ssa::SourceAggregateMember::new(1, 1, 32, 32, "b"),
            ],
        )];
        if twice {
            types.push(r2ssa::SourceType::new(3, node(1), 64, 64));
            layouts.push(r2ssa::SourceAggregateLayout::new(
                1,
                3,
                64,
                64,
                "node",
                [r2ssa::SourceAggregateMember::new(0, 2, 0, 64, "x")],
            ));
        }
        r2ssa::SourceTypeGraph::new(types, layouts).expect("a node graph")
    }

    /// One spelling naming two layouts names no one layout: the tag is neither defined nor spelled.
    #[test]
    fn a_tag_two_layouts_share_is_not_defined() {
        let once = nodes(false);
        assert!(Tags::of_graph(Some(&once)).defines("node", false));
        let twice = nodes(true);
        let tags = Tags::of_graph(Some(&twice));
        assert!(!tags.defines("node", false));
        assert!(!tags.agrees("node", false, Some(&twice)));
        // A callee's graph agrees only where it lays the tag out alike.
        let own = Tags::of_graph(Some(&once));
        assert!(own.agrees("node", false, Some(&once)));
        assert!(!own.agrees("node", false, Some(&twice)));
        assert!(!own.agrees("node", false, None));
    }

    /// `typedef struct pool { lock *made; int32_t size; } pool;` where `lock` names `struct lock_s`,
    /// which the graph states and never lays out (pigz's `free_pool`).
    fn pool() -> r2ssa::SourceTypeGraph {
        let parts = r2ssa::SourceTypeGraphParts {
            types: vec![
                r2ssa::SourceType::new(
                    0,
                    r2ssa::SourceTypeKind::Struct { aggregate_id: 0 },
                    128,
                    64,
                ),
                r2ssa::SourceType::new(1, r2ssa::SourceTypeKind::Opaque { tag_id: 0 }, 0, 0),
                r2ssa::SourceType::new(
                    2,
                    r2ssa::SourceTypeKind::Pointer {
                        target_type_id: 1,
                        const_target: false,
                    },
                    64,
                    64,
                ),
                r2ssa::SourceType::new(3, r2ssa::SourceTypeKind::SignedInteger, 32, 32),
            ],
            aggregates: vec![r2ssa::SourceAggregateLayout::new(
                0,
                0,
                128,
                64,
                "pool",
                [
                    r2ssa::SourceAggregateMember::new(0, 2, 0, 64, "made"),
                    r2ssa::SourceAggregateMember::new(1, 3, 64, 32, "size"),
                ],
            )],
            opaque_tags: vec![r2ssa::SourceOpaqueTag::new(
                0,
                r2ssa::SourceTagKeyword::Struct,
                "lock_s",
            )],
            aliases: vec![
                r2ssa::SourceTypeAlias::new("lock".to_owned(), 1),
                r2ssa::SourceTypeAlias::new("pool".to_owned(), 0),
            ],
            ..r2ssa::SourceTypeGraphParts::default()
        };
        r2ssa::SourceTypeGraph::from_parts(parts).expect("a pool graph")
    }

    /// A struct holding a pointer to a tag the graph states and does not lay out is defined, and
    /// the tag is declared incomplete before it; a tag the graph never states is not named.
    #[test]
    fn a_pointer_to_an_incomplete_tag_the_graph_states_is_named() {
        let graph = pool();
        let tags = Tags::of_graph(Some(&graph));
        assert!(tags.defines("pool", false));
        assert!(tags.names("lock_s", false));
        assert!(!tags.names("lock_s", true));
        assert!(!tags.names("fcn_401000_arg0", false));
        assert!(tags.declares("lock_s", false, Some(&graph)));
        assert!(!tags.declares("lock_s", false, None));
        let mut c = crate::ast::CFunction::new("free_pool", CType::Void);
        c.externs.push(crate::ast::CExternDecl {
            name: "drop".to_owned(),
            ret_type: CType::Void,
            params: Some(vec![CType::Pointer(Box::new(CType::Struct("pool".into())))]),
            variadic: false,
            noreturn: false,
            address: None,
        });
        let order = (tags.definitions(&c).into_iter())
            .map(|tag| (tag.name, tag.members.len()))
            .collect::<Vec<_>>();
        assert_eq!(order, [("lock_s".to_owned(), 0), ("pool".to_owned(), 2)]);
    }

    /// A graph stating only an opaque tag `item` of `keyword`, behind a pointer.
    fn opaque_item(keyword: r2ssa::SourceTagKeyword) -> r2ssa::SourceTypeGraph {
        let parts = r2ssa::SourceTypeGraphParts {
            types: vec![
                r2ssa::SourceType::new(0, r2ssa::SourceTypeKind::Opaque { tag_id: 0 }, 0, 0),
                r2ssa::SourceType::new(
                    1,
                    r2ssa::SourceTypeKind::Pointer {
                        target_type_id: 0,
                        const_target: false,
                    },
                    64,
                    64,
                ),
            ],
            opaque_tags: vec![r2ssa::SourceOpaqueTag::new(0, keyword, "item")],
            ..r2ssa::SourceTypeGraphParts::default()
        };
        r2ssa::SourceTypeGraph::from_parts(parts).expect("an item graph")
    }

    /// A caller's `struct item*` and a callee's `union item*` have no one declaration: neither is
    /// named, both fall to their class, and the proof line names the tag (Codex on #383).
    #[test]
    fn a_tag_two_graphs_state_as_different_kinds_is_not_named() {
        let own = opaque_item(r2ssa::SourceTagKeyword::Struct);
        let callee = opaque_item(r2ssa::SourceTagKeyword::Union);
        let alone = Tags::of_parts(Some(&own), &std::collections::BTreeMap::new(), &[]);
        assert!(alone.names("item", false));
        assert!(alone.conflicting().is_empty());
        let tags = Tags::of_parts(Some(&own), &std::collections::BTreeMap::new(), &[&callee]);
        assert!(!tags.names("item", false));
        assert!(!tags.declares("item", true, Some(&callee)));
        assert!(!tags.admits("item", true, Some(&callee)));
        assert_eq!(tags.conflicting(), ["item".to_owned()]);
    }
}
