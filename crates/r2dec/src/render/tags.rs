//! D4: each struct and union tag a staged rendering spells, defined once at the layout the
//! function's declared type graph states (doc/adr-decompiler-rewrite.md); no other tag is spelled.

use std::collections::{BTreeMap, BTreeSet};

use super::{RenderInput, calls};
use crate::ast::{CAggregateDef, CFunction, CType};

/// The tags one function's declared types let the unit define, with each one's members as spelled.
pub(super) struct Tags {
    /// Each definable tag as r2types states it, which a callee's own graph must state alike.
    stated: BTreeMap<String, r2types::AggregateDefinition>,
    defined: BTreeMap<String, (bool, Vec<(CType, String)>)>,
}

impl Tags {
    pub(super) fn of(input: &RenderInput<'_>) -> Self {
        Self::of_graph(input.type_graph())
    }

    /// The greatest set of laid-out aggregates whose members C spells naming only tags in the set;
    /// each round drops a tag or ends, so at most one round per aggregate.
    fn of_graph(graph: Option<&r2ssa::SourceTypeGraph>) -> Self {
        let stated = (graph.iter())
            .flat_map(|graph| graph.aggregates().iter().map(move |layout| (graph, layout)))
            .filter_map(|(graph, layout)| {
                let definition = r2types::aggregate_members(graph, layout.name())?;
                Some((layout.name().to_owned(), definition))
            })
            .collect::<BTreeMap<_, _>>();
        let mut candidates = (stated.iter())
            .map(|(name, definition)| (name.clone(), definition.is_union))
            .collect::<BTreeMap<_, _>>();
        loop {
            let defined = (stated.iter())
                .filter(|(name, _)| candidates.contains_key(*name))
                .filter_map(|(name, definition)| {
                    let members = spelled_members(&definition.members, &candidates)?;
                    Some((name.clone(), (definition.is_union, members)))
                })
                .collect::<BTreeMap<_, _>>();
            if defined.len() == candidates.len() {
                return Self { stated, defined };
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

    /// Whether `graph`, a callee's own, lays tag `name` out as the unit defines it.
    pub(super) fn agrees(
        &self,
        name: &str,
        is_union: bool,
        graph: Option<&r2ssa::SourceTypeGraph>,
    ) -> bool {
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
                && spelled.insert(name, is_union).is_none()
            {
                pending.extend(members.iter().map(|(ty, _)| ty.clone()));
            }
        }
        let mut placed = BTreeSet::new();
        let mut ordered = Vec::with_capacity(spelled.len());
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
) -> Option<Vec<(CType, String)>> {
    (members.iter())
        .map(|(ty, member)| Some((spelled_member(ty, defined)?, member.clone())))
        .collect()
}

/// A member's type as the definition spells it: an array of a spelled element, a tag held by
/// value that is itself defined, or a type C spells with tags only behind pointers.
fn spelled_member(ty: &CType, defined: &BTreeMap<String, bool>) -> Option<CType> {
    match ty {
        CType::Array(element, Some(length)) => Some(CType::Array(
            Box::new(spelled_member(element, defined)?),
            Some(*length),
        )),
        CType::Struct(tag) => (defined.get(tag) == Some(&false)).then(|| ty.clone()),
        CType::Union(tag) => (defined.get(tag) == Some(&true)).then(|| ty.clone()),
        _ => calls::spellable(ty, &|tag, is_union| defined.get(tag) == Some(&is_union)),
    }
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
}
