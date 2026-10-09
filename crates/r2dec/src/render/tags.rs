//! D4: each struct and union tag a staged rendering spells, defined once at the layout the
//! function's declared type graph states (doc/adr-decompiler-rewrite.md); no other tag is spelled.

use std::collections::{BTreeMap, BTreeSet};

use super::{RenderInput, calls};
use crate::ast::{CAggregateDef, CFunction, CType};

/// The tags one function's declared types let the unit define, with each one's members as spelled.
pub(super) struct Tags {
    defined: BTreeMap<String, Vec<(CType, String)>>,
}

impl Tags {
    /// The greatest set of laid-out aggregates whose members C spells naming only tags in the set;
    /// each round drops a tag or ends, so at most one round per aggregate.
    pub(super) fn of(input: &RenderInput<'_>) -> Self {
        let Some(graph) = input.type_graph() else {
            return Self {
                defined: BTreeMap::new(),
            };
        };
        let stated = (graph.aggregates().iter())
            .filter_map(|layout| {
                let members = r2types::aggregate_members(graph, layout.name())?;
                Some((layout.name().to_owned(), members))
            })
            .collect::<BTreeMap<_, _>>();
        let mut candidates = stated.keys().cloned().collect::<BTreeSet<_>>();
        loop {
            let spelled = (stated.iter())
                .filter(|(name, _)| candidates.contains(*name))
                .filter_map(|(name, members)| {
                    Some((name.clone(), spelled_members(members, &candidates)?))
                })
                .collect::<BTreeMap<_, _>>();
            if spelled.len() == candidates.len() {
                return Self { defined: spelled };
            }
            candidates = spelled.into_keys().collect();
        }
    }

    /// Whether the unit defines tag `name`, so a declaration may spell it.
    pub(super) fn defines(&self, name: &str) -> bool {
        self.defined.contains_key(name)
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
            if let Some(members) = self.defined.get(&name)
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
        let members = &self.defined[name];
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
    defined: &BTreeSet<String>,
) -> Option<Vec<(CType, String)>> {
    (members.iter())
        .map(|(ty, member)| Some((spelled_member(ty, defined)?, member.clone())))
        .collect()
}

/// A member's type as the definition spells it: an array of a spelled element, a tag held by
/// value that is itself defined, or a type C spells with tags only behind pointers.
fn spelled_member(ty: &CType, defined: &BTreeSet<String>) -> Option<CType> {
    match ty {
        CType::Array(element, Some(length)) => Some(CType::Array(
            Box::new(spelled_member(element, defined)?),
            Some(*length),
        )),
        CType::Struct(tag) | CType::Union(tag) => defined.contains(tag).then(|| ty.clone()),
        _ => calls::spellable(ty, &|tag| defined.contains(tag)),
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
