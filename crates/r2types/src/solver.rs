//! The type of each node: the meet of every bound its equality class carries.
//!
//! The constraint language only tightens (see [`Constraint`]). `Equal` merges
//! two nodes into one class, which a union-find resolves exactly, and after
//! that no constraint relates one class to another: `Subtype` bounds one class
//! from above by a type the constraint states. So the solution is a single
//! left fold of [`TypeLattice::meet`] over each class's bounds, in constraint
//! order, and there is no fixpoint to iterate and nothing to converge.
//!
//! Why the fold is the fixpoint the worklist this replaces iterated towards:
//! `meet(x, b)` is a lower bound of both operands, and it is `x` itself
//! whenever `x` already lies below `b` (the subtype test `meet_pair` makes
//! first). After the fold has met `b`, the class type lies below `b` and only
//! descends afterwards, so meeting `b` again returns it unchanged. Every bound
//! is therefore satisfied by the folded type, and a round of re-applying them
//! -- the worklist's second round -- changes nothing.
//!
//! The worklist also accepted joins, priority overrides and field rewrites.
//! Mixed with meets over one class those do not settle: `x = int32_t` (a join)
//! and `x <: int8_t` (a meet) alternate for ever, and a round cap of 64 cut
//! the alternation off and read out whatever state the cut left, with
//! `converged` false and nobody reading it. None of those constraints had a
//! producer, so they are gone rather than capped.

use std::collections::HashMap;

use r2ssa::SSAVar;

use crate::constraint::{Constraint, SolverNode};
use crate::lattice::TypeLattice;
use crate::model::{TypeArena, TypeId};

type VarId = usize;

/// The solved types, complete by construction.
///
/// A node is present exactly when its class carries at least one bound, and
/// its type is the meet of all of them. `Bottom` (or a pointer to it) is the
/// meet of bounds that cannot all hold, which a reader treats as a refusal of
/// that node's type.
#[derive(Debug, Clone)]
pub struct SolvedTypes<K = SSAVar> {
    pub arena: TypeArena,
    pub var_types: HashMap<K, TypeId>,
}

/// Solve a constraint set.
///
/// O(C α(N)) for the classes plus one meet per bound after the first on its
/// class, each memoised on the operand pair.
pub fn solve_constraints<K: SolverNode>(
    mut arena: TypeArena,
    constraints: &[Constraint<K>],
) -> SolvedTypes<K> {
    let mut nodes = NodeInterner::<K>::default();
    let mut classes = NodeClasses::default();
    let mut bounds = Vec::new();
    for constraint in constraints {
        match constraint {
            Constraint::Equal { a, b, .. } => {
                let a = nodes.intern(a, &mut classes);
                let b = nodes.intern(b, &mut classes);
                classes.union(a, b);
            }
            Constraint::Subtype { var, ty, .. } => {
                bounds.push((nodes.intern(var, &mut classes), *ty));
            }
        }
    }

    let mut class_types: Vec<Option<TypeId>> = vec![None; nodes.len()];
    let mut meets: HashMap<(TypeId, TypeId), TypeId> = HashMap::new();
    for (node, bound) in bounds {
        let class = classes.find(node);
        let met = match class_types[class] {
            None => bound,
            Some(current) => *meets
                .entry((current, bound))
                .or_insert_with(|| TypeLattice::meet(&mut arena, current, bound)),
        };
        class_types[class] = Some(met);
    }

    let mut var_types = HashMap::new();
    for (id, node) in nodes.into_nodes().into_iter().enumerate() {
        if let Some(ty) = class_types[classes.find(id)] {
            var_types.insert(node, ty);
        }
    }
    SolvedTypes { arena, var_types }
}

#[derive(Debug)]
struct NodeInterner<K> {
    ids: HashMap<K, VarId>,
    nodes: Vec<K>,
}

impl<K> Default for NodeInterner<K> {
    fn default() -> Self {
        Self {
            ids: HashMap::new(),
            nodes: Vec::new(),
        }
    }
}

impl<K: SolverNode> NodeInterner<K> {
    fn intern(&mut self, node: &K, classes: &mut NodeClasses) -> VarId {
        if let Some(id) = self.ids.get(node).copied() {
            return id;
        }
        let id = classes.add();
        self.nodes.push(node.clone());
        self.ids.insert(node.clone(), id);
        id
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn into_nodes(self) -> Vec<K> {
        self.nodes
    }
}

/// Union-find over interned nodes, by rank with path compression.
#[derive(Debug, Default)]
struct NodeClasses {
    parent: Vec<VarId>,
    rank: Vec<u8>,
}

impl NodeClasses {
    fn add(&mut self) -> VarId {
        let id = self.parent.len();
        self.parent.push(id);
        self.rank.push(0);
        id
    }

    fn find(&mut self, node: VarId) -> VarId {
        let mut root = node;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut current = node;
        while self.parent[current] != root {
            let next = self.parent[current];
            self.parent[current] = root;
            current = next;
        }
        root
    }

    fn union(&mut self, a: VarId, b: VarId) {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return;
        }
        let (high, low) = if self.rank[a] < self.rank[b] {
            (b, a)
        } else {
            (a, b)
        };
        self.parent[low] = high;
        if self.rank[high] == self.rank[low] {
            self.rank[high] = self.rank[high].saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint::ConstraintSource;
    use crate::model::{Signedness, Type};

    fn bound(var: &SSAVar, ty: TypeId) -> Constraint {
        Constraint::Subtype {
            var: var.clone(),
            ty,
            source: ConstraintSource::Inferred,
        }
    }

    fn equal(a: &SSAVar, b: &SSAVar) -> Constraint {
        Constraint::Equal {
            a: a.clone(),
            b: b.clone(),
            source: ConstraintSource::Inferred,
        }
    }

    #[test]
    fn one_bound_reaches_every_member_of_an_equality_chain() {
        let mut arena = TypeArena::default();
        let top = arena.top();
        let void_ptr = arena.ptr(top);
        let vars = (0..4)
            .map(|i| SSAVar::new(format!("tmp:{i}"), 0, 8))
            .collect::<Vec<_>>();
        let mut constraints = vec![bound(&vars[0], void_ptr)];
        constraints.extend(vars.windows(2).map(|pair| equal(&pair[0], &pair[1])));

        let solved = solve_constraints(arena, &constraints);
        for var in &vars {
            assert_eq!(solved.var_types.get(var), Some(&void_ptr), "{var:?}");
        }
    }

    /// Each class holds the meet of the bounds on any of its members, and one
    /// class's contradiction is its own: it refuses that class and no other.
    #[test]
    fn a_class_is_the_meet_of_the_bounds_on_all_its_members() {
        let mut arena = TypeArena::default();
        let top = arena.top();
        let void_ptr = arena.ptr(top);
        let byte = arena.int(8, Signedness::Unknown);
        let byte_ptr = arena.ptr(byte);
        let signed = arena.int(32, Signedness::Signed);
        let unsigned = arena.int(32, Signedness::Unsigned);
        let pointers = (0..12)
            .map(|i| SSAVar::new(format!("ptr:{i}"), 0, 8))
            .collect::<Vec<_>>();
        let scalar = SSAVar::new("scalar", 0, 4);
        let untouched = SSAVar::new("untouched", 0, 4);

        let mut constraints = pointers
            .windows(2)
            .map(|pair| equal(&pair[0], &pair[1]))
            .collect::<Vec<_>>();
        constraints.push(bound(&pointers[0], void_ptr));
        constraints.push(bound(&pointers[5], byte_ptr));
        constraints.push(bound(&pointers[11], void_ptr));
        constraints.push(bound(&scalar, signed));
        constraints.push(bound(&scalar, unsigned));
        constraints.push(equal(&untouched, &untouched));

        let solved = solve_constraints(arena, &constraints);
        for var in &pointers {
            assert_eq!(solved.var_types.get(var), Some(&byte_ptr), "{var:?}");
        }
        let scalar_ty = solved.var_types[&scalar];
        assert_eq!(solved.arena.get(scalar_ty), &Type::Bottom);
        assert_eq!(solved.var_types.get(&untouched), None);
    }

    /// The fold is a fixpoint: meeting any bound of a class into the class's
    /// solved type returns that type, so no further round could change it.
    /// That is the whole of what the round-capped worklist computed.
    #[test]
    fn a_solved_class_satisfies_every_bound_on_it() {
        let mut arena = TypeArena::default();
        let top = arena.top();
        let candidates = [
            arena.int(64, Signedness::Unknown),
            arena.int(32, Signedness::Unknown),
            arena.int(32, Signedness::Signed),
            arena.int(8, Signedness::Signed),
            arena.bool_ty(),
            arena.float(64),
            arena.float(32),
            arena.ptr(top),
        ];
        let byte = arena.int(8, Signedness::Unknown);
        let byte_ptr = arena.ptr(byte);
        let word = arena.int(64, Signedness::Unsigned);
        let word_ptr = arena.ptr(word);
        let types = candidates
            .into_iter()
            .chain([byte_ptr, word_ptr])
            .collect::<Vec<_>>();

        // Every ordered pair and triple of candidate bounds, each on its own node.
        let mut constraints = Vec::new();
        let mut cases = Vec::new();
        for (i, first) in types.iter().enumerate() {
            for (j, second) in types.iter().enumerate() {
                for (k, third) in types.iter().enumerate() {
                    let var = SSAVar::new(format!("case:{i}:{j}:{k}"), 0, 8);
                    let bounds = [*first, *second, *third];
                    constraints.extend(bounds.iter().map(|ty| bound(&var, *ty)));
                    cases.push((var, bounds));
                }
            }
        }

        let mut solved = solve_constraints(arena, &constraints);
        for (var, bounds) in cases {
            let ty = solved.var_types[&var];
            for bound in bounds {
                assert_eq!(
                    TypeLattice::meet(&mut solved.arena, ty, bound),
                    ty,
                    "{var:?}: re-meeting {:?} into {:?} moved it",
                    solved.arena.get(bound),
                    solved.arena.get(ty)
                );
            }
        }
    }
}
