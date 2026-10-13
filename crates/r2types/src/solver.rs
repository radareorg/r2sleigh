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

/// Solve a constraint set: the constraints replayed through one [`IncrementalSolver`].
///
/// O(C α(N)) for the classes plus one meet per bound after the first on its
/// class, each memoised on the operand pair.
pub fn solve_constraints<K: SolverNode>(
    arena: TypeArena,
    constraints: &[Constraint<K>],
) -> SolvedTypes<K> {
    let mut solver = IncrementalSolver::new(arena);
    for constraint in constraints {
        match constraint {
            Constraint::Equal { a, b, .. } => solver.equal(a, b),
            Constraint::Subtype { var, ty, .. } => solver.bound(var, *ty),
        }
    }
    solver.into_solved()
}

/// The classes and their types as constraints arrive, so a constraint found late joins the
/// solution without a restart (adr-next-pass model 5).
///
/// A class's type is the meet of every bound on its members: a bound meets it into its class,
/// a union meets the two classes' types. `TypeLattice::meet` is the greatest lower bound of the
/// subtype order (lattice.rs, its properties tested), so the result does not depend on the order
/// constraints arrive in, and equals a batch solve of the same set. `O(α(N))` per constraint plus
/// one memoised meet.
#[derive(Debug)]
pub struct IncrementalSolver<K> {
    arena: TypeArena,
    nodes: NodeInterner<K>,
    classes: NodeClasses,
    /// Each class's type, held at its root.
    types: Vec<Option<TypeId>>,
    meets: HashMap<(TypeId, TypeId), TypeId>,
}

impl<K: SolverNode> IncrementalSolver<K> {
    pub fn new(arena: TypeArena) -> Self {
        Self {
            arena,
            nodes: NodeInterner::default(),
            classes: NodeClasses::default(),
            types: Vec::new(),
            meets: HashMap::new(),
        }
    }

    /// The arena types are interned into, the solver's own.
    pub fn arena(&self) -> &TypeArena {
        &self.arena
    }

    pub fn arena_mut(&mut self) -> &mut TypeArena {
        &mut self.arena
    }

    /// `a` and `b` are one variable.
    pub fn equal(&mut self, a: &K, b: &K) {
        let (a, b) = (self.intern(a), self.intern(b));
        let (a, b) = (self.classes.find(a), self.classes.find(b));
        if a == b {
            return;
        }
        let met = match (self.types[a], self.types[b]) {
            (Some(x), Some(y)) => Some(self.meet(x, y)),
            (x, y) => x.or(y),
        };
        let root = self.classes.union(a, b);
        self.types[root] = met;
    }

    /// `node` lies below `ty`.
    pub fn bound(&mut self, node: &K, ty: TypeId) {
        let node = self.intern(node);
        let class = self.classes.find(node);
        let met = match self.types[class] {
            None => ty,
            Some(current) => self.meet(current, ty),
        };
        self.types[class] = Some(met);
    }

    /// The type of `node`'s class, where some bound reached it.
    pub fn type_of(&mut self, node: &K) -> Option<TypeId> {
        let id = self.nodes.get(node)?;
        let class = self.classes.find(id);
        self.types[class]
    }

    /// The class `node` is in, by its root, seeing the node first where it is new.
    pub fn class_seeing(&mut self, node: &K) -> usize {
        let id = self.intern(node);
        self.classes.find(id)
    }

    /// The class `node` is in, by its root, where the node has been seen.
    pub fn class_of(&mut self, node: &K) -> Option<usize> {
        let id = self.nodes.get(node)?;
        Some(self.classes.find(id))
    }

    /// Every node whose class has a type, with it, in the order the nodes were first seen.
    pub fn typed(&mut self) -> Vec<(K, TypeId)> {
        let mut typed = Vec::new();
        for id in 0..self.nodes.nodes.len() {
            if let Some(ty) = self.types[self.classes.find(id)] {
                typed.push((self.nodes.nodes[id].clone(), ty));
            }
        }
        typed
    }

    /// Every node with a typed class, and its type.
    pub fn into_solved(mut self) -> SolvedTypes<K> {
        let mut var_types = HashMap::new();
        for (id, node) in std::mem::take(&mut self.nodes)
            .into_nodes()
            .into_iter()
            .enumerate()
        {
            if let Some(ty) = self.types[self.classes.find(id)] {
                var_types.insert(node, ty);
            }
        }
        SolvedTypes {
            arena: self.arena,
            var_types,
        }
    }

    fn intern(&mut self, node: &K) -> VarId {
        let id = self.nodes.intern(node, &mut self.classes);
        if id == self.types.len() {
            self.types.push(None);
        }
        id
    }

    fn meet(&mut self, a: TypeId, b: TypeId) -> TypeId {
        let key = (a.min(b), a.max(b));
        if let Some(met) = self.meets.get(&key) {
            return *met;
        }
        let met = TypeLattice::meet(&mut self.arena, a, b);
        self.meets.insert(key, met);
        met
    }
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

    fn get(&self, node: &K) -> Option<VarId> {
        self.ids.get(node).copied()
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

    /// Merge two classes; the root that stands for both.
    fn union(&mut self, a: VarId, b: VarId) -> VarId {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return a;
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
        high
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
