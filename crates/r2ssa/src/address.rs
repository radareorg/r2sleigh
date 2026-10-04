//! Canonical parameter-relative address provenance.
//!
//! This pass owns affine pointer identity for prepared SSA. It propagates
//! parameter bases through arithmetic and proven stack spills so object,
//! memory-SSA, summary, symbolic, type, and render consumers share one fact.
//!
//! Which values are the same address is not decided here: it is the value
//! view's (`crate::view`), projected. A value is the address its
//! same-integer root is -- the end of its chain of copies, same-width casts
//! and zero extensions of a full-width root -- and nothing else is: a lane, a
//! truncation, a sign extension, a `New` or a cast of another width is a
//! different value, whatever it was read from.
//!
//! The affine scalar an address is displaced by is a form modulo `2^w` over
//! the unsigned values of its terms, `w` the width of the value it describes.
//! Addition, subtraction, negation and multiplication or shifting by a
//! constant keep the width, so they combine their operands' forms. A
//! zero-extended root is its root's unsigned value, one term, whatever form
//! the root had at its narrower width -- `(uint64_t)(uint32_t)(i + 1)` is not
//! `i + 1` where the addition wrapped. A sign extension and a truncation are
//! terms of their own.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use r2il::SpaceId;
use serde::{Deserialize, Serialize};

use crate::view::ValueViews;
use crate::{
    CanonicalStorageId, SSAFunction, SSAOp, SSAVar, SourceMachineContext, SsaGraph,
    StackAddressRoot, ValueId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AffineAddressTerm {
    pub value: ValueId,
    pub coefficient: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParameterAddressExpression {
    pub parameter: usize,
    /// Canonical full-width register storage that seeded this parameter base.
    /// Absent only when SSA was prepared without a machine context.
    pub parameter_storage: Option<CanonicalStorageId>,
    pub terms: Vec<AffineAddressTerm>,
    pub offset: i64,
}

/// One dereference on the way from a parameter to a pointee base.
///
/// `offset` is where the pointer was read from inside the object the step
/// starts in, and `size` is the width of that read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PointeeStep {
    pub offset: i64,
    pub size: u32,
}

/// An address relative to memory reached *through* a parameter.
///
/// `*(arg0 + 0x38)` is a pointer the function loaded, and `*(that + 0)` is an
/// address inside whatever it points to. Before this existed such an address
/// had no provenance at all: the loaded value is a fresh unknown, so every
/// access through it fell into the escaped-unknown object, and any analysis
/// that wanted to summarize it had to ask a solver to enumerate concrete
/// addresses for a pointer it had already been handed by name. The path is the
/// identity: the same parameter and the same sequence of loads reach the same
/// object, and two different paths are two objects that may alias.
///
/// A path is finite by construction. Each step is a distinct load on a
/// definition chain, and a phi only carries an expression its sources agree
/// on, so a loop that walks `p = p->next` produces no expression rather than an
/// unbounded one. The collector still bounds the length by the number of loads
/// in the function, which is the most steps any chain can have.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PointeeAddressExpression {
    /// The parameter the chain starts from.
    pub root: usize,
    pub root_storage: Option<CanonicalStorageId>,
    /// The loads taken from the parameter to the pointee base, in order.
    pub path: Vec<PointeeStep>,
    pub terms: Vec<AffineAddressTerm>,
    pub offset: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressProvenanceFacts {
    pub parameter_expressions: BTreeMap<ValueId, ParameterAddressExpression>,
    /// Addresses reached through at least one load from a parameter. Kept
    /// apart from `parameter_expressions` so that everything reading the
    /// latter keeps its meaning: a parameter expression is directly
    /// parameter-relative, a pointee expression never is.
    pub pointee_expressions: BTreeMap<ValueId, PointeeAddressExpression>,
}

impl AddressProvenanceFacts {
    pub fn parameter_expression(&self, value: ValueId) -> Option<&ParameterAddressExpression> {
        self.parameter_expressions.get(&value)
    }

    pub fn pointee_expression(&self, value: ValueId) -> Option<&PointeeAddressExpression> {
        self.pointee_expressions.get(&value)
    }
}

/// What an address is relative to, inside the collector.
///
/// One affine mechanism serves both bases; only the public view splits them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AddressBase {
    Parameter {
        index: usize,
        storage: Option<CanonicalStorageId>,
    },
    Pointee {
        root: usize,
        root_storage: Option<CanonicalStorageId>,
        path: Vec<PointeeStep>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AddressExpression {
    base: AddressBase,
    terms: Vec<AffineAddressTerm>,
    offset: i64,
}

impl AddressExpression {
    /// The address one load further along: the value read at this address,
    /// treated as a pointer, at offset zero inside what it points to.
    fn dereferenced(&self, size: u32) -> Option<Self> {
        if !self.terms.is_empty() {
            return None;
        }
        let step = PointeeStep {
            offset: self.offset,
            size,
        };
        let base = match &self.base {
            AddressBase::Parameter { index, storage } => AddressBase::Pointee {
                root: *index,
                root_storage: *storage,
                path: vec![step],
            },
            AddressBase::Pointee {
                root,
                root_storage,
                path,
            } => {
                let mut path = path.clone();
                path.push(step);
                AddressBase::Pointee {
                    root: *root,
                    root_storage: *root_storage,
                    path,
                }
            }
        };
        Some(Self {
            base,
            terms: Vec::new(),
            offset: 0,
        })
    }

    fn path_len(&self) -> usize {
        match &self.base {
            AddressBase::Parameter { .. } => 0,
            AddressBase::Pointee { path, .. } => path.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AffineScalar {
    terms: BTreeMap<ValueId, i128>,
    constant: i128,
}

/// A spill slot: where it is, and how wide the value stored there is. A
/// read of the same place at another width is a lane of the stored value, or
/// more than it, and never the address it held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SpillSlotKey {
    root: StackAddressRoot,
    space: SpaceId,
    width: u32,
}

fn memory_space_order(space: SpaceId) -> (u8, u32) {
    match space {
        SpaceId::Ram => (0, 0),
        SpaceId::Register => (1, 0),
        SpaceId::Unique => (2, 0),
        SpaceId::Const => (3, 0),
        SpaceId::Custom(id) => (4, id),
    }
}

impl Ord for SpillSlotKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| memory_space_order(self.space).cmp(&memory_space_order(other.space)))
            .then_with(|| self.width.cmp(&other.width))
    }
}

impl PartialOrd for SpillSlotKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl AffineScalar {
    fn constant(value: i64) -> Self {
        Self {
            terms: BTreeMap::new(),
            constant: i128::from(value),
        }
    }

    fn term(value: ValueId) -> Self {
        Self {
            terms: BTreeMap::from([(value, 1)]),
            constant: 0,
        }
    }

    fn combine(mut self, other: Self, sign: i128) -> Option<Self> {
        self.constant = self
            .constant
            .checked_add(other.constant.checked_mul(sign)?)?;
        for (value, coefficient) in other.terms {
            let delta = coefficient.checked_mul(sign)?;
            let coefficient = self.terms.entry(value).or_default();
            *coefficient = coefficient.checked_add(delta)?;
        }
        self.terms.retain(|_, coefficient| *coefficient != 0);
        Some(self)
    }

    fn scale(mut self, factor: i128) -> Option<Self> {
        self.constant = self.constant.checked_mul(factor)?;
        for coefficient in self.terms.values_mut() {
            *coefficient = coefficient.checked_mul(factor)?;
        }
        self.terms.retain(|_, coefficient| *coefficient != 0);
        Some(self)
    }
}

struct AddressCollector<'a> {
    function: &'a SSAFunction,
    /// The function's prep facts, where it was prepared.
    prep: Option<&'a crate::DecompilePrepFacts>,
    graph: &'a SsaGraph,
    /// Which values carry the same bits; absent only where no preparation
    /// ran, and then there is no formal to propagate either.
    views: Option<&'a ValueViews>,
    definitions: HashMap<SSAVar, SSAOp>,
    /// Each value's expression as the solve has it: absent while nothing
    /// has ruled one in or out.
    expressions: BTreeMap<ValueId, Cell>,
    /// The values whose expression is the formal they are, placed before any
    /// block is read and fixed.
    seeded: BTreeSet<ValueId>,
    scalar_memo: HashMap<ValueId, Option<AffineScalar>>,
    scalar_visiting: HashSet<ValueId>,
    /// What each block's spill slots hold where control leaves it.
    stack_out: BTreeMap<u64, Spills>,
    /// The number of loads in the function: the most dereferences any chain
    /// can take, and so the bound on a pointee path.
    load_count: usize,
}

/// A value's settled expression: one, or none.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cell {
    Expr(AddressExpression),
    Not,
}

/// A value's expression as derived from its inputs now.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Derived {
    Pending,
    Expr(AddressExpression),
    Not,
}

/// What a spill slot holds: one expression, or one still pending.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Held {
    Pending,
    Expr(AddressExpression),
}

/// Each spill slot's content where control stands.
type Spills = BTreeMap<SpillSlotKey, Held>;

impl<'a> AddressCollector<'a> {
    fn new(
        function: &'a SSAFunction,
        prep: Option<&'a crate::DecompilePrepFacts>,
        graph: &'a SsaGraph,
        _machine_context: Option<&SourceMachineContext>,
    ) -> Self {
        let definitions = function
            .blocks()
            .iter()
            .flat_map(|block| block.ops().iter())
            .filter_map(|op| op.dst().map(|dst| (dst.clone(), op.clone())))
            .collect();
        let mut expressions = BTreeMap::new();
        if let Some(prep) = prep {
            // Every formal, not only those that arrived at their ABI storage's
            // full width. A narrow parameter -- an `unsigned` in `w1` where
            // the convention names `x1` -- is a lane projection rather than a
            // base, and seeding only the bases left it unpropagated: its spill
            // and reload carried no parameter expression, so a callee indexing
            // through it stated a reach nothing could scale. The storage kept
            // beside the index is still the value's own, so a consumer that
            // maps storage back to an argument sees what it saw before.
            for (var, parameter) in prep
                .formal_parameter_bases
                .iter()
                .chain(prep.formal_parameters.iter())
            {
                if let Some(value) = graph.value_id_for_var(var) {
                    expressions
                        .entry(value)
                        .or_insert_with(|| AddressExpression {
                            base: AddressBase::Parameter {
                                index: *parameter,
                                storage: graph
                                    .value(value)
                                    .and_then(|value| value.canonical_storage),
                            },
                            terms: Vec::new(),
                            offset: 0,
                        });
                }
            }
        }
        let load_count = function
            .blocks()
            .iter()
            .flat_map(|block| block.ops().iter())
            .filter(|op| {
                matches!(
                    op,
                    SSAOp::Load { .. } | SSAOp::LoadLinked { .. } | SSAOp::LoadGuarded { .. }
                )
            })
            .count();
        Self {
            function,
            prep,
            graph,
            views: prep.map(|prep| &prep.views),
            definitions,
            seeded: expressions.keys().copied().collect(),
            expressions: expressions
                .into_iter()
                .map(|(value, expression)| (value, Cell::Expr(expression)))
                .collect(),
            scalar_memo: HashMap::new(),
            scalar_visiting: HashSet::new(),
            stack_out: BTreeMap::new(),
            load_count,
        }
    }

    /// Solve every value's expression and every block's spill slots together
    /// (doc/adr-fixpoint.md, K2).
    ///
    /// The two feed each other: a reload's expression is what its slot
    /// holds, and a slot holds the expression of the value stored there. Both
    /// are solved optimistically. A value is pending until something rules
    /// its expression in or out; a merge keeps what its known inputs agree
    /// on; a slot survives a merge where every reached predecessor holds it.
    /// A cell or slot only descends -- pending, one expression, none -- so
    /// each moves at most twice, which bounds the work. A value's change
    /// re-reads every block that reads it, wherever it is, and a block whose
    /// slots change re-reads its successors.
    fn collect(mut self) -> AddressProvenanceFacts {
        let order = self.function.block_addrs().to_vec();
        let rank = order
            .iter()
            .enumerate()
            .map(|(index, addr)| (*addr, index))
            .collect::<BTreeMap<_, _>>();
        let mut readers = BTreeMap::<ValueId, BTreeSet<usize>>::new();
        let mut slots = 0usize;
        for (index, &addr) in order.iter().enumerate() {
            let Some(block) = self.function.get_block(addr) else {
                continue;
            };
            let read = block
                .phis()
                .iter()
                .flat_map(|phi| phi.sources.iter().map(|(_, source)| source))
                .chain(block.ops().iter().flat_map(SSAOp::sources));
            for var in read {
                for var in [var, self.same_integer_root(var)] {
                    if let Some(value) = self.graph.value_id_for_var(var) {
                        readers.entry(value).or_default().insert(index);
                    }
                }
            }
            slots += block
                .ops()
                .iter()
                .filter(|op| matches!(op, SSAOp::Store { .. } | SSAOp::StoreGuarded { .. }))
                .count();
        }
        let budget = order
            .len()
            .saturating_mul(
                self.graph
                    .values
                    .len()
                    .saturating_add(slots)
                    .saturating_mul(2)
                    .saturating_add(1),
            )
            .max(1);
        let mut work = (0..order.len()).collect::<BTreeSet<_>>();
        let mut visits = 0usize;
        while let Some(index) = work.pop_first() {
            visits += 1;
            if visits > budget {
                r2il::refusal_evidence!(
                    "address-provenance",
                    "{:#x}: did not settle within {budget} block visits",
                    self.function.entry
                );
                return AddressProvenanceFacts::default();
            }
            let block_addr = order[index];
            let Some(block) = self.function.get_block(block_addr) else {
                continue;
            };
            let Some(mut spills) = self.entering(block_addr) else {
                continue;
            };
            let moved = self.transfer_ops(block, &mut spills);
            for value in moved {
                work.extend(readers.get(&value).into_iter().flatten().copied());
            }
            if self.stack_out.get(&block_addr) != Some(&spills) {
                self.stack_out.insert(block_addr, spills);
                work.extend(
                    self.function
                        .successors(block_addr)
                        .into_iter()
                        .filter_map(|succ| rank.get(&succ).copied()),
                );
            }
        }
        let mut facts = AddressProvenanceFacts::default();
        for (value, cell) in self.expressions {
            let Cell::Expr(expression) = cell else {
                continue;
            };
            match expression.base {
                AddressBase::Parameter { index, storage } => {
                    facts.parameter_expressions.insert(
                        value,
                        ParameterAddressExpression {
                            parameter: index,
                            parameter_storage: storage,
                            terms: expression.terms,
                            offset: expression.offset,
                        },
                    );
                }
                AddressBase::Pointee {
                    root,
                    root_storage,
                    path,
                } => {
                    facts.pointee_expressions.insert(
                        value,
                        PointeeAddressExpression {
                            root,
                            root_storage,
                            path,
                            terms: expression.terms,
                            offset: expression.offset,
                        },
                    );
                }
            }
        }
        facts
    }

    /// The spill slots a block is entered with: what every reached
    /// predecessor agrees on, nothing at the function's root, and `None`
    /// where no predecessor has been reached yet.
    fn entering(&self, block_addr: u64) -> Option<Spills> {
        if block_addr == self.function.root() {
            return Some(Spills::new());
        }
        let mut reached = self
            .function
            .predecessors(block_addr)
            .into_iter()
            .filter_map(|pred| self.stack_out.get(&pred));
        let first = reached.next()?.clone();
        Some(reached.fold(first, |held, other| {
            held.into_iter()
                .filter_map(|(slot, cell)| {
                    let merged = match (cell, other.get(&slot)?) {
                        (Held::Pending, theirs) => theirs.clone(),
                        (mine, Held::Pending) => mine,
                        (Held::Expr(a), Held::Expr(b)) if a == *b => Held::Expr(a),
                        _ => return None,
                    };
                    Some((slot, merged))
                })
                .collect()
        }))
    }

    /// Derive one block's values and its slots, in program order, from the
    /// slots it is entered with; returns the values whose cell moved.
    fn transfer_ops(&mut self, block: &crate::block::SSABlock, stack: &mut Spills) -> Vec<ValueId> {
        let mut moved = Vec::new();
        for phi in block.phis() {
            // What the sources known so far agree on.
            let derived = phi
                .sources
                .iter()
                .map(|(_, source)| self.cell_for_var(source))
                .fold(Derived::Pending, |held, source| match (held, source) {
                    (Derived::Pending, other) | (other, Derived::Pending) => other,
                    (Derived::Expr(a), Derived::Expr(b)) if a == b => Derived::Expr(a),
                    _ => Derived::Not,
                });
            self.settle(&phi.dst, derived, &mut moved);
        }
        for op in block.ops() {
            match op {
                SSAOp::Store { space, addr, val }
                | SSAOp::StoreGuarded {
                    space, addr, val, ..
                } => {
                    if let Some(root) = self.stack_root(addr) {
                        // A store replaces whatever any read of the place
                        // would have found, at every width.
                        stack.retain(|slot, _| slot.root != root || slot.space != *space);
                        let slot = SpillSlotKey {
                            root,
                            space: *space,
                            width: val.size,
                        };
                        match self.cell_for_var(val) {
                            Derived::Expr(expression) => {
                                stack.insert(slot, Held::Expr(expression));
                            }
                            Derived::Pending => {
                                stack.insert(slot, Held::Pending);
                            }
                            Derived::Not => {}
                        }
                    }
                }
                SSAOp::Load { dst, space, addr }
                | SSAOp::LoadLinked {
                    dst, space, addr, ..
                }
                | SSAOp::LoadGuarded {
                    dst, space, addr, ..
                } => {
                    let slot = self.stack_root(addr).and_then(|root| {
                        stack.get(&SpillSlotKey {
                            root,
                            space: *space,
                            width: dst.size,
                        })
                    });
                    let derived = match slot {
                        Some(Held::Expr(expression)) => Derived::Expr(expression.clone()),
                        Some(Held::Pending) => Derived::Pending,
                        None if *space == SpaceId::Ram => match self.cell_for_var(addr) {
                            // The value read at a known address, taken as a
                            // pointer: its own address is one step further
                            // along the chain from the parameter.
                            Derived::Expr(expression)
                                if expression.path_len() < self.load_count =>
                            {
                                expression
                                    .dereferenced(dst.size)
                                    .map_or(Derived::Not, Derived::Expr)
                            }
                            Derived::Pending => Derived::Pending,
                            _ => Derived::Not,
                        },
                        None => Derived::Not,
                    };
                    self.settle(dst, derived, &mut moved);
                    continue;
                }
                _ => {}
            }
            if let Some(dst) = op.dst() {
                let derived = self.derive_op_expression(op);
                self.settle(dst, derived, &mut moved);
            }
        }
        moved
    }

    /// Record what was derived for `var`, never rising: a cell only moves
    /// from pending to one expression to none, and two different
    /// expressions for one value meet to none.
    fn settle(&mut self, var: &SSAVar, derived: Derived, moved: &mut Vec<ValueId>) {
        let Some(value) = self.graph.value_id_for_var(var) else {
            return;
        };
        if self.seeded.contains(&value) {
            return;
        }
        let next = match (self.expressions.get(&value), derived) {
            (_, Derived::Pending) => return,
            (None, Derived::Expr(expression)) => Cell::Expr(expression),
            (Some(Cell::Expr(held)), Derived::Expr(expression)) if *held == expression => return,
            (Some(Cell::Not), _) => return,
            _ => Cell::Not,
        };
        self.expressions.insert(value, next);
        moved.push(value);
    }

    fn derive_op_expression(&mut self, op: &SSAOp) -> Derived {
        match op {
            SSAOp::IntAdd { a, b, .. } => self.derive_additive_expression(a, b, 1, 1),
            SSAOp::PtrAdd {
                base,
                index,
                element_size,
                ..
            } => self.derive_additive_expression(base, index, 1, i128::from(*element_size)),
            SSAOp::IntSub { a, b, .. } => self.derive_additive_expression(a, b, -1, 1),
            SSAOp::PtrSub {
                base,
                index,
                element_size,
                ..
            } => self.derive_additive_expression(base, index, -1, i128::from(*element_size)),
            // Any other definition is its same-integer root's address, where
            // the view says it has one: a copy, a same-width cast or a zero
            // extension of a full-width root. A narrowed, sign-extended or
            // otherwise converted pointer is a scalar the body computes with.
            op => {
                let Some(dst) = op.dst() else {
                    return Derived::Not;
                };
                let root = self.same_integer_root(dst).clone();
                match root != *dst {
                    true => self.cell_for_var(&root),
                    false => Derived::Not,
                }
            }
        }
    }

    /// The same integer root `var` has, by the view.
    fn same_integer_root<'v>(&self, var: &'v SSAVar) -> &'v SSAVar
    where
        'a: 'v,
    {
        match self.views {
            Some(views) => views.same_integer_root(var),
            None => var,
        }
    }

    /// An address plus a scalar: one operand is an address and the other a
    /// scalar the analysis can state. An operand still pending is taken as
    /// no address for now, which can only take the answer down later; two
    /// addresses are not one.
    fn derive_additive_expression(
        &mut self,
        left: &SSAVar,
        right: &SSAVar,
        right_sign: i128,
        right_scale: i128,
    ) -> Derived {
        let (left_cell, right_cell) = (self.cell_for_var(left), self.cell_for_var(right));
        let derived = match (&left_cell, &right_cell) {
            (Derived::Expr(_), Derived::Expr(_)) => return Derived::Not,
            (Derived::Expr(base), _) => self
                .scalar_for_var(right)
                .and_then(|delta| delta.scale(right_sign.checked_mul(right_scale)?))
                .and_then(|delta| add_delta(base.clone(), delta)),
            (_, Derived::Expr(base)) if right_sign > 0 => self
                .scalar_for_var(left)
                .and_then(|delta| add_delta(base.clone(), delta)),
            (Derived::Pending, _) | (_, Derived::Pending) => return Derived::Pending,
            _ => None,
        };
        derived.map_or(Derived::Not, Derived::Expr)
    }

    /// What the solve has for `var` so far.
    fn cell_for_var(&self, var: &SSAVar) -> Derived {
        let Some(value) = self.graph.value_id_for_var(var) else {
            return Derived::Not;
        };
        match self.expressions.get(&value) {
            Some(Cell::Expr(expression)) => Derived::Expr(expression.clone()),
            Some(Cell::Not) => Derived::Not,
            // A value nothing defines -- an entry value no formal seeded --
            // is no address the analysis can state, and never will be.
            None if !self.definitions.contains_key(var) && !self.defined_by_phi(value) => {
                Derived::Not
            }
            None => Derived::Pending,
        }
    }

    fn defined_by_phi(&self, value: ValueId) -> bool {
        self.graph.def_inst(value).is_some()
    }

    fn stack_root(&self, var: &SSAVar) -> Option<StackAddressRoot> {
        let prep = self.prep?;
        prep.stack_address_root_of(var)
            .or_else(|| prep.stack_address_root_of(prep.canonical_root(var)))
            .copied()
    }

    fn scalar_for_var(&mut self, var: &SSAVar) -> Option<AffineScalar> {
        let value = self.graph.value_id_for_var(var)?;
        self.scalar_for_value(value)
    }

    fn scalar_for_value(&mut self, value: ValueId) -> Option<AffineScalar> {
        if let Some(cached) = self.scalar_memo.get(&value) {
            return cached.clone();
        }
        if !self.scalar_visiting.insert(value) {
            return None;
        }
        let result = self.compute_scalar(value);
        self.scalar_visiting.remove(&value);
        self.scalar_memo.insert(value, result.clone());
        result
    }

    fn compute_scalar(&mut self, value: ValueId) -> Option<AffineScalar> {
        let var = self.graph.value(value)?.var.clone();
        if let Some(constant) = signed_constant(&var) {
            return Some(AffineScalar::constant(constant));
        }
        // The same integer as its root: the root's form where the widths
        // agree, and where the root was widened, its unsigned value as one
        // term -- the root's form holds only modulo its own width.
        let root = self.same_integer_root(&var).clone();
        if root != var {
            if root.size == var.size {
                return self.scalar_for_var(&root);
            }
            return Some(match self.graph.value_id_for_var(&root) {
                Some(root) => AffineScalar::term(root),
                None => AffineScalar::term(value),
            });
        }
        let Some(op) = self.definitions.get(&var).cloned() else {
            return Some(AffineScalar::term(value));
        };
        match op {
            SSAOp::IntNegate { src, .. } => self.scalar_for_var(&src)?.scale(-1),
            SSAOp::IntAdd { a, b, .. } => self
                .scalar_for_var(&a)?
                .combine(self.scalar_for_var(&b)?, 1),
            SSAOp::IntSub { a, b, .. } => self
                .scalar_for_var(&a)?
                .combine(self.scalar_for_var(&b)?, -1),
            SSAOp::IntMult { a, b, .. } => {
                let left = self.scalar_for_var(&a)?;
                let right = self.scalar_for_var(&b)?;
                if left.terms.is_empty() {
                    right.scale(left.constant)
                } else if right.terms.is_empty() {
                    left.scale(right.constant)
                } else {
                    None
                }
            }
            SSAOp::IntLeft { a, b, .. } => {
                let shift = self.scalar_for_var(&b)?;
                if !shift.terms.is_empty() {
                    return None;
                }
                let shift = u32::try_from(shift.constant).ok()?;
                self.scalar_for_var(&a)?.scale(1i128.checked_shl(shift)?)
            }
            _ => Some(AffineScalar::term(value)),
        }
    }
}

fn add_delta(mut base: AddressExpression, delta: AffineScalar) -> Option<AddressExpression> {
    let mut terms = base
        .terms
        .drain(..)
        .map(|term| (term.value, i128::from(term.coefficient)))
        .collect::<BTreeMap<_, _>>();
    for (value, coefficient) in delta.terms {
        let current = terms.entry(value).or_default();
        *current = current.checked_add(coefficient)?;
    }
    terms.retain(|_, coefficient| *coefficient != 0);
    base.offset = i64::try_from(i128::from(base.offset).checked_add(delta.constant)?).ok()?;
    base.terms = terms
        .into_iter()
        .map(|(value, coefficient)| {
            Some(AffineAddressTerm {
                value,
                coefficient: i64::try_from(coefficient).ok()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(base)
}

fn signed_constant(var: &SSAVar) -> Option<i64> {
    let value = var.constant_bits()?;
    let bits = var.size.saturating_mul(8).min(64);
    if bits == 0 || bits == 64 {
        return Some(value as i64);
    }
    let sign = 1u64.checked_shl(bits - 1)?;
    let mask = 1u64.checked_shl(bits)?.wrapping_sub(1);
    let value = value & mask;
    Some(if value & sign == 0 {
        value as i64
    } else {
        (value | !mask) as i64
    })
}

pub(crate) fn collect_address_provenance(
    function: &SSAFunction,
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    machine_context: Option<&SourceMachineContext>,
) -> AddressProvenanceFacts {
    AddressCollector::new(function, prep, graph, machine_context).collect()
}

#[cfg(test)]
mod tests {
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    use crate::{
        CanonicalStorageId, CanonicalStorageSpace, ObjectKind, PointeeStep, RelativeMemoryAddress,
        SSAOp, SourceAbiParameterSpec, SourceFunctionInterface, SourceFunctionReturn,
        SourceStackSlotSpec, SsaArtifact, StackAddressBase,
    };

    fn aarch64_two_arg_arch() -> ArchSpec {
        let mut arch = ArchSpec::new("aarch64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("x0", 0, 8));
        arch.add_register(RegisterDef::new("w0", 0, 4));
        arch.add_register(RegisterDef::new("x1", 8, 8));
        arch.add_register(RegisterDef::new("w1", 8, 4));
        arch.add_register(RegisterDef::new("sp", 16, 8));
        arch
    }

    fn exact_parameter_interface(
        revision: &[u8],
        parameter_count: usize,
    ) -> SourceFunctionInterface {
        SourceFunctionInterface::new_exact(
            revision.to_vec(),
            "aarch64-test",
            (0..parameter_count).map(|index| {
                SourceAbiParameterSpec::new(
                    index as u32,
                    CanonicalStorageId {
                        space: CanonicalStorageSpace::Register,
                        offset: (index as u64) * 8,
                        size: 8,
                    },
                )
            }),
            SourceFunctionReturn::Void,
            [],
        )
        .expect("valid exact parameter interface")
    }

    #[test]
    fn context_free_parameter_spill_does_not_invent_a_stack_root() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntSub {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(16, 8),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
            val: Varnode::register(0, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, 8),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::IntMult {
            dst: Varnode::unique(0x30, 8),
            a: Varnode::register(8, 8),
            b: Varnode::constant(40, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x40, 8),
            a: Varnode::unique(0x20, 8),
            b: Varnode::unique(0x30, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x50, 8),
            a: Varnode::unique(0x40, 8),
            b: Varnode::constant(16, 8),
        });
        let artifact = SsaArtifact::for_symbolic(&[block], Some(&arch)).expect("artifact");
        let value = artifact
            .graph()
            .values
            .iter()
            .find(|value| value.var.name().starts_with("tmp:50"))
            .expect("address value");
        assert!(
            artifact
                .addresses()
                .parameter_expression(value.id)
                .is_none()
        );
    }

    #[test]
    fn a_pointer_loaded_from_a_parameter_gets_a_pointee_expression() {
        let arch = aarch64_two_arg_arch();
        let interface = exact_parameter_interface(b"pointee-provenance", 1);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(0, 8),
            b: Varnode::constant(0x38, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, 8),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x30, 8),
            a: Varnode::unique(0x20, 8),
            b: Varnode::constant(0x10, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x40, 8),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x30, 8),
        });
        let artifact = SsaArtifact::for_symbolic_with_interface(&[block], Some(&arch), interface)
            .expect("artifact");
        let value = |name: &str| {
            artifact
                .graph()
                .values
                .iter()
                .find(|value| value.var.name() == name)
                .map(|value| value.id)
                .expect(name)
        };
        // The address x0 + 0x38 is directly parameter-relative, as before.
        let first_address = artifact
            .addresses()
            .parameter_expression(value("tmp:10"))
            .expect("parameter expression");
        assert_eq!((first_address.parameter, first_address.offset), (0, 0x38));
        assert!(
            artifact
                .addresses()
                .pointee_expression(value("tmp:10"))
                .is_none()
        );
        // The value loaded there is a pointer into a pointee object, and is
        // deliberately not a parameter expression: everything reading those
        // keeps its meaning.
        assert!(
            artifact
                .addresses()
                .parameter_expression(value("tmp:20"))
                .is_none()
        );
        let loaded = artifact
            .addresses()
            .pointee_expression(value("tmp:20"))
            .expect("pointee expression for the loaded pointer");
        assert_eq!(loaded.root, 0);
        assert_eq!(
            loaded.path,
            vec![PointeeStep {
                offset: 0x38,
                size: 8
            }]
        );
        assert_eq!(loaded.offset, 0);
        // Arithmetic on it stays inside the same object.
        let inner = artifact
            .addresses()
            .pointee_expression(value("tmp:30"))
            .expect("offset pointee expression");
        assert_eq!(inner.path, loaded.path);
        assert_eq!(inner.offset, 0x10);
        // And a second load is one step further along the chain.
        let second = artifact
            .addresses()
            .pointee_expression(value("tmp:40"))
            .expect("second-level pointee expression");
        assert_eq!(second.path.len(), 2);
        assert_eq!(
            second.path[1],
            PointeeStep {
                offset: 0x10,
                size: 8
            }
        );
        // The object model names the chain.
        let object = artifact
            .objects()
            .object_for_value(value("tmp:30"), SpaceId::Ram)
            .expect("pointee object");
        assert_eq!(
            artifact.objects().access_path(object).as_deref(),
            Some("*(arg0 + 0x38)")
        );
        assert_eq!(artifact.objects().root_parameter(object), Some(0));
    }

    #[test]
    fn parameter_spill_reload_provenance_is_bound_to_exact_memory_space() {
        let mut arch = aarch64_two_arg_arch();
        arch.add_register(RegisterDef::new("lr", 24, 8));
        let register_storage = |offset| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let parameter_storage = register_storage(0);
        let stack_pointer_storage = register_storage(16);
        let return_address_storage = register_storage(24);
        let interface = SourceFunctionInterface::new_exact(
            b"exact-space-parameter-spill".to_vec(),
            "aarch64-test",
            [SourceAbiParameterSpec::new(0, parameter_storage)],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                stack_pointer_storage,
                -8,
                8,
            )],
        )
        .and_then(|interface| interface.with_return_address_storage(return_address_storage))
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer_storage))
        .expect("exact source interface");

        let mut block = R2ILBlock::new(0x1100, 4);
        block.push(R2ILOp::IntSub {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(16, 8),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
            val: Varnode::register(0, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, 8),
            space: SpaceId::Custom(7),
            addr: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Custom(7),
            addr: Varnode::unique(0x10, 8),
            val: Varnode::register(0, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x28, 8),
            space: SpaceId::Custom(7),
            addr: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::register(24, 8),
        });

        let artifact = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("decompile artifact");
        let loaded_values = artifact
            .get_block(0x1100)
            .expect("entry block")
            .ops()
            .iter()
            .filter_map(|op| match op {
                SSAOp::Load { dst, space, .. } if *space == SpaceId::Custom(7) => artifact
                    .graph()
                    .value_id_for_var(dst)
                    .map(|value| (dst.name(), value)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(loaded_values.len(), 2);
        let crossed = loaded_values
            .iter()
            .find(|(name, _)| name.starts_with("tmp:20"))
            .expect("cross-space reload")
            .1;
        let exact = loaded_values
            .iter()
            .find(|(name, _)| name.starts_with("tmp:28"))
            .expect("same-space reload")
            .1;
        assert!(artifact.addresses().parameter_expression(crossed).is_none());
        assert_eq!(
            artifact
                .addresses()
                .parameter_expression(exact)
                .map(|expression| expression.parameter),
            Some(0)
        );
    }

    /// A slot a pointer was spilled to, read back at half its width, holds
    /// the pointer's low word, which is not the pointer.
    #[test]
    fn a_narrower_reload_of_a_spilled_parameter_is_not_the_parameter() {
        let arch = aarch64_two_arg_arch();
        let register_storage = |offset| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let stack_pointer_storage = register_storage(16);
        let interface = SourceFunctionInterface::new_exact(
            b"narrow-spill-reload".to_vec(),
            "aarch64-test",
            [SourceAbiParameterSpec::new(0, register_storage(0))],
            SourceFunctionReturn::Void,
            [SourceStackSlotSpec::new_local(
                StackAddressBase::StackPointer,
                stack_pointer_storage,
                -8,
                8,
            )],
        )
        .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer_storage))
        .expect("exact source interface");
        let mut block = R2ILBlock::new(0x1100, 4);
        block.push(R2ILOp::IntSub {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(16, 8),
            b: Varnode::constant(8, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
            val: Varnode::register(0, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, 4),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x28, 8),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
        });
        let artifact = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("decompile artifact");
        let loaded = |name: &str| {
            artifact
                .graph()
                .values
                .iter()
                .find(|value| value.var.name().starts_with(name))
                .map(|value| value.id)
                .expect(name)
        };
        assert!(
            artifact
                .addresses()
                .parameter_expression(loaded("tmp:20"))
                .is_none()
        );
        assert_eq!(
            artifact
                .addresses()
                .parameter_expression(loaded("tmp:28"))
                .map(|expression| expression.parameter),
            Some(0)
        );
    }

    #[test]
    fn narrow_scalar_formal_is_not_a_parameter_address_base() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x10, 4),
            a: Varnode::register(8, 4),
            b: Varnode::constant(4, 4),
        });
        let artifact = SsaArtifact::for_symbolic(&[block], Some(&arch)).expect("artifact");
        // The body reads four bytes of `x1` and no more, so that read is the
        // value itself; either way it is not the parameter's address base.
        let scalar = artifact
            .graph()
            .values
            .iter()
            .find(|value| {
                value.var.size == 4
                    && (value.var.name().eq_ignore_ascii_case("w1")
                        || value.var.name().starts_with("tmp:lane:"))
            })
            .expect("narrow formal read");
        assert!(
            artifact
                .addresses()
                .parameter_expression(scalar.id)
                .is_none()
        );
    }

    /// The id of the one value the lift names `name`.
    fn value_named(artifact: &SsaArtifact, name: &str) -> crate::ValueId {
        artifact
            .graph()
            .values
            .iter()
            .find(|value| value.var.name() == name)
            .map(|value| value.id)
            .unwrap_or_else(|| panic!("no value {name}"))
    }

    /// A 32-bit parameter in `w1`, zero-extended, is the parameter's unsigned
    /// value and so its address; sign-extended it is another integer wherever
    /// its top bit is set, and so no address of the parameter at all.
    #[test]
    fn a_sign_extended_parameter_is_not_the_parameter_it_extends() {
        let arch = aarch64_two_arg_arch();
        let register = |offset, size| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        };
        let interface = SourceFunctionInterface::new_exact(
            b"sign-extended-parameter".to_vec(),
            "aarch64-test",
            [
                SourceAbiParameterSpec::new(0, register(0, 8)),
                SourceAbiParameterSpec::new(1, register(8, 4)),
            ],
            SourceFunctionReturn::Void,
            [],
        )
        .expect("valid exact parameter interface");
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntSExt {
            dst: Varnode::unique(0x10, 8),
            src: Varnode::register(8, 4),
        });
        block.push(R2ILOp::IntZExt {
            dst: Varnode::unique(0x18, 8),
            src: Varnode::register(8, 4),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x20, 1),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x28, 1),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x18, 8),
        });
        let artifact = SsaArtifact::for_decompile_with_interface(&[block], Some(&arch), interface)
            .expect("artifact");
        let expression = |name| {
            artifact
                .addresses()
                .parameter_expression(value_named(&artifact, name))
                .map(|expression| (expression.parameter, expression.offset))
        };
        assert_eq!(expression("tmp:10"), None);
        assert_eq!(expression("tmp:18"), Some((1, 0)));
    }

    /// `x0 + 4 * (uint64_t)(uint32_t)(w1 + 1)` is not `x0 + 4 * w1 + 4`: the
    /// addition wraps at 32 bits, so the widened sum is one term.
    #[test]
    fn a_widened_narrow_sum_is_one_term_of_the_address() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x10, 4),
            a: Varnode::register(8, 4),
            b: Varnode::constant(1, 4),
        });
        block.push(R2ILOp::IntZExt {
            dst: Varnode::unique(0x18, 8),
            src: Varnode::unique(0x10, 4),
        });
        block.push(R2ILOp::IntMult {
            dst: Varnode::unique(0x20, 8),
            a: Varnode::unique(0x18, 8),
            b: Varnode::constant(4, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x28, 8),
            a: Varnode::register(0, 8),
            b: Varnode::unique(0x20, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x30, 4),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x28, 8),
        });
        let artifact = SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&arch),
            exact_parameter_interface(b"widened-sum", 2),
        )
        .expect("artifact");
        let address = artifact
            .addresses()
            .parameter_expression(value_named(&artifact, "tmp:28"))
            .expect("x0 plus an index");
        assert_eq!(address.parameter, 0);
        assert_eq!(address.offset, 0, "{address:?}");
        assert_eq!(
            address.terms,
            vec![crate::AffineAddressTerm {
                value: value_named(&artifact, "tmp:10"),
                coefficient: 4,
            }]
        );
    }

    /// `x0 + (uint64_t)(uint32_t)x1` adds the low word of `x1`, not `x1`.
    #[test]
    fn a_truncated_index_is_its_own_term() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Subpiece {
            dst: Varnode::unique(0x10, 4),
            src: Varnode::register(8, 8),
            offset: 0,
        });
        block.push(R2ILOp::IntZExt {
            dst: Varnode::unique(0x18, 8),
            src: Varnode::unique(0x10, 4),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x20, 8),
            a: Varnode::register(0, 8),
            b: Varnode::unique(0x18, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x28, 1),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x20, 8),
        });
        let artifact = SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&arch),
            exact_parameter_interface(b"truncated-index", 2),
        )
        .expect("artifact");
        let address = artifact
            .addresses()
            .parameter_expression(value_named(&artifact, "tmp:20"))
            .expect("x0 plus an index");
        assert_eq!(
            address.terms,
            vec![crate::AffineAddressTerm {
                value: value_named(&artifact, "tmp:18"),
                coefficient: 1,
            }]
        );
    }

    #[test]
    fn adding_two_full_width_parameter_bases_is_not_certified() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(0, 8),
            b: Varnode::register(8, 8),
        });
        let artifact = SsaArtifact::for_symbolic(&[block], Some(&arch)).expect("artifact");
        let sum = artifact
            .graph()
            .values
            .iter()
            .find(|value| value.var.name().starts_with("tmp:10"))
            .expect("sum");
        assert!(artifact.addresses().parameter_expression(sum.id).is_none());
    }

    #[test]
    fn context_free_pointer_spill_does_not_invent_a_stack_root() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntSub {
            dst: Varnode::register(16, 8),
            a: Varnode::register(16, 8),
            b: Varnode::constant(32, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x20, 8),
            a: Varnode::register(16, 8),
            b: Varnode::constant(16, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x20, 8),
            val: Varnode::register(0, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x30, 8),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x20, 8),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::unique(0x38, 8),
            src: Varnode::constant(40, 8),
        });
        block.push(R2ILOp::IntMult {
            dst: Varnode::unique(0x40, 8),
            a: Varnode::register(8, 8),
            b: Varnode::unique(0x38, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x50, 8),
            a: Varnode::unique(0x30, 8),
            b: Varnode::unique(0x40, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(16, 8),
            val: Varnode::unique(0x50, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x60, 8),
            space: SpaceId::Ram,
            addr: Varnode::register(16, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x70, 8),
            a: Varnode::unique(0x60, 8),
            b: Varnode::constant(16, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x70, 8),
            val: Varnode::constant(1, 4),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x80, 8),
            space: SpaceId::Ram,
            addr: Varnode::register(16, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x90, 8),
            a: Varnode::unique(0x80, 8),
            b: Varnode::constant(4, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0xa0, 2),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x90, 8),
        });

        let artifact = SsaArtifact::for_decompile(&[block], Some(&arch)).expect("artifact");
        let value = artifact
            .graph()
            .values
            .iter()
            .find(|value| value.var.name().starts_with("tmp:90"))
            .expect("field address value");
        assert!(
            artifact
                .addresses()
                .parameter_expression(value.id)
                .is_none()
        );
    }

    #[test]
    fn context_free_loop_spill_does_not_invent_a_stack_root() {
        let arch = aarch64_two_arg_arch();
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::IntSub {
            dst: Varnode::register(16, 8),
            a: Varnode::register(16, 8),
            b: Varnode::constant(8, 8),
        });
        entry.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(16, 8),
            val: Varnode::register(0, 8),
        });
        entry.push(R2ILOp::Branch {
            target: Varnode::constant(0x1004, 8),
        });

        let mut header = R2ILBlock::new(0x1004, 4);
        header.push(R2ILOp::Load {
            dst: Varnode::unique(0x10, 8),
            space: SpaceId::Ram,
            addr: Varnode::register(16, 8),
        });
        header.push(R2ILOp::CBranch {
            target: Varnode::constant(0x100c, 8),
            cond: Varnode::register(8, 8),
        });

        let mut backedge = R2ILBlock::new(0x1008, 4);
        backedge.push(R2ILOp::Branch {
            target: Varnode::constant(0x1004, 8),
        });

        let mut exit = R2ILBlock::new(0x100c, 4);
        exit.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });

        let artifact = SsaArtifact::for_decompile(&[entry, header, backedge, exit], Some(&arch))
            .expect("artifact");
        let loaded = artifact
            .graph()
            .values
            .iter()
            .find(|value| {
                value.var.name() == "tmp:10"
                    && artifact.graph().def_inst(value.id).is_some_and(|inst| {
                        matches!(
                            artifact.graph().inst(inst).map(|inst| &inst.payload),
                            Some(crate::graph::InstPayload::Op(crate::SSAOp::Load { .. }))
                        )
                    })
            })
            .expect("reloaded parameter");
        assert!(
            artifact
                .addresses()
                .parameter_expression(loaded.id)
                .is_none()
        );
    }

    #[test]
    fn affine_field_ranges_keep_independent_memory_versions() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntMult {
            dst: Varnode::unique(0x10, 8),
            a: Varnode::register(8, 8),
            b: Varnode::constant(40, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x20, 8),
            a: Varnode::register(0, 8),
            b: Varnode::unique(0x10, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x30, 8),
            a: Varnode::unique(0x20, 8),
            b: Varnode::constant(16, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::unique(0x30, 8),
            val: Varnode::constant(0, 4),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::unique(0x40, 8),
            a: Varnode::unique(0x20, 8),
            b: Varnode::constant(4, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x50, 2),
            space: SpaceId::Ram,
            addr: Varnode::unique(0x40, 8),
        });
        let artifact = SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&arch),
            exact_parameter_interface(b"affine-field-ranges", 2),
        )
        .expect("source-bound artifact");
        let (load_index, _) = artifact
            .get_block(0x1000)
            .expect("block")
            .ops()
            .iter()
            .enumerate()
            .find(|(_, op)| matches!(op, SSAOp::Load { .. }))
            .expect("load");
        let uses = artifact
            .inst_at(0x1000, load_index)
            .and_then(|inst| artifact.memory_uses_for_inst(inst))
            .expect("memory use");
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0].version.version, 0);
        assert!(matches!(
            artifact
                .objects()
                .object(uses[0].location.object)
                .map(|object| &object.kind),
            Some(ObjectKind::Parameter { index: 0, .. })
        ));
        assert!(matches!(
            &uses[0].location.address,
            RelativeMemoryAddress::Affine { terms, offset }
                if *offset == 4 && terms.len() == 1 && terms[0].coefficient == 40
        ));
    }

    #[test]
    fn distinct_parameter_bases_remain_may_alias() {
        let arch = aarch64_two_arg_arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::register(0, 8),
            val: Varnode::constant(0x42, 1),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::unique(0x10, 1),
            space: SpaceId::Ram,
            addr: Varnode::register(8, 8),
        });
        let artifact = SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&arch),
            exact_parameter_interface(b"distinct-parameter-bases", 2),
        )
        .expect("source-bound artifact");
        let block = artifact.get_block(0x1000).expect("block");
        let store_index = block
            .ops()
            .iter()
            .position(|op| matches!(op, SSAOp::Store { .. }))
            .expect("store");
        let load_index = block
            .ops()
            .iter()
            .position(|op| matches!(op, SSAOp::Load { .. }))
            .expect("load");
        let written = artifact
            .inst_at(0x1000, store_index)
            .and_then(|inst| artifact.memory_defs_for_inst(inst))
            .and_then(|defs| defs.first())
            .expect("memory def")
            .next_version;
        let uses = artifact
            .inst_at(0x1000, load_index)
            .and_then(|inst| artifact.memory_uses_for_inst(inst))
            .expect("memory use");
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0].version, written);
        assert_ne!(uses[0].location.object, written.object);
    }
}
