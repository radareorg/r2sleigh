//! Condition chains: nested tests written as one `&&`/`||` test, with the BDD identity check
//! that proves the test is the blocks' (`doc/adr-structure-dominator-tree.md` §3, 2026-10-22).

use std::collections::{BTreeMap, BTreeSet};

use crate::ast::{BinaryOp, CExpr, CStmt, RenderObservationId, UnaryOp};

/// Most blocks one chain may test.
const MAX_ATOMS: usize = 16;
/// Most BDD nodes one chain check may create; past it the chain is refused.
const NODE_BUDGET: usize = 512;

/// Why a chain was not written, or why the text that claims one is not the machine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainFault {
    TooManyAtoms,
    NodeBudget,
    /// The test is not `&&`, `||` and `!` over one unmarked head and marked blocks.
    Shape,
    /// A block the chain tests does not end in a two-way conditional branch.
    NotConditional {
        block: u64,
    },
    /// A block past the head is entered from outside the chain.
    Outside {
        block: u64,
    },
    /// A block past the head is written as text of its own.
    Rendered {
        block: u64,
    },
    ExitCount {
        found: usize,
    },
    /// An edge of the DAG runs against the order the test evaluates its atoms in.
    Unordered,
    /// An atom decides nothing: both its edges lead to the same function.
    NotReduced,
    /// The DAG's exit function is not the test's.
    Different,
    /// No `&&`/`||` spelling of the DAG is read-once.
    NotShortCircuit,
}

impl ChainFault {
    pub(crate) const fn clause(self) -> &'static str {
        match self {
            Self::TooManyAtoms => "too-many-atoms",
            Self::NodeBudget => "node-budget",
            Self::Shape => "shape",
            Self::NotConditional { .. } => "not-conditional",
            Self::Outside { .. } => "outside",
            Self::Rendered { .. } => "rendered",
            Self::ExitCount { .. } => "exit-count",
            Self::Unordered => "unordered",
            Self::NotReduced => "not-reduced",
            Self::Different => "different",
            Self::NotShortCircuit => "not-short-circuit",
        }
    }
}

impl std::fmt::Display for ChainFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.clause())?;
        match self {
            Self::NotConditional { block } | Self::Outside { block } => write!(f, " {block:#x}"),
            Self::Rendered { block } => write!(f, " {block:#x}"),
            Self::ExitCount { found } => write!(f, " {found}"),
            _ => Ok(()),
        }
    }
}

const FALSE: u32 = 0;
const TRUE: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    And,
    Or,
}

/// A reduced ordered BDD over atom positions, built under a node budget.
struct Bdd {
    /// `(position, low, high)`; ids 0 and 1 are the constants.
    nodes: Vec<(usize, u32, u32)>,
    unique: BTreeMap<(usize, u32, u32), u32>,
    apply: BTreeMap<(Op, u32, u32), u32>,
    budget: usize,
}

impl Bdd {
    fn new(budget: usize) -> Self {
        Self {
            nodes: vec![(usize::MAX, FALSE, FALSE), (usize::MAX, TRUE, TRUE)],
            unique: BTreeMap::new(),
            apply: BTreeMap::new(),
            budget,
        }
    }

    /// The node testing `at` with these children; `None` where it would test nothing.
    fn node(&mut self, at: usize, low: u32, high: u32) -> Result<u32, ChainFault> {
        if low == high {
            return Ok(low);
        }
        if let Some(found) = self.unique.get(&(at, low, high)) {
            return Ok(*found);
        }
        if self.nodes.len() >= self.budget {
            return Err(ChainFault::NodeBudget);
        }
        let id = u32::try_from(self.nodes.len()).map_err(|_| ChainFault::NodeBudget)?;
        self.nodes.push((at, low, high));
        self.unique.insert((at, low, high), id);
        Ok(id)
    }

    fn literal(&mut self, at: usize, positive: bool) -> Result<u32, ChainFault> {
        match positive {
            true => self.node(at, FALSE, TRUE),
            false => self.node(at, TRUE, FALSE),
        }
    }

    fn at(&self, id: u32) -> (usize, u32, u32) {
        self.nodes[id as usize]
    }

    fn combine(&mut self, op: Op, left: u32, right: u32) -> Result<u32, ChainFault> {
        let (left, right) = (left.min(right), left.max(right));
        match (op, left, right) {
            (Op::And, FALSE, _) | (Op::Or, TRUE, _) => return Ok(left),
            (Op::And, TRUE, other) | (Op::Or, FALSE, other) => return Ok(other),
            _ if left == right => return Ok(left),
            _ => {}
        }
        if let Some(found) = self.apply.get(&(op, left, right)) {
            return Ok(*found);
        }
        let (left_at, left_low, left_high) = self.at(left);
        let (right_at, right_low, right_high) = self.at(right);
        let at = left_at.min(right_at);
        let split = |node_at, low, high, whole| match node_at == at {
            true => (low, high),
            false => (whole, whole),
        };
        let (left_low, left_high) = split(left_at, left_low, left_high, left);
        let (right_low, right_high) = split(right_at, right_low, right_high, right);
        let low = self.combine(op, left_low, right_low)?;
        let high = self.combine(op, left_high, right_high)?;
        let made = self.node(at, low, high)?;
        self.apply.insert((op, left, right), made);
        Ok(made)
    }

    fn not(&mut self, id: u32) -> Result<u32, ChainFault> {
        match id {
            FALSE => Ok(TRUE),
            TRUE => Ok(FALSE),
            _ => {
                let (at, low, high) = self.at(id);
                let (low, high) = (self.not(low)?, self.not(high)?);
                self.node(at, low, high)
            }
        }
    }

    fn formula(&mut self, formula: &Formula, position: &[usize]) -> Result<u32, ChainFault> {
        match formula {
            Formula::Atom { node, positive } => self.literal(position[*node], *positive),
            Formula::And(left, right) | Formula::Or(left, right) => {
                let op = match formula {
                    Formula::And(..) => Op::And,
                    _ => Op::Or,
                };
                let (left, right) = (
                    self.formula(left, position)?,
                    self.formula(right, position)?,
                );
                self.combine(op, left, right)
            }
        }
    }
}

/// A test as `&&`, `||` and atoms, negation only at the atoms; an atom is a node of the DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Formula {
    Atom { node: usize, positive: bool },
    And(Box<Formula>, Box<Formula>),
    Or(Box<Formula>, Box<Formula>),
}

impl Formula {
    fn atom(node: usize, positive: bool) -> Self {
        Self::Atom { node, positive }
    }

    fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

    /// The test that holds exactly when this one does not.
    fn negated(&self) -> Self {
        match self {
            Self::Atom { node, positive } => Self::atom(*node, !positive),
            Self::And(left, right) => left.negated().or(right.negated()),
            Self::Or(left, right) => left.negated().and(right.negated()),
        }
    }

    /// The nodes in the order the test evaluates them: left to right.
    fn atoms(&self, into: &mut Vec<usize>) {
        match self {
            Self::Atom { node, .. } => into.push(*node),
            Self::And(left, right) | Self::Or(left, right) => {
                left.atoms(into);
                right.atoms(into);
            }
        }
    }

    /// The same test with each node `n` renamed `names[n]`.
    fn renumbered(&self, names: &[usize]) -> Self {
        match self {
            Self::Atom { node, positive } => Self::atom(names[*node], *positive),
            Self::And(left, right) => left.renumbered(names).and(right.renumbered(names)),
            Self::Or(left, right) => left.renumbered(names).or(right.renumbered(names)),
        }
    }

    fn negations(&self) -> usize {
        match self {
            Self::Atom { positive, .. } => usize::from(!positive),
            Self::And(left, right) | Self::Or(left, right) => left.negations() + right.negations(),
        }
    }
}

/// Where a test's edge goes: another test of the chain, or out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Edge {
    Node(usize),
    Exit(usize),
}

/// The decision DAG of a chain: node 0 is its head, each node's `(true, false)` edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dag {
    pub(crate) nodes: Vec<(Edge, Edge)>,
    pub(crate) exits: usize,
}

/// Whether `exit` is reached exactly when `formula` holds; the DAG must be the test's trace, which
/// is its reduced ordered BDD under the order it reads its atoms in (ADR §3).
pub(crate) fn verify(dag: &Dag, formula: &Formula, exit: usize) -> Result<bool, ChainFault> {
    verify_within(dag, formula, exit, NODE_BUDGET)
}

/// [`verify`] building at most `budget` BDD nodes; a chain that needs more is refused.
fn verify_within(
    dag: &Dag,
    formula: &Formula,
    exit: usize,
    budget: usize,
) -> Result<bool, ChainFault> {
    if dag.exits != 2 {
        return Err(ChainFault::ExitCount { found: dag.exits });
    }
    let mut order = Vec::new();
    formula.atoms(&mut order);
    let mut position = vec![usize::MAX; dag.nodes.len()];
    for (at, node) in order.iter().enumerate() {
        match position.get_mut(*node) {
            Some(slot) if *slot == usize::MAX => *slot = at,
            _ => return Err(ChainFault::Shape),
        }
    }
    if order.len() != dag.nodes.len() || order.first() != Some(&0) {
        return Err(ChainFault::Shape);
    }
    for (node, (on_true, on_false)) in dag.nodes.iter().enumerate() {
        for edge in [on_true, on_false] {
            if let Edge::Node(next) = edge
                && position[node] >= position[*next]
            {
                return Err(ChainFault::Unordered);
            }
        }
    }
    let mut bdd = Bdd::new(budget);
    let mut function = vec![FALSE; dag.nodes.len()];
    let edge_function = |function: &[u32], edge: Edge| match edge {
        Edge::Node(next) => function[next],
        Edge::Exit(reached) => u32::from(reached == exit),
    };
    for node in order.iter().rev() {
        let (on_true, on_false) = dag.nodes[*node];
        let (high, low) = (
            edge_function(&function, on_true),
            edge_function(&function, on_false),
        );
        if high == low {
            return Err(ChainFault::NotReduced);
        }
        function[*node] = bdd.node(position[*node], low, high)?;
    }
    // Each atom is reached from the head, or the DAG and the test name different blocks.
    let mut reached = BTreeSet::from([0usize]);
    let mut pending = vec![0usize];
    while let Some(node) = pending.pop() {
        for edge in [dag.nodes[node].0, dag.nodes[node].1] {
            if let Edge::Node(next) = edge
                && reached.insert(next)
            {
                pending.push(next);
            }
        }
    }
    if reached.len() != dag.nodes.len() {
        return Err(ChainFault::Shape);
    }
    let written = bdd.formula(formula, &position)?;
    if function[0] == written {
        return Ok(true);
    }
    let unwritten = bdd.not(written)?;
    match function[0] == unwritten {
        true => Ok(false),
        false => Err(ChainFault::Different),
    }
}

/// A read-once `&&`/`||` spelling of "the chain reaches `exit`" from `node`, where the DAG has one;
/// only a candidate, [`verify`] is the proof.
fn derive(dag: &Dag, node: usize, exit: usize) -> Option<Formula> {
    let (on_true, on_false) = dag.nodes[node];
    let reaches = |edge: Edge| match edge {
        Edge::Exit(reached) => Some(reached == exit),
        Edge::Node(_) => None,
    };
    match (on_true, on_false) {
        (Edge::Exit(a), Edge::Exit(b)) => match (a == exit, b == exit) {
            (true, false) => Some(Formula::atom(node, true)),
            (false, true) => Some(Formula::atom(node, false)),
            _ => None,
        },
        (Edge::Node(next), edge @ Edge::Exit(_)) => {
            let rest = derive(dag, next, exit)?;
            Some(match reaches(edge)? {
                true => Formula::atom(node, false).or(rest),
                false => Formula::atom(node, true).and(rest),
            })
        }
        (edge @ Edge::Exit(_), Edge::Node(next)) => {
            let rest = derive(dag, next, exit)?;
            Some(match reaches(edge)? {
                true => Formula::atom(node, true).or(rest),
                false => Formula::atom(node, false).and(rest),
            })
        }
        (Edge::Node(first), Edge::Node(second)) => {
            // One of the two hands on to the other on one edge and leaves by an exit on the
            // other: it is taken, then leaves, exactly when `leaves` holds.
            [(first, true, second), (second, false, first)]
                .into_iter()
                .find_map(|(taken, taken_positive, rest)| {
                    let (on_true, on_false) = dag.nodes[taken];
                    let (leaves_on, left) = match (on_true, on_false) {
                        (Edge::Node(next), Edge::Exit(left)) if next == rest => (false, left),
                        (Edge::Exit(left), Edge::Node(next)) if next == rest => (true, left),
                        _ => return None,
                    };
                    let leaves =
                        Formula::atom(node, taken_positive).and(Formula::atom(taken, leaves_on));
                    let rest = derive(dag, rest, exit)?;
                    Some(match left == exit {
                        true => leaves.or(rest),
                        false => leaves.negated().and(rest),
                    })
                })
        }
    }
}

/// The test the chain is written as, and which exit it reaches: the block of text `body` where
/// one is, since it reads as the `if`'s body, else the exit with fewer negations.
fn spell(dag: &Dag, body: Option<usize>) -> Result<(Formula, usize), ChainFault> {
    let mut best: Option<(Formula, usize)> = None;
    for exit in [body.unwrap_or(0), 1 - body.unwrap_or(0)] {
        let Some(formula) = derive(dag, 0, exit) else {
            continue;
        };
        if !verify(dag, &formula, exit)? {
            continue;
        }
        if body.is_some() && best.is_none() {
            return Ok((formula, exit));
        }
        if best
            .as_ref()
            .is_none_or(|(held, _)| formula.negations() < held.negations())
        {
            best = Some((formula, exit));
        }
    }
    best.ok_or(ChainFault::NotShortCircuit)
}

/// What the certificate reads of a rendered test: its atoms in evaluation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Written {
    pub(crate) formula: Formula,
    /// By node: the block whose marker the atom carries. The head's is first.
    pub(crate) blocks: Vec<u64>,
    /// By node: the markers the atom carries.
    pub(crate) marks: Vec<Vec<RenderObservationId>>,
}

/// The single block a marker set names.
fn single_block(
    ids: &[RenderObservationId],
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
) -> Option<u64> {
    let mut blocks = ids.iter().filter_map(|id| block_of(*id));
    let first = blocks.next()?;
    blocks.all(|block| block == first).then_some(first)
}

/// Whether some part of `expr` carries the marker of a block.
fn marked(expr: &CExpr, block_of: &dyn Fn(RenderObservationId) -> Option<u64>) -> bool {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        if let CExpr::Observed { ids, .. } = expr
            && ids.iter().any(|id| block_of(id).is_some())
        {
            return true;
        }
        pending.extend(expr.children());
    }
    false
}

/// The test as atoms when one carries a block's marker, else `Ok(None)`; every atom is marked, so a
/// `!` is the writer's own and never the lowering's. One atom is a rotated loop's test, with its polarity.
pub(crate) fn read(
    test: &CExpr,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
) -> Result<Option<Written>, ChainFault> {
    if !marked(test, block_of) {
        return Ok(None);
    }
    let mut atoms = Vec::new();
    let formula = read_into(test, true, block_of, &mut atoms)?;
    match atoms.is_empty() {
        true => Err(ChainFault::Shape),
        false => {
            let (blocks, marks) = atoms.into_iter().unzip();
            Ok(Some(Written {
                formula,
                blocks,
                marks,
            }))
        }
    }
}

/// An atom of a written test: its block and the markers it carries.
type ReadAtom = (u64, Vec<RenderObservationId>);

fn read_into(
    expr: &CExpr,
    positive: bool,
    block_of: &dyn Fn(RenderObservationId) -> Option<u64>,
    atoms: &mut Vec<ReadAtom>,
) -> Result<Formula, ChainFault> {
    match expr {
        CExpr::Observed { ids, .. } => {
            let marks: Vec<_> = ids.iter().collect();
            let block = single_block(&marks, block_of).ok_or(ChainFault::Shape)?;
            atoms.push((block, marks));
            Ok(Formula::atom(atoms.len() - 1, positive))
        }
        CExpr::Paren(inner) => read_into(inner, positive, block_of, atoms),
        CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } => read_into(operand, !positive, block_of, atoms),
        CExpr::Binary {
            op: op @ (BinaryOp::And | BinaryOp::Or),
            left,
            right,
        } => {
            let left = read_into(left, positive, block_of, atoms)?;
            let right = read_into(right, positive, block_of, atoms)?;
            // Under a negation the connective flips, as the atoms did.
            Ok(match (*op == BinaryOp::And) == positive {
                true => left.and(right),
                false => left.or(right),
            })
        }
        _ => Err(ChainFault::Shape),
    }
}

/// The machine's side of a written chain, as the certificate reads it from the CFG.
pub(crate) trait Machine {
    /// Where an edge out of the chain arrives; two edges to one place are one exit.
    type Exit: Copy + PartialEq;
    /// A block's `(true, false)` targets, when it ends in a two-way branch.
    fn successors(&self, block: u64) -> Option<(u64, u64)>;
    fn arrives(&self, target: u64) -> Self::Exit;
    fn entered_from_outside(&self, block: u64, chain: &BTreeSet<u64>) -> bool;
}

/// The exits a written chain has in the CFG, each labelled by the side of the test that reaches it.
pub(crate) fn exits<M: Machine>(
    head: u64,
    written: &Written,
    machine: &M,
) -> Result<[(M::Exit, bool); 2], ChainFault> {
    let blocks = &written.blocks;
    let members: BTreeSet<u64> = blocks.iter().copied().collect();
    if members.len() != blocks.len() || blocks.first() != Some(&head) {
        return Err(ChainFault::Shape);
    }
    let mut targets: Vec<M::Exit> = Vec::new();
    let mut nodes = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let (on_true, on_false) =
            (machine.successors(*block)).ok_or(ChainFault::NotConditional { block: *block })?;
        if index > 0 && machine.entered_from_outside(*block, &members) {
            return Err(ChainFault::Outside { block: *block });
        }
        // Only an edge to a later test is inside the DAG: one back to the head or an earlier test leaves it.
        let mut edge = |target: u64| match blocks.iter().position(|member| *member == target) {
            Some(at) if at > index => Edge::Node(at),
            _ => Edge::Exit(exit_index(&mut targets, machine.arrives(target))),
        };
        let (on_true, on_false) = (edge(on_true), edge(on_false));
        nodes.push((on_true, on_false));
    }
    let [first, second] = targets[..] else {
        return Err(ChainFault::ExitCount {
            found: targets.len(),
        });
    };
    let dag = Dag { nodes, exits: 2 };
    let first_is_true = verify(&dag, &written.formula, 0)?;
    Ok([(first, first_is_true), (second, !first_is_true)])
}

/// The place of `arrived` among the exits seen so far, which it joins when it is new.
fn exit_index<T: PartialEq>(targets: &mut Vec<T>, arrived: T) -> usize {
    targets
        .iter()
        .position(|held| *held == arrived)
        .unwrap_or_else(|| {
            targets.push(arrived);
            targets.len() - 1
        })
}

/// What the collapse reads of the markers the tree carries, and the copies it asks for.
pub(crate) trait Marks {
    /// The block a marker was written for.
    fn block_of(&self, id: RenderObservationId) -> Option<u64>;
    /// A marker of its own for the same block and instruction, for one more occurrence of it.
    fn copy_of(&mut self, id: RenderObservationId) -> RenderObservationId;
}

/// `test` as the writer's atoms: a test with no marker becomes one atom carrying a copy of each of `ids`.
pub(super) fn as_atoms(
    test: CExpr,
    ids: impl IntoIterator<Item = RenderObservationId>,
    marks: &mut dyn Marks,
) -> CExpr {
    match carries_marker(&test) {
        true => test,
        false => CExpr::observe_all(ids.into_iter().map(|id| marks.copy_of(id)), test),
    }
}

/// The test that holds where `test` does not, over marked atoms: they take the `!` and the
/// connectives swap. An integer comparison reads as its opposite once certified (`respell_negations`).
pub(super) fn negated(test: CExpr) -> CExpr {
    match test {
        CExpr::Binary {
            op: op @ (BinaryOp::And | BinaryOp::Or),
            left,
            right,
        } if carries_marker(&left) || carries_marker(&right) => {
            let flipped = if op == BinaryOp::And {
                BinaryOp::Or
            } else {
                BinaryOp::And
            };
            CExpr::binary(flipped, negated(*left), negated(*right))
        }
        CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } if carries_marker(&operand) => *operand,
        atom => CExpr::unary(UnaryOp::Not, atom),
    }
}

/// Whether a test carries a block's marker somewhere, which the lowering never puts there.
fn carries_marker(expr: &CExpr) -> bool {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        if matches!(expr, CExpr::Observed { .. }) {
            return true;
        }
        pending.extend(expr.children());
    }
    false
}

/// The chains written, and the ones refused with the head and the reason.
#[derive(Debug, Default)]
pub(crate) struct Report {
    pub(crate) collapsed: usize,
    pub(crate) refused: Vec<(u64, ChainFault)>,
}

/// Write each condition chain of the placed tree as one test where the DAG proves out: a block past
/// the head is a test whose text is nothing else. At most `MAX_ATOMS` blocks per head.
pub(crate) fn collapse(body: &mut CStmt, marks: &mut dyn Marks) -> Report {
    let mut references = BTreeMap::new();
    count_gotos(body, &mut references, 1);
    let mut pass = Pass {
        marks,
        references,
        report: Report::default(),
    };
    pass.stmt(body);
    pass.report
}

/// Add `by` to each label the gotos of `stmt` name.
fn count_gotos(stmt: &CStmt, into: &mut BTreeMap<String, isize>, by: isize) {
    match stmt {
        CStmt::Goto(label) => *into.entry(label.clone()).or_default() += by,
        CStmt::Observed { stmt, .. } => count_gotos(stmt, into, by),
        CStmt::Block(stmts) => stmts.iter().for_each(|stmt| count_gotos(stmt, into, by)),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            count_gotos(then_body, into, by);
            if let Some(else_body) = else_body {
                count_gotos(else_body, into, by);
            }
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                count_gotos(init, into, by);
            }
            count_gotos(body, into, by);
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => count_gotos(body, into, by),
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                case.body
                    .iter()
                    .for_each(|stmt| count_gotos(stmt, into, by));
            }
            if let Some(default) = default {
                default.iter().for_each(|stmt| count_gotos(stmt, into, by));
            }
        }
        _ => {}
    }
}

struct Pass<'e> {
    marks: &'e mut dyn Marks,
    /// Gotos to each label in the tree as it now stands.
    references: BTreeMap<String, isize>,
    report: Report,
}

impl Pass<'_> {
    fn stmt(&mut self, stmt: &mut CStmt) {
        match stmt {
            CStmt::Observed { stmt, .. } => self.stmt(stmt),
            CStmt::Block(stmts) => self.sequence(stmts),
            CStmt::If {
                then_body,
                else_body,
                ..
            } => {
                self.stmt(then_body);
                if let Some(else_body) = else_body {
                    self.stmt(else_body);
                }
            }
            CStmt::For { body, .. } | CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => {
                self.stmt(body)
            }
            CStmt::Switch { cases, default, .. } => {
                for case in cases {
                    self.sequence(&mut case.body);
                }
                if let Some(default) = default {
                    self.sequence(default);
                }
            }
            _ => {}
        }
    }

    /// Indexes the regions of a sequence once: a chain forgets the ones it consumes and their
    /// statements stay until the sequence ends, so no position moves (ADR §5, 2026-10-23).
    fn sequence(&mut self, stmts: &mut Vec<CStmt>) {
        let mut regions = self.test_regions(stmts);
        let mut consumed = BTreeSet::new();
        for at in 0..stmts.len() {
            if consumed.contains(&at) {
                continue;
            }
            self.chain_at(stmts, at, &mut regions, &mut consumed);
            self.stmt(&mut stmts[at]);
        }
        if !consumed.is_empty() {
            let mut index = 0;
            stmts.retain(|_| {
                index += 1;
                !consumed.contains(&(index - 1))
            });
        }
    }

    /// The labelled regions of a sequence that hold one test and nothing else, by label.
    fn test_regions(&self, stmts: &[CStmt]) -> Regions {
        #[cfg(test)]
        INDEXED.with(|read| read.set(read.get() + stmts.len()));
        let mut regions = Regions::new();
        for (index, stmt) in stmts.iter().enumerate() {
            if let Some((label, test)) = labelled_test(stmt)
                && test_block(test, &*self.marks).is_some()
            {
                regions.insert(label.to_owned(), index);
            }
        }
        regions
    }

    /// Write the chain headed by `stmts[at]` as one `if`, or record why it is not one; the regions
    /// it consumes leave `regions` and join `consumed`.
    fn chain_at(
        &mut self,
        stmts: &mut [CStmt],
        at: usize,
        regions: &mut Regions,
        consumed: &mut BTreeSet<usize>,
    ) {
        let Some(head) = test_block(&stmts[at], &*self.marks) else {
            return;
        };
        let explore = Explore {
            marks: &*self.marks,
            stmts,
            after: at,
            regions,
            nodes: Vec::new(),
            edges: Vec::new(),
            exits: Vec::new(),
            shared: BTreeMap::new(),
            removed: BTreeSet::new(),
        };
        let planned = match explore.run(&stmts[at]) {
            Ok(explored) if explored.nodes.len() < 2 => return,
            Ok(explored) => explored.plan(&self.references),
            Err(fault) => Err(fault),
        };
        match planned {
            Ok(plan) => {
                let written = self.write(plan.chain);
                // The gotos the old text held go with it; the new text's stay.
                count_gotos(&stmts[at], &mut self.references, -1);
                for removed in &plan.removed {
                    count_gotos(&stmts[*removed], &mut self.references, -1);
                }
                count_gotos(&written, &mut self.references, 1);
                stmts[at] = written;
                consume(stmts, plan.removed, regions, consumed);
                self.report.collapsed += 1;
            }
            Err(fault) => {
                r2il::refusal_evidence!("chain-refused", "{head:#x}: {fault}");
                self.report.refused.push((head, fault));
            }
        }
    }

    /// The `if` a chain is written as: every atom carries its block's marker, the head a copy of its own.
    fn write(&mut self, chain: Chain) -> CStmt {
        let Chain {
            tests,
            formula,
            taken,
            other,
        } = chain;
        let head_marks = tests[0].marks.clone();
        let marked: Vec<CExpr> = tests
            .into_iter()
            .enumerate()
            .map(|(node, test)| {
                // The head's own markers stay on its statement.
                let marks: Vec<_> = match node {
                    0 => test
                        .marks
                        .iter()
                        .map(|id| self.marks.copy_of(*id))
                        .collect(),
                    _ => test.marks,
                };
                CExpr::observe_all(marks, test.cond)
            })
            .collect();
        CStmt::observe_all(
            head_marks,
            CStmt::if_stmt(spell_expr(&formula, &marked), taken, Some(other)),
        )
    }
}

/// The test as an expression over the marked atoms, `a && b && c` grouped to the left.
fn spell_expr(formula: &Formula, atoms: &[CExpr]) -> CExpr {
    fn operands<'f>(formula: &'f Formula, and: bool, into: &mut Vec<&'f Formula>) {
        match formula {
            Formula::And(left, right) if and => {
                operands(left, and, into);
                operands(right, and, into);
            }
            Formula::Or(left, right) if !and => {
                operands(left, and, into);
                operands(right, and, into);
            }
            other => into.push(other),
        }
    }
    match formula {
        Formula::Atom { node, positive } => match positive {
            true => atoms[*node].clone(),
            false => CExpr::unary(UnaryOp::Not, atoms[*node].clone()),
        },
        Formula::And(..) | Formula::Or(..) => {
            let and = matches!(formula, Formula::And(..));
            let mut parts = Vec::new();
            operands(formula, and, &mut parts);
            let op = if and { BinaryOp::And } else { BinaryOp::Or };
            let mut parts = parts.into_iter().map(|part| spell_expr(part, atoms));
            let first = parts.next().expect("a connective has operands");
            parts.fold(first, |left, right| CExpr::binary(op, left, right))
        }
    }
}

/// A negated integer comparison over a marked atom (a chain's, a rotated loop's) reads as the
/// opposite comparison. After the final certificate, which reads the `!`; the table is tested whole.
pub(crate) fn respell_negations(stmt: &mut CStmt) {
    match stmt {
        CStmt::Observed { stmt, .. } => respell_negations(stmt),
        CStmt::Block(stmts) => stmts.iter_mut().for_each(respell_negations),
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            respell_test(cond);
            respell_negations(then_body);
            if let Some(else_body) = else_body {
                respell_negations(else_body);
            }
        }
        CStmt::While { cond, body } | CStmt::DoWhile { body, cond } => {
            respell_test(cond);
            respell_negations(body);
        }
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                respell_negations(init);
            }
            respell_negations(body);
        }
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                case.body.iter_mut().for_each(respell_negations);
            }
            if let Some(default) = default {
                default.iter_mut().for_each(respell_negations);
            }
        }
        _ => {}
    }
}

fn respell_test(test: &mut CExpr) {
    match test {
        CExpr::Observed { expr, .. } | CExpr::Paren(expr) => respell_test(expr),
        CExpr::Binary {
            op: BinaryOp::And | BinaryOp::Or,
            left,
            right,
        } => {
            respell_test(left);
            respell_test(right);
        }
        // Only a chain's negation, which is written over a marked atom; any other is the lowering's.
        CExpr::Unary {
            op: UnaryOp::Not,
            operand,
        } if matches!(**operand, CExpr::Observed { .. }) => {
            if opposite(operand) {
                let inner = std::mem::replace(&mut **operand, CExpr::IntLit(0));
                *test = inner;
            }
        }
        _ => {}
    }
}

/// Turn a comparison, through the markers and the cast to a flag, into its opposite. Whether it
/// was one; an expression that is not is left as it was.
fn opposite(expr: &mut CExpr) -> bool {
    match expr {
        CExpr::Observed { expr, .. } | CExpr::Paren(expr) => opposite(expr),
        CExpr::Cast { expr, .. } => opposite(expr),
        CExpr::Binary { op, .. } => {
            let flipped = match op {
                BinaryOp::Eq => BinaryOp::Ne,
                BinaryOp::Ne => BinaryOp::Eq,
                BinaryOp::Lt => BinaryOp::Ge,
                BinaryOp::Le => BinaryOp::Gt,
                BinaryOp::Gt => BinaryOp::Le,
                BinaryOp::Ge => BinaryOp::Lt,
                _ => return false,
            };
            *op = flipped;
            true
        }
        _ => false,
    }
}

/// The labelled regions of a sequence that hold one test and nothing else, by label.
type Regions = BTreeMap<String, usize>;

/// Take the regions at `removed` out of the index; their statements stay until the sequence ends.
fn consume(
    stmts: &[CStmt],
    removed: Vec<usize>,
    regions: &mut Regions,
    consumed: &mut BTreeSet<usize>,
) {
    for at in removed {
        if let Some((label, _)) = labelled_test(&stmts[at]) {
            regions.remove(label);
        }
        consumed.insert(at);
    }
}

/// A block that holds a label and one statement: the label, and the statement.
fn labelled_test(stmt: &CStmt) -> Option<(&str, &CStmt)> {
    match stmt {
        CStmt::Block(held) => match held.as_slice() {
            [CStmt::Label(label), test] => Some((label, test)),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
thread_local! {
    /// The statements read, in this thread, to find the regions of a sequence.
    static INDEXED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The block a marked `if` with both arms is the test of.
fn test_block(stmt: &CStmt, marks: &dyn Marks) -> Option<u64> {
    let CStmt::Observed { stmt: inner, .. } = stmt else {
        return None;
    };
    let CStmt::If {
        else_body: Some(_), ..
    } = &**inner
    else {
        return None;
    };
    single_block(&stmt.observation_ids(), &|id| marks.block_of(id))
}

/// One test of the chain: the block, its markers and its condition.
struct Test<'s> {
    block: u64,
    marks: Vec<RenderObservationId>,
    cond: &'s CExpr,
}

fn conditional<'s>(stmt: &'s CStmt, marks: &dyn Marks) -> Option<(Test<'s>, &'s CStmt, &'s CStmt)> {
    let block = test_block(stmt, marks)?;
    let CStmt::Observed { stmt: inner, .. } = stmt else {
        return None;
    };
    let CStmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = &**inner
    else {
        return None;
    };
    let marks = stmt.observation_ids().into_owned();
    Some((Test { block, marks, cond }, then_body, else_body))
}

/// The one statement an arm is, through blocks that hold only it.
fn sole(arm: &CStmt) -> &CStmt {
    match arm {
        CStmt::Block(stmts) if stmts.len() == 1 => sole(&stmts[0]),
        other => other,
    }
}

/// Where an exit's text comes from: a transfer bare enough to say twice, or a block of its own.
enum Exit<'s> {
    Goto(&'s str),
    Continue,
    /// A block nothing else reaches, with the edge's own text before it.
    Body(&'s CStmt),
}

impl Exit<'_> {
    /// Whether two edges leave the same way: bare transfers to one place. A block is never said twice.
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Goto(a), Self::Goto(b)) => a == b,
            (Self::Continue, Self::Continue) => true,
            _ => false,
        }
    }

    fn text(&self) -> CStmt {
        match self {
            Self::Goto(label) => CStmt::Goto((*label).to_owned()),
            Self::Continue => CStmt::Continue,
            Self::Body(arm) => (*arm).clone(),
        }
    }
}

/// A chain found in the tree, before any of it is changed.
struct Explore<'s> {
    marks: &'s dyn Marks,
    stmts: &'s [CStmt],
    after: usize,
    regions: &'s Regions,
    nodes: Vec<Test<'s>>,
    edges: Vec<(Edge, Edge)>,
    exits: Vec<Exit<'s>>,
    /// Per label of a region the chain consumes: its node, and how often the chain jumps there.
    shared: BTreeMap<&'s str, (usize, usize)>,
    removed: BTreeSet<usize>,
}

/// The chain as the text will hold it: the atoms in node order, the test, and the two arms.
struct Chain {
    tests: Vec<Atom>,
    formula: Formula,
    taken: CStmt,
    other: CStmt,
}

/// One atom of a chain to write.
struct Atom {
    marks: Vec<RenderObservationId>,
    cond: CExpr,
}

/// What rewriting the chain does.
struct Plan {
    chain: Chain,
    removed: Vec<usize>,
}

impl<'s> Explore<'s> {
    fn run(mut self, head: &'s CStmt) -> Result<Self, ChainFault> {
        self.test_at(head, None)?;
        Ok(self)
    }

    /// Add the test `stmt` is, and the tests and exits its arms lead to.
    fn test_at(&mut self, stmt: &'s CStmt, region: Option<usize>) -> Result<usize, ChainFault> {
        let Some((test, on_true, on_false)) = conditional(stmt, self.marks) else {
            return Err(ChainFault::Shape);
        };
        if self.nodes.len() >= MAX_ATOMS {
            return Err(ChainFault::TooManyAtoms);
        }
        if self.nodes.iter().any(|held| held.block == test.block) {
            return Err(ChainFault::Shape);
        }
        let index = self.nodes.len();
        self.nodes.push(test);
        self.edges.push((Edge::Exit(0), Edge::Exit(0)));
        if let Some(region) = region {
            self.removed.insert(region);
        }
        let on_true = self.edge(on_true)?;
        let on_false = self.edge(on_false)?;
        self.edges[index] = (on_true, on_false);
        Ok(index)
    }

    /// Where one arm of a test leads.
    fn edge(&mut self, arm: &'s CStmt) -> Result<Edge, ChainFault> {
        match sole(arm) {
            CStmt::Goto(label) => self.jump(label),
            CStmt::Continue => Ok(self.exit(Exit::Continue)),
            inner if test_block(inner, self.marks).is_some() => {
                Ok(Edge::Node(self.test_at(inner, None)?))
            }
            _ => {
                self.exits.push(Exit::Body(arm));
                Ok(Edge::Exit(self.exits.len() - 1))
            }
        }
    }

    /// Where a `goto` leads: the test of a region the chain consumes, or an exit.
    fn jump(&mut self, label: &'s str) -> Result<Edge, ChainFault> {
        if let Some(held) = self.shared.get_mut(label) {
            held.1 += 1;
            return Ok(Edge::Node(held.0));
        }
        let region = (self.regions.get(label).copied()).filter(|at| *at > self.after);
        let Some(index) = region else {
            return Ok(self.exit(Exit::Goto(label)));
        };
        let stmts = self.stmts;
        let Some((_, test)) = labelled_test(&stmts[index]) else {
            return Err(ChainFault::Shape);
        };
        let node = self.test_at(test, Some(index))?;
        self.shared.insert(label, (node, 1));
        Ok(Edge::Node(node))
    }

    fn exit(&mut self, exit: Exit<'s>) -> Edge {
        let at = self.exits.iter().position(|held| held.same(&exit));
        Edge::Exit(at.unwrap_or_else(|| {
            self.exits.push(exit);
            self.exits.len() - 1
        }))
    }

    /// The `if` the chain is written as, and the regions it consumes.
    fn plan(self, references: &BTreeMap<String, isize>) -> Result<Plan, ChainFault> {
        if self.exits.len() != 2 {
            return Err(ChainFault::ExitCount {
                found: self.exits.len(),
            });
        }
        // A region the chain consumes is entered by nothing but the chain.
        for (label, (node, jumps)) in &self.shared {
            if references.get(*label).copied() != Some(*jumps as isize) {
                return Err(ChainFault::Outside {
                    block: self.nodes[*node].block,
                });
            }
        }
        let dag = Dag {
            nodes: self.edges.clone(),
            exits: 2,
        };
        let body = (self.exits.iter()).position(|exit| matches!(exit, Exit::Body(_)));
        let (formula, taken) = spell(&dag, body)?;
        // The atoms in the order the test reads them, so the nodes of the formula are positions.
        let mut order = Vec::new();
        formula.atoms(&mut order);
        let mut renumbered = vec![0; order.len()];
        for (position, node) in order.iter().enumerate() {
            renumbered[*node] = position;
        }
        let tests = order
            .iter()
            .map(|node| Atom {
                marks: self.nodes[*node].marks.clone(),
                cond: self.nodes[*node].cond.clone(),
            })
            .collect();
        Ok(Plan {
            chain: Chain {
                tests,
                formula: formula.renumbered(&renumbered),
                taken: self.exits[taken].text(),
                other: self.exits[1 - taken].text(),
            },
            removed: self.removed.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::test_render_observation_id;
    use crate::symbol::SymbolId;

    /// The DAG of `a`, `b`, `c` as nodes 0, 1, 2 with exits X = 0 and Y = 1.
    fn dag(nodes: &[(Edge, Edge)]) -> Dag {
        Dag {
            nodes: nodes.to_vec(),
            exits: 2,
        }
    }

    const X: Edge = Edge::Exit(0);
    const Y: Edge = Edge::Exit(1);

    fn node(index: usize) -> Edge {
        Edge::Node(index)
    }

    /// `a ? (b ? X : Y) : Y`
    fn and_chain() -> Dag {
        dag(&[(node(1), Y), (X, Y)])
    }

    /// `(a || b) && c`: both of the first two reach `c`, which then decides.
    fn or_then_and() -> Dag {
        dag(&[(node(2), node(1)), (node(2), Y), (X, Y)])
    }

    /// `(a && b) || c`: `c` is the way on from both of the first two.
    fn and_then_or() -> Dag {
        dag(&[(node(1), node(2)), (X, node(2)), (X, Y)])
    }

    fn written(dag: &Dag) -> (String, usize) {
        let (formula, exit) = spell(dag, None).expect("it spells");
        (show(&formula), exit)
    }

    fn show(formula: &Formula) -> String {
        let name = |node: &usize| ["a", "b", "c", "d"][*node];
        match formula {
            Formula::Atom { node, positive } => match positive {
                true => name(node).to_owned(),
                false => format!("!{}", name(node)),
            },
            Formula::And(left, right) => format!("({} && {})", show(left), show(right)),
            Formula::Or(left, right) => format!("({} || {})", show(left), show(right)),
        }
    }

    #[test]
    fn a_nested_test_is_a_conjunction_and_a_shared_continuation_is_a_grouped_connective() {
        assert_eq!(written(&and_chain()), ("(a && b)".to_owned(), 0));
        assert_eq!(written(&or_then_and()), ("((a || b) && c)".to_owned(), 0));
        assert_eq!(written(&and_then_or()), ("((a && b) || c)".to_owned(), 0));
    }

    #[test]
    fn the_exit_with_fewer_negations_is_the_one_the_test_reaches() {
        // `a ? Y : (b ? Y : X)` reaches X by `!a && !b`, and Y by `a || b`.
        let reaches_y_unless_neither = dag(&[(Y, node(1)), (Y, X)]);
        assert_eq!(
            written(&reaches_y_unless_neither),
            ("(a || b)".to_owned(), 1)
        );
    }

    #[test]
    fn a_dag_no_read_once_test_spells_is_refused() {
        // `a ? (b ? X : Y) : (c ? X : Y)` is a selection between two tests, not a connective.
        let selection = dag(&[(node(1), node(2)), (X, Y), (X, Y)]);
        assert_eq!(spell(&selection, None), Err(ChainFault::NotShortCircuit));
    }

    #[test]
    fn a_test_whose_function_is_not_the_dags_is_different() {
        let wrong = Formula::atom(0, true).or(Formula::atom(1, true));
        assert_eq!(verify(&and_chain(), &wrong, 0), Err(ChainFault::Different));
        let right = Formula::atom(0, true).and(Formula::atom(1, true));
        assert_eq!(verify(&and_chain(), &right, 0), Ok(true));
        assert_eq!(verify(&and_chain(), &right, 1), Ok(false));
    }

    #[test]
    fn an_edge_against_the_evaluation_order_or_a_test_that_decides_nothing_is_refused() {
        // `b` is written first, but the DAG tests `a` before it.
        let backwards = Formula::atom(1, true).and(Formula::atom(0, true));
        assert_eq!(verify(&and_chain(), &backwards, 0), Err(ChainFault::Shape));
        // Written `a && b` over a DAG whose edge from `b` runs to `a`.
        let loops = dag(&[(node(1), Y), (node(0), X)]);
        let both = Formula::atom(0, true).and(Formula::atom(1, true));
        assert_eq!(verify(&loops, &both, 0), Err(ChainFault::Unordered));
        // `b` leads to the same exit on both edges: it decides nothing.
        let idle = dag(&[(node(1), Y), (X, X)]);
        assert_eq!(verify(&idle, &both, 0), Err(ChainFault::NotReduced));
    }

    #[test]
    fn a_chain_that_needs_more_nodes_than_the_budget_is_refused_whole() {
        let right = Formula::atom(0, true).and(Formula::atom(1, true));
        assert_eq!(
            verify_within(&and_chain(), &right, 0, 4),
            Err(ChainFault::NodeBudget)
        );
        assert_eq!(verify_within(&and_chain(), &right, 0, 5), Ok(true));
    }

    #[test]
    fn a_chain_of_three_exits_is_not_a_chain() {
        let three = Dag {
            nodes: vec![
                (Edge::Exit(0), Edge::Exit(1)),
                (Edge::Exit(2), Edge::Exit(0)),
            ],
            exits: 3,
        };
        let formula = Formula::atom(0, true);
        assert_eq!(
            verify(&three, &formula, 0),
            Err(ChainFault::ExitCount { found: 3 })
        );
    }

    // -- The rewrite over a placed tree.

    /// Markers whose block is their index, and copies numbered from 1000 on the block they copy.
    struct Fixture {
        copies: Vec<u64>,
    }

    impl Marks for Fixture {
        fn block_of(&self, id: RenderObservationId) -> Option<u64> {
            match id.index() as usize {
                index if index >= 1000 => self.copies.get(index - 1000).copied(),
                index => Some(index as u64),
            }
        }

        fn copy_of(&mut self, id: RenderObservationId) -> RenderObservationId {
            self.copies.push(self.block_of(id).expect("a marker"));
            test_render_observation_id(999 + self.copies.len() as u32)
        }
    }

    fn marker(block: u32, stmt: CStmt) -> CStmt {
        CStmt::observe_one(test_render_observation_id(block), stmt)
    }

    /// The condition of block `block`, which prints as its address.
    fn cond(block: i64) -> CExpr {
        CExpr::int(block)
    }

    /// A block's test, with `on_true` and `on_false` as its arms.
    fn test(block: u32, on_true: CStmt, on_false: CStmt) -> CStmt {
        marker(
            block,
            CStmt::if_stmt(cond(i64::from(block)), on_true, Some(on_false)),
        )
    }

    /// The region placement writes for a block that holds only its test.
    fn region(test: CStmt) -> CStmt {
        CStmt::Block(vec![test])
    }

    fn jump(label: &str) -> CStmt {
        CStmt::Goto(label.to_owned())
    }

    fn labelled(label: &str, test: CStmt) -> CStmt {
        CStmt::Block(vec![CStmt::Label(label.to_owned()), test])
    }

    /// A block of text nothing else reaches.
    fn body(block: u32) -> CStmt {
        CStmt::Block(vec![marker(
            block,
            CStmt::Expr(CExpr::int(i64::from(block))),
        )])
    }

    fn run(stmts: Vec<CStmt>) -> (Vec<CStmt>, Report, Fixture) {
        let mut marks = Fixture { copies: Vec::new() };
        let mut body = CStmt::Block(stmts);
        let report = collapse(&mut body, &mut marks);
        let CStmt::Block(stmts) = body else {
            unreachable!("a block stays a block")
        };
        (stmts, report, marks)
    }

    /// The test of the first statement as text, markers shown as `[block:...]`.
    fn text(e: &CExpr, marks: &Fixture) -> String {
        match e {
            CExpr::Observed { ids, expr } => {
                let blocks: Vec<_> = ids.iter().filter_map(|id| marks.block_of(id)).collect();
                format!("[{blocks:?}:{}]", text(expr, marks))
            }
            CExpr::IntLit(value) => format!("{value:#x}"),
            CExpr::Unary { operand, .. } => format!("!{}", text(operand, marks)),
            CExpr::Binary { op, left, right } => {
                let sign = if *op == BinaryOp::And { "&&" } else { "||" };
                format!("({} {sign} {})", text(left, marks), text(right, marks))
            }
            _ => "?".to_owned(),
        }
    }

    fn test_text(stmt: &CStmt, marks: &Fixture) -> String {
        match stmt.unobserved() {
            CStmt::If { cond, .. } => text(cond, marks),
            other => panic!("not an if: {other:?}"),
        }
    }

    #[test]
    fn nested_tests_with_a_shared_exit_are_one_conjunction() {
        // if (a) { if (b) { X } else goto L } else goto L; L: ...
        let stmts = vec![
            test(0x10, region(test(0x20, body(0x30), jump("L"))), jump("L")),
            CStmt::Block(vec![CStmt::Label("L".to_owned()), body(0x40)]),
        ];
        let (stmts, report, marks) = run(stmts);
        assert_eq!(report.collapsed, 1, "{:?}", report.refused);
        let CStmt::Observed { ids, stmt } = &stmts[0] else {
            panic!("the head stays a marked statement");
        };
        assert_eq!(ids.iter().map(|id| id.index()).collect::<Vec<_>>(), [0x10]);
        let CStmt::If {
            then_body,
            else_body,
            ..
        } = &**stmt
        else {
            panic!("an if");
        };
        // The head's atom carries a copy of its marker, and the second test its own.
        assert_eq!(test_text(&stmts[0], &marks), "([[16]:0x10] && [[32]:0x20])");
        assert_eq!(marks.copies, [0x10]);
        assert!(matches!(then_body.unobserved(), CStmt::Block(_)));
        assert!(matches!(else_body.as_deref(), Some(CStmt::Goto(label)) if label == "L"));
    }

    #[test]
    fn a_chain_whose_exits_are_both_jumps_is_written_with_the_fewer_negations() {
        // if (a) goto L1; else if (b) goto L1; else goto L2: `a || b` reaches L1 with none.
        let stmts = vec![
            test(0x10, jump("L1"), region(test(0x20, jump("L1"), jump("L2")))),
            CStmt::Block(vec![CStmt::Label("L1".to_owned()), body(0x40)]),
            CStmt::Block(vec![CStmt::Label("L2".to_owned()), body(0x50)]),
        ];
        let (stmts, report, marks) = run(stmts);
        assert_eq!(report.collapsed, 1, "{:?}", report.refused);
        assert_eq!(test_text(&stmts[0], &marks), "([[16]:0x10] || [[32]:0x20])");
        let CStmt::If { then_body, .. } = stmts[0].unobserved() else {
            panic!("an if");
        };
        assert!(matches!(&**then_body, CStmt::Goto(label) if label == "L1"));
    }

    #[test]
    fn a_shared_test_that_both_arms_reach_by_goto_is_consumed() {
        // (a || b) && c: if (a) goto C else if (b) goto C else goto Y; C: if (c) { X } else goto Y
        let stmts = vec![
            test(0x10, jump("C"), region(test(0x20, jump("C"), jump("Y")))),
            labelled("C", test(0x30, body(0x50), jump("Y"))),
            CStmt::Block(vec![CStmt::Label("Y".to_owned()), body(0x60)]),
        ];
        let (stmts, report, marks) = run(stmts);
        assert_eq!(report.collapsed, 1, "{:?}", report.refused);
        assert_eq!(stmts.len(), 2, "the shared region went with the chain");
        assert_eq!(
            test_text(&stmts[0], &marks),
            "(([[16]:0x10] || [[32]:0x20]) && [[48]:0x30])"
        );
    }

    #[test]
    fn a_test_with_other_reachers_is_not_consumed() {
        // The shared test C is also jumped to from elsewhere.
        let stmts = vec![
            test(0x10, jump("C"), region(test(0x20, jump("C"), jump("Y")))),
            labelled("C", test(0x30, body(0x50), jump("Y"))),
            CStmt::Block(vec![
                CStmt::Label("Y".to_owned()),
                body(0x60),
                CStmt::Goto("C".to_owned()),
            ]),
        ];
        let (stmts, report, _) = run(stmts);
        assert_eq!(report.collapsed, 0);
        assert_eq!(
            report.refused,
            [(0x10, ChainFault::Outside { block: 0x30 })]
        );
        assert_eq!(stmts.len(), 3, "nothing was written");
    }

    #[test]
    fn a_block_that_renders_text_is_no_member() {
        let chain = |inner: CStmt| {
            vec![
                test(0x10, region(inner), jump("L")),
                CStmt::Block(vec![CStmt::Label("L".to_owned()), body(0x40)]),
            ]
        };
        // The second block renders a statement before its test.
        let text = CStmt::Block(vec![
            marker(0x20, CStmt::Expr(CExpr::int(1))),
            test(0x20, body(0x30), jump("L")),
        ]);
        let (_, report, _) = run(chain(text));
        assert_eq!(report.collapsed, 0);
        assert!(
            report.refused.is_empty(),
            "no second test, so no chain to refuse"
        );
    }

    #[test]
    fn exits_that_carry_different_copies_are_different_exits() {
        // Both arms goto L, but the inner one first copies a merge variable.
        let copy = CStmt::Block(vec![CStmt::Expr(CExpr::int(7)), jump("L")]);
        let stmts = vec![
            test(0x10, region(test(0x20, body(0x30), copy)), jump("L")),
            CStmt::Block(vec![CStmt::Label("L".to_owned()), body(0x40)]),
        ];
        let (_, report, _) = run(stmts);
        assert_eq!(report.collapsed, 0);
        assert_eq!(report.refused, [(0x10, ChainFault::ExitCount { found: 3 })]);
    }

    #[test]
    fn a_selection_between_two_tests_is_refused_with_its_reason() {
        // if (a) { if (b) X else Y } else { if (c) X else Y } with X and Y bare transfers.
        let stmts = vec![test(
            0x10,
            region(test(0x20, jump("X"), jump("Y"))),
            region(test(0x30, jump("X"), jump("Y"))),
        )];
        let (_, report, _) = run(stmts);
        assert_eq!(report.collapsed, 0);
        assert_eq!(report.refused, [(0x10, ChainFault::NotShortCircuit)]);
    }

    #[test]
    fn a_negated_comparison_atom_reads_as_the_opposite_comparison_and_nothing_else_does() {
        let mut symbols = crate::symbol::SymbolTable::new();
        let x = CExpr::var(symbols.declare_or_reuse("x"));
        let compare = |op| CExpr::binary(op, x.clone(), CExpr::int(0));
        let cast = |expr: CExpr| CExpr::cast(crate::ast::CType::Bool, expr);
        let marked = |expr: CExpr| CExpr::observe_one(test_render_observation_id(0x20), expr);
        let not = |expr: CExpr| CExpr::unary(UnaryOp::Not, expr);
        // `!x == 0` over a marked atom is `x != 0`; the marker stays.
        let mut chain = CExpr::binary(
            BinaryOp::And,
            marked(cast(compare(BinaryOp::Lt))),
            not(marked(cast(compare(BinaryOp::Eq)))),
        );
        respell_test(&mut chain);
        let CExpr::Binary { right, .. } = &chain else {
            panic!("a conjunction");
        };
        let CExpr::Observed { expr, .. } = &**right else {
            panic!("the marker stays");
        };
        let CExpr::Cast { expr, .. } = &**expr else {
            panic!("the cast stays");
        };
        assert!(matches!(
            &**expr,
            CExpr::Binary {
                op: BinaryOp::Ne,
                ..
            }
        ));
        // A float comparison has no opposite, and the lowering's own negation is left alone.
        let mut float = not(marked(cast(compare(BinaryOp::FLt))));
        respell_test(&mut float);
        assert!(matches!(float, CExpr::Unary { .. }));
        let mut lowered = not(cast(compare(BinaryOp::Eq)));
        respell_test(&mut lowered);
        assert!(matches!(lowered, CExpr::Unary { .. }));
    }

    /// Whether `expr` holds with `a` and `b` bound to the integers `x` and `y`.
    fn truth(expr: &CExpr, (a, b): (SymbolId, SymbolId), (x, y): (i128, i128)) -> bool {
        let at = |side: &CExpr| match side.unobserved() {
            CExpr::Var(symbol) if *symbol == a => x,
            CExpr::Var(symbol) if *symbol == b => y,
            other => panic!("an operand: {other:?}"),
        };
        match expr {
            CExpr::Observed { expr, .. } | CExpr::Paren(expr) | CExpr::Cast { expr, .. } => {
                truth(expr, (a, b), (x, y))
            }
            CExpr::Unary {
                op: UnaryOp::Not,
                operand,
            } => !truth(operand, (a, b), (x, y)),
            CExpr::Binary { op, left, right } => {
                let (l, r) = (at(left), at(right));
                match op {
                    BinaryOp::Eq => l == r,
                    BinaryOp::Ne => l != r,
                    BinaryOp::Lt => l < r,
                    BinaryOp::Le => l <= r,
                    BinaryOp::Gt => l > r,
                    BinaryOp::Ge => l >= r,
                    other => panic!("not an integer comparison: {other:?}"),
                }
            }
            other => panic!("not a test: {other:?}"),
        }
    }

    /// The operand pairs a comparison is told apart on, at each width read signed and unsigned:
    /// every pair at 8 bits, the edges of the range (0, 1, the sign boundary, the maximum) wider.
    fn operand_grid() -> Vec<(u32, bool, (i128, i128))> {
        let widths = [8u32, 16, 32, 64];
        let readings = widths
            .into_iter()
            .flat_map(|bits| [(bits, false), (bits, true)]);
        let mut grid = Vec::new();
        for (bits, signed) in readings {
            let read = move |pattern: u128| match signed && pattern >> (bits - 1) == 1 {
                true => pattern as i128 - (1 << bits),
                false => pattern as i128,
            };
            let mask = (1u128 << bits) - 1;
            let sign = 1u128 << (bits - 1);
            let patterns: Vec<u128> = match bits {
                8 => (0..=mask).collect(),
                _ => vec![0, 1, 2, sign - 1, sign, sign + 1, mask - 1, mask],
            };
            let pairs = patterns
                .iter()
                .flat_map(|a| patterns.iter().map(|b| (*a, *b)));
            grid.extend(pairs.map(|(a, b)| (bits, signed, (read(a), read(b)))));
        }
        grid
    }

    /// The first operand pair on which `respelled` is not the exact negation of `original`.
    fn disagreement(
        original: &CExpr,
        respelled: &CExpr,
        vars: (SymbolId, SymbolId),
        grid: &[(u32, bool, (i128, i128))],
    ) -> Option<String> {
        grid.iter().find_map(|(bits, signed, pair)| {
            let negated = !truth(original, vars, *pair);
            (truth(respelled, vars, *pair) != negated)
                .then(|| format!("{pair:?} ({bits} bits, signed {signed})"))
        })
    }

    #[test]
    fn every_row_of_the_opposite_table_is_the_exact_negation() {
        let mut symbols = crate::symbol::SymbolTable::new();
        let (a, b) = (symbols.declare_or_reuse("a"), symbols.declare_or_reuse("b"));
        let marked = |expr: CExpr| CExpr::observe_one(test_render_observation_id(0x20), expr);
        let flag = |expr: CExpr| CExpr::cast(crate::ast::CType::Bool, expr);
        let not = |expr: CExpr| CExpr::unary(UnaryOp::Not, expr);
        let grid = operand_grid();
        for op in [
            BinaryOp::Eq,
            BinaryOp::Ne,
            BinaryOp::Lt,
            BinaryOp::Le,
            BinaryOp::Gt,
            BinaryOp::Ge,
        ] {
            let compare = || CExpr::binary(op, CExpr::var(a), CExpr::var(b));
            // The shapes a chain's atom and a rotated loop's test take: bare, through the flag cast,
            // and through the parentheses the printer may add.
            for atom in [
                compare(),
                flag(compare()),
                CExpr::Paren(Box::new(flag(compare()))),
            ] {
                let mut respelled = not(marked(atom.clone()));
                respell_test(&mut respelled);
                assert!(
                    !matches!(respelled, CExpr::Unary { .. }),
                    "{op:?} is respelled: {respelled:?}"
                );
                let wrong = disagreement(&atom, &respelled, (a, b), &grid);
                assert_eq!(wrong, None, "{op:?}: the respelling is not the negation");
            }
        }
        // A float comparison is false on a NaN, so its negation is no comparison and stays a `!`.
        for op in [BinaryOp::FLt, BinaryOp::FLe, BinaryOp::FGt, BinaryOp::FGe] {
            let mut kept = not(marked(CExpr::binary(op, CExpr::var(a), CExpr::var(b))));
            respell_test(&mut kept);
            assert!(matches!(kept, CExpr::Unary { .. }), "{op:?}: {kept:?}");
        }
    }

    /// The statements read to find regions while `collapse` writes `chains` sibling chains, each with
    /// a tail of its own, so that none of them removes a statement.
    fn indexed_for(chains: u32) -> usize {
        let mut stmts = Vec::new();
        for chain in 0..chains {
            let (head, second, taken, tail) =
                (4 * chain + 1, 4 * chain + 2, 4 * chain + 3, 4 * chain + 4);
            let label = format!("L{chain}");
            stmts.push(test(
                head,
                region(test(second, body(taken), jump(&label))),
                jump(&label),
            ));
            stmts.push(CStmt::Block(vec![CStmt::Label(label), body(tail)]));
        }
        let before = INDEXED.with(std::cell::Cell::get);
        let (_, report, _) = run(stmts);
        assert_eq!(report.collapsed, chains as usize, "{:?}", report.refused);
        INDEXED.with(std::cell::Cell::get) - before
    }

    #[test]
    fn the_regions_of_a_sequence_are_indexed_once_however_many_chains_it_holds() {
        // Doubling the chains at most doubles the statements read; re-indexing after each chain
        // would quadruple them.
        let (few, many) = (indexed_for(100), indexed_for(200));
        assert!(
            many <= 2 * few,
            "{few} statements read for 100 chains, {many} for 200"
        );
    }

    #[test]
    fn a_chain_that_consumes_a_region_leaves_the_regions_after_it_where_they_are() {
        // Three heads in a row, each with the shared test it jumps to after it: (a || b) && c.
        let chain = |head: u32, label: &'static str| {
            [
                test(
                    head,
                    jump(label),
                    region(test(head + 1, jump(label), jump("Y"))),
                ),
                labelled(label, test(head + 2, body(head + 3), jump("Y"))),
            ]
        };
        let mut stmts = Vec::new();
        for (head, label) in [(0x10, "C1"), (0x20, "C2"), (0x30, "C3")] {
            stmts.extend(chain(head, label));
        }
        stmts.push(CStmt::Block(vec![CStmt::Label("Y".to_owned()), body(0x60)]));
        let (stmts, report, marks) = run(stmts);
        assert_eq!(report.collapsed, 3, "{:?}", report.refused);
        assert_eq!(
            stmts.len(),
            4,
            "the three shared tests went with their chains"
        );
        for (at, head) in [(0, 0x10), (1, 0x20), (2, 0x30)] {
            let expected = format!(
                "(([[{a}]:{a:#x}] || [[{b}]:{b:#x}]) && [[{c}]:{c:#x}])",
                a = head,
                b = head + 1,
                c = head + 2
            );
            assert_eq!(test_text(&stmts[at], &marks), expected);
        }
        assert!(
            matches!(&stmts[3], CStmt::Block(held) if matches!(&held[0], CStmt::Label(y) if y == "Y"))
        );
    }

    #[test]
    fn a_consumed_region_is_not_read_for_chains_of_its_own() {
        // The shared test holds a nested test, so its text would be a chain again if it were read.
        let stmts = vec![
            test(0x10, jump("C"), region(test(0x20, jump("C"), jump("Y")))),
            labelled(
                "C",
                test(0x30, region(test(0x40, body(0x50), jump("Y"))), jump("Y")),
            ),
            CStmt::Block(vec![CStmt::Label("Y".to_owned()), body(0x60)]),
        ];
        let (stmts, report, marks) = run(stmts);
        assert_eq!(report.collapsed, 1, "{:?}", report.refused);
        assert_eq!(report.refused, []);
        assert_eq!(stmts.len(), 2);
        assert_eq!(
            test_text(&stmts[0], &marks),
            "((([[16]:0x10] || [[32]:0x20]) && [[48]:0x30]) && [[64]:0x40])"
        );
    }

    #[test]
    fn a_chain_is_written_wherever_it_sits_in_the_tree() {
        // The chain is the else arm of an outer test, which is not part of it.
        let inner = region(test(
            0x20,
            region(test(0x30, body(0x40), jump("L"))),
            jump("L"),
        ));
        let stmts = vec![
            test(0x10, body(0x50), inner),
            CStmt::Block(vec![CStmt::Label("L".to_owned()), body(0x60)]),
        ];
        let (stmts, report, marks) = run(stmts);
        assert_eq!(report.collapsed, 1, "{:?}", report.refused);
        let CStmt::If { else_body, .. } = stmts[0].unobserved() else {
            panic!("the outer test stays");
        };
        let CStmt::Block(arm) = else_body.as_deref().expect("an else") else {
            panic!("a block arm");
        };
        assert_eq!(test_text(&arm[0], &marks), "([[32]:0x20] && [[48]:0x30])");
    }
}
