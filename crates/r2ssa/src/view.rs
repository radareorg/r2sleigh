//! Which values carry the same bits: one fact, computed once.
//!
//! Every value is described relative to a root it was read from:
//! `view(v) = (root, prefix_bits, extension)` states that the low
//! `prefix_bits` bits of `v` are the low `prefix_bits` bits of `root`, and
//! `extension` says what the bits of `v` above the prefix are -- none
//! (`Exact`: the prefix is the whole value), zero, copies of the prefix's top
//! bit, or nothing stated.
//!
//! The invariant this owns is the one identity rests on: *two values are the
//! same bits only when their bits are equal at their full width*. An
//! extension, a lane at a non-zero offset, and a truncation followed by an
//! extension are never the value they came from. Earlier the canonical-root
//! map gave `SUBPIECE(x, 8)` the root of `x`'s low lane (and for a literal its
//! low bytes), and the stack-reload certificate treated every unary operation
//! as preserving its operand; together they bound the sign word of a
//! `cqo` to the parameter it was computed from. The view is exact for the
//! operations below and gives every other value its own root, so the only
//! claims it makes are the ones the operations prove:
//!
//! | operation | view of the output |
//! |---|---|
//! | copy, same-width cast, same-width call restore | the input's |
//! | `SUBPIECE(x, 0)` to `w` bits | `x`'s, its prefix cut to `w` |
//! | `ZEXT(x)` | `x`'s prefix, zero above it (where `x` stated zero or nothing above) |
//! | `SEXT(x)` | `x`'s prefix, sign above it (zero where `x` stated zero) |
//! | `INSERT(_, x, 0)`, `PIECE(_, x)` | `x`'s prefix, nothing stated above |
//! | `INSERT(w, x, k)`, `x` the bits of `y` at `k` | `w`'s prefix grown past `x` where `w` and `y` share a root and cover `k` |
//! | any other `INSERT(w, x, k > 0)` | `w`'s prefix cut to `k`, nothing stated above |
//! | a phi | the common view of its inputs, else its own |
//! | anything else, `SUBPIECE(x, k > 0)` included | its own |
//!
//! A constant lane `SUBPIECE(c, k)` is therefore never read off the root: the
//! constant folder computes it as `(c >> 8k) & mask`, and until it has, the
//! lane is its own value.
//!
//! The views are an index over dense ids: a function's [`VarId`]s, for the
//! passes that run before it is sealed, or a sealed graph's [`ValueId`]s,
//! which is what the prep facts and every later stage hold. Each id's width
//! and constant bits are kept beside the views, so a question about an id
//! reads no name.
//!
//! **Cost.** One pass over the operations builds the definitions, Tarjan's
//! algorithm orders the values that read another's view by strongly connected
//! component in `O(V + E)`, and each component is evaluated after every
//! component it reads. A component with no cycle is one transfer per value.
//! A cycle (loop-carried copies through phis) is evaluated optimistically, the
//! way SCCP evaluates constants: a phi starts unvisited, takes the view its
//! known inputs agree on, and falls to its own root the first time two of
//! them disagree. A phi falls at most once and every other value only follows
//! its input, so the component settles after at most one pass per fallen phi
//! plus one -- the lattice `{unvisited, view, own}` has height two, which is
//! the whole termination argument, and no pass is counted. Every lookup after
//! the solve is `O(1)`.

use std::collections::HashMap;

use crate::dense::{DenseId, IdMap, IdVec};
use crate::function::SSAFunction;
use crate::graph::{SsaGraph, ValueId};
use crate::op::{SSAOp, var_facts};
use crate::value_table::VarId;
use crate::var::SSAVar;

/// What the bits of a value above its view's prefix are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ViewExtension {
    /// There are none: the prefix is the whole value.
    Exact,
    /// Every bit above the prefix is zero.
    Zero,
    /// Every bit above the prefix repeats the prefix's top bit.
    Sign,
    /// Nothing is stated about the bits above the prefix.
    Unknown,
}

/// A value's bits, stated relative to the root they were read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueView<I> {
    /// The value whose low bits these are.
    pub root: I,
    /// How many of the low bits are the root's.
    pub prefix_bits: u32,
    /// What the bits above the prefix are.
    pub extension: ViewExtension,
}

impl<I> ValueView<I> {
    /// Whether this view states the value's every bit from its root's low
    /// `prefix_bits`: nothing above the prefix is left unstated.
    pub fn determines_value(&self) -> bool {
        self.extension != ViewExtension::Unknown
    }
}

/// How a value derived from another relates to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ViewRelation {
    /// The same bits at the same width.
    Identity,
    /// Computed from it, but not the same bits.
    Derived,
}

/// The one name every value with the same bits at the same width is given:
/// a value of the function, or the literal a constant root determines, which
/// need not be a value the function holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Representative<I> {
    Value(I),
    Literal { bits: u64, size: u32 },
}

impl<I: Copy> Representative<I> {
    /// The representative, where it is a value of the function.
    pub fn value(self) -> Option<I> {
        match self {
            Self::Value(id) => Some(id),
            Self::Literal { .. } => None,
        }
    }
}

/// An id's width in bytes and, for a constant, its bits.
type Facts = (u32, Option<u64>);

/// The view of every value of one function, and each value's representative.
///
/// A value is recorded only where its view is not its own. The representative
/// is the one value every value with the same bits at the same width is
/// named by: the root itself when the value is the root's whole width, the
/// literal a constant root determines, and otherwise the first value of the
/// class in definition order. A value whose view leaves bits unstated is its
/// own representative.
#[derive(Debug, Clone)]
pub struct ValueViews<I> {
    views: IdMap<I, ValueView<I>>,
    representatives: IdMap<I, Representative<I>>,
    low_lanes: LowLanes<I>,
    facts: IdVec<I, Facts>,
}

/// By root, each width at which a value is exactly the root's low bits, and the first such value.
type LowLanes<I> = IdMap<I, Vec<(u32, I)>>;

impl<I: DenseId> PartialEq for ValueViews<I> {
    fn eq(&self, other: &Self) -> bool {
        // The low lanes are read off the views and representatives.
        self.views == other.views
            && self.representatives == other.representatives
            && self.facts == other.facts
    }
}

impl<I: DenseId> Eq for ValueViews<I> {}

impl<I: DenseId> Default for ValueViews<I> {
    fn default() -> Self {
        Self {
            views: IdMap::new(0),
            representatives: IdMap::new(0),
            low_lanes: IdMap::new(0),
            facts: IdVec::from_fn(0, |_| (0, None)),
        }
    }
}

impl ValueViews<VarId> {
    /// The view of every variable `function` defines, over its own ids: for
    /// the passes that rewrite it before it is sealed.
    pub(crate) fn compute(function: &SSAFunction) -> Self {
        let table = function.values();
        let facts = IdVec::from_fn(table.len(), |id| var_facts(table.var(id)));
        let mut nodes = Vec::new();
        let mut definitions = Vec::new();
        // The entry lanes first: they are the caller's values, in hand
        // before the body defines anything, so they come first in definition
        // order as the representative of their class. A lane no operation
        // names is no value of the function, and names none.
        for (lane, root) in function.entry_lanes() {
            nodes.push(lane);
            definitions.push(Definition::Step(root, lane_step(&facts, lane, root)));
        }
        let mut offsets = IdMap::new(facts.len());
        for block in function.blocks() {
            for phi in block.phis() {
                nodes.push(phi.dst);
                definitions.push(Definition::Phi(
                    phi.sources.iter().map(|(_, source)| *source).collect(),
                ));
            }
            for op in block.ops() {
                record_offset(op, |id| facts[*id], &mut offsets);
            }
            for (dst, definition) in block
                .ops()
                .iter()
                .filter_map(|op| definition_of(op, |id| facts[*id]))
            {
                nodes.push(dst);
                definitions.push(definition);
            }
        }
        Solver::over(nodes, definitions, facts, offsets).solve()
    }
}

impl ValueViews<ValueId> {
    /// The same fact over a graph's values: what the prep facts hold, and
    /// what every pass that reads the graph asks, by the same rules.
    pub(crate) fn of_graph(graph: &SsaGraph) -> Self {
        let facts = IdVec::from_fn(graph.values.len(), |id: ValueId| {
            var_facts(&graph.values[id.0 as usize].var)
        });
        let mut nodes = Vec::new();
        let mut definitions = Vec::new();
        // The entry lanes first, as over a function.
        for (lane, root) in &graph.entry_lanes {
            if let (Some(lane), Some(root)) =
                (graph.value_id_for_var(lane), graph.value_id_for_var(root))
            {
                nodes.push(lane);
                definitions.push(Definition::Step(root, lane_step(&facts, lane, root)));
            }
        }
        let mut offsets = IdMap::new(facts.len());
        for inst in &graph.insts {
            if let crate::graph::InstPayload::Op(op) = &inst.payload {
                record_offset(op, |id| facts[*id], &mut offsets);
            }
            if let Some((dst, definition)) = graph_definition(&facts, inst) {
                nodes.push(dst);
                definitions.push(definition);
            }
        }
        Solver::over(nodes, definitions, facts, offsets).solve()
    }
}

impl<I: DenseId + std::hash::Hash> ValueViews<I> {
    /// An id's width in bits.
    fn bits(&self, id: I) -> u32 {
        self.facts
            .get(id)
            .map_or(0, |(size, _)| size.saturating_mul(8))
    }

    /// An id's width in bytes.
    pub fn size(&self, id: I) -> u32 {
        self.facts.get(id).map_or(0, |(size, _)| *size)
    }

    /// The bits of a constant id.
    pub fn constant(&self, id: I) -> Option<u64> {
        self.facts.get(id).and_then(|(_, bits)| *bits)
    }

    /// The view of `id`: its own where nothing derives it.
    pub fn view(&self, id: I) -> ValueView<I> {
        self.views.get(id).copied().unwrap_or(ValueView {
            root: id,
            prefix_bits: self.bits(id),
            extension: ViewExtension::Exact,
        })
    }

    /// The recorded view of `id`, where it is not its own.
    pub fn derived_view(&self, id: I) -> Option<&ValueView<I>> {
        self.views.get(id)
    }

    /// The representative every value with `id`'s bits at `id`'s width is
    /// named by.
    pub fn representative(&self, id: I) -> Representative<I> {
        self.representatives
            .get(id)
            .copied()
            .unwrap_or(Representative::Value(id))
    }

    /// The representative of `id`, where it is not `id` itself.
    pub fn representative_of(&self, id: I) -> Option<Representative<I>> {
        self.representatives.get(id).copied()
    }

    /// The representative of `id` where it is a value -- `id` itself when
    /// it has none -- and `None` where it is a literal no value holds.
    pub fn representative_value(&self, id: I) -> Option<I> {
        self.representative(id).value()
    }

    /// The constant bits `id`'s representative is, where it is a literal or
    /// a constant value.
    pub fn representative_constant(&self, id: I) -> Option<(u64, u32)> {
        match self.representative(id) {
            Representative::Literal { bits, size } => Some((bits, size)),
            Representative::Value(value) => Some((self.constant(value)?, self.size(value))),
        }
    }

    /// The value that is exactly `root`'s low `bits`: the root at its own width, else the first
    /// value of that class in definition order.
    pub fn low_lane_value(&self, root: I, bits: u32) -> Option<I> {
        if self.bits(root) == bits {
            return Some(root);
        }
        self.low_lanes
            .get(root)?
            .iter()
            .find(|(width, _)| *width == bits)
            .map(|(_, value)| *value)
    }

    /// Whether `a` and `b` are the same bits at the same width.
    pub fn same_bits(&self, a: I, b: I) -> bool {
        if a == b {
            return true;
        }
        if self.size(a) != self.size(b) {
            return false;
        }
        let (left, right) = (self.view(a), self.view(b));
        left == right && left.determines_value()
    }

    /// How `derived`, a value computed from `source`, relates to it: the same
    /// bits, or something else computed from them.
    pub fn relation(&self, derived: I, source: I) -> ViewRelation {
        if self.same_bits(derived, source) {
            ViewRelation::Identity
        } else {
            ViewRelation::Derived
        }
    }

    /// The value `id` is a copy of: its root, where `id` carries every bit
    /// of the root and nothing else, at the root's own width; otherwise `id`.
    ///
    /// Unlike the representative, which may be any member of a class, the
    /// root dominates every value it is the copy root of: each transparent
    /// step reads an operand, which dominates the step, and a phi takes a
    /// root only when every input already has it, so the root dominates every
    /// predecessor and so the phi. A pass that rewrites the graph may name it
    /// in their place.
    pub fn copy_root(&self, id: I) -> I {
        match self.views.get(id) {
            Some(view)
                if view.extension == ViewExtension::Exact
                    && view.prefix_bits == self.bits(id)
                    && self.bits(view.root) == self.bits(id) =>
            {
                view.root
            }
            _ => id,
        }
    }

    /// The value `id` equals as an unsigned integer: its root, where `id`
    /// holds the root's whole width with zeros above; otherwise `id`.
    ///
    /// This is the chain of copies and zero extensions a literal or an
    /// address is read through: a zero-extended pointer is still the pointer,
    /// and a truncated or sign-extended one is not.
    pub fn same_integer_root(&self, id: I) -> I {
        match self.views.get(id) {
            Some(view)
                if view.prefix_bits == self.bits(view.root)
                    && matches!(view.extension, ViewExtension::Exact | ViewExtension::Zero) =>
            {
                view.root
            }
            _ => id,
        }
    }
}

/// Every graph value's copy-class value, indexed by value: one `O(V)` table
/// for the passes that ask per value. A class whose representative is a
/// literal the graph holds is named by that value; a literal it does not
/// hold names no value, and the value names itself.
pub(crate) fn class_values(graph: &SsaGraph, views: Option<&ValueViews<ValueId>>) -> Vec<ValueId> {
    graph
        .values
        .iter()
        .map(|value| class_value(graph, views, value.id))
        .collect()
}

/// The graph value naming `value`'s copy class -- the values with its bits
/// at its width: the representative where the graph holds it, else `value`.
pub(crate) fn class_value(
    graph: &SsaGraph,
    views: Option<&ValueViews<ValueId>>,
    value: ValueId,
) -> ValueId {
    let Some(views) = views else {
        return value;
    };
    match views.representative(value) {
        Representative::Value(representative) => representative,
        Representative::Literal { bits, size } => graph
            .value_id_for_var(&SSAVar::constant(bits, size))
            .unwrap_or(value),
    }
}

/// `value`'s class, normalized so that two values with the same bits at the
/// same width compare equal: a literal the graph holds is that value, and a
/// literal it does not hold stays a literal.
pub(crate) fn class_key(
    graph: &SsaGraph,
    views: &ValueViews<ValueId>,
    value: ValueId,
) -> Representative<ValueId> {
    match views.representative(value) {
        Representative::Literal { bits, size } => graph
            .value_id_for_var(&SSAVar::constant(bits, size))
            .map_or(
                Representative::Literal { bits, size },
                Representative::Value,
            ),
        held => held,
    }
}

/// A view in its canonical form: a prefix no wider than the value or the
/// root, `Exact` exactly when the prefix is the whole value, and no view at
/// all where no bit is the root's.
fn normalized<I>(
    root: I,
    root_bits: u32,
    prefix: u32,
    extension: ViewExtension,
    width: u32,
) -> Option<ValueView<I>> {
    let prefix = prefix.min(width).min(root_bits);
    if prefix == 0 {
        return None;
    }
    let extension = if prefix == width {
        ViewExtension::Exact
    } else if extension == ViewExtension::Exact {
        // A prefix shorter than the value with nothing stated above it.
        ViewExtension::Unknown
    } else {
        extension
    };
    Some(ValueView {
        root,
        prefix_bits: prefix,
        extension,
    })
}

/// How an operation's output reads its one transparent input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The same bits.
    Copy,
    /// The low bits, at the output's narrower width.
    Low,
    /// Zero extension.
    ZeroExtend,
    /// Sign extension.
    SignExtend,
    /// The input is the output's low bits; nothing is stated above it.
    LowLane,
}

/// How an entry-lane formal reads its root: the root's low bits, as a
/// `Subpiece` at offset zero would. Nothing defines the formal -- it is the
/// caller's value -- but its bits are the root's.
fn lane_step<I: DenseId>(facts: &IdVec<I, Facts>, lane: I, root: I) -> Step {
    match facts[lane].0 == facts[root].0 {
        true => Step::Copy,
        false => Step::Low,
    }
}

/// What an operation's output is made of, where the view can say.
///
/// `facts` says an operand's width and, for a constant, its bits: read off
/// the operand itself in a function's operations, off the graph's value in
/// the graph's.
fn step_of<V>(op: &SSAOp<V>, facts: impl Fn(&V) -> (u32, Option<u64>)) -> Option<(&V, &V, Step)> {
    let size = |operand: &V| facts(operand).0;
    let same_width = |dst: &V, src: &V| size(dst) == size(src);
    match op {
        SSAOp::Copy { dst, src } | SSAOp::Cast { dst, src } | SSAOp::CallRestore { dst, src }
            if same_width(dst, src) =>
        {
            Some((dst, src, Step::Copy))
        }
        SSAOp::Subpiece {
            dst,
            src,
            offset: 0,
        } if size(dst) == size(src) => Some((dst, src, Step::Copy)),
        SSAOp::Subpiece {
            dst,
            src,
            offset: 0,
        } if size(dst) < size(src) => Some((dst, src, Step::Low)),
        SSAOp::IntZExt { dst, src } if size(dst) >= size(src) => Some((
            dst,
            src,
            if same_width(dst, src) {
                Step::Copy
            } else {
                Step::ZeroExtend
            },
        )),
        SSAOp::IntSExt { dst, src } if size(dst) >= size(src) => Some((
            dst,
            src,
            if same_width(dst, src) {
                Step::Copy
            } else {
                Step::SignExtend
            },
        )),
        SSAOp::Insert(insert)
            if facts(&insert.position).1 == Some(0) && size(&insert.value) <= size(&insert.dst) =>
        {
            Some((
                &insert.dst,
                &insert.value,
                if same_width(&insert.dst, &insert.value) {
                    Step::Copy
                } else {
                    Step::LowLane
                },
            ))
        }
        SSAOp::Piece { dst, lo, .. } if size(lo) < size(dst) => Some((dst, lo, Step::LowLane)),
        _ => None,
    }
}

/// Whether an operation's output is its first operand's unsigned value: a
/// copy or a zero extension.
///
/// The same rule the view applies, for the walks that read a value through
/// its definitions rather than through the solved view -- the constant
/// folder's, over a graph no preparation has run on.
pub(crate) fn preserves_integer<V>(
    op: &SSAOp<V>,
    facts: impl Fn(&V) -> (u32, Option<u64>),
) -> bool {
    !matches!(op, SSAOp::Insert(_) | SSAOp::Piece { .. })
        && matches!(
            step_of(op, facts),
            Some((_, _, Step::Copy | Step::ZeroExtend))
        )
}

/// How an operation defines its output for the solver: one transparent input,
/// or a lane inserted at a constant position above the low bits.
fn definition_of<I: Copy>(
    op: &SSAOp<I>,
    facts: impl Fn(&I) -> Facts,
) -> Option<(I, Definition<I>)> {
    if let Some((dst, src, step)) = step_of(op, &facts) {
        return Some((*dst, Definition::Step(*src, step)));
    }
    let SSAOp::Insert(insert) = op else {
        return None;
    };
    let lsb_bits = u32::try_from(facts(&insert.position).1?)
        .ok()
        .filter(|bits| *bits > 0)?;
    let end = lsb_bits.checked_add(facts(&insert.value).0.saturating_mul(8))?;
    (end <= facts(&insert.dst).0.saturating_mul(8)).then_some((
        insert.dst,
        Definition::Insert {
            base: insert.src,
            lane: insert.value,
            lsb_bits,
        },
    ))
}

/// Which bits of which value a lane is: `SUBPIECE(y, k)` at `k > 0` is `y`'s
/// bits from `8k`, and a same-width copy of a lane is that lane.
fn record_offset<I: DenseId>(
    op: &SSAOp<I>,
    facts: impl Fn(&I) -> Facts,
    offsets: &mut IdMap<I, (I, u32)>,
) {
    let found = match op {
        SSAOp::Subpiece { dst, src, offset } if *offset > 0 => {
            Some((*dst, (*src, offset.saturating_mul(8))))
        }
        SSAOp::Copy { dst, src } if facts(dst).0 == facts(src).0 => {
            offsets.get(*src).map(|lane| (*dst, *lane))
        }
        _ => None,
    };
    if let Some((lane, source)) = found {
        offsets.insert(lane, source);
    }
}

/// The view of an output, given its input's view.
fn transfer<I: DenseId>(
    facts: &IdVec<I, Facts>,
    step: Step,
    input: &ValueView<I>,
    output: I,
) -> Option<ValueView<I>> {
    let width = facts[output].0.saturating_mul(8);
    let ValueView {
        root,
        prefix_bits: prefix,
        extension,
    } = *input;
    let root_bits = facts[root].0.saturating_mul(8);
    match step {
        Step::Copy => Some(*input),
        // A narrower read keeps the prefix it still covers, and above that
        // whatever the input stated up to its own width.
        Step::Low => normalized(root, root_bits, prefix, extension, width),
        Step::ZeroExtend => {
            let above = match extension {
                ViewExtension::Exact | ViewExtension::Zero => ViewExtension::Zero,
                // Sign copies up to the input's width and zeros past it is
                // neither; the prefix still holds.
                ViewExtension::Sign | ViewExtension::Unknown => ViewExtension::Unknown,
            };
            normalized(root, root_bits, prefix, above, width)
        }
        Step::SignExtend => {
            let above = match extension {
                ViewExtension::Exact | ViewExtension::Sign => ViewExtension::Sign,
                // The input's top bit is one of the zeros above its prefix,
                // so the extension copies a zero.
                ViewExtension::Zero => ViewExtension::Zero,
                ViewExtension::Unknown => ViewExtension::Unknown,
            };
            normalized(root, root_bits, prefix, above, width)
        }
        Step::LowLane => normalized(root, root_bits, prefix, ViewExtension::Unknown, width),
    }
}

/// How a value is defined, for the solver.
enum Definition<I> {
    Phi(Vec<I>),
    Step(I, Step),
    /// `INSERT(base, lane, lsb_bits)` with `lsb_bits > 0`.
    Insert {
        base: I,
        lane: I,
        lsb_bits: u32,
    },
}

struct Solver<I> {
    /// Every value the view can derive, in definition order.
    nodes: Vec<I>,
    definitions: Vec<Definition<I>>,
    index: IdMap<I, usize>,
    facts: IdVec<I, Facts>,
    /// Each lane read from another value above its low bits: that value, and the bit it starts at.
    offsets: IdMap<I, (I, u32)>,
}

impl<I: DenseId + std::hash::Hash> Solver<I> {
    fn over(
        nodes: Vec<I>,
        definitions: Vec<Definition<I>>,
        facts: IdVec<I, Facts>,
        offsets: IdMap<I, (I, u32)>,
    ) -> Self {
        let mut index = IdMap::new(facts.len());
        for (at, node) in nodes.iter().enumerate() {
            index.insert(*node, at);
        }
        Self {
            nodes,
            definitions,
            index,
            facts,
            offsets,
        }
    }

    /// A value's own view: its every bit, its own root.
    fn own(&self, id: I) -> ValueView<I> {
        ValueView {
            root: id,
            prefix_bits: self.facts[id].0.saturating_mul(8),
            extension: ViewExtension::Exact,
        }
    }

    fn inputs(&self, node: usize) -> Vec<usize> {
        match &self.definitions[node] {
            Definition::Phi(sources) => sources
                .iter()
                .filter_map(|source| self.index.get(*source).copied())
                .collect(),
            Definition::Step(source, _) => self.index.get(*source).copied().into_iter().collect(),
            Definition::Insert { base, lane, .. } => [
                Some(*base),
                self.offsets.get(*lane).map(|(source, _)| *source),
            ]
            .into_iter()
            .flatten()
            .filter_map(|input| self.index.get(input).copied())
            .collect(),
        }
    }

    fn solve(self) -> ValueViews<I> {
        let count = self.nodes.len();
        let mut work = Work {
            state: vec![None; count],
            fallen: vec![false; count],
            queued: vec![false; count],
            pending: Vec::new(),
        };
        let successors = (0..count).map(|node| self.inputs(node)).collect::<Vec<_>>();
        let components = strongly_connected_components(&successors);
        let mut component_of = vec![usize::MAX; count];
        for (id, member) in components
            .iter()
            .enumerate()
            .flat_map(|(id, component)| component.iter().map(move |member| (id, *member)))
        {
            component_of[member] = id;
        }
        // Readers inside the same component, to re-evaluate when a view moves.
        let mut readers = vec![Vec::new(); count];
        for (node, input) in successors
            .iter()
            .enumerate()
            .flat_map(|(node, inputs)| inputs.iter().map(move |input| (node, *input)))
            .filter(|(node, input)| component_of[*input] == component_of[*node])
        {
            readers[input].push(node);
        }
        for component in &components {
            self.settle(component, &readers, &mut work);
        }

        let mut views = IdMap::new(self.facts.len());
        for (node, view) in work.state.into_iter().enumerate() {
            let id = self.nodes[node];
            if let Some(view) = view.filter(|view| view.root != id) {
                views.insert(id, view);
            }
        }
        let (representatives, low_lanes) = representatives(&self.nodes, &views, &self.facts);
        ValueViews {
            views,
            representatives,
            low_lanes,
            facts: self.facts,
        }
    }

    /// Evaluate one component to its fixed point. Every component it reads
    /// is settled already, so only its own members move.
    fn settle(&self, component: &[usize], readers: &[Vec<usize>], work: &mut Work<I>) {
        work.pending.extend(component.iter().rev().copied());
        for member in component {
            work.queued[*member] = true;
        }
        loop {
            self.drain(readers, work);
            // A cycle nothing outside it enters leaves its phis unvisited;
            // each is its own root, and what reads it follows.
            let Some(unreached) = component
                .iter()
                .copied()
                .find(|member| work.state[*member].is_none() && self.is_phi(*member))
            else {
                break;
            };
            work.fallen[unreached] = true;
            work.pending.push(unreached);
            work.queued[unreached] = true;
        }
    }

    /// Evaluate what is pending until nothing moves; a value that moves
    /// queues its readers.
    fn drain(&self, readers: &[Vec<usize>], work: &mut Work<I>) {
        while let Some(node) = work.pending.pop() {
            work.queued[node] = false;
            let next = self.evaluate(node, &work.state, &mut work.fallen);
            if next == work.state[node] {
                continue;
            }
            work.state[node] = next;
            let queued = &mut work.queued;
            work.pending.extend(
                readers[node]
                    .iter()
                    .copied()
                    .filter(|reader| !std::mem::replace(&mut queued[*reader], true)),
            );
        }
    }

    fn is_phi(&self, node: usize) -> bool {
        matches!(self.definitions[node], Definition::Phi(_))
    }

    /// The view of an input: the solver's state for a value it derives, the
    /// value's own for any other.
    fn input_view(&self, id: I, state: &[Option<ValueView<I>>]) -> Option<ValueView<I>> {
        match self.index.get(id) {
            Some(index) => state[*index],
            None => Some(self.own(id)),
        }
    }

    fn evaluate(
        &self,
        node: usize,
        state: &[Option<ValueView<I>>],
        fallen: &mut [bool],
    ) -> Option<ValueView<I>> {
        let id = self.nodes[node];
        if fallen[node] {
            return Some(self.own(id));
        }
        let sources = match &self.definitions[node] {
            Definition::Step(source, step) => {
                let input = self.input_view(*source, state)?;
                return Some(
                    transfer(&self.facts, *step, &input, id).unwrap_or_else(|| self.own(id)),
                );
            }
            Definition::Insert {
                base,
                lane,
                lsb_bits,
            } => {
                let base = self.input_view(*base, state)?;
                let lane_end = lsb_bits.saturating_add(self.facts[*lane].0.saturating_mul(8));
                let continued = match self.offsets.get(*lane).copied() {
                    Some((source, from)) if from == *lsb_bits => {
                        let source = self.input_view(source, state)?;
                        self.continued(id, &base, &source, *lsb_bits..lane_end)
                    }
                    _ => None,
                };
                // Bits below the lane are the base's whatever the lane is.
                let below = || {
                    let root_bits = self.facts[base.root].0.saturating_mul(8);
                    let width = self.facts[id].0.saturating_mul(8);
                    let prefix = base.prefix_bits.min(*lsb_bits);
                    normalized(base.root, root_bits, prefix, ViewExtension::Unknown, width)
                };
                return Some(continued.or_else(below).unwrap_or_else(|| self.own(id)));
            }
            Definition::Phi(sources) => sources,
        };
        // An input not reached yet is assumed to agree.
        let mut views = sources
            .iter()
            .filter_map(|source| self.input_view(*source, state));
        let first = views.next()?;
        if views.all(|view| view == first) {
            return Some(first);
        }
        fallen[node] = true;
        Some(self.own(id))
    }
}

impl<I: DenseId + std::hash::Hash> Solver<I> {
    /// `INSERT(base, lane, lane.start)` where `lane` holds `source`'s bits there: the output is the
    /// shared root up to the lane's end where `base` covers the bits below it and `source` the lane's.
    fn continued(
        &self,
        id: I,
        base: &ValueView<I>,
        source: &ValueView<I>,
        lane: std::ops::Range<u32>,
    ) -> Option<ValueView<I>> {
        let covers = base.root == source.root
            && base.prefix_bits >= lane.start
            && source.prefix_bits >= lane.end;
        if !covers {
            return None;
        }
        // Bits the base already stated as the root's past the lane stay stated.
        if base.prefix_bits >= lane.end {
            return Some(*base);
        }
        let root_bits = self.facts[base.root].0.saturating_mul(8);
        let width = self.facts[id].0.saturating_mul(8);
        normalized(
            base.root,
            root_bits,
            lane.end,
            ViewExtension::Unknown,
            width,
        )
    }
}

/// The solver's state, and its worklist.
struct Work<I> {
    state: Vec<Option<ValueView<I>>>,
    /// Phis that have fallen to their own root, for good.
    fallen: Vec<bool>,
    /// Whether a value is on `pending`; every flag is clear between
    /// components, since draining clears each one it pops.
    queued: Vec<bool>,
    pending: Vec<usize>,
}

/// How one graph instruction defines its output, where the view reads it.
fn graph_definition(
    facts: &IdVec<ValueId, Facts>,
    inst: &crate::graph::GraphInst,
) -> Option<(ValueId, Definition<ValueId>)> {
    match &inst.payload {
        crate::graph::InstPayload::Phi { .. } => {
            Some((inst.output?, Definition::Phi(inst.inputs.clone())))
        }
        crate::graph::InstPayload::Op(op) => definition_of(op, |id| facts[*id]),
    }
}

const UNVISITED: usize = usize::MAX;

/// The strongly connected components of a graph given as each node's
/// successors, each after every component it reaches (Tarjan, iteratively),
/// with its members in index order so a loop's header phi comes first.
fn strongly_connected_components(successors: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let count = successors.len();
    let mut tarjan = Tarjan {
        order: vec![UNVISITED; count],
        low: vec![0; count],
        on_stack: vec![false; count],
        stack: Vec::new(),
        components: Vec::new(),
        next: 0,
    };
    for start in 0..count {
        if tarjan.order[start] == UNVISITED {
            tarjan.run(start, successors);
        }
    }
    tarjan.components
}

struct Tarjan {
    order: Vec<usize>,
    low: Vec<usize>,
    on_stack: Vec<bool>,
    stack: Vec<usize>,
    components: Vec<Vec<usize>>,
    next: usize,
}

impl Tarjan {
    fn enter(&mut self, node: usize) {
        self.order[node] = self.next;
        self.low[node] = self.next;
        self.next += 1;
        self.stack.push(node);
        self.on_stack[node] = true;
    }

    /// One depth-first walk from `start`, with an explicit stack of
    /// (node, index of the next successor to look at).
    fn run(&mut self, start: usize, successors: &[Vec<usize>]) {
        let mut frames = vec![(start, 0usize)];
        self.enter(start);
        while let Some(&mut (node, ref mut edge)) = frames.last_mut() {
            let Some(&successor) = successors[node].get(*edge) else {
                frames.pop();
                self.leave(node, frames.last().map(|(parent, _)| *parent));
                continue;
            };
            *edge += 1;
            if self.order[successor] == UNVISITED {
                self.enter(successor);
                frames.push((successor, 0));
            } else if self.on_stack[successor] {
                self.low[node] = self.low[node].min(self.order[successor]);
            }
        }
    }

    /// Finish `node`: hand its low link to its parent, and close a component
    /// where it is the root of one.
    fn leave(&mut self, node: usize, parent: Option<usize>) {
        if let Some(parent) = parent {
            self.low[parent] = self.low[parent].min(self.low[node]);
        }
        if self.low[node] != self.order[node] {
            return;
        }
        let mut component = Vec::new();
        while let Some(member) = self.stack.pop() {
            self.on_stack[member] = false;
            component.push(member);
            if member == node {
                break;
            }
        }
        component.sort_unstable();
        self.components.push(component);
    }
}

/// The representative of every value whose view is not its own.
fn representatives<I: DenseId + std::hash::Hash>(
    order: &[I],
    views: &IdMap<I, ValueView<I>>,
    facts: &IdVec<I, Facts>,
) -> (IdMap<I, Representative<I>>, LowLanes<I>) {
    let bits = |id: I| facts[id].0.saturating_mul(8);
    // The first value of each class, keyed by the class: its root, width,
    // prefix and extension. Only looked up, never iterated.
    let mut first_of_class = HashMap::<(I, u32, u32, ViewExtension), I>::new();
    let mut representatives = IdMap::new(facts.len());
    let mut low_lanes = LowLanes::<I>::new(facts.len());
    for id in order {
        let Some(view) = views.get(*id) else {
            continue;
        };
        let width = bits(*id);
        let representative = if view.prefix_bits == width && bits(view.root) == width {
            Representative::Value(view.root)
        } else if !view.determines_value() {
            continue;
        } else if let Some(literal) = literal_of_view(view, facts[view.root].1, width) {
            Representative::Literal {
                bits: literal,
                size: facts[*id].0,
            }
        } else {
            let first = *first_of_class
                .entry((view.root, width, view.prefix_bits, view.extension))
                .or_insert(*id);
            if first == *id {
                note_low_lane(&mut low_lanes, view, width, *id);
                continue;
            }
            Representative::Value(first)
        };
        representatives.insert(*id, representative);
    }
    (representatives, low_lanes)
}

/// Record `id`, the first of its class, as its root's low lane at `width` bits where it is exactly that.
fn note_low_lane<I: DenseId>(low_lanes: &mut LowLanes<I>, view: &ValueView<I>, width: u32, id: I) {
    if view.prefix_bits != width {
        return;
    }
    match low_lanes.get_mut(view.root) {
        Some(lanes) => lanes.push((width, id)),
        None => {
            low_lanes.insert(view.root, vec![(width, id)]);
        }
    }
}

/// The literal a view of a constant determines at `width` bits, where it fits
/// a constant. `root_bits` is the root's constant, where it is one.
fn literal_of_view<I>(view: &ValueView<I>, root_bits: Option<u64>, width: u32) -> Option<u64> {
    let constant = u128::from(root_bits?);
    let mask = |bits: u32| {
        if bits >= 128 {
            u128::MAX
        } else {
            (1u128 << bits) - 1
        }
    };
    let low = constant & mask(view.prefix_bits);
    let value = match view.extension {
        ViewExtension::Exact | ViewExtension::Zero => low,
        ViewExtension::Sign => {
            let negative = view.prefix_bits > 0 && (low >> (view.prefix_bits - 1)) & 1 == 1;
            if negative {
                (low | !mask(view.prefix_bits)) & mask(width)
            } else {
                low
            }
        }
        ViewExtension::Unknown => return None,
    };
    u64::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table of ids with the given width and constant bits each, for
    /// asking the view's rules about values no function holds.
    fn facts(values: &[(u32, Option<u64>)]) -> IdVec<VarId, Facts> {
        IdVec::from_fn(values.len(), |id: VarId| values[id.0 as usize])
    }

    fn own(facts: &IdVec<VarId, Facts>, id: u32) -> ValueView<VarId> {
        ValueView {
            root: VarId(id),
            prefix_bits: facts[VarId(id)].0 * 8,
            extension: ViewExtension::Exact,
        }
    }

    fn literal(facts: &IdVec<VarId, Facts>, view: &ValueView<VarId>, width: u32) -> Option<u64> {
        literal_of_view(view, facts[view.root].1, width)
    }
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn arch() -> crate::Arch {
        crate::Arch::new(arch_spec())
    }

    fn arch_spec() -> ArchSpec {
        let mut arch = ArchSpec::new("views");
        arch.add_register(RegisterDef::new("rax", 0, 8));
        arch.add_register(RegisterDef::new("rbx", 8, 8));
        arch.add_register(RegisterDef::new("ecx", 16, 4));
        arch.add_register(RegisterDef::new("ax", 24, 2));
        arch.add_register(RegisterDef::new("ah", 32, 1));
        arch.add_register(RegisterDef::new("pc", 0x80, 8));
        arch
    }

    /// The function the blocks lift to, with its identity facts and nothing
    /// folded: the constant folder is not what these ask about.
    fn prepared(blocks: &[R2ILBlock]) -> SSAFunction {
        SSAFunction::from_blocks_raw(blocks, Some(&arch())).expect("raw SSA builds")
    }

    /// The one variable some operation defines into `storage_offset` at `size`.
    fn defined(function: &SSAFunction, offset: u64, size: u32) -> SSAVar {
        function
            .named_blocks()
            .iter()
            .flat_map(|block| block.ops())
            .filter_map(SSAOp::dst)
            .find(|dst| {
                function
                    .canonical_storage_for_var(dst)
                    .is_some_and(|storage| storage.offset == offset && storage.size == size)
            })
            .cloned()
            .expect("a definition of that storage")
    }

    #[test]
    fn lanes_copied_in_order_into_a_register_are_the_bits_they_came_from() {
        // rax's low and high words written from rbx's, in place: rax is rbx (movaps).
        let mut arch = arch_spec();
        arch.add_register(RegisterDef::new("eax", 0, 4));
        arch.add_register(RegisterDef::new("raxh", 4, 4));
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Subpiece {
            dst: reg(0, 4),
            src: reg(8, 8),
            offset: 0,
        });
        block.push(R2ILOp::Subpiece {
            dst: reg(4, 4),
            src: reg(8, 8),
            offset: 4,
        });
        block.push(R2ILOp::Return { target: reg(0, 8) });
        let function =
            SSAFunction::from_blocks_raw(&[block], Some(&crate::Arch::from(arch.clone())))
                .expect("raw SSA builds");
        let views = ValueViews::compute(&function);
        let table = function.values();
        let id = |var: &SSAVar| table.id_of(var).expect("interned");
        // The value returned: the second write, after both lanes.
        let rax = function
            .named_blocks()
            .iter()
            .flat_map(|block| block.ops())
            .filter_map(SSAOp::dst)
            .filter(|dst| dst.name().eq_ignore_ascii_case("rax"))
            .last()
            .cloned()
            .expect("rax written");
        let rbx = function
            .named_blocks()
            .iter()
            .flat_map(|block| block.ops())
            .flat_map(SSAOp::sources)
            .find(|src| src.name().eq_ignore_ascii_case("rbx") && src.version == 0)
            .cloned()
            .expect("rbx read at entry");
        assert!(
            views.same_bits(id(&rax), id(&rbx)),
            "{:?}",
            views.view(id(&rax))
        );
    }

    #[test]
    fn a_lane_written_above_keeps_the_bits_below_it() {
        // rax's low word from rbx, then its high word a constant: rax's low word is still rbx's.
        let mut arch = arch_spec();
        arch.add_register(RegisterDef::new("eax", 0, 4));
        arch.add_register(RegisterDef::new("raxh", 4, 4));
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Subpiece {
            dst: reg(0, 4),
            src: reg(8, 8),
            offset: 0,
        });
        block.push(R2ILOp::Copy {
            dst: reg(4, 4),
            src: Varnode::constant(7, 4),
        });
        block.push(R2ILOp::Return { target: reg(0, 8) });
        let function =
            SSAFunction::from_blocks_raw(&[block], Some(&crate::Arch::from(arch.clone())))
                .expect("raw SSA builds");
        let views = ValueViews::compute(&function);
        let table = function.values();
        let rax = function
            .named_blocks()
            .iter()
            .flat_map(|block| block.ops())
            .filter_map(SSAOp::dst)
            .filter(|dst| dst.name().eq_ignore_ascii_case("rax"))
            .last()
            .cloned()
            .expect("rax written");
        let view = views.view(table.id_of(&rax).expect("interned"));
        assert_eq!(
            (
                function.var(view.root).name(),
                view.prefix_bits,
                view.extension
            ),
            ("rbx", 32, ViewExtension::Unknown),
            "{view:?}"
        );
    }

    #[test]
    fn a_lane_of_a_constant_above_its_low_bytes_is_never_its_low_bytes() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: reg(0, 8),
            src: Varnode::constant(0x1122_3344_5566_7788, 8),
        });
        block.push(R2ILOp::Subpiece {
            dst: reg(16, 4),
            src: reg(0, 8),
            offset: 4,
        });
        block.push(R2ILOp::Return { target: reg(16, 4) });
        let function = prepared(&[block]);
        let facts = function.prep_facts_for_test();
        let facts = &facts;
        let high = defined(&function, 16, 4);
        let literal =
            crate::semantic::resolve_const_value(&facts.graph, Some(facts), facts.value(&high));
        assert_ne!(
            literal,
            Some(0x5566_7788),
            "SUBPIECE(c, 4) is c's high word, never its low one"
        );
        assert!(
            literal.is_none() || literal == Some(0x1122_3344),
            "{literal:?}"
        );
    }

    #[test]
    fn a_high_byte_read_of_a_merge_of_constants_is_not_the_low_byte() {
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1008, 8),
            cond: reg(8, 1),
        });
        let mut left = R2ILBlock::new(0x1004, 4);
        left.push(R2ILOp::Copy {
            dst: reg(24, 2),
            src: Varnode::constant(0x1234, 2),
        });
        left.push(R2ILOp::Branch {
            target: Varnode::constant(0x100c, 8),
        });
        let mut right = R2ILBlock::new(0x1008, 4);
        right.push(R2ILOp::Copy {
            dst: reg(24, 2),
            src: Varnode::constant(0x1234, 2),
        });
        let mut merge = R2ILBlock::new(0x100c, 4);
        merge.push(R2ILOp::Subpiece {
            dst: reg(32, 1),
            src: reg(24, 2),
            offset: 1,
        });
        merge.push(R2ILOp::Return { target: reg(32, 1) });
        let function = prepared(&[entry, left, right, merge]);
        let facts = function.prep_facts_for_test();
        let facts = &facts;
        let merged = function
            .named_block(0x100c)
            .and_then(|block| block.phis().first().map(|phi| phi.dst.clone()))
            .expect("the two copies merge");
        // The merge is the constant: both arms agree on it.
        assert_eq!(
            class_key(&facts.graph, &facts.views, facts.value(&merged)),
            Representative::Value(facts.value(&SSAVar::constant(0x1234, 2)))
        );
        let high = defined(&function, 32, 1);
        assert_ne!(
            crate::semantic::resolve_const_value(&facts.graph, Some(facts), facts.value(&high)),
            Some(0x34),
            "AH of 0x1234 is 0x12, not the low byte"
        );
    }

    #[test]
    fn a_sign_word_is_its_own_value_and_a_zero_extended_read_back_is_the_read() {
        // rbx = load; rax = SEXT(ebx-width load) high half; ecx = SUBPIECE(ZEXT(load), 0).
        let mut block = R2ILBlock::new(0x1000, 4);
        let wide = Varnode::new(SpaceId::Unique, 0x100, 16);
        let narrow = Varnode::new(SpaceId::Unique, 0x200, 4);
        block.push(R2ILOp::Load {
            dst: reg(8, 8),
            space: SpaceId::Ram,
            addr: reg(0, 8),
        });
        block.push(R2ILOp::IntSExt {
            dst: wide.clone(),
            src: reg(8, 8),
        });
        block.push(R2ILOp::Subpiece {
            dst: reg(0, 8),
            src: wide,
            offset: 8,
        });
        block.push(R2ILOp::Load {
            dst: narrow.clone(),
            space: SpaceId::Ram,
            addr: reg(0, 8),
        });
        block.push(R2ILOp::IntZExt {
            dst: reg(8, 8),
            src: narrow,
        });
        block.push(R2ILOp::Subpiece {
            dst: reg(16, 4),
            src: reg(8, 8),
            offset: 0,
        });
        block.push(R2ILOp::Return { target: reg(16, 4) });
        let function = prepared(&[block]);
        let facts = function.prep_facts_for_test();
        let facts = &facts;
        let ops = function.named_blocks()[0].ops().to_vec();
        let loaded = ops
            .iter()
            .filter_map(|op| match op {
                SSAOp::Load { dst, .. } => Some(dst.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [first_load, second_load] = loaded.as_slice() else {
            panic!("two loads: {ops:?}")
        };
        let sign_word = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Subpiece { dst, offset: 8, .. } => Some(dst.clone()),
                _ => None,
            })
            .expect("the high half");
        let value = |var: &SSAVar| facts.value(var);
        assert!(!facts.same_bits(value(&sign_word), value(first_load)));
        assert_eq!(
            facts.canonical_root(value(&sign_word)),
            Representative::Value(value(&sign_word))
        );
        let read_back = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Subpiece { dst, offset: 0, .. } => Some(dst.clone()),
                _ => None,
            })
            .expect("the low lane");
        assert!(facts.same_bits(value(&read_back), value(second_load)));
        assert_eq!(
            facts.canonical_root(value(&read_back)),
            Representative::Value(value(second_load))
        );
    }

    #[test]
    fn a_sign_word_is_not_the_value_it_was_extended_from() {
        // t: 8 bytes, wide: 16, sign: 8, low: 8.
        let table = facts(&[(8, None), (16, None), (8, None), (8, None)]);
        let (t, wide, sign, low) = (VarId(0), VarId(1), VarId(2), VarId(3));
        let high = transfer(&table, Step::SignExtend, &own(&table, 0), wide).expect("a view");
        assert_eq!(high.root, t);
        assert_eq!(high.extension, ViewExtension::Sign);
        let width = |id: &VarId| table[*id];
        // SUBPIECE(SEXT(t), 8) has no step at all: the lane is its own value.
        assert!(
            step_of(
                &SSAOp::Subpiece {
                    dst: sign,
                    src: wide,
                    offset: 8,
                },
                width
            )
            .is_none()
        );
        // SUBPIECE(SEXT(t), 0) is t again.
        let subpiece = SSAOp::Subpiece {
            dst: low,
            src: wide,
            offset: 0,
        };
        let (_, _, step) = step_of(&subpiece, width).expect("a low lane");
        let back = transfer(&table, step, &high, low).expect("a view");
        assert_eq!(back, own(&table, 0));
    }

    #[test]
    fn a_zero_extended_lane_read_back_at_its_width_is_the_lane() {
        // loaded: 4 bytes, x0: 8, w0: 4.
        let table = facts(&[(4, None), (8, None), (4, None)]);
        let wide = transfer(&table, Step::ZeroExtend, &own(&table, 0), VarId(1)).expect("a view");
        assert_eq!(wide.extension, ViewExtension::Zero);
        assert_eq!(wide.prefix_bits, 32);
        let narrow = transfer(&table, Step::Low, &wide, VarId(2)).expect("a view");
        assert_eq!(narrow, own(&table, 0));
    }

    #[test]
    fn a_constant_view_determines_only_the_bits_it_covers() {
        // 0: the constant 0x1122334455667788; 1: a four-byte lane of it;
        // 2: the byte 0x80; 3, 4: four-byte results; 5: a value whose name
        // spells a constant but which holds no bits.
        let table = facts(&[
            (8, Some(0x1122_3344_5566_7788)),
            (4, None),
            (1, Some(0x80)),
            (4, None),
            (4, None),
            (8, None),
        ]);
        let low = transfer(&table, Step::Low, &own(&table, 0), VarId(1)).expect("a view");
        assert_eq!(literal(&table, &low, 32), Some(0x5566_7788));
        let extended =
            transfer(&table, Step::SignExtend, &own(&table, 2), VarId(3)).expect("a view");
        assert_eq!(literal(&table, &extended, 32), Some(0xffff_ff80));
        let unknown = transfer(&table, Step::LowLane, &own(&table, 2), VarId(4)).expect("a view");
        assert_eq!(literal(&table, &unknown, 32), None);
        // The bits are what makes a constant, whatever it is named: a value
        // with none supplies none.
        let named_low = transfer(&table, Step::Low, &own(&table, 5), VarId(1)).expect("a view");
        assert_eq!(literal(&table, &named_low, 32), None);
        assert_eq!(var_facts(&SSAVar::new("const:0x1234", 0, 8)).1, None);
        assert_eq!(
            var_facts(&SSAVar::constant(0x1234, 8).renamed("not-a-constant")).1,
            Some(0x1234)
        );
    }
}
