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
//! | a phi | the common view of its inputs, else its own |
//! | anything else, `SUBPIECE(x, k > 0)` included | its own |
//!
//! A constant lane `SUBPIECE(c, k)` is therefore never read off the root: the
//! constant folder computes it as `(c >> 8k) & mask`, and until it has, the
//! lane is its own value.
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
//! the whole termination argument, and no pass is counted.

use std::collections::HashMap;

use crate::function::SSAFunction;
use crate::op::SSAOp;
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValueView {
    /// The value whose low bits these are.
    pub root: SSAVar,
    /// How many of the low bits are the root's.
    pub prefix_bits: u32,
    /// What the bits above the prefix are.
    pub extension: ViewExtension,
}

impl ValueView {
    /// A value that is its own root.
    pub fn own(var: &SSAVar) -> Self {
        Self {
            root: var.clone(),
            prefix_bits: bits(var),
            extension: ViewExtension::Exact,
        }
    }

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

/// The view of every value of one function, and each value's representative.
///
/// A value is recorded only where its view is not its own. The representative
/// is the one variable every value with the same bits at the same width is
/// named by: the root itself when the value is the root's whole width, the
/// literal a constant root determines, and otherwise the first value of the
/// class in definition order. A value whose view leaves bits unstated is its
/// own representative.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueViews {
    views: HashMap<SSAVar, ValueView>,
    representatives: HashMap<SSAVar, SSAVar>,
}

impl ValueViews {
    /// Compute the view of every value `function` defines.
    pub(crate) fn compute(function: &SSAFunction) -> Self {
        Solver::new(function).solve()
    }

    /// The same fact, read off a graph rather than the function it was
    /// built from: the passes that hold only the graph ask it here, by the
    /// same rules, instead of keeping rules of their own.
    pub(crate) fn of_graph(graph: &crate::graph::SsaGraph) -> Self {
        Solver::from_graph(graph).solve()
    }

    /// The view of `var`: its own where nothing derives it.
    pub fn view(&self, var: &SSAVar) -> ValueView {
        self.views
            .get(var)
            .cloned()
            .unwrap_or_else(|| ValueView::own(var))
    }

    /// The recorded view of `var`, where it is not its own.
    pub fn derived_view(&self, var: &SSAVar) -> Option<&ValueView> {
        self.views.get(var)
    }

    /// The variable every value with `var`'s bits at `var`'s width is named by.
    pub fn representative<'a>(&'a self, var: &'a SSAVar) -> &'a SSAVar {
        self.representatives.get(var).unwrap_or(var)
    }

    /// The representative of `var`, where it is not `var` itself.
    pub fn representative_of(&self, var: &SSAVar) -> Option<&SSAVar> {
        self.representatives.get(var)
    }

    /// Every value with a representative other than itself, and that representative.
    pub fn representatives(&self) -> impl Iterator<Item = (&SSAVar, &SSAVar)> {
        self.representatives.iter()
    }

    /// Whether `a` and `b` are the same bits at the same width.
    pub fn same_bits(&self, a: &SSAVar, b: &SSAVar) -> bool {
        if a == b {
            return true;
        }
        if a.size != b.size {
            return false;
        }
        let (left, right) = (self.view(a), self.view(b));
        left == right && left.determines_value()
    }

    /// How `derived`, a value computed from `source`, relates to it: the same
    /// bits, or something else computed from them.
    pub fn relation(&self, derived: &SSAVar, source: &SSAVar) -> ViewRelation {
        if self.same_bits(derived, source) {
            ViewRelation::Identity
        } else {
            ViewRelation::Derived
        }
    }

    /// The value `var` is a copy of: its root, where `var` carries every bit
    /// of the root and nothing else, at the root's own width; otherwise `var`.
    ///
    /// Unlike the representative, which may be any member of a class, the
    /// root dominates every value it is the copy root of: each transparent
    /// step reads an operand, which dominates the step, and a phi takes a
    /// root only when every input already has it, so the root dominates every
    /// predecessor and so the phi. A pass that rewrites the graph may name it
    /// in their place.
    pub fn copy_root<'a>(&'a self, var: &'a SSAVar) -> &'a SSAVar {
        match self.views.get(var) {
            Some(view)
                if view.extension == ViewExtension::Exact
                    && view.prefix_bits == bits(var)
                    && bits(&view.root) == bits(var) =>
            {
                &view.root
            }
            _ => var,
        }
    }

    /// The value `var` equals as an unsigned integer: its root, where `var`
    /// holds the root's whole width with zeros above; otherwise `var`.
    ///
    /// This is the chain of copies and zero extensions a literal or an
    /// address is read through: a zero-extended pointer is still the pointer,
    /// and a truncated or sign-extended one is not.
    pub fn same_integer_root<'a>(&'a self, var: &'a SSAVar) -> &'a SSAVar {
        match self.views.get(var) {
            Some(view)
                if view.prefix_bits == bits(&view.root)
                    && matches!(view.extension, ViewExtension::Exact | ViewExtension::Zero) =>
            {
                &view.root
            }
            _ => var,
        }
    }
}

/// The graph value naming `var`'s copy class -- the values with its bits at
/// its width: the representative where the graph holds it, else `var`'s own.
pub(crate) fn class_value(
    graph: &crate::graph::SsaGraph,
    views: Option<&ValueViews>,
    var: &SSAVar,
) -> Option<crate::graph::ValueId> {
    views
        .map(|views| views.representative(var))
        .and_then(|representative| graph.value_id_for_var(representative))
        .or_else(|| graph.value_id_for_var(var))
}

/// Every graph value's copy-class value, indexed by value: one `O(V)` table
/// for the passes that ask per value.
pub(crate) fn class_values(
    graph: &crate::graph::SsaGraph,
    views: Option<&ValueViews>,
) -> Vec<crate::graph::ValueId> {
    graph
        .values
        .iter()
        .map(|value| class_value(graph, views, &value.var).unwrap_or(value.id))
        .collect()
}

/// The width of a value, in bits.
fn bits(var: &SSAVar) -> u32 {
    var.size.saturating_mul(8)
}

/// A view in its canonical form: a prefix no wider than the value or the
/// root, `Exact` exactly when the prefix is the whole value, and no view at
/// all where no bit is the root's.
fn normalized(
    root: &SSAVar,
    prefix: u32,
    extension: ViewExtension,
    width: u32,
) -> Option<ValueView> {
    let prefix = prefix.min(width).min(bits(root));
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
        root: root.clone(),
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

/// What an operation's output is made of, where the view can say.
fn step_of(op: &SSAOp) -> Option<(&SSAVar, &SSAVar, Step)> {
    let same_width = |dst: &SSAVar, src: &SSAVar| dst.size == src.size;
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
        } if dst.size == src.size => Some((dst, src, Step::Copy)),
        SSAOp::Subpiece {
            dst,
            src,
            offset: 0,
        } if dst.size < src.size => Some((dst, src, Step::Low)),
        SSAOp::IntZExt { dst, src } if dst.size >= src.size => Some((
            dst,
            src,
            if same_width(dst, src) {
                Step::Copy
            } else {
                Step::ZeroExtend
            },
        )),
        SSAOp::IntSExt { dst, src } if dst.size >= src.size => Some((
            dst,
            src,
            if same_width(dst, src) {
                Step::Copy
            } else {
                Step::SignExtend
            },
        )),
        SSAOp::Insert(insert)
            if insert.position.constant_bits() == Some(0)
                && insert.value.size <= insert.dst.size =>
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
        SSAOp::Piece { dst, lo, .. } if lo.size < dst.size => Some((dst, lo, Step::LowLane)),
        _ => None,
    }
}

/// Whether an operation's output is its first operand's unsigned value: a
/// copy or a zero extension.
///
/// The same rule the view applies, for the walks that read a value through
/// its definitions rather than through the solved view -- the constant
/// folder's, over a graph no preparation has run on.
pub(crate) fn preserves_integer(op: &SSAOp) -> bool {
    !matches!(op, SSAOp::Insert(_) | SSAOp::Piece { .. })
        && matches!(step_of(op), Some((_, _, Step::Copy | Step::ZeroExtend)))
}

/// The view of an output, given its input's view.
fn transfer(step: Step, input: &ValueView, output: &SSAVar) -> Option<ValueView> {
    let width = bits(output);
    let ValueView {
        root,
        prefix_bits: prefix,
        extension,
    } = input;
    match step {
        Step::Copy => Some(input.clone()),
        // A narrower read keeps the prefix it still covers, and above that
        // whatever the input stated up to its own width.
        Step::Low => normalized(root, *prefix, *extension, width),
        Step::ZeroExtend => {
            let above = match extension {
                ViewExtension::Exact | ViewExtension::Zero => ViewExtension::Zero,
                // Sign copies up to the input's width and zeros past it is
                // neither; the prefix still holds.
                ViewExtension::Sign | ViewExtension::Unknown => ViewExtension::Unknown,
            };
            normalized(root, *prefix, above, width)
        }
        Step::SignExtend => {
            let above = match extension {
                ViewExtension::Exact | ViewExtension::Sign => ViewExtension::Sign,
                // The input's top bit is one of the zeros above its prefix,
                // so the extension copies a zero.
                ViewExtension::Zero => ViewExtension::Zero,
                ViewExtension::Unknown => ViewExtension::Unknown,
            };
            normalized(root, *prefix, above, width)
        }
        Step::LowLane => normalized(root, *prefix, ViewExtension::Unknown, width),
    }
}

/// How a value is defined, for the solver.
enum Definition<'a> {
    Phi(Vec<&'a SSAVar>),
    Step(&'a SSAVar, Step),
}

struct Solver<'a> {
    /// Every value the view can derive, in definition order.
    nodes: Vec<&'a SSAVar>,
    definitions: Vec<Definition<'a>>,
    index: HashMap<&'a SSAVar, usize>,
}

impl<'a> Solver<'a> {
    fn new(function: &'a SSAFunction) -> Self {
        let mut nodes = Vec::new();
        let mut definitions = Vec::new();
        for block in function.blocks() {
            for phi in &block.phis {
                nodes.push(&phi.dst);
                definitions.push(Definition::Phi(
                    phi.sources.iter().map(|(_, source)| source).collect(),
                ));
            }
            for (dst, src, step) in block.ops.iter().filter_map(step_of) {
                nodes.push(dst);
                definitions.push(Definition::Step(src, step));
            }
        }
        Self::over(nodes, definitions)
    }

    fn from_graph(graph: &'a crate::graph::SsaGraph) -> Self {
        let (nodes, definitions) = graph
            .insts
            .iter()
            .filter_map(|inst| graph_definition(graph, inst))
            .unzip();
        Self::over(nodes, definitions)
    }

    fn over(nodes: Vec<&'a SSAVar>, definitions: Vec<Definition<'a>>) -> Self {
        let index = nodes
            .iter()
            .enumerate()
            .map(|(index, var)| (*var, index))
            .collect();
        Self {
            nodes,
            definitions,
            index,
        }
    }

    fn inputs(&self, node: usize) -> Vec<usize> {
        match &self.definitions[node] {
            Definition::Phi(sources) => sources
                .iter()
                .filter_map(|source| self.index.get(source).copied())
                .collect(),
            Definition::Step(source, _) => self.index.get(source).copied().into_iter().collect(),
        }
    }

    fn solve(self) -> ValueViews {
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

        let views = work
            .state
            .into_iter()
            .enumerate()
            .filter_map(|(node, view)| {
                let var = self.nodes[node];
                view.filter(|view| view.root != *var)
                    .map(|view| (var.clone(), view))
            })
            .collect::<HashMap<_, _>>();
        let representatives = representatives(&self.nodes, &views);
        ValueViews {
            views,
            representatives,
        }
    }

    /// Evaluate one component to its fixed point. Every component it reads
    /// is settled already, so only its own members move.
    fn settle(&self, component: &[usize], readers: &[Vec<usize>], work: &mut Work) {
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
    fn drain(&self, readers: &[Vec<usize>], work: &mut Work) {
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
    fn input_view(&self, var: &SSAVar, state: &[Option<ValueView>]) -> Option<ValueView> {
        match self.index.get(var) {
            Some(index) => state[*index].clone(),
            None => Some(ValueView::own(var)),
        }
    }

    fn evaluate(
        &self,
        node: usize,
        state: &[Option<ValueView>],
        fallen: &mut [bool],
    ) -> Option<ValueView> {
        let var = self.nodes[node];
        if fallen[node] {
            return Some(ValueView::own(var));
        }
        let sources = match &self.definitions[node] {
            Definition::Step(source, step) => {
                let input = self.input_view(source, state)?;
                return Some(transfer(*step, &input, var).unwrap_or_else(|| ValueView::own(var)));
            }
            Definition::Phi(sources) => sources,
        };
        // An input not reached yet is assumed to agree.
        let mut views = sources
            .iter()
            .filter_map(|source| self.input_view(source, state));
        let first = views.next()?;
        if views.all(|view| view == first) {
            return Some(first);
        }
        fallen[node] = true;
        Some(ValueView::own(var))
    }
}

/// The solver's state, and its worklist.
struct Work {
    state: Vec<Option<ValueView>>,
    /// Phis that have fallen to their own root, for good.
    fallen: Vec<bool>,
    /// Whether a value is on `pending`; every flag is clear between
    /// components, since draining clears each one it pops.
    queued: Vec<bool>,
    pending: Vec<usize>,
}

/// How one graph instruction defines its output, where the view reads it.
fn graph_definition<'a>(
    graph: &'a crate::graph::SsaGraph,
    inst: &'a crate::graph::GraphInst,
) -> Option<(&'a SSAVar, Definition<'a>)> {
    match &inst.payload {
        crate::graph::InstPayload::Phi { .. } => {
            let output = graph.value(inst.output?)?;
            let sources = inst
                .inputs
                .iter()
                .filter_map(|input| graph.value(*input))
                .map(|input| &input.var)
                .collect();
            Some((&output.var, Definition::Phi(sources)))
        }
        crate::graph::InstPayload::Op(op) => {
            step_of(op).map(|(dst, src, step)| (dst, Definition::Step(src, step)))
        }
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
fn representatives(
    order: &[&SSAVar],
    views: &HashMap<SSAVar, ValueView>,
) -> HashMap<SSAVar, SSAVar> {
    let mut first_of_class = HashMap::<(&SSAVar, u32, u32, ViewExtension), &SSAVar>::new();
    let mut representatives = HashMap::new();
    for var in order {
        let Some(view) = views.get(*var) else {
            continue;
        };
        let width = bits(var);
        let representative = if view.prefix_bits == width && bits(&view.root) == width {
            view.root.clone()
        } else if !view.determines_value() {
            continue;
        } else if let Some(literal) = literal_of_view(view, width) {
            SSAVar::constant(literal, var.size)
        } else {
            let first = *first_of_class
                .entry((&view.root, width, view.prefix_bits, view.extension))
                .or_insert(*var);
            if first == *var {
                continue;
            }
            first.clone()
        };
        representatives.insert((*var).clone(), representative);
    }
    representatives
}

/// The literal a view of a constant determines at `width` bits, where it fits
/// a constant.
fn literal_of_view(view: &ValueView, width: u32) -> Option<u64> {
    let constant = u128::from(view.root.constant_bits()?);
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
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    fn var(name: &str, version: u32, size: u32) -> SSAVar {
        SSAVar::new(name, version, size)
    }

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(SpaceId::Register, offset, size)
    }

    fn arch() -> ArchSpec {
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
        let mut function =
            SSAFunction::from_blocks_raw(blocks, Some(&arch())).expect("raw SSA builds");
        function.refresh_decompile_prep_facts();
        function
    }

    /// The one variable some operation defines into `storage_offset` at `size`.
    fn defined(function: &SSAFunction, offset: u64, size: u32) -> SSAVar {
        function
            .blocks()
            .iter()
            .flat_map(|block| &block.ops)
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
        let facts = function.decompile_prep_facts().expect("identity facts");
        let high = defined(&function, 16, 4);
        let literal = crate::semantic::resolve_const_value(Some(facts), &high);
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
        let facts = function.decompile_prep_facts().expect("identity facts");
        let merged = function
            .get_block(0x100c)
            .and_then(|block| block.phis.first())
            .map(|phi| phi.dst.clone())
            .expect("the two copies merge");
        // The merge is the constant: both arms agree on it.
        assert_eq!(facts.canonical_root(&merged), &SSAVar::constant(0x1234, 2));
        let high = defined(&function, 32, 1);
        assert_ne!(
            crate::semantic::resolve_const_value(Some(facts), &high),
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
        let facts = function.decompile_prep_facts().expect("identity facts");
        let ops = &function.blocks()[0].ops;
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
        assert!(!facts.same_bits(&sign_word, first_load));
        assert_eq!(facts.canonical_root(&sign_word), &sign_word);
        let read_back = ops
            .iter()
            .find_map(|op| match op {
                SSAOp::Subpiece { dst, offset: 0, .. } => Some(dst.clone()),
                _ => None,
            })
            .expect("the low lane");
        assert!(facts.same_bits(&read_back, second_load));
        assert_eq!(facts.canonical_root(&read_back), second_load);
    }

    #[test]
    fn a_sign_word_is_not_the_value_it_was_extended_from() {
        let t = var("tmp:t", 1, 8);
        let wide = var("tmp:wide", 1, 16);
        let sign = var("RDX", 3, 8);
        let low = var("RAX", 3, 8);
        let high = transfer(Step::SignExtend, &ValueView::own(&t), &wide).expect("a view");
        assert_eq!(high.root, t);
        assert_eq!(high.extension, ViewExtension::Sign);
        // SUBPIECE(SEXT(t), 8) has no step at all: the lane is its own value.
        assert!(
            step_of(&SSAOp::Subpiece {
                dst: sign,
                src: wide.clone(),
                offset: 8,
            })
            .is_none()
        );
        // SUBPIECE(SEXT(t), 0) is t again.
        let (_, _, step) = step_of(&SSAOp::Subpiece {
            dst: low.clone(),
            src: wide,
            offset: 0,
        })
        .expect("a low lane");
        let back = transfer(step, &high, &low).expect("a view");
        assert_eq!(back, ValueView::own(&t));
    }

    #[test]
    fn a_zero_extended_lane_read_back_at_its_width_is_the_lane() {
        let loaded = var("tmp:load", 1, 4);
        let x0 = var("X0", 1, 8);
        let w0 = var("W0", 1, 4);
        let wide = transfer(Step::ZeroExtend, &ValueView::own(&loaded), &x0).expect("a view");
        assert_eq!(wide.extension, ViewExtension::Zero);
        assert_eq!(wide.prefix_bits, 32);
        let narrow = transfer(Step::Low, &wide, &w0).expect("a view");
        assert_eq!(narrow, ValueView::own(&loaded));
    }

    #[test]
    fn a_constant_view_determines_only_the_bits_it_covers() {
        let constant = SSAVar::constant(0x1122_3344_5566_7788, 8);
        let low =
            transfer(Step::Low, &ValueView::own(&constant), &var("tmp:l", 1, 4)).expect("a view");
        assert_eq!(literal_of_view(&low, 32), Some(0x5566_7788));
        let byte = SSAVar::constant(0x80, 1);
        let extended = transfer(
            Step::SignExtend,
            &ValueView::own(&byte),
            &var("tmp:s", 1, 4),
        )
        .expect("a view");
        assert_eq!(literal_of_view(&extended, 32), Some(0xffff_ff80));
        let unknown =
            transfer(Step::LowLane, &ValueView::own(&byte), &var("tmp:u", 1, 4)).expect("a view");
        assert_eq!(literal_of_view(&unknown, 32), None);
        // A display name spelled like a constant supplies no bits; the bits
        // are what makes a constant, whatever it is named.
        let named = var("const:0x1234", 0, 8);
        let named_low =
            transfer(Step::Low, &ValueView::own(&named), &var("tmp:n", 1, 4)).expect("a view");
        assert_eq!(literal_of_view(&named_low, 32), None);
        let renamed = SSAVar::constant(0x1234, 8).renamed("not-a-constant");
        let renamed_low =
            transfer(Step::Low, &ValueView::own(&renamed), &var("tmp:r", 1, 4)).expect("a view");
        assert_eq!(literal_of_view(&renamed_low, 32), Some(0x1234));
    }
}
