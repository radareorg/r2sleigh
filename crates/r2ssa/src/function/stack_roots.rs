//! Which values are positions in the stack frame, and where
//! (doc/adr-fixpoint.md, K2).
//!
//! A value's root is `base + offset`. The stack pointer, or a declared
//! frame base, is rooted at entry; a copy keeps its operand's root; adding
//! or subtracting a constant moves it. A merge is rooted where every input
//! that is rooted agrees, which is how a stack pointer carried around a loop
//! is rooted: the back edge's root is the one entering, unless the body
//! drifts.
//!
//! Each root is solved optimistically on the sparse fixpoint driver, over a
//! lattice of height two per value: `Pending` (nothing has ruled the value
//! out yet), `At(root)`, `Not`. A merge meets its inputs, ignoring the
//! pending ones; so a loop-carried pointer starts from the root entering the
//! loop and keeps it only if the back edge brings the same root back. That
//! is the greatest fixpoint, which the speculate-verify-roll-back rounds this
//! replaces approximated. A value still pending when the cells settle is one
//! nothing roots, and has no root.
//!
//! Three facts come out:
//!
//! - **exact** roots, in the declared coordinates;
//! - **entry** roots, in the entry stack pointer's coordinates, solved only
//!   over values as wide as it and only where nothing the function calls can
//!   move it;
//! - **indexed** roots, for an address inside a frame object at an offset
//!   the machine computes: derived after the exact ones, and only for a
//!   value with no exact root, because an exact position is the stronger
//!   fact.
//!
//! One `and` that masks the stack pointer to an alignment roots a frame of
//! its own (`Realigned`): the masked pointer's distance from the entry is
//! not known, but every push and local below it is at a stated distance from
//! it. It is found after a first solve, since only that solve says which
//! value is the stack pointer, and seeded for a second. Two such masks are
//! two origins nothing here can tell apart, and neither is rooted.

use super::{StackAddressBase, StackAddressRoot};
use crate::dense::{Csr, IdMap};
use crate::fixpoint::Exhausted;
use crate::graph::{InstPayload, SsaGraph, ValueId};
use crate::op::SSAOp;
use crate::view::{Representative, ValueViews};

/// A root for some of a graph's values.
pub(crate) type RootMap = IdMap<ValueId, StackAddressRoot>;

/// The solved roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Roots {
    pub exact: RootMap,
    pub entry: RootMap,
    pub indexed: RootMap,
}

/// A value's root, as the solve has it so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rooted {
    /// Nothing has ruled it out: the optimistic top.
    Pending,
    At(StackAddressRoot),
    Not,
}

impl Rooted {
    /// Two values on two paths: the same root, or none.
    fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Pending, other) | (other, Self::Pending) => other,
            (Self::At(a), Self::At(b)) if a == b => Self::At(a),
            _ => Self::Not,
        }
    }

    fn root(self) -> Option<StackAddressRoot> {
        match self {
            Self::At(root) => Some(root),
            Self::Pending | Self::Not => None,
        }
    }
}

/// An operation that can root its output.
enum Rule {
    Merge(Vec<ValueId>),
    Copy(ValueId),
    Add(ValueId, ValueId),
    Sub(ValueId, ValueId),
}

/// The values a root can flow to, in definition order, with each one's
/// rule and who reads it.
struct Flow {
    order: Vec<ValueId>,
    rules: IdMap<ValueId, Rule>,
    readers: Csr<ValueId, ValueId>,
}

impl Flow {
    fn of(graph: &SsaGraph, views: &ValueViews<ValueId>) -> Self {
        let mut order = Vec::new();
        let mut rules = IdMap::new(graph.values.len());
        let mut reads = Vec::new();
        for inst in &graph.insts {
            let Some(dst) = inst.output else {
                continue;
            };
            let rule = match &inst.payload {
                InstPayload::Phi { .. } => Rule::Merge(inst.inputs.clone()),
                InstPayload::Op(op) => match *op {
                    SSAOp::Copy { dst, src }
                    | SSAOp::Cast { dst, src }
                    | SSAOp::CallRestore { dst, src }
                        if views.size(dst) == views.size(src) =>
                    {
                        Rule::Copy(src)
                    }
                    SSAOp::IntAdd { a, b, .. } => Rule::Add(a, b),
                    SSAOp::IntSub { a, b, .. } => Rule::Sub(a, b),
                    _ => continue,
                },
            };
            // `dst` reads each operand and the operand's representative,
            // whose root an operand also answers with.
            let inputs = match &rule {
                Rule::Merge(sources) => sources.clone(),
                Rule::Copy(src) => vec![*src],
                Rule::Add(a, b) | Rule::Sub(a, b) => vec![*a, *b],
            };
            for input in inputs {
                reads.push((input, dst));
                if let Some(representative) = views.representative_value(input) {
                    reads.push((representative, dst));
                }
            }
            order.push(dst);
            rules.insert(dst, rule);
        }
        Self {
            order,
            rules,
            readers: Csr::from_pairs(graph.values.len(), reads),
        }
    }
}

/// What the entry states: the roots its declared bases have, in the
/// declared coordinates and in the entry stack pointer's, and that
/// pointer's width where entry roots are solved at all.
pub(super) struct Seeds {
    pub exact: RootMap,
    pub entry: RootMap,
    pub entry_size: Option<u32>,
}

/// Solve every root of `graph` from its seeds.
pub(super) fn solve(
    graph: &SsaGraph,
    entry: u64,
    views: &ValueViews<ValueId>,
    seeds: Seeds,
) -> Result<Roots, Exhausted> {
    let Seeds {
        exact: mut exact_seeds,
        entry: mut entry_seeds,
        entry_size,
    } = seeds;
    let flow = Flow::of(graph, views);
    let mut exact = rooted(&flow, views, &exact_seeds, None)?;
    if let Some(origin) = realigned(graph, entry, views, &exact, entry_size) {
        let root = StackAddressRoot {
            base: StackAddressBase::Realigned,
            offset: 0,
        };
        exact_seeds.insert(origin, root);
        entry_seeds.insert(origin, root);
        exact = rooted(&flow, views, &exact_seeds, None)?;
    }
    let entry = match entry_size {
        Some(size) => rooted(&flow, views, &entry_seeds, Some(size))?,
        None => IdMap::new(graph.values.len()),
    };
    let indexed = indexed(&flow, views, &exact)?;
    Ok(Roots {
        exact,
        entry,
        indexed,
    })
}

/// The settled root of every value `flow` reaches from `seeds`. Where
/// `width` is given, only values that wide carry a root.
fn rooted(
    flow: &Flow,
    views: &ValueViews<ValueId>,
    seeds: &RootMap,
    width: Option<u32>,
) -> Result<RootMap, Exhausted> {
    let fits = |id: ValueId| width.is_none_or(|width| views.size(id) == width);
    let cells = crate::fixpoint::sparse(
        "stack-roots",
        2,
        &flow.order,
        &flow.readers,
        Rooted::Pending,
        |dst, cells| {
            let of = |id: ValueId| value_of(id, views, seeds, cells);
            match &flow.rules[dst] {
                _ if !fits(dst) => Rooted::Not,
                Rule::Merge(sources) if sources.iter().all(|source| fits(*source)) => sources
                    .iter()
                    .fold(Rooted::Pending, |held, source| held.meet(of(*source))),
                Rule::Copy(src) if fits(*src) => of(*src),
                Rule::Add(a, b) if fits(*a) && fits(*b) => displaced(of(*a), delta(*b, views), 1)
                    .meet_either(displaced(of(*b), delta(*a, views), 1)),
                Rule::Sub(a, b) if fits(*a) && fits(*b) => displaced(of(*a), delta(*b, views), -1),
                _ => Rooted::Not,
            }
        },
    )?;
    let mut roots = seeds.clone();
    for (id, cell) in cells.iter() {
        if let Some(root) = cell.root() {
            roots.insert(id, root);
        }
    }
    Ok(roots)
}

/// A root moved by a constant, `sign` saying which way; pending while the
/// root is, and nothing without a constant to move it by.
fn displaced(base: Rooted, delta: Option<i64>, sign: i64) -> Rooted {
    let Some(delta) = delta else {
        return Rooted::Not;
    };
    match base {
        Rooted::At(root) => delta
            .checked_mul(sign)
            .and_then(|delta| root.offset.checked_add(delta))
            .map_or(Rooted::Not, |offset| {
                Rooted::At(StackAddressRoot {
                    base: root.base,
                    offset,
                })
            }),
        other => other,
    }
}

impl Rooted {
    /// A sum is rooted by whichever operand is a root plus a constant: a
    /// root from either side, pending while either may still be one.
    fn meet_either(self, other: Self) -> Self {
        match (self, other) {
            (Self::At(root), _) | (_, Self::At(root)) => Self::At(root),
            (Self::Pending, _) | (_, Self::Pending) => Self::Pending,
            (Self::Not, Self::Not) => Self::Not,
        }
    }
}

/// A value's root: its own, or its representative's, which carries the same
/// bits; a seed or a constant answers at once. A literal representative is
/// no position.
fn value_of(
    id: ValueId,
    views: &ValueViews<ValueId>,
    seeds: &RootMap,
    cells: &IdMap<ValueId, Rooted>,
) -> Rooted {
    let own = |id: ValueId| match seeds.get(id) {
        Some(root) => Rooted::At(*root),
        None => cells.get(id).copied().unwrap_or(Rooted::Not),
    };
    let representative = match views.representative(id) {
        Representative::Value(representative) => own(representative),
        Representative::Literal { .. } => Rooted::Not,
    };
    match (own(id), representative) {
        (Rooted::At(root), _) | (_, Rooted::At(root)) => Rooted::At(root),
        (Rooted::Pending, _) | (_, Rooted::Pending) => Rooted::Pending,
        (Rooted::Not, Rooted::Not) => Rooted::Not,
    }
}

/// The constant a value displaces an address by, read through a copy: an
/// AArch64 `add x29, sp, 0x60` materialises the `0x60` in a temporary.
pub(super) fn delta(id: ValueId, views: &ValueViews<ValueId>) -> Option<i64> {
    views
        .constant(id)
        .and_then(|bits| signed(bits, views.size(id)))
        .or_else(|| {
            let (bits, size) = views.representative_constant(id)?;
            signed(bits, size)
        })
}

/// A constant read as a signed displacement at its own width.
fn signed(value: u64, size: u32) -> Option<i64> {
    let bits = size.checked_mul(8)?;
    match bits {
        64 => Some(value as i64),
        1..=63 => {
            let sign = 1u64 << (bits - 1);
            let mask = (1u64 << bits) - 1;
            let value = value & mask;
            Some(match value & sign {
                0 => value as i64,
                _ => (value | !mask) as i64,
            })
        }
        _ => None,
    }
}

/// A value's exact root, or its representative's.
fn exact_of(id: ValueId, views: &ValueViews<ValueId>, exact: &RootMap) -> Option<StackAddressRoot> {
    exact
        .get(id)
        .or_else(|| exact.get(views.representative_value(id)?))
        .copied()
}

/// The one value an `and` realigns the stack pointer into, where exactly
/// one does.
fn realigned(
    graph: &SsaGraph,
    entry: u64,
    views: &ValueViews<ValueId>,
    exact: &RootMap,
    entry_size: Option<u32>,
) -> Option<ValueId> {
    let aligns = |value: ValueId, mask: ValueId| {
        let alignment = delta(mask, views).and_then(i64::checked_neg);
        exact_of(value, views, exact)
            .is_some_and(|root| root.base == StackAddressBase::StackPointer)
            && alignment.is_some_and(|alignment| {
                alignment >= 2 && alignment.unsigned_abs().is_power_of_two()
            })
    };
    let mut candidates = graph.insts.iter().filter_map(|inst| match inst.payload {
        InstPayload::Op(SSAOp::IntAnd { dst, a, b })
            if entry_size == Some(views.size(dst)) && (aligns(a, b) || aligns(b, a)) =>
        {
            Some(dst)
        }
        _ => None,
    });
    let origin = candidates.next()?;
    if candidates.next().is_some() {
        r2il::refusal_evidence!(
            "stack-root-realign",
            "{:#x}: more than one mask realigns the stack pointer",
            entry
        );
        return None;
    }
    r2il::refusal_evidence!(
        "stack-root-realign",
        "{:#x}: {} is the realigned frame's origin",
        entry,
        graph.values[origin.0 as usize].var
    );
    Some(origin)
}

/// The frame object each sum or difference without an exact root is inside,
/// where one operand is inside it and the other is an index nothing folds:
/// `buf + i`, `buf + i + 4`, `buf + i - 3`.
fn indexed(
    flow: &Flow,
    views: &ValueViews<ValueId>,
    exact: &RootMap,
) -> Result<RootMap, Exhausted> {
    let exact_of = |id: ValueId| exact_of(id, views, exact);
    let cells = crate::fixpoint::sparse(
        "indexed-stack-roots",
        2,
        &flow.order,
        &flow.readers,
        Rooted::Pending,
        |dst, cells| {
            if exact_of(dst).is_some() {
                return Rooted::Not;
            }
            let indexed_of = |id: ValueId| {
                let own = |id: ValueId| cells.get(id).copied().unwrap_or(Rooted::Not);
                let representative = views.representative_value(id).map_or(Rooted::Not, own);
                own(id).meet_either(representative)
            };
            // Inside an object: exactly placed in it, or already indexed.
            let inside = |id: ValueId| match exact_of(id) {
                Some(root) => Rooted::At(root),
                None => indexed_of(id),
            };
            // An index nothing folds and that is no position in an object.
            let opaque = |id: ValueId| {
                delta(id, views).is_none()
                    && exact_of(id).is_none()
                    && indexed_of(id) == Rooted::Not
            };
            match &flow.rules[dst] {
                Rule::Add(a, b) => {
                    let by_index = |base: ValueId, index: ValueId| match opaque(index) {
                        true => inside(base),
                        false => Rooted::Not,
                    };
                    let by_constant =
                        |base: ValueId, constant: ValueId| match delta(constant, views) {
                            Some(_) => indexed_of(base),
                            None => Rooted::Not,
                        };
                    by_index(*a, *b)
                        .meet_either(by_index(*b, *a))
                        .meet_either(by_constant(*a, *b))
                        .meet_either(by_constant(*b, *a))
                }
                Rule::Sub(a, b) => match delta(*b, views) {
                    Some(_) => indexed_of(*a),
                    None => Rooted::Not,
                },
                Rule::Merge(_) | Rule::Copy(_) => Rooted::Not,
            }
        },
    )?;
    let mut roots = IdMap::new(exact.len().max(cells.len()));
    for (id, cell) in cells.iter() {
        if let Some(root) = cell.root() {
            roots.insert(id, root);
        }
    }
    Ok(roots)
}
