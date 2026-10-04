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

use std::collections::BTreeMap;

use super::{SSAFunction, StackAddressBase, StackAddressRoot};
use crate::fixpoint::Exhausted;
use crate::op::SSAOp;
use crate::var::SSAVar;
use crate::view::ValueViews;

/// The solved roots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Roots {
    pub exact: BTreeMap<SSAVar, StackAddressRoot>,
    pub entry: BTreeMap<SSAVar, StackAddressRoot>,
    pub indexed: BTreeMap<SSAVar, StackAddressRoot>,
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
enum Rule<'a> {
    Merge(Vec<&'a SSAVar>),
    Copy(&'a SSAVar),
    Add(&'a SSAVar, &'a SSAVar),
    Sub(&'a SSAVar, &'a SSAVar),
}

/// The values a root can flow to, in definition order, with each one's
/// rule and who reads it.
struct Flow<'a> {
    order: Vec<SSAVar>,
    rules: BTreeMap<SSAVar, Rule<'a>>,
    readers: BTreeMap<SSAVar, Vec<SSAVar>>,
}

impl<'a> Flow<'a> {
    fn of(function: &'a SSAFunction, views: &ValueViews) -> Self {
        let mut flow = Self {
            order: Vec::new(),
            rules: BTreeMap::new(),
            readers: BTreeMap::new(),
        };
        for block in function.blocks() {
            for phi in block.phis() {
                let sources = phi.sources.iter().map(|(_, source)| source).collect();
                flow.define(&phi.dst, Rule::Merge(sources), views);
            }
            for op in block.ops() {
                let (dst, rule) = match op {
                    SSAOp::Copy { dst, src }
                    | SSAOp::Cast { dst, src }
                    | SSAOp::CallRestore { dst, src }
                        if dst.size == src.size =>
                    {
                        (dst, Rule::Copy(src))
                    }
                    SSAOp::IntAdd { dst, a, b } => (dst, Rule::Add(a, b)),
                    SSAOp::IntSub { dst, a, b } => (dst, Rule::Sub(a, b)),
                    _ => continue,
                };
                flow.define(dst, rule, views);
            }
        }
        flow
    }

    /// Record `dst`'s rule, and that it reads each operand and the
    /// operand's representative, whose root an operand also answers with.
    fn define(&mut self, dst: &SSAVar, rule: Rule<'a>, views: &ValueViews) {
        let inputs = match &rule {
            Rule::Merge(sources) => sources.clone(),
            Rule::Copy(src) => vec![*src],
            Rule::Add(a, b) | Rule::Sub(a, b) => vec![*a, *b],
        };
        for input in inputs {
            for read in [input, views.representative(input)] {
                self.readers
                    .entry(read.clone())
                    .or_default()
                    .push(dst.clone());
            }
        }
        self.order.push(dst.clone());
        self.rules.insert(dst.clone(), rule);
    }
}

/// Solve every root of `function` from its `exact` and `entry` seeds.
/// `entry_size` is the entry stack pointer's width, where entry roots are
/// solved at all.
pub(super) fn solve(
    function: &SSAFunction,
    views: &ValueViews,
    mut exact_seeds: BTreeMap<SSAVar, StackAddressRoot>,
    mut entry_seeds: BTreeMap<SSAVar, StackAddressRoot>,
    entry_size: Option<u32>,
) -> Result<Roots, Exhausted> {
    let flow = Flow::of(function, views);
    let mut exact = rooted(&flow, views, &exact_seeds, None)?;
    if let Some(origin) = realigned(function, views, &exact, entry_size) {
        let root = StackAddressRoot {
            base: StackAddressBase::Realigned,
            offset: 0,
        };
        exact_seeds.insert(origin.clone(), root);
        entry_seeds.insert(origin, root);
        exact = rooted(&flow, views, &exact_seeds, None)?;
    }
    let entry = match entry_size {
        Some(size) => rooted(&flow, views, &entry_seeds, Some(size))?,
        None => BTreeMap::new(),
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
    flow: &Flow<'_>,
    views: &ValueViews,
    seeds: &BTreeMap<SSAVar, StackAddressRoot>,
    width: Option<u32>,
) -> Result<BTreeMap<SSAVar, StackAddressRoot>, Exhausted> {
    let fits = |var: &SSAVar| width.is_none_or(|width| var.size == width);
    let cells = crate::fixpoint::sparse(
        "stack-roots",
        2,
        &flow.order,
        &flow.readers,
        Rooted::Pending,
        |dst, cells| {
            let of = |var: &SSAVar| value_of(var, views, seeds, cells);
            match &flow.rules[dst] {
                _ if !fits(dst) => Rooted::Not,
                Rule::Merge(sources) if sources.iter().all(|source| fits(source)) => sources
                    .iter()
                    .fold(Rooted::Pending, |held, source| held.meet(of(source))),
                Rule::Copy(src) if fits(src) => of(src),
                Rule::Add(a, b) if fits(a) && fits(b) => displaced(of(a), delta(b, views), 1)
                    .meet_either(displaced(of(b), delta(a, views), 1)),
                Rule::Sub(a, b) if fits(a) && fits(b) => displaced(of(a), delta(b, views), -1),
                _ => Rooted::Not,
            }
        },
    )?;
    let mut roots = seeds.clone();
    roots.extend(
        cells
            .into_iter()
            .filter_map(|(var, cell)| Some((var, cell.root()?))),
    );
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
/// bits; a seed or a constant answers at once.
fn value_of(
    var: &SSAVar,
    views: &ValueViews,
    seeds: &BTreeMap<SSAVar, StackAddressRoot>,
    cells: &BTreeMap<SSAVar, Rooted>,
) -> Rooted {
    let own = |var: &SSAVar| match seeds.get(var) {
        Some(root) => Rooted::At(*root),
        None => cells.get(var).copied().unwrap_or(Rooted::Not),
    };
    let representative = views.representative(var);
    match (own(var), own(representative)) {
        (Rooted::At(root), _) | (_, Rooted::At(root)) => Rooted::At(root),
        (Rooted::Pending, _) | (_, Rooted::Pending) => Rooted::Pending,
        (Rooted::Not, Rooted::Not) => Rooted::Not,
    }
}

/// The constant a value displaces an address by, read through a copy: an
/// AArch64 `add x29, sp, 0x60` materialises the `0x60` in a temporary.
pub(super) fn delta(var: &SSAVar, views: &ValueViews) -> Option<i64> {
    signed(var).or_else(|| signed(views.representative(var)))
}

/// A constant read as a signed displacement at its own width.
fn signed(var: &SSAVar) -> Option<i64> {
    let value = var.constant_bits()?;
    let bits = var.size.checked_mul(8)?;
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

/// The one value an `and` realigns the stack pointer into, where exactly
/// one does.
fn realigned(
    function: &SSAFunction,
    views: &ValueViews,
    exact: &BTreeMap<SSAVar, StackAddressRoot>,
    entry_size: Option<u32>,
) -> Option<SSAVar> {
    let aligns = |value: &SSAVar, mask: &SSAVar| {
        let root = exact
            .get(value)
            .or_else(|| exact.get(views.representative(value)));
        let alignment = delta(mask, views).and_then(i64::checked_neg);
        root.is_some_and(|root| root.base == StackAddressBase::StackPointer)
            && alignment.is_some_and(|alignment| {
                alignment >= 2 && alignment.unsigned_abs().is_power_of_two()
            })
    };
    let mut candidates = function
        .blocks()
        .iter()
        .flat_map(|block| block.ops())
        .filter_map(|op| match op {
            SSAOp::IntAnd { dst, a, b }
                if entry_size == Some(dst.size) && (aligns(a, b) || aligns(b, a)) =>
            {
                Some(dst.clone())
            }
            _ => None,
        });
    let origin = candidates.next()?;
    if candidates.next().is_some() {
        r2il::refusal_evidence!(
            "stack-root-realign",
            "{:#x}: more than one mask realigns the stack pointer",
            function.entry
        );
        return None;
    }
    r2il::refusal_evidence!(
        "stack-root-realign",
        "{:#x}: {origin} is the realigned frame's origin",
        function.entry
    );
    Some(origin)
}

/// The frame object each sum or difference without an exact root is inside,
/// where one operand is inside it and the other is an index nothing folds:
/// `buf + i`, `buf + i + 4`, `buf + i - 3`.
fn indexed(
    flow: &Flow<'_>,
    views: &ValueViews,
    exact: &BTreeMap<SSAVar, StackAddressRoot>,
) -> Result<BTreeMap<SSAVar, StackAddressRoot>, Exhausted> {
    let exact_of = |var: &SSAVar| {
        exact
            .get(var)
            .or_else(|| exact.get(views.representative(var)))
            .copied()
    };
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
            let indexed_of = |var: &SSAVar| {
                let own = |var: &SSAVar| cells.get(var).copied().unwrap_or(Rooted::Not);
                own(var).meet_either(own(views.representative(var)))
            };
            // Inside an object: exactly placed in it, or already indexed.
            let inside = |var: &SSAVar| match exact_of(var) {
                Some(root) => Rooted::At(root),
                None => indexed_of(var),
            };
            // An index nothing folds and that is no position in an object.
            let opaque = |var: &SSAVar| {
                delta(var, views).is_none()
                    && exact_of(var).is_none()
                    && indexed_of(var) == Rooted::Not
            };
            match &flow.rules[dst] {
                Rule::Add(a, b) => {
                    let by_index = |base: &SSAVar, index: &SSAVar| match opaque(index) {
                        true => inside(base),
                        false => Rooted::Not,
                    };
                    let by_constant =
                        |base: &SSAVar, constant: &SSAVar| match delta(constant, views) {
                            Some(_) => indexed_of(base),
                            None => Rooted::Not,
                        };
                    by_index(a, b)
                        .meet_either(by_index(b, a))
                        .meet_either(by_constant(a, b))
                        .meet_either(by_constant(b, a))
                }
                Rule::Sub(a, b) => match delta(b, views) {
                    Some(_) => indexed_of(a),
                    None => Rooted::Not,
                },
                Rule::Merge(_) | Rule::Copy(_) => Rooted::Not,
            }
        },
    )?;
    Ok(cells
        .into_iter()
        .filter_map(|(var, cell)| Some((var, cell.root()?)))
        .collect())
}
