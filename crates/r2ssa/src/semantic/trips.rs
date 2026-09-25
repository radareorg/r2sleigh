//! How many times a loop's header runs, from its induction, its exit test and the values it compares (doc/ssa.md, "Loop trip counts").

use super::*;
use crate::values::ValueRanges;

/// One loop as its count reads it.
pub(crate) struct TripLoop<'a> {
    pub(crate) loop_: NaturalLoop<'a>,
    pub(crate) condition: Option<PredicateId>,
    pub(crate) inductions: &'a [InductionFact],
}

/// Trip counts for one function's loops.
pub(crate) struct TripCounter<'a> {
    function: &'a SSAFunction,
    graph: &'a SsaGraph,
    predicates: &'a PredicateFacts,
    values: &'a ValueRanges,
    /// Each value's form modulo a width, or the value whose definition is not affine.
    forms: BTreeMap<(u32, ValueId), Result<Form, ValueId>>,
}

/// The exit test resolved against the induction it reads.
struct ExitTest<'a> {
    induction: &'a InductionFact,
    evidence: TripTest,
    /// The step as a signed integer: the addend, or the subtrahend negated.
    delta: i128,
    exit: Exit,
}

/// When control leaves, read as the tested iterate against the bound.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Exit {
    Equal,
    Unequal,
    Ordered(Order),
}

/// An ordered comparison: the iterate's relation to the bound, read signed or not.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Order {
    relation: Relation,
    signed: bool,
}

/// The iterate's order against the bound.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Relation {
    Below,
    AtMost,
    Above,
    AtLeast,
}

/// How a definition is affine in its operands, modulo any width its operands keep.
#[derive(Clone, Copy)]
enum Affine {
    Same(ValueId),
    Negated(ValueId),
    Sum(ValueId, ValueId),
    Difference(ValueId, ValueId),
    Product(ValueId, ValueId),
    Shifted(ValueId, ValueId),
}

/// `Σ coefficient·value + constant` modulo a width the caller carries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Form {
    terms: BTreeMap<ValueId, u64>,
    constant: u64,
}

impl ExitTest<'_> {
    /// One where the test reads the update, a step ahead of the merge.
    const fn ahead(&self) -> u64 {
        self.evidence.reads_update as u64
    }
}

impl<'a> TripCounter<'a> {
    pub(crate) fn new(
        function: &'a SSAFunction,
        graph: &'a SsaGraph,
        predicates: &'a PredicateFacts,
        values: &'a ValueRanges,
    ) -> Self {
        Self {
            function,
            graph,
            predicates,
            values,
            forms: BTreeMap::new(),
        }
    }

    /// The header's run count with the test that proves it, or why none is stated.
    pub(crate) fn count(&mut self, lp: &TripLoop<'_>) -> Result<LoopTrips, TripRefusal> {
        let exiting = single_exit(self.function, lp.loop_)?;
        let test = self.exit_test(lp, exiting)?;
        let width = test.induction.width_bits;
        let bound = self.form(test.evidence.bound, width);
        if bound
            .as_ref()
            .is_err_and(|blocker| self.defined_in(*blocker, lp.loop_.body))
        {
            return Err(TripRefusal::BoundVariesInLoop);
        }
        let start = self.form(test.induction.init, width);
        let count = match test.exit {
            Exit::Equal => {
                let (Ok(start), Ok(bound)) = (start, bound) else {
                    return Err(TripRefusal::BoundNotAffine);
                };
                self.equal_trips(lp.loop_.header, &test, &bound.minus(&start, width))?
            }
            exit => {
                let (Some(start), Some(bound)) = (constant(&start), constant(&bound)) else {
                    return Err(TripRefusal::CountNotAffine);
                };
                exact(match exit {
                    Exit::Ordered(order) => order.first(&test, start, bound)?,
                    _ => first_unequal(&test, start, bound),
                })?
            }
        };
        Ok(LoopTrips {
            count,
            test: test.evidence,
        })
    }

    /// The exiting block's comparison, where one side is an induction's merge or update.
    fn exit_test<'l>(&self, lp: &TripLoop<'l>, exiting: u64) -> Result<ExitTest<'l>, TripRefusal> {
        let body = lp.loop_.body;
        let predicate = lp
            .condition
            .and_then(|id| self.predicates.predicates.get(&id))
            .filter(|fact| {
                fact.block_addr == exiting
                    && body.contains(&fact.true_target) != body.contains(&fact.false_target)
            })
            .ok_or(TripRefusal::ExitNotInduction)?;
        let tested = [&predicate.comparison, &predicate.evaluated_comparison]
            .into_iter()
            .flatten()
            .find_map(|compare| self.tested_induction(lp, predicate, compare));
        tested.unwrap_or(Err(TripRefusal::ExitNotInduction))
    }

    /// The test where one side of `compare` is a single-latch induction's merge or update at its width.
    fn tested_induction<'l>(
        &self,
        lp: &TripLoop<'l>,
        predicate: &PredicateFact,
        compare: &CompareProvenance,
    ) -> Option<Result<ExitTest<'l>, TripRefusal>> {
        let leaves_when = !lp.loop_.body.contains(&predicate.true_target);
        let sides = [
            (compare.lhs, compare.rhs, true),
            (compare.rhs, compare.lhs, false),
        ];
        sides.into_iter().find_map(|(tested, bound, tested_left)| {
            let (induction, reads_update) = lp.inductions.iter().find_map(|induction| {
                (induction.phi == tested)
                    .then_some((induction, false))
                    .or((induction.update == tested).then_some((induction, true)))
            })?;
            let width = Some(induction.width_bits);
            let fits = lp.loop_.latches.len() == 1
                && lp.loop_.latches.contains(&induction.latch)
                && self.width_of(tested) == width
                && self.width_of(bound) == width
                && induction.validate(self.graph);
            fits.then(|| {
                Ok(ExitTest {
                    induction,
                    evidence: TripTest {
                        predicate: predicate.id,
                        induction: induction.phi,
                        reads_update,
                        bound,
                    },
                    delta: additive(induction.step)?,
                    exit: exit_of(compare.kind, tested_left, leaves_when),
                })
            })
        })
    }

    /// A count from an equality exit: exact for constant ends, or symbolic where a guard rules out its zero.
    fn equal_trips(
        &mut self,
        header: u64,
        test: &ExitTest<'_>,
        difference: &Form,
    ) -> Result<TripCount, TripRefusal> {
        let width = test.induction.width_bits;
        let step = test.induction.step.apply(0, width);
        if let Some(difference) = difference.as_constant() {
            return exact(first_equal(difference, step, test.ahead(), width)?);
        }
        if step & 1 == 0 {
            return Err(TripRefusal::EvenStep);
        }
        // `(k + ahead)·step ≡ difference`, so the count `k + 1` is `difference·step⁻¹ + 1 − ahead`.
        let count = difference
            .scaled(inverse(step), width)
            .plus(&Form::constant(1 - test.ahead(), width), width);
        let guard = self
            .zero_guard(header, &count, width)
            .ok_or(TripRefusal::ZeroNotExcluded)?;
        Ok(TripCount::Symbolic {
            form: EntryAffineForm {
                width_bits: width,
                terms: count.terms,
                constant: count.constant,
            },
            guard,
        })
    }

    /// The nearest assumption holding at the header, or a block dominating it, that proves the count is not zero.
    fn zero_guard(&mut self, header: u64, count: &Form, width: u32) -> Option<TripGuard> {
        let domtree = self.function.domtree();
        let mut at = Some(header);
        while let Some(block) = at {
            if let Some(assumption) = self.nonzero_at(block, count, width) {
                return Some(TripGuard { block, assumption });
            }
            at = domtree.idom(block);
        }
        None
    }

    /// An edge that dominates `block` testing two sides whose difference is a unit multiple of the count.
    fn nonzero_at(&mut self, block: u64, count: &Form, width: u32) -> Option<BlockAssumption> {
        let (function, predicates) = (self.function, self.predicates);
        let assumptions = predicates.block_assumptions.get(&block).into_iter();
        assumptions
            .flatten()
            .filter(|assumption| {
                crate::values::edge_dominates(function, assumption.predecessor, block)
            })
            .find(|assumption| {
                let Some(fact) = predicates.predicates.get(&assumption.predicate) else {
                    return false;
                };
                fact.true_target != fact.false_target
                    && [&fact.comparison, &fact.evaluated_comparison]
                        .into_iter()
                        .flatten()
                        .filter(|compare| implies_unequal(compare.kind, assumption.truth))
                        .any(|compare| self.difference_divides(compare, count, width))
            })
            .cloned()
    }

    /// Whether `lhs − rhs` is an odd multiple of the count at its width.
    fn difference_divides(
        &mut self,
        compare: &CompareProvenance,
        count: &Form,
        width: u32,
    ) -> bool {
        if self.width_of(compare.lhs) != Some(width) {
            return false;
        }
        match (self.form(compare.lhs, width), self.form(compare.rhs, width)) {
            (Ok(lhs), Ok(rhs)) => unit_multiple(&lhs.minus(&rhs, width), count, width),
            _ => false,
        }
    }

    fn width_of(&self, value: ValueId) -> Option<u32> {
        self.graph
            .value(value)
            .map(|value| value.var.size.saturating_mul(8))
    }

    fn defined_in(&self, value: ValueId, body: &BTreeSet<u64>) -> bool {
        self.graph
            .def_inst(value)
            .and_then(|inst| self.graph.inst(inst))
            .and_then(|inst| self.graph.block(inst.block))
            .is_some_and(|block| body.contains(&block.addr))
    }

    /// The value's affine form over entry values modulo `2^width`, or the value that stops it.
    fn form(&mut self, value: ValueId, width: u32) -> Result<Form, ValueId> {
        let mut pending = vec![(value, false)];
        let mut open = BTreeSet::new();
        while let Some((at, operands_known)) = pending.pop() {
            if self.forms.contains_key(&(width, at)) {
                continue;
            }
            let known = match (operands_known, open.insert(at)) {
                (true, _) => Some(self.combine(at, width)),
                // A cycle reached through no merge is not a definition this can read.
                (false, false) => Some(Err(at)),
                (false, true) => self.leaf(at, width),
            };
            if let Some(known) = known {
                self.forms.insert((width, at), known);
                continue;
            }
            pending.push((at, true));
            let operands = self.affine(at).map_or_else(Vec::new, operands_of);
            pending.extend(operands.into_iter().map(|operand| (operand, false)));
        }
        self.forms
            .get(&(width, value))
            .cloned()
            .unwrap_or(Err(value))
    }

    /// The form a value has without reading its operands, where it has one.
    fn leaf(&self, at: ValueId, width: u32) -> Option<Result<Form, ValueId>> {
        if self.width_of(at).is_none_or(|bits| bits < width) {
            return Some(Err(at));
        }
        if let Some(constant) = self.constant_value(at) {
            return Some(Ok(Form::constant(constant, width)));
        }
        if self.graph.def_inst(at).is_none() {
            return Some(Ok(Form::atom(at)));
        }
        self.affine(at).is_none().then_some(Err(at))
    }

    fn constant_value(&self, at: ValueId) -> Option<u64> {
        let literal = self.graph.value(at)?.var.constant_bits();
        literal.or_else(|| self.values.get(at)?.as_constant())
    }

    fn affine(&self, at: ValueId) -> Option<Affine> {
        let inst = self.graph.inst(self.graph.def_inst(at)?)?;
        let InstPayload::Op(op) = &inst.payload else {
            return None;
        };
        let input = |index: usize| inst.inputs.get(index).copied();
        let (first, second) = (input(0)?, input(1));
        Some(match op {
            SSAOp::Copy { .. }
            | SSAOp::IntZExt { .. }
            | SSAOp::IntSExt { .. }
            | SSAOp::Trunc { .. }
            | SSAOp::Subpiece { offset: 0, .. } => Affine::Same(first),
            SSAOp::IntAnd { .. } | SSAOp::IntOr { .. } if second == Some(first) => {
                Affine::Same(first)
            }
            SSAOp::IntNegate { .. } => Affine::Negated(first),
            SSAOp::IntAdd { .. } => Affine::Sum(first, second?),
            SSAOp::IntSub { .. } => Affine::Difference(first, second?),
            SSAOp::IntMult { .. } => Affine::Product(first, second?),
            SSAOp::IntLeft { .. } => Affine::Shifted(first, second?),
            _ => return None,
        })
    }

    /// A definition's form from its operands' forms, which are already known.
    fn combine(&self, at: ValueId, width: u32) -> Result<Form, ValueId> {
        let form = |operand: ValueId| {
            self.forms
                .get(&(width, operand))
                .cloned()
                .unwrap_or(Err(operand))
        };
        match self.affine(at).ok_or(at)? {
            Affine::Same(value) => form(value),
            Affine::Negated(value) => Ok(form(value)?.scaled(mask(width), width)),
            Affine::Sum(left, right) => Ok(form(left)?.plus(&form(right)?, width)),
            Affine::Difference(left, right) => Ok(form(left)?.minus(&form(right)?, width)),
            Affine::Product(left, right) => {
                let (left, right) = (form(left)?, form(right)?);
                match (left.as_constant(), right.as_constant()) {
                    (Some(factor), _) => Ok(right.scaled(factor, width)),
                    (_, Some(factor)) => Ok(left.scaled(factor, width)),
                    _ => Err(at),
                }
            }
            Affine::Shifted(value, places) => {
                let places = self.constant_value(places).ok_or(at)?;
                let factor = u32::try_from(places)
                    .ok()
                    .and_then(|places| 1u64.checked_shl(places))
                    .unwrap_or(0);
                Ok(form(value)?.scaled(factor, width))
            }
        }
    }
}

impl Form {
    fn constant(value: u64, width: u32) -> Self {
        Self {
            terms: BTreeMap::new(),
            constant: value & mask(width),
        }
    }

    fn atom(value: ValueId) -> Self {
        Self {
            terms: BTreeMap::from([(value, 1)]),
            constant: 0,
        }
    }

    fn as_constant(&self) -> Option<u64> {
        self.terms.is_empty().then_some(self.constant)
    }

    fn plus(&self, other: &Self, width: u32) -> Self {
        let mut sum = self.clone();
        for (value, coefficient) in &other.terms {
            let entry = sum.terms.entry(*value).or_default();
            *entry = entry.wrapping_add(*coefficient) & mask(width);
        }
        sum.terms.retain(|_, coefficient| *coefficient != 0);
        sum.constant = sum.constant.wrapping_add(other.constant) & mask(width);
        sum
    }

    fn minus(&self, other: &Self, width: u32) -> Self {
        self.plus(&other.scaled(mask(width), width), width)
    }

    fn scaled(&self, factor: u64, width: u32) -> Self {
        Self {
            terms: self
                .terms
                .iter()
                .map(|(value, coefficient)| {
                    (*value, coefficient.wrapping_mul(factor) & mask(width))
                })
                .filter(|(_, coefficient)| *coefficient != 0)
                .collect(),
            constant: self.constant.wrapping_mul(factor) & mask(width),
        }
    }
}

fn operands_of(affine: Affine) -> Vec<ValueId> {
    match affine {
        Affine::Same(value) | Affine::Negated(value) | Affine::Shifted(value, _) => vec![value],
        Affine::Sum(left, right)
        | Affine::Difference(left, right)
        | Affine::Product(left, right) => vec![left, right],
    }
}

fn constant(form: &Result<Form, ValueId>) -> Option<u64> {
    form.as_ref().ok()?.as_constant()
}

/// The count one more than the last trip's index, which a `u64` holds unless it is `2^64`.
fn exact(first: u128) -> Result<TripCount, TripRefusal> {
    u64::try_from(first + 1)
        .map(TripCount::Exact)
        .map_err(|_| TripRefusal::ZeroNotExcluded)
}

/// The least `k ≥ 0` with `(k + ahead)·step ≡ difference` modulo `2^width`.
fn first_equal(difference: u64, step: u64, ahead: u64, width: u32) -> Result<u128, TripRefusal> {
    let twos = step.trailing_zeros();
    if twos >= width || difference & mask(twos) != 0 {
        return Err(TripRefusal::EvenStep);
    }
    let period = width - twos;
    let solution = (difference >> twos).wrapping_mul(inverse(step >> twos)) & mask(period);
    let modulus = 1u128 << period;
    Ok((u128::from(solution) + modulus - u128::from(ahead)) % modulus)
}

/// An exit taken when the iterate differs from the bound: the first iterate, or the one after it.
fn first_unequal(test: &ExitTest<'_>, start: u64, bound: u64) -> u128 {
    let width = test.induction.width_bits;
    let step = test.induction.step.apply(0, width);
    let first = start.wrapping_add(test.ahead().wrapping_mul(step)) & mask(width);
    u128::from(first == bound)
}

impl Order {
    /// The least `k` at which the exit holds, where every iterate up to it keeps its width and sign.
    fn first(self, test: &ExitTest<'_>, start: u64, bound: u64) -> Result<u128, TripRefusal> {
        let Self { relation, signed } = self;
        let (width, delta) = (test.induction.width_bits, test.delta);
        let (low, high) = span(width, signed);
        let first = read(start, width, signed) + i128::from(test.ahead()) * delta;
        let bound = read(bound, width, signed);
        let reached = match relation {
            Relation::AtLeast => at_least(first, delta, bound),
            Relation::Above => at_least(first, delta, bound + 1),
            Relation::AtMost => at_least(-first, -delta, -bound),
            Relation::Below => at_least(-first, -delta, 1 - bound),
        };
        let steps = reached.ok_or(TripRefusal::MayWrap)?;
        let last = first + steps * delta;
        match (low..=high).contains(&first) && (low..=high).contains(&last) {
            true => u128::try_from(steps).map_err(|_| TripRefusal::MayWrap),
            false => Err(TripRefusal::MayWrap),
        }
    }
}

/// The step as a signed integer, where it adds or subtracts a constant.
fn additive(step: InductionStep) -> Result<i128, TripRefusal> {
    match step {
        InductionStep::AddConst(addend) => Ok(i128::from(addend)),
        InductionStep::SubConst(subtrahend) => Ok(-i128::from(subtrahend)),
        InductionStep::Affine { .. } => Err(TripRefusal::AffineStep),
    }
}

impl StructuredLoopFact {
    /// Whether the stated trips are what this loop's graph proves, recounted from its blocks and inductions.
    pub fn validate_trips(&self, artifact: &crate::SsaArtifact) -> bool {
        let function = artifact.function();
        let body = self.body.iter().copied().collect::<BTreeSet<_>>();
        let latches = self.latches.iter().copied().collect::<BTreeSet<_>>();
        let exits = LoopExits::of(function, &body);
        let inductions = artifact.structured().inductions.values();
        let inductions = inductions
            .filter(|induction| induction.loop_id == self.id)
            .cloned()
            .collect::<Vec<_>>();
        let lp = TripLoop {
            loop_: NaturalLoop {
                id: self.id,
                header: self.header,
                latches: &latches,
                body: &body,
                exits: &exits,
            },
            condition: self.condition,
            inductions: &inductions,
        };
        let (graph, predicates) = (artifact.graph(), artifact.predicates());
        TripCounter::new(function, graph, predicates, artifact.values()).count(&lp) == self.trips
    }
}

/// The block whose edge is the loop's only way out, where it tests on every trip.
fn single_exit(function: &SSAFunction, loop_: NaturalLoop<'_>) -> Result<u64, TripRefusal> {
    if loop_.exits.leaves_function {
        return Err(TripRefusal::BodyLeaves);
    }
    let mut edges = loop_.exits.edges.iter();
    let (Some((exiting, _)), None) = (edges.next(), edges.next()) else {
        return Err(TripRefusal::MultipleExits);
    };
    match loop_
        .latches
        .iter()
        .all(|latch| function.dominates(*exiting, *latch))
    {
        true => Ok(*exiting),
        false => Err(TripRefusal::ExitSkipped),
    }
}

/// The least `k ≥ 0` with `start + k·step ≥ target` over the integers.
fn at_least(start: i128, step: i128, target: i128) -> Option<i128> {
    if start >= target {
        return Some(0);
    }
    (step > 0).then(|| (target - start + step - 1) / step)
}

/// A value of a width read as an integer, signed or not.
fn read(value: u64, width: u32, signed: bool) -> i128 {
    let value = i128::from(value & mask(width));
    match signed && (value >> (width - 1)) & 1 == 1 {
        true => value - (1i128 << width),
        false => value,
    }
}

/// The integers a width holds, signed or not.
fn span(width: u32, signed: bool) -> (i128, i128) {
    match signed {
        true => (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1),
        false => (0, (1i128 << width) - 1),
    }
}

/// Whether `lhs kind rhs` taken the way `truth` says makes the two sides differ.
fn implies_unequal(kind: CompareKind, truth: bool) -> bool {
    matches!(
        (kind, truth),
        (CompareKind::Equal, false)
            | (
                CompareKind::NotEqual | CompareKind::Less | CompareKind::SignedLess,
                true
            )
            | (CompareKind::LessEqual | CompareKind::SignedLessEqual, false)
    )
}

/// Whether `difference` is the count times an odd factor, so one is zero exactly when the other is.
fn unit_multiple(difference: &Form, count: &Form, width: u32) -> bool {
    let Some((value, coefficient)) = count.terms.iter().find(|(_, c)| *c & 1 == 1) else {
        return difference == count || *difference == count.scaled(mask(width), width);
    };
    let unit = difference.terms.get(value).map_or(0, |found| {
        found.wrapping_mul(inverse(*coefficient)) & mask(width)
    });
    unit & 1 == 1 && *difference == count.scaled(unit, width)
}

/// When control leaves, from the comparison, the side the iterate is on, and the truth that leaves.
fn exit_of(kind: CompareKind, tested_left: bool, leaves_when: bool) -> Exit {
    let (relation, signed) = match kind {
        CompareKind::Equal | CompareKind::NotEqual => {
            return match (kind == CompareKind::Equal) == leaves_when {
                true => Exit::Equal,
                false => Exit::Unequal,
            };
        }
        CompareKind::Less => (Relation::Below, false),
        CompareKind::SignedLess => (Relation::Below, true),
        CompareKind::LessEqual => (Relation::AtMost, false),
        CompareKind::SignedLessEqual => (Relation::AtMost, true),
    };
    let relation = match tested_left {
        true => relation,
        false => relation.mirrored(),
    };
    let relation = match leaves_when {
        true => relation,
        false => relation.negated(),
    };
    Exit::Ordered(Order { relation, signed })
}

impl Relation {
    /// The same order with its sides swapped: `b < x` is `x > b`.
    const fn mirrored(self) -> Self {
        match self {
            Self::Below => Self::Above,
            Self::AtMost => Self::AtLeast,
            Self::Above => Self::Below,
            Self::AtLeast => Self::AtMost,
        }
    }

    /// The order that holds where this one does not: `!(x < b)` is `x >= b`.
    const fn negated(self) -> Self {
        match self {
            Self::Below => Self::AtLeast,
            Self::AtMost => Self::Above,
            Self::Above => Self::AtMost,
            Self::AtLeast => Self::Below,
        }
    }
}

/// An odd number is its own inverse to three bits, and each round doubles them: `3·2^5 = 96 ≥ 64`.
const NEWTON_ROUNDS: usize = 5;

/// The inverse of an odd number modulo `2^64`, by Newton's iteration doubling the correct bits.
fn inverse(odd: u64) -> u64 {
    (0..NEWTON_ROUNDS).fold(odd, |inverse, _| {
        inverse.wrapping_mul(2u64.wrapping_sub(odd.wrapping_mul(inverse)))
    })
}

const fn mask(width: u32) -> u64 {
    match width >= 64 {
        true => u64::MAX,
        false => (1u64 << width) - 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SsaArtifact;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, Varnode};

    type Trips = Result<TripCount, TripRefusal>;

    /// Code mapped at one address, in a program that declares no other function.
    struct Code {
        base: u64,
        bytes: &'static [u8],
    }

    impl crate::body::Program for Code {
        fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
            let offset = usize::try_from(vaddr.checked_sub(self.base)?).ok()?;
            let slice = self.bytes.get(offset..).filter(|slice| !slice.is_empty())?;
            Some(slice[..slice.len().min(max)].to_vec())
        }

        /// The code is the one run it maps, and it runs.
        fn region(&self, vaddr: u64) -> Option<crate::body::Region> {
            let end = self.base + self.bytes.len() as u64;
            (self.base..end)
                .contains(&vaddr)
                .then_some(crate::body::Region {
                    start: self.base,
                    end,
                    execute: true,
                    write: false,
                })
        }

        fn is_entry(&self, _vaddr: u64) -> bool {
            false
        }
    }

    /// The function the bytes begin at `entry`, lifted and prepared.
    fn lifted(arch: &str, code: Code, entry: u64) -> SsaArtifact {
        let machine = r2sleigh_lift::embedded_machine(arch).expect("an embedded machine");
        let body = crate::body::lift_body(entry, &machine.disasm, &code, &BTreeMap::new())
            .expect("the body lifts");
        let blocks = body
            .blocks
            .iter()
            .map(|block| block.lifted.clone())
            .collect::<Vec<_>>();
        SsaArtifact::for_decompile(&blocks, Some(&machine.arch)).expect("an artifact")
    }

    /// The trip counts of 32-bit x86 code mapped at `0x1000`.
    fn x86(bytes: &'static [u8]) -> Vec<Trips> {
        trips_of(&lifted(
            "x86",
            Code {
                base: 0x1000,
                bytes,
            },
            0x1000,
        ))
    }

    /// Each loop's count, once its stated trips recount the same from the graph.
    fn trips_of(artifact: &SsaArtifact) -> Vec<Trips> {
        let loops = artifact.structured().loops.values();
        let checked = loops.inspect(|fact| assert!(fact.validate_trips(artifact)));
        checked.map(|fact| Ok(fact.trips.clone()?.count)).collect()
    }

    /// `counter = start`, then a header that runs `ops` and branches back while `cond` holds.
    fn self_loop(size: u32, start: u64, ops: Vec<R2ILOp>) -> Vec<Trips> {
        let mut arch = ArchSpec::new("trip-test");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("rip", 16, 8));
        arch.add_register(RegisterDef::new("cond", 24, 1));
        arch.add_register(RegisterDef::new("counter", 40, size));
        let mut entry = R2ILBlock::new(0x7000, 4);
        entry.push(R2ILOp::Copy {
            dst: counter(size),
            src: Varnode::constant(start, size),
        });
        entry.push(R2ILOp::Branch {
            target: Varnode::ram(0x7010, 8),
        });
        let mut header = R2ILBlock::new(0x7010, 4);
        for op in ops {
            header.push(op);
        }
        header.push(R2ILOp::CBranch {
            target: Varnode::ram(0x7010, 8),
            cond: cond(),
        });
        let mut exit = R2ILBlock::new(0x7014, 4);
        exit.push(R2ILOp::Return {
            target: Varnode::register(16, 8),
        });
        let artifact = SsaArtifact::for_decompile(&[entry, header, exit], Some(&arch));
        trips_of(&artifact.expect("an artifact"))
    }

    fn counter(size: u32) -> Varnode {
        Varnode::register(40, size)
    }

    fn cond() -> Varnode {
        Varnode::register(24, 1)
    }

    fn step(size: u32, addend: u64) -> R2ILOp {
        R2ILOp::IntAdd {
            dst: counter(size),
            a: counter(size),
            b: Varnode::constant(addend, size),
        }
    }

    #[test]
    fn a_counted_down_register_runs_its_start_many_times() {
        // mov edx, 8; L: sub edx, 1; jne L; ret
        let bytes = &[0xba, 0x08, 0, 0, 0, 0x83, 0xea, 0x01, 0x75, 0xfb, 0xc3];
        assert_eq!(x86(bytes), [Ok(TripCount::Exact(8))]);
    }

    #[test]
    fn an_equality_exit_is_solved_through_wrap_by_the_steps_inverse() {
        // An 8-bit counter from 10 by 3 meets 5 only after wrapping: 10 + 3·169 = 517 = 2·256 + 5.
        let ops = vec![
            R2ILOp::IntNotEqual {
                dst: cond(),
                a: counter(1),
                b: Varnode::constant(5, 1),
            },
            step(1, 3),
        ];
        assert_eq!(self_loop(1, 10, ops), [Ok(TripCount::Exact(170))]);
    }

    #[test]
    fn a_carrier_wider_than_a_word_states_no_count() {
        let ops = vec![
            R2ILOp::IntNotEqual {
                dst: cond(),
                a: counter(16),
                b: Varnode::constant(5, 16),
            },
            step(16, 3),
        ];
        assert_eq!(self_loop(16, 10, ops), [Err(TripRefusal::ExitNotInduction)]);
    }

    #[test]
    fn an_ordered_exit_counts_where_no_iterate_wraps_and_refuses_where_one_may() {
        // From 0 by 4 while the update is below 100: the update reaches 100 on the twenty-fifth run.
        let below = |size: u32, bound: u64| R2ILOp::IntLess {
            dst: cond(),
            a: counter(size),
            b: Varnode::constant(bound, size),
        };
        let counted = self_loop(8, 0, vec![step(8, 4), below(8, 100)]);
        assert_eq!(counted, [Ok(TripCount::Exact(25))]);
        // From 250 by 4 at eight bits: the second update is 258, which the byte cannot hold.
        let wrapping = self_loop(1, 250, vec![step(1, 4), below(1, 255)]);
        assert_eq!(wrapping, [Err(TripRefusal::MayWrap)]);
        // A signed byte from -10 by 3 while the update is below 5: -10, -7, -4, -1, 2.
        let signed_below = |bound: u64| R2ILOp::IntSLess {
            dst: cond(),
            a: counter(1),
            b: Varnode::constant(bound, 1),
        };
        let signed = self_loop(1, 0xf6, vec![step(1, 3), signed_below(5)]);
        assert_eq!(signed, [Ok(TripCount::Exact(5))]);
        // From 120 by 4 while below 127: the second update is 128, past the sign boundary.
        let crossing = self_loop(1, 120, vec![step(1, 4), signed_below(127)]);
        assert_eq!(crossing, [Err(TripRefusal::MayWrap)]);
    }

    #[test]
    fn an_even_step_counts_only_where_it_divides_the_distance() {
        // mov edx, 7; L: sub edx, 2; jne L; ret -- seven is odd, so zero is never reached.
        let from_seven = &[0xba, 0x07, 0, 0, 0, 0x83, 0xea, 0x02, 0x75, 0xfb, 0xc3];
        assert_eq!(x86(from_seven), [Err(TripRefusal::EvenStep)]);
        // mov edx, 8; L: sub edx, 2; jne L; ret -- 8, 6, 4, 2.
        let from_eight = &[0xba, 0x08, 0, 0, 0, 0x83, 0xea, 0x02, 0x75, 0xfb, 0xc3];
        assert_eq!(x86(from_eight), [Ok(TripCount::Exact(4))]);
    }

    #[test]
    fn a_bound_loaded_inside_the_loop_or_a_second_exit_states_no_count() {
        // mov edx, 8; L: mov ecx, [eax]; sub edx, 1; cmp edx, ecx; jne L; ret
        let loaded = &[
            0xba, 0x08, 0, 0, 0, 0x8b, 0x08, 0x83, 0xea, 0x01, 0x39, 0xca, 0x75, 0xf7, 0xc3,
        ];
        assert_eq!(x86(loaded), [Err(TripRefusal::BoundVariesInLoop)]);
        // mov edx, 8; L: test ecx, ecx; je out; sub edx, 1; jne L; out: ret
        let two_exits = &[
            0xba, 0x08, 0, 0, 0, 0x85, 0xc9, 0x74, 0x05, 0x83, 0xea, 0x01, 0x75, 0xf7, 0xc3,
        ];
        assert_eq!(x86(two_exits), [Err(TripRefusal::MultipleExits)]);
    }

    /// `fnv1a32` from `hashes_gcc_x64_O2`, `0x401330` to `0x401366`.
    const FNV1A32: &[u8] = &[
        0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x85, 0xf6, 0x74, 0x27, 0x48, 0x01, 0xfe, 0xb8, 0xc5, 0x9d,
        0x1c, 0x81, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xb6, 0x17, 0x48, 0x83, 0xc7,
        0x01, 0x31, 0xd0, 0x69, 0xc0, 0x93, 0x01, 0x00, 0x01, 0x48, 0x39, 0xfe, 0x75, 0xec, 0xc3,
        0x0f, 0x1f, 0x00, 0xb8, 0xc5, 0x9d, 0x1c, 0x81, 0xc3,
    ];

    #[test]
    fn a_pointer_walked_to_its_end_runs_its_length_once_the_guard_excludes_zero() {
        let code = || Code {
            base: 0x401330,
            bytes: FNV1A32,
        };
        let artifact = lifted("x86-64", code(), 0x401330);
        let length = artifact
            .graph()
            .values
            .iter()
            .find(|value| value.var.to_string() == "RSI_0")
            .expect("rsi at entry")
            .id;
        let form = EntryAffineForm {
            width_bits: 64,
            terms: BTreeMap::from([(length, 1)]),
            constant: 0,
        };
        let [
            Ok(TripCount::Symbolic {
                form: counted,
                guard,
            }),
        ] = &trips_of(&artifact)[..]
        else {
            panic!("one symbolic count");
        };
        assert_eq!(*counted, form);
        // The guard is `test rsi, rsi; je` taken not equal, on the edge into the preheader.
        let (block, assumption) = (guard.block, &guard.assumption);
        assert_eq!(
            (block, assumption.predecessor, assumption.truth),
            (0x401339, 0x401330, false)
        );
        // The test is `cmp rsi, rdi` after `add rdi, 1`: the pointer's update against the end.
        let loop_fact = artifact
            .structured()
            .loops
            .values()
            .next()
            .expect("the loop");
        let test = loop_fact.trips.as_ref().expect("a count").test;
        let name = |value: ValueId| artifact.graph().value(value).map(|v| v.var.to_string());
        let tested = (name(test.induction), name(test.bound), test.reads_update);
        assert_eq!(tested, (Some("RDI_1".into()), Some("RSI_1".into()), true));
        // Entered past `test rsi, rsi; je`, nothing says the length is not zero, which is 2^64 trips.
        let unguarded = lifted("x86-64", code(), 0x401339);
        assert_eq!(trips_of(&unguarded), [Err(TripRefusal::ZeroNotExcluded)]);
    }
}
