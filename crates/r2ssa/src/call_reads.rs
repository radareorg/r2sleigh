//! What one call may read of its convention's argument locations, derived once per callee
//! statement (doc/adr-result-side.md, "What a call reads, and what escapes").

use r2source::convention::SlotClass;
use r2source::{
    CanonicalStorageId, ConventionModel, SourceCallSiteInterface, SourceParameterLocation,
};

use crate::site_boundary::{LaneBytes, ResultLanes};

/// Where a printf-family call's format arrives, and the tail's vector registers, which only a
/// floating conversion reads (doc/adr-call-boundary.md, "S15 as built").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatTail {
    pub format: CanonicalStorageId,
    pub floats: Vec<CanonicalStorageId>,
}

/// Stack ranges from a call's pointer; `None` where nothing bounds them.
pub type StackArea = Option<Vec<(i64, i64)>>;

/// What a call to one callee may write of its caller's stack beside its reads (D377); a callee
/// with no entry may write any of it up to the caller's entry pointer. Spans are minted only by
/// the frame walk that classified every transfer of the body (D411).
///
/// ```compile_fail,E0423
/// let forged = r2ssa::call_reads::StackWrites(());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackWrites(Writes);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Writes {
    /// A declaration's: only its argument area, which the convention gives the callee.
    Arguments,
    /// A walked body's: these ranges from the call's stack pointer.
    Within(Box<[(i64, i64)]>),
    /// A cycle member's first assumption, which its solve accepts only where its read states the same.
    Assumed(Vec<(i64, i64)>),
}

/// The frame walk saw every operation of the body through [`crate::SSAOp::transfer`], whose match
/// has no wildcard arm, so its calls and tail transfers are every transfer (D381, D411).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Transfers(());

impl Transfers {
    pub(crate) const fn classified() -> Self {
        Self(())
    }
}

impl StackWrites {
    /// A declaration's: the convention gives the callee its argument area and nothing else.
    pub const fn arguments() -> Self {
        Self(Writes::Arguments)
    }

    /// A walked body's spans, from a walk that classified every transfer.
    pub(crate) fn within(spans: Vec<(i64, i64)>, _: Transfers) -> Self {
        Self(Writes::Within(spans.into()))
    }

    /// A cycle member's first assumption (r2engine `resolved`): no write of its caller's stack. Its
    /// solve keeps it only where the member's own read states the same.
    pub const fn cycle_seed() -> Self {
        Self(Writes::Assumed(Vec::new()))
    }

    /// The spans from the call's stack pointer; `None` for the argument area.
    pub fn spans(&self) -> Option<&[(i64, i64)]> {
        match &self.0 {
            Writes::Arguments => None,
            Writes::Within(spans) => Some(spans),
            Writes::Assumed(spans) => Some(spans),
        }
    }
}

/// Why a call's listed registers are all it may read (D411): a cited declaration, or a callee whose
/// arity r2ssa holds exact. The every-location default has none.
///
/// ```compile_fail,E0423
/// let forged = r2ssa::call_reads::ReadBound(());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadBound(Bounded);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bounded {
    Cited,
    Arity,
}

impl r2source::Negative for ReadBound {
    const FACTS: &'static [r2source::NegativeFact] = &[
        r2source::NegativeFact::IgnoredReads,
        r2source::NegativeFact::CallReadBytes,
    ];
}

impl r2source::Negative for StackWrites {
    const FACTS: &'static [r2source::NegativeFact] = &[r2source::NegativeFact::IncomingWrites];
}

impl ReadBound {
    /// A row or document that cites the declaration.
    pub const fn cited(_: r2source::Citation) -> Self {
        Self(Bounded::Cited)
    }

    /// A complete fixed site interface, or a callee statement whose arity is exact.
    pub(crate) const fn arity() -> Self {
        Self(Bounded::Arity)
    }
}

/// The argument locations a call may read: an upper bound only where `bound` holds a witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallReads {
    /// Each argument register it may read: the stated ones first, then the convention's in order.
    pub(crate) registers: Vec<CanonicalStorageId>,
    /// The variadic count register, read with a tail and bounding the vector registers it counts.
    pub(crate) count_register: Option<CanonicalStorageId>,
    /// A printf format in registers with no count register (AAPCS64): what bounds its vector reads.
    pub(crate) format: Option<FormatTail>,
    /// The stack it may read, as ranges from the stack pointer before the transfer; none where
    /// nothing bounds it.
    pub(crate) stack: Option<Vec<(i64, i64)>>,
    /// The stack it may write, from the same pointer; none where nothing bounds it (D377).
    pub(crate) writes: Option<Vec<(i64, i64)>>,
    /// What bounds the registers to `registers`; none for the every-location default.
    pub(crate) bound: Option<ReadBound>,
}

impl CallReads {
    /// The default for a callee nothing states: every argument register, the count register and
    /// any of the caller's stack. O(locations).
    pub fn every_location(model: &ConventionModel) -> Self {
        let classes = [SlotClass::Integer, SlotClass::Float].into_iter();
        Self {
            registers: classes
                .flat_map(|class| model.arguments(class).iter().copied())
                .collect(),
            count_register: model.forms.count_register,
            format: None,
            stack: None,
            writes: None,
            bound: None,
        }
    }

    /// A complete, fixed interface: its arguments, the slots its callee's body proves unread left
    /// out (`is_hole`); every location where the callee states its reads unbounded (an uncited
    /// row, D411). O(arguments).
    pub fn exact(interface: &SourceCallSiteInterface, model: Option<&ConventionModel>) -> Self {
        let unbounded = (interface.exact_callee_interface())
            .is_some_and(|callee| callee.unbounded_reads().is_some());
        match (unbounded, model) {
            (false, _) => Self::exact_listed(interface, model),
            (true, Some(model)) => Self::every_location(model),
            (true, None) => Self {
                bound: None,
                stack: None,
                writes: None,
                ..Self::exact_listed(interface, None)
            },
        }
    }

    /// The listed arguments of a complete fixed interface, holes left out. O(arguments).
    fn exact_listed(interface: &SourceCallSiteInterface, model: Option<&ConventionModel>) -> Self {
        let holes = (interface.exact_callee_interface().into_iter())
            .flat_map(|callee| callee.parameters())
            .filter(|parameter| parameter.is_hole())
            .map(r2source::SourceAbiParameterSpec::index)
            .collect::<Vec<_>>();
        let read = (interface.arguments().iter())
            .filter(|argument| !holes.contains(&argument.index()))
            .map(|argument| argument.location());
        Self::of_locations(read, model)
    }

    /// Each parameter a body-proven callee reads, holes left out, at the call's stack pointer; none
    /// where one is past the address space. O(parameters).
    pub(crate) fn callee_locations(
        callee: &r2source::SourceFunctionInterface,
    ) -> Option<Vec<SourceParameterLocation>> {
        (callee.parameters().iter())
            .filter(|parameter| !parameter.is_hole())
            .map(|parameter| callee.at_call_site(parameter.location()))
            .collect()
    }

    /// The registers and stack slots read, with the stack the convention reserves for the callee.
    pub(crate) fn of_locations(
        read: impl Iterator<Item = SourceParameterLocation>,
        model: Option<&ConventionModel>,
    ) -> Self {
        let reserved = model
            .and_then(|model| model.stack_arguments())
            .map_or(0, |placement| placement.first_offset().max(0));
        let (mut registers, mut stack) = (Vec::new(), vec![(0, reserved)]);
        for location in read {
            match location {
                SourceParameterLocation::Register(storage) => registers.push(storage),
                SourceParameterLocation::Stack {
                    offset, size_bytes, ..
                } => stack.push((offset, offset.saturating_add(i64::from(size_bytes)))),
            }
        }
        Self {
            registers,
            count_register: None,
            format: None,
            writes: Some(stack.clone()),
            stack: Some(stack),
            bound: Some(ReadBound::arity()),
        }
    }

    /// These reads with what the callee may write of the stack: a declaration its argument area,
    /// a body what it states, any where nothing states it (D377). O(ranges).
    #[must_use]
    pub fn writing(mut self, writes: Option<&StackWrites>) -> Self {
        self.writes = match writes.map(StackWrites::spans) {
            Some(None) => self.writes,
            Some(Some(spans)) => Some(spans.to_vec()),
            None => None,
        };
        self
    }

    /// A placed library row (r2engine `Placement::reads`) whose citation fixes the parameters: only
    /// those registers. The stack is not bounded here.
    pub fn cited(registers: Vec<CanonicalStorageId>, citation: r2source::Citation) -> Self {
        Self {
            registers,
            count_register: None,
            format: None,
            stack: None,
            writes: None,
            bound: Some(ReadBound::cited(citation)),
        }
    }

    /// A placed library row nothing bounds: its fixed registers and every other one. The stack is
    /// not bounded here.
    pub fn unbounded(
        registers: Vec<CanonicalStorageId>,
        count_register: Option<CanonicalStorageId>,
        format: Option<FormatTail>,
    ) -> Self {
        Self {
            registers,
            count_register,
            format,
            stack: None,
            writes: None,
            bound: None,
        }
    }

    /// These reads with their stack read and written bounded by `stack` (a counted printf, D409).
    #[must_use]
    pub(crate) fn on_stack(mut self, stack: Vec<(i64, i64)>) -> Self {
        (self.stack, self.writes) = (Some(stack.clone()), Some(stack));
        self
    }

    /// These reads where the format's literal converts no floating operand: its tail's vector
    /// registers left out.
    #[must_use]
    pub fn without_format_floats(&self) -> Self {
        let mut reads = self.clone();
        if let Some(format) = &self.format {
            reads.registers.retain(|read| !format.floats.contains(read));
        }
        reads
    }

    pub fn registers(&self) -> &[CanonicalStorageId] {
        &self.registers
    }

    pub const fn count_register(&self) -> Option<CanonicalStorageId> {
        self.count_register
    }

    pub const fn format(&self) -> Option<&FormatTail> {
        self.format.as_ref()
    }

    pub fn stack(&self) -> Option<&[(i64, i64)]> {
        self.stack.as_deref()
    }

    pub fn writes(&self) -> Option<&[(i64, i64)]> {
        self.writes.as_deref()
    }

    /// What bounds the reads to [`Self::registers`]; `None` where any argument register may be read.
    pub const fn bound(&self) -> Option<ReadBound> {
        self.bound
    }

    /// Whether the call reads none of `carrier`: an argument or count register of `model` this
    /// bounded list leaves out (D283). Any other register may be read: x8, a static chain.
    pub fn reads_none_of(&self, model: &ConventionModel, carrier: CanonicalStorageId) -> bool {
        self.reads_none_within(&Self::every_location(model), carrier)
    }

    /// [`Self::reads_none_of`] against `every`, the model's [`Self::every_location`], built once
    /// per call by a caller asking for several carriers.
    pub fn reads_none_within(&self, every: &Self, carrier: CanonicalStorageId) -> bool {
        let overlaps = |storage: &CanonicalStorageId| {
            crate::semantic::register_storages_overlap(*storage, carrier)
        };
        let located = (every.registers.iter().chain(&every.count_register)).any(overlaps);
        let listed = (self.registers.iter().chain(&self.count_register)).any(overlaps);
        self.bound.is_some() && located && !listed
    }

    /// The bytes of the result registers these registers cover, with the count register's where
    /// `counted`: a callee's own calls set the count themselves, so only a caller's call takes it.
    pub fn takes(&self, lanes: ResultLanes, counted: bool) -> LaneBytes {
        let count = self.count_register.filter(|_| counted);
        LaneBytes::covered_by(lanes, &[&self.registers[..], count.as_slice()].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_placed_row_bounds_no_stack_and_takes_its_count_only_at_a_caller() {
        let register = |offset| CanonicalStorageId {
            space: r2source::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let lanes = ResultLanes {
            integer: Some(register(0)),
            ..ResultLanes::default()
        };
        let reads = CallReads::unbounded(vec![register(56)], Some(register(0)), None);
        assert_eq!(reads.stack, None);
        assert!(reads.takes(lanes, true).touches(0));
        assert!(!reads.takes(lanes, false).touches(0));
    }
}
