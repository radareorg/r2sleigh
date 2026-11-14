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
/// with no entry may write any of it up to the caller's entry pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackWrites {
    /// A declaration's: only its argument area, which the convention gives the callee.
    Arguments,
    /// A walked body's: these ranges from the call's stack pointer.
    #[doc(alias = "default_deny_incoming_writes")]
    Within(Box<[(i64, i64)]>),
}

/// The argument locations a call may read: an upper bound only where `stated`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallReads {
    /// Each argument register it may read: the stated ones first, then the convention's in order.
    pub registers: Vec<CanonicalStorageId>,
    /// The variadic count register, read with a tail and bounding the vector registers it counts.
    pub count_register: Option<CanonicalStorageId>,
    /// A printf format in registers with no count register (AAPCS64): what bounds its vector reads.
    pub format: Option<FormatTail>,
    /// The stack it may read, as ranges from the stack pointer before the transfer; none where
    /// nothing bounds it.
    pub stack: Option<Vec<(i64, i64)>>,
    /// The stack it may write, from the same pointer; none where nothing bounds it (D377).
    pub writes: Option<Vec<(i64, i64)>>,
    /// Whether the callee's statement bounds the registers; the every-location default does not.
    pub stated: bool,
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
            stated: false,
        }
    }

    /// A complete, fixed interface: its arguments, the slots its callee's body proves unread left
    /// out (`is_hole`). O(arguments).
    pub fn exact(interface: &SourceCallSiteInterface, model: Option<&ConventionModel>) -> Self {
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

    /// The locations a callee whose body proves its arity reads: each parameter, a hole left out,
    /// at the call's stack pointer (`CalleeStatement`); none where one is past the address space.
    /// O(parameters).
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
            stated: true,
        }
    }

    /// These reads with what the callee may write of the stack: a declaration its argument area,
    /// a body what it states, any where nothing states it (D377). O(ranges).
    #[must_use]
    pub fn writing(mut self, writes: Option<&StackWrites>) -> Self {
        self.writes = match writes {
            Some(StackWrites::Arguments) => self.writes,
            Some(StackWrites::Within(spans)) => Some(spans.to_vec()),
            None => None,
        };
        self
    }

    /// A placed library row (r2engine `Placement::reads`): `stated` where its citation fixes the
    /// parameters, else the fixed registers and every other one. The stack is not bounded here.
    pub fn placed(
        registers: Vec<CanonicalStorageId>,
        count_register: Option<CanonicalStorageId>,
        format: Option<FormatTail>,
        stated: bool,
    ) -> Self {
        Self {
            registers,
            count_register,
            format,
            stack: None,
            writes: None,
            stated,
        }
    }

    /// Whether the call reads none of `carrier`: an argument or count register of `model` this
    /// stated list leaves out (D283). Any other register may be read: x8, a static chain.
    pub fn reads_none_of(&self, model: &ConventionModel, carrier: CanonicalStorageId) -> bool {
        let overlaps = |storage: &CanonicalStorageId| {
            crate::semantic::register_storages_overlap(*storage, carrier)
        };
        let every = Self::every_location(model);
        let located = (every.registers.iter().chain(&every.count_register)).any(overlaps);
        let listed = (self.registers.iter().chain(&self.count_register)).any(overlaps);
        self.stated && located && !listed
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
        let reads = CallReads::placed(vec![register(56)], Some(register(0)), None, false);
        assert_eq!(reads.stack, None);
        assert!(reads.takes(lanes, true).touches(0));
        assert!(!reads.takes(lanes, false).touches(0));
    }
}
