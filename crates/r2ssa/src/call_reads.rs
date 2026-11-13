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
                .flat_map(|class| model.argument_registers(class))
                .collect(),
            count_register: model.forms.count_register,
            format: None,
            stack: None,
            stated: false,
        }
    }

    /// A complete, fixed interface: its register arguments, the stack the convention reserves for
    /// the callee and each stack slot it places. O(arguments).
    pub fn exact(interface: &SourceCallSiteInterface, model: Option<&ConventionModel>) -> Self {
        let reserved = model
            .and_then(|model| model.stack_arguments())
            .map_or(0, |placement| placement.first_offset().max(0));
        let (mut registers, mut stack) = (Vec::new(), vec![(0, reserved)]);
        for argument in interface.arguments() {
            match argument.location() {
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
            stack: Some(stack),
            stated: true,
        }
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
            stated,
        }
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
