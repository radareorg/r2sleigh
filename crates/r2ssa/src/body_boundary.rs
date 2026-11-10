//! What one body states at its boundary: how it uses each argument slot, the bytes it leaves in
//! each result lane, and why its arity is a floor (doc/adr-call-boundary.md, "Evidence (r2ssa)").

use r2source::{Basis, SourceArityFloor, SourceFloorCause, SourceParameterLocation};

use crate::CallSiteId;
use crate::dense::{DenseId, IdVec};
use crate::site_boundary::{ByteMask, LaneId};

/// One location of one section, numbered densely in convention order: integer, float, stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(pub u32);

impl DenseId for SlotId {
    fn index(self) -> usize {
        self.0 as usize
    }
    fn from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("fewer than 2^32 slots"))
    }
}

impl DenseId for LaneId {
    fn index(self) -> usize {
        usize::from(self.0)
    }
    fn from_index(index: usize) -> Self {
        Self(u8::try_from(index).expect("fewer than 256 result lanes"))
    }
}

/// What the body does with the value a slot holds at entry; the order is the fixpoint's, lowest
/// first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlotUse {
    /// Never read, or read only by an operation that folds it to a constant (`xor edx, edx`).
    Unread,
    /// Only stored to a frame slot: -O0 homes a declared parameter whether it is used or not.
    Homed { loaded: bool, escapes: bool },
    /// Read only by the variadic prologue's register save area.
    SaveArea,
    /// Handed unchanged to these calls, whose callees' statements read it.
    HandedOn {
        bytes: ByteMask,
        to: Box<[CallSiteId]>,
    },
    /// The entry value is used.
    Read { bytes: ByteMask },
    /// Read by a kind of read no rule proves, such as a call of unproven arity.
    Unknown(SourceFloorCause),
}

impl SlotUse {
    /// Whether the use proves the slot is a parameter (rule 1).
    pub const fn proves(&self) -> bool {
        matches!(self, Self::Read { .. } | Self::HandedOn { .. })
    }

    /// The basis a parameter at this slot rests on: a hole is the convention's.
    pub const fn basis(&self) -> Basis {
        match self {
            Self::Read { .. } | Self::Unknown(_) => Basis::Decoded,
            Self::HandedOn { .. } => Basis::Solved,
            Self::Unread | Self::Homed { .. } | Self::SaveArea => Basis::Convention,
        }
    }
}

/// Which section a slot is a location of (`ConventionModel::sections`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    Integer,
    Float,
    /// Microsoft x64's positions, each an integer or a float register.
    Shared,
    Stack,
}

/// Where one slot is: its section, its position there, and the location a parameter at it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub section: Section,
    pub position: u16,
    pub location: SourceParameterLocation,
}

/// What one body states at its boundary (`PreparedFunctionFacts::body_boundary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyBoundary {
    pub slots: IdVec<SlotId, SlotUse>,
    pub locations: IdVec<SlotId, Slot>,
    /// Each result lane's bytes joined over every return; `None` where a return's value is not
    /// resolved, empty where no return is reached.
    pub results: IdVec<LaneId, Option<crate::lanes::Bytes>>,
    pub floor: Option<SourceArityFloor>,
}

/// Rules 1 to 3 over one register section: how many leading slots are parameters, and why the
/// slots past them may still be read. O(slots).
pub fn section_rule(uses: &[SlotUse]) -> (usize, Vec<SourceFloorCause>) {
    let count = uses.iter().rposition(SlotUse::proves).map_or(0, |k| k + 1);
    let causes = uses[count..].iter().filter_map(|used| match used {
        SlotUse::Homed { .. } => Some(SourceFloorCause::Homed),
        SlotUse::Unknown(cause) => Some(*cause),
        _ => None,
    });
    (count, causes.collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read() -> SlotUse {
        SlotUse::Read {
            bytes: ByteMask(0xff),
        }
    }

    #[test]
    fn a_read_at_position_k_makes_every_slot_below_it_a_parameter() {
        let uses = [SlotUse::Unread, read(), SlotUse::Unread, read()];
        assert_eq!(section_rule(&uses), (4, Vec::new()));
        assert_eq!(uses[0].basis(), Basis::Convention);
    }

    #[test]
    fn a_homed_slot_past_the_reads_is_a_floor_and_no_parameter() {
        let homed = SlotUse::Homed {
            loaded: false,
            escapes: false,
        };
        let uses = [read(), homed.clone(), homed];
        assert_eq!(
            section_rule(&uses),
            (1, vec![SourceFloorCause::Homed, SourceFloorCause::Homed])
        );
    }

    #[test]
    fn a_save_area_read_proves_no_parameter() {
        let uses = [read(), SlotUse::SaveArea, SlotUse::SaveArea];
        assert_eq!(section_rule(&uses), (1, Vec::new()));
    }

    #[test]
    fn the_uses_are_ordered_for_the_fixpoint() {
        let handed = SlotUse::HandedOn {
            bytes: ByteMask(0xff),
            to: Box::new([CallSiteId(0)]),
        };
        let mut uses = [
            SlotUse::Unknown(SourceFloorCause::RegisterRead),
            read(),
            handed.clone(),
            SlotUse::SaveArea,
            SlotUse::Unread,
        ];
        uses.sort();
        assert_eq!(uses[0], SlotUse::Unread);
        assert_eq!(uses[2], handed);
        assert!(matches!(uses[4], SlotUse::Unknown(_)));
    }
}
