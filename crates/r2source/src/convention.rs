//! One calling convention: the cspec's `ProtoModel` joined with the ABI's `ConventionRow`, held
//! once per convention by r2engine (doc/adr-call-boundary.md, "The joined model").

use std::ops::Range;

pub use r2abi::{ConventionId, Extension, SlotClass};

use crate::{
    CanonicalStorageId, SourceBoundaryReads, SourceCallEffect, SourceConventionSlots,
    SourceEntryStack, SourceMachineRolesError, SourceRegisterSaveArea,
    SourceStackArgumentPlacement, SourceStackGuard,
};

/// Every location of one class, in the convention's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub class: SectionClass,
    pub locations: Box<[Location]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionClass {
    Integer,
    Float,
    /// Integer and float alternatives sharing positions (Microsoft x64).
    Shared,
    /// The caller's argument area: the first slot from the stack pointer entering the call, and
    /// the step to the next.
    Stack {
        first: i64,
        step: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    Register {
        storage: CanonicalStorageId,
        /// The widest value the location takes.
        bytes: u8,
        class: SlotClass,
        /// The argument position; alternatives of a shared position have one.
        position: u16,
        extension: Extension,
    },
    Stack {
        offset: i64,
        bytes: u32,
    },
}

/// Where a result may be returned, and who states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultLane {
    pub storage: CanonicalStorageId,
    pub class: SlotClass,
    pub extension: Extension,
    pub stated_by: LaneSource,
    /// What the lane holds at entry, by the convention.
    pub entry: LaneEntry,
    /// The position in `results` of the lane this one holds a result only beside.
    pub follows: Option<usize>,
}

/// What a result lane holds at entry (doc/adr-result-side.md, "The lane set").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneEntry {
    /// An argument location: its entry bytes are the caller's argument.
    Input,
    /// No argument location: its entry bytes define nothing (scratch-result case 1).
    Scratch,
    /// The convention states it empty at entry (SysV 3.2.1: the x87 stack).
    Empty,
}

/// The convention's typed result lanes, each absent where it names none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedResults {
    pub integer: Option<CanonicalStorageId>,
    pub float: Option<CanonicalStorageId>,
    pub second: Option<CanonicalStorageId>,
}

/// More lanes than a site's boundary tracks: such a set is refused, and states no result `void`.
pub const RESULT_LANES: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneSource {
    /// The compiler specification's `<output>`.
    Specification,
    /// A cited ABI override the specification omits (`SpecOverride::Results`).
    Override,
}

/// Who owns an entry-relative stack range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedRange {
    /// `localrange`: the callee's own data.
    Callee(Range<i64>),
    /// A shared position's home in the area the caller allocates (Microsoft x64).
    Home {
        position: u8,
        at: Range<i64>,
    },
    /// `paramrange`.
    Arguments(Range<i64>),
    ReturnAddress(Range<i64>),
}

/// Who owns one entry-relative stack byte: `ConventionModel::owner`, the one caller-region rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackOwner {
    /// Below the entry stack pointer, or a range the convention gives the callee.
    Callee,
    /// A shared position's home, which the caller allocates and the callee may write.
    Home {
        position: u8,
    },
    ReturnAddress,
    /// The caller's: its argument area and what lies above it.
    Caller,
}

impl StackOwner {
    /// Whether the callee may write the byte as its own storage.
    pub const fn callee_owned(self) -> bool {
        matches!(self, Self::Callee | Self::Home { .. })
    }

    /// The rule without a model: the frame grows down from the entry stack pointer.
    pub const fn growing_down(offset: i64) -> Self {
        if offset < 0 {
            Self::Callee
        } else {
            Self::Caller
        }
    }
}

/// Some bytes of one register: `d8` is `v8` bytes 0..8, MXCSR's control bits are byte 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneSet {
    pub storage: CanonicalStorageId,
    pub bytes: Range<u8>,
}

impl Ord for LaneSet {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let key = |lanes: &Self| (lanes.storage, lanes.bytes.start, lanes.bytes.end);
        key(self).cmp(&key(other))
    }
}

impl PartialOrd for LaneSet {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl LaneSet {
    /// The whole register.
    pub fn whole(storage: CanonicalStorageId) -> Self {
        let bytes = 0..u8::try_from(storage.size).unwrap_or(u8::MAX);
        Self { storage, bytes }
    }

    /// The bytes as a storage of their own.
    pub fn narrowed(&self) -> CanonicalStorageId {
        CanonicalStorageId {
            space: self.storage.space,
            offset: self.storage.offset + u64::from(self.bytes.start),
            size: u32::from(self.bytes.end - self.bytes.start),
        }
    }
}

/// What a boundary of this convention has beyond its locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryForms {
    pub frame_pointer: Option<CanonicalStorageId>,
    pub red_zone: u32,
    pub save_area: Option<SourceRegisterSaveArea>,
    /// SysV `al`: the count of vector arguments a variadic callee is handed.
    pub count_register: Option<CanonicalStorageId>,
    pub entry_stack: Option<SourceEntryStack>,
    /// Every variadic argument on the stack, whatever registers are free (Apple arm64).
    pub variadic_on_stack: bool,
    /// The platform's stack protector word, addressed from a reserved register.
    pub guard: Option<SourceStackGuard>,
    /// The runtime's lowest stack pointer (Go's `g.stackguard0`).
    pub stack_bound: Option<SourceStackGuard>,
}

/// One convention on one target, every register resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConventionModel {
    pub id: ConventionId,
    /// Integer, float and stack apart; Microsoft x64's shared positions and the stack.
    pub sections: Box<[Section]>,
    /// The pointer to a result the caller allocates (AAPCS64 x8).
    pub hidden_return: Option<CanonicalStorageId>,
    pub results: Box<[ResultLane]>,
    /// The citation that states `results` every lane a result comes back in; none where nothing
    /// does or the set is refused, and then no result of the convention is `void`.
    pub results_complete: Option<&'static str>,
    pub owned: Box<[OwnedRange]>,
    /// What a call leaves as it found it: the specification's `unaffected`, less the return
    /// address, and the ABI's callee-saved control bits.
    pub preserved: Box<[LaneSet]>,
    pub killed: Box<[LaneSet]>,
    pub likely_trash: Box<[LaneSet]>,
    /// What the platform reserves to the system, which no call writes.
    pub reserved: Box<[LaneSet]>,
    /// The register a call leaves the return address in, where the machine uses one.
    pub link: Option<CanonicalStorageId>,
    pub forms: BoundaryForms,
    /// Why every function under the convention is refused, where it is.
    pub refused: Option<&'static str>,
}

impl ConventionModel {
    fn register_locations(&self) -> impl Iterator<Item = &Location> {
        (self.sections.iter())
            .filter(|section| !matches!(section.class, SectionClass::Stack { .. }))
            .flat_map(|section| section.locations.iter())
    }

    /// The argument registers of one class, in the convention's order.
    pub fn argument_registers(&self, of: SlotClass) -> impl Iterator<Item = CanonicalStorageId> {
        self.register_locations()
            .filter_map(move |location| match *location {
                Location::Register { storage, class, .. } if class == of => Some(storage),
                _ => None,
            })
    }

    /// The specification's result registers of one class, in its order.
    pub fn result_registers(&self, of: SlotClass) -> impl Iterator<Item = CanonicalStorageId> {
        (self.results.iter())
            .filter(move |lane| lane.class == of && lane.stated_by == LaneSource::Specification)
            .map(|lane| lane.storage)
    }

    /// The first stack argument and the step to the next.
    pub fn stack_arguments(&self) -> Option<SourceStackArgumentPlacement> {
        self.sections
            .iter()
            .find_map(|section| match section.class {
                SectionClass::Stack { first, step } => {
                    SourceStackArgumentPlacement::new(first, step)
                }
                _ => None,
            })
    }

    /// Who owns the stack byte at `offset` from the entry stack pointer; O(owned ranges).
    pub fn owner(&self, offset: i64) -> StackOwner {
        let stated = self.owned.iter().find_map(|range| match range {
            OwnedRange::Home { position, at } if at.contains(&offset) => Some(StackOwner::Home {
                position: *position,
            }),
            OwnedRange::Callee(at) if at.contains(&offset) => Some(StackOwner::Callee),
            OwnedRange::ReturnAddress(at) if at.contains(&offset) => {
                Some(StackOwner::ReturnAddress)
            }
            _ => None,
        });
        stated.unwrap_or(StackOwner::growing_down(offset))
    }

    /// The home of argument position `position`, where the convention states one.
    pub fn home(&self, position: u8) -> Option<Range<i64>> {
        self.owned.iter().find_map(|range| match range {
            OwnedRange::Home { position: of, at } if *of == position => Some(at.clone()),
            _ => None,
        })
    }

    /// Whether integer and float arguments count one position sequence together.
    pub fn shares_positions(&self) -> bool {
        (self.sections.iter()).any(|section| section.class == SectionClass::Shared)
    }

    /// The typed result lanes: the integer register, the float one and the second integer one,
    /// which holds a two-register value's high half.
    pub fn typed_results(&self) -> TypedResults {
        let results = self
            .result_registers(SlotClass::Integer)
            .collect::<Vec<_>>();
        let integer = results.first().copied();
        let second = (results.get(1).copied())
            .filter(|second| integer.is_some_and(|first| first.size == second.size));
        let float = self.result_registers(SlotClass::Float).next();
        TypedResults {
            integer,
            float,
            second,
        }
    }

    /// The candidate slots: a view of this model, as the snapshot carries it.
    pub fn convention_slots(&self) -> Result<SourceConventionSlots, SourceMachineRolesError> {
        let TypedResults {
            integer: result,
            float: float_result,
            second,
        } = self.typed_results();
        Ok(
            SourceConventionSlots::new(
                self.id,
                self.argument_registers(SlotClass::Integer),
                result,
            )
            .and_then(|slots| {
                slots.with_float_slots(self.argument_registers(SlotClass::Float), float_result)
            })
            .and_then(|slots| slots.with_second_result_slot(second))?
            .with_shared_positions(self.shares_positions())
            .with_stack_arguments(self.stack_arguments())
            .with_variadic_tail_on_stack(self.forms.variadic_on_stack)
            .with_register_save_area(self.forms.save_area)
            .with_variadic_count_register(self.forms.count_register)
            .with_entry_stack(self.forms.entry_stack),
        )
    }

    /// What a call does to the registers, a view of this model: clobbered is every location a call
    /// reads or writes, `killedbycall` and the return address, less what is preserved or reserved.
    pub fn call_effect(&self) -> Result<SourceCallEffect, SourceMachineRolesError> {
        let inputs = self
            .register_locations()
            .filter_map(|location| match *location {
                Location::Register { storage, .. } => Some(storage),
                Location::Stack { .. } => None,
            })
            .chain(self.hidden_return)
            .collect::<Vec<_>>();
        let outputs = (self.results.iter())
            .filter(|lane| lane.stated_by == LaneSource::Specification)
            .map(|lane| lane.storage)
            .collect::<Vec<_>>();
        let mut preserved = self
            .preserved
            .iter()
            .map(LaneSet::narrowed)
            .collect::<Vec<_>>();
        preserved.sort_unstable();
        preserved.dedup();
        let reserved = self.reserved.iter().map(LaneSet::narrowed);
        let reserved = reserved.collect::<Vec<_>>();
        let kept = preserved
            .iter()
            .chain(&reserved)
            .copied()
            .collect::<Vec<_>>();
        let mut clobbered = (inputs.iter().chain(&outputs).copied())
            .chain(self.killed.iter().map(LaneSet::narrowed))
            .chain(self.link)
            .collect::<Vec<_>>();
        clobbered.retain(|storage| !kept.iter().any(|kept| overlap(*kept, *storage)));
        let call_reads = inputs.into_iter().chain(self.forms.count_register);
        SourceBoundaryReads::new(call_reads, outputs)
            .and_then(|reads| SourceCallEffect::new(clobbered, preserved, reads))
            .and_then(|effect| effect.with_system_reserved(reserved))
            .and_then(|effect| effect.with_stack_guard(self.forms.guard))
            .and_then(|effect| effect.with_stack_bound(self.forms.stack_bound))
    }
}

/// Whether two storages share a byte.
fn overlap(left: CanonicalStorageId, right: CanonicalStorageId) -> bool {
    left.space == right.space
        && left.offset < right.offset + u64::from(right.size)
        && right.offset < left.offset + u64::from(left.size)
}
