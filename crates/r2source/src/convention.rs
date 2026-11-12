//! One calling convention: the cspec's `ProtoModel` joined with the ABI's `ConventionRow`, held
//! once per convention by r2engine (doc/adr-call-boundary.md, "The joined model").

use std::ops::{Deref, Range};

pub use r2abi::{ConventionId, Extension, SlotClass};

use crate::contracts::{
    covers_every_byte, register_storages_overlap, sorted_storages, storage_sets_overlap,
    valid_register_storage,
};
use crate::{
    CanonicalStorageId, SourceBoundaryReads, SourceCallEffect, SourceCallRegisterEffect,
    SourceConventionSlots, SourceEntryStack, SourceMachineRolesError, SourceRegisterSaveArea,
    SourceSecurityCookie, SourceStackArgumentPlacement, SourceStackGuard,
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

impl Location {
    /// The register, where the location is one.
    pub const fn register(&self) -> Option<CanonicalStorageId> {
        match *self {
            Self::Register { storage, .. } => Some(storage),
            Self::Stack { .. } => None,
        }
    }
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
    /// The `/GS` cookie the PE load configuration names.
    pub security_cookie: Option<SourceSecurityCookie>,
}

/// One convention on one target, every register resolved: what `ConventionModel::new` checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConventionParts {
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

/// A convention's parts, checked once, with the index every register question reads (S34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConventionModel {
    parts: ConventionParts,
    index: Derived,
}

/// The parts read in place; no `DerefMut`, so the index never goes stale.
impl Deref for ConventionModel {
    type Target = ConventionParts;

    fn deref(&self) -> &ConventionParts {
        &self.parts
    }
}

/// Why `ConventionModel::new` refuses a model (ambiguous positions), or refuses only its effect
/// (`effect_refused`: two duties of one register contradict).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRefusal {
    /// A location, lane or result that is no register.
    NotARegister,
    /// One integer argument register named twice: its position is ambiguous.
    RegisterTwice,
    /// A second integer result with no first, or overlapping it.
    UnpairedSecondResult,
    /// A reserved lane also preserved or clobbered, or a clobbered one also preserved.
    Contradictory,
    /// A stack guard's base no call leaves reserved, or a stack bound's no call keeps.
    UnkeptBase,
}

impl ModelRefusal {
    pub const fn why(self) -> &'static str {
        match self {
            Self::NotARegister => "the convention names a location that is no register",
            Self::RegisterTwice => "the convention names one register twice",
            Self::UnpairedSecondResult => "the convention's second result pairs no first",
            Self::Contradictory => "the convention keeps and clobbers one register",
            Self::UnkeptBase => "the convention's stack guard or bound rests on a clobbered base",
        }
    }
}

/// What every register question reads, built once by `ConventionModel::new`; sorted slices.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Derived {
    /// The integer and the float argument registers, each in the convention's order.
    arguments: [Box<[CanonicalStorageId]>; 2],
    /// Each argument register and first typed result with its class, sorted.
    roles: Box<[(CanonicalStorageId, SlotClass)]>,
    /// What a call does, or why the convention states nothing consistent about it.
    effect: Result<Effect, ModelRefusal>,
}

/// What a call does to the registers and reads of them, each set sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Effect {
    clobbered: Box<[CanonicalStorageId]>,
    preserved: Box<[CanonicalStorageId]>,
    reserved: Box<[CanonicalStorageId]>,
    call_reads: Box<[CanonicalStorageId]>,
    result_reads: Box<[CanonicalStorageId]>,
}

impl Derived {
    /// The checks `convention_slots` ran, then the index; O(L log L) in the model's locations
    /// and lanes. The effect's own checks refuse only the effect, as `call_effect` did.
    fn of(parts: &ConventionParts) -> Result<Self, ModelRefusal> {
        let register = |storage: &CanonicalStorageId| valid_register_storage(*storage);
        let TypedResults {
            integer,
            float,
            second,
        } = parts.typed_results();
        let integers = (parts.argument_registers(SlotClass::Integer)).collect::<Box<[_]>>();
        let floats = (parts.argument_registers(SlotClass::Float)).collect::<Box<[_]>>();
        let mut named = (integers.iter().chain(&integer)).chain(floats.iter().chain(&float));
        if !named.all(register) {
            return Err(ModelRefusal::NotARegister);
        }
        if (1..integers.len()).any(|at| integers[..at].contains(&integers[at])) {
            return Err(ModelRefusal::RegisterTwice);
        }
        if let Some(second) = second {
            let first = integer.ok_or(ModelRefusal::UnpairedSecondResult)?;
            if !register(&second) || register_storages_overlap(first, second) {
                return Err(ModelRefusal::UnpairedSecondResult);
            }
        }
        let mut roles = (integers.iter().chain(&integer))
            .map(|storage| (*storage, SlotClass::Integer))
            .chain((floats.iter().chain(&float)).map(|storage| (*storage, SlotClass::Float)))
            .collect::<Vec<_>>();
        roles.sort_unstable();
        roles.dedup();
        Ok(Self {
            arguments: [integers, floats],
            roles: roles.into_boxed_slice(),
            effect: Effect::of(parts),
        })
    }
}

impl Effect {
    /// Clobbered is every location a call reads or writes, `killedbycall` and the link, less
    /// what is preserved or reserved; the checks are `call_effect`'s.
    fn of(parts: &ConventionParts) -> Result<Self, ModelRefusal> {
        let inputs = (parts.register_locations())
            .filter_map(Location::register)
            .chain(parts.hidden_return)
            .collect::<Vec<_>>();
        let result_reads = sorted_storages(
            (parts.results.iter())
                .filter(|lane| lane.stated_by == LaneSource::Specification)
                .map(|lane| lane.storage),
        );
        let call_reads = sorted_storages(inputs.iter().copied().chain(parts.forms.count_register));
        let preserved = sorted_storages(parts.preserved.iter().map(LaneSet::narrowed));
        let reserved = sorted_storages(parts.reserved.iter().map(LaneSet::narrowed));
        let kept = |storage: &CanonicalStorageId| {
            (preserved.iter().chain(&reserved)).any(|kept| overlap(*kept, *storage))
        };
        let clobbered = (inputs.into_iter().chain(result_reads.iter().copied()))
            .chain(parts.killed.iter().map(LaneSet::narrowed))
            .chain(parts.link)
            .filter(|storage| !kept(storage));
        let clobbered = sorted_storages(clobbered);
        let mut held = (call_reads.iter().chain(&result_reads).chain(&clobbered))
            .chain(preserved.iter().chain(&reserved));
        if !held.all(|storage| valid_register_storage(*storage)) {
            return Err(ModelRefusal::NotARegister);
        }
        if storage_sets_overlap(&clobbered, &preserved)
            || storage_sets_overlap(&reserved, &clobbered)
            || storage_sets_overlap(&reserved, &preserved)
        {
            return Err(ModelRefusal::Contradictory);
        }
        let unreserved = |base| !covers_every_byte(&reserved, base);
        let unkept = |base| unreserved(base) && !covers_every_byte(&preserved, base);
        let guard = (parts.forms.guard).is_some_and(|guard| unreserved(guard.base));
        if guard || (parts.forms.stack_bound).is_some_and(|bound| unkept(bound.base)) {
            return Err(ModelRefusal::UnkeptBase);
        }
        Ok(Self {
            clobbered,
            preserved,
            reserved,
            call_reads,
            result_reads,
        })
    }
}

impl ConventionParts {
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
}

impl ConventionModel {
    /// Check the parts and index them once (`Derived::of`).
    pub fn new(parts: ConventionParts) -> Result<Self, ModelRefusal> {
        let index = Derived::of(&parts)?;
        Ok(Self { parts, index })
    }

    /// The argument registers of one class, in the convention's order; none for the stack's.
    pub fn arguments(&self, class: SlotClass) -> &[CanonicalStorageId] {
        match class {
            SlotClass::Integer => &self.index.arguments[0],
            SlotClass::Float => &self.index.arguments[1],
            SlotClass::Stack | SlotClass::HiddenReturn => &[],
        }
    }

    /// The register of argument `position` among those of `class`; O(1).
    pub fn argument(&self, class: SlotClass, position: usize) -> Option<CanonicalStorageId> {
        self.arguments(class).get(position).copied()
    }

    /// The class of the argument or first result register holding all of `storage`; `None`
    /// where no register of exactly one class does. O(log L) to the candidates, then a scan.
    pub fn class_of(&self, storage: CanonicalStorageId) -> Option<SlotClass> {
        let roles = &self.index.roles;
        let starting = roles.partition_point(|(slot, _)| {
            (slot.space, slot.offset) <= (storage.space, storage.offset)
        });
        let end = |at: CanonicalStorageId| at.offset + u64::from(at.size);
        let holds =
            |slot: &CanonicalStorageId| slot.space == storage.space && end(storage) <= end(*slot);
        let held = |class| (roles[..starting].iter()).any(|(slot, of)| *of == class && holds(slot));
        match (held(SlotClass::Integer), held(SlotClass::Float)) {
            (true, false) => Some(SlotClass::Integer),
            (false, true) => Some(SlotClass::Float),
            _ => None,
        }
    }

    /// Why the convention states no consistent call effect, where it does not; then every answer
    /// about a call is the one for no model (ruling 2.1).
    pub fn effect_refused(&self) -> Option<ModelRefusal> {
        self.index.effect.as_ref().err().copied()
    }

    /// What a call does to a storage: reserved where every byte is, preserved where every byte
    /// is, else clobbered, as is every storage under a refused effect. O(L).
    pub fn effect_on(&self, storage: CanonicalStorageId) -> SourceCallRegisterEffect {
        let Ok(effect) = &self.index.effect else {
            return SourceCallRegisterEffect::Clobbered;
        };
        if covers_every_byte(&effect.reserved, storage) {
            SourceCallRegisterEffect::SystemReserved
        } else if covers_every_byte(&effect.preserved, storage) {
            SourceCallRegisterEffect::Preserved
        } else {
            SourceCallRegisterEffect::Clobbered
        }
    }

    pub fn clobbers(&self, storage: CanonicalStorageId) -> bool {
        self.effect_on(storage) == SourceCallRegisterEffect::Clobbered
    }

    pub fn preserves(&self, storage: CanonicalStorageId) -> bool {
        self.effect_on(storage) == SourceCallRegisterEffect::Preserved
    }

    pub fn reserves(&self, storage: CanonicalStorageId) -> bool {
        self.effect_on(storage) == SourceCallRegisterEffect::SystemReserved
    }

    /// Every location a call reads or writes, `killedbycall` and the link, less what is kept;
    /// none under a refused effect, where every register is clobbered.
    pub fn clobbered(&self) -> Option<&[CanonicalStorageId]> {
        self.index
            .effect
            .as_ref()
            .ok()
            .map(|effect| &*effect.clobbered)
    }

    /// Each preserved lane as a storage of its own; none under a refused effect.
    pub fn preserved_registers(&self) -> &[CanonicalStorageId] {
        self.index
            .effect
            .as_ref()
            .map_or(&[], |effect| &effect.preserved)
    }

    /// Each lane reserved to the system as a storage of its own; none under a refused effect.
    pub fn system_reserved(&self) -> &[CanonicalStorageId] {
        self.index
            .effect
            .as_ref()
            .map_or(&[], |effect| &effect.reserved)
    }

    /// What a call reads without an operand naming it: the argument registers, the hidden result
    /// pointer and the count register; none under a refused effect, where it reads every one.
    pub fn call_reads(&self) -> Option<&[CanonicalStorageId]> {
        self.index
            .effect
            .as_ref()
            .ok()
            .map(|effect| &*effect.call_reads)
    }

    /// Where the platform keeps the stack guard, where it states one; none under a refused effect.
    pub fn stack_guard(&self) -> Option<SourceStackGuard> {
        self.forms.guard.filter(|_| self.index.effect.is_ok())
    }

    /// Where the convention keeps the lowest stack pointer, where it states one; none under a
    /// refused effect.
    pub fn stack_bound(&self) -> Option<SourceStackGuard> {
        self.forms.stack_bound.filter(|_| self.index.effect.is_ok())
    }

    /// What a return hands back, the specification's result registers; none under a refused
    /// effect.
    pub fn result_reads(&self) -> Option<&[CanonicalStorageId]> {
        self.index
            .effect
            .as_ref()
            .ok()
            .map(|effect| &*effect.result_reads)
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

    /// A call under this convention or `other` reads and writes what either does and keeps what
    /// both keep; each register keeps its first position (ADR "S34 step 4 as built"). O(lanes).
    pub fn either(&self, other: &Self) -> Result<Self, ModelRefusal> {
        let union = |left: &[LaneSet], right: &[LaneSet]| {
            let mut all = left.iter().chain(right).cloned().collect::<Vec<_>>();
            all.sort();
            all.dedup();
            all.into_boxed_slice()
        };
        let named = (self.register_locations()).filter_map(Location::register);
        let named = named.collect::<Vec<_>>();
        let new = |location: &&Location| location.register().is_none_or(|it| !named.contains(&it));
        let theirs = other.sections.iter().map(|section| Section {
            class: section.class,
            locations: section.locations.iter().filter(new).copied().collect(),
        });
        let mine = |lane: &ResultLane| self.results.iter().any(|it| it.storage == lane.storage);
        let results = (self.results.iter().copied())
            .chain(
                other
                    .results
                    .iter()
                    .filter(|lane| !mine(lane))
                    .map(|lane| ResultLane {
                        follows: None,
                        ..*lane
                    }),
            )
            .collect();
        Self::new(ConventionParts {
            sections: self.sections.iter().cloned().chain(theirs).collect(),
            hidden_return: self.hidden_return.or(other.hidden_return),
            results,
            results_complete: None,
            preserved: (self.preserved.iter())
                .filter(|lanes| other.preserved.contains(lanes))
                .cloned()
                .collect(),
            killed: union(&self.killed, &other.killed),
            likely_trash: union(&self.likely_trash, &other.likely_trash),
            reserved: union(&self.reserved, &other.reserved),
            forms: BoundaryForms {
                count_register: self.forms.count_register.or(other.forms.count_register),
                ..self.forms.clone()
            },
            ..self.parts.clone()
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CanonicalStorageSpace;

    fn register(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    fn integers(offsets: &[u64]) -> Section {
        let locations = offsets.iter().enumerate().map(|(position, offset)| {
            let position = u16::try_from(position).expect("a position");
            Location::Register {
                storage: register(*offset, 8),
                bytes: 8,
                class: SlotClass::Integer,
                position,
                extension: Extension::Unspecified,
            }
        });
        Section {
            class: SectionClass::Integer,
            locations: locations.collect(),
        }
    }

    /// Arguments at the `arguments` offsets, the result at 0, `preserved` and `reserved` kept.
    fn parts(arguments: &[u64], preserved: &[u64], reserved: &[u64]) -> ConventionParts {
        let lanes = |at: &[u64]| {
            at.iter()
                .map(|it| LaneSet::whole(register(*it, 8)))
                .collect()
        };
        ConventionParts {
            id: ConventionId::SysVAmd64,
            sections: Box::new([integers(arguments)]),
            hidden_return: None,
            results: Box::new([ResultLane {
                storage: register(0, 8),
                class: SlotClass::Integer,
                extension: Extension::Unspecified,
                stated_by: LaneSource::Specification,
                entry: LaneEntry::Scratch,
                follows: None,
            }]),
            results_complete: None,
            owned: Box::default(),
            preserved: lanes(preserved),
            killed: Box::default(),
            likely_trash: Box::default(),
            reserved: lanes(reserved),
            link: None,
            forms: BoundaryForms {
                frame_pointer: None,
                red_zone: 0,
                save_area: None,
                count_register: None,
                entry_stack: None,
                variadic_on_stack: false,
                guard: None,
                stack_bound: None,
                security_cookie: None,
            },
            refused: None,
        }
    }

    /// Each register question has one answer: by position, by class, by what a call does to it.
    #[test]
    fn a_model_answers_positions_classes_and_effects_from_its_index() {
        let model = ConventionModel::new(parts(&[0x38, 0x30], &[0x18], &[0x20])).expect("a model");
        assert_eq!(
            model.argument(SlotClass::Integer, 1),
            Some(register(0x30, 8))
        );
        assert_eq!(model.argument(SlotClass::Integer, 2), None);
        assert!(model.arguments(SlotClass::Float).is_empty());
        assert_eq!(model.class_of(register(0x30, 4)), Some(SlotClass::Integer));
        assert_eq!(
            model.class_of(register(0x4, 8)),
            None,
            "straddles the result"
        );
        assert_eq!(model.class_of(register(0x18, 8)), None, "no argument");
        assert!(model.reserves(register(0x20, 8)));
        assert!(model.preserves(register(0x18, 4)));
        assert!(model.clobbers(register(0x18, 16)), "half preserved");
        let clobbered = [register(0, 8), register(0x30, 8), register(0x38, 8)];
        assert_eq!(model.clobbered(), Some(&clobbered[..]));
        assert_eq!(model.call_reads(), Some(&clobbered[1..]));
        assert_eq!(model.result_reads(), Some(&[register(0, 8)][..]));
    }

    /// Ambiguous positions refuse the model. A contradictory effect refuses only the effect, so
    /// every call under it is clobbering.
    #[test]
    fn an_ambiguous_model_is_refused_and_a_contradictory_effect_clobbers_everything() {
        let twice = ConventionModel::new(parts(&[0x38, 0x38], &[], &[]));
        assert_eq!(twice.err(), Some(ModelRefusal::RegisterTwice));
        let refused = |parts| {
            ConventionModel::new(parts)
                .expect("a model")
                .effect_refused()
        };
        let both = parts(&[0x38], &[0x18], &[0x18]);
        assert_eq!(refused(both.clone()), Some(ModelRefusal::Contradictory));
        let mut unkept = parts(&[0x38], &[], &[]);
        unkept.forms.guard = Some(SourceStackGuard {
            base: register(0x20, 8),
            offset: 0x28,
            width: 8,
        });
        assert_eq!(refused(unkept), Some(ModelRefusal::UnkeptBase));
        let model = ConventionModel::new(both).expect("a model");
        assert!(model.clobbers(register(0x18, 8)));
        assert!(model.call_reads().is_none() && model.preserved_registers().is_empty());
        assert!(model.stack_guard().is_none());
        assert_eq!(
            model.argument(SlotClass::Integer, 0),
            Some(register(0x38, 8))
        );
    }

    /// A join names each argument register once, reads what either reads, keeps what both keep.
    #[test]
    fn a_join_names_each_register_once_and_keeps_what_both_keep() {
        let one = ConventionModel::new(parts(&[0x38, 0x30], &[0x18, 0x28], &[])).expect("one");
        let other = ConventionModel::new(parts(&[0x08, 0x30], &[0x18], &[])).expect("other");
        let join = one.either(&other).expect("a join");
        let named = [0x38, 0x30, 0x08].map(|it| register(it, 8));
        assert_eq!(join.arguments(SlotClass::Integer), named);
        assert!(join.preserves(register(0x18, 8)));
        assert!(join.clobbers(register(0x28, 8)), "only one keeps it");
        let reads = join.call_reads().expect("an effect");
        assert!(reads.contains(&register(0x08, 8)));
    }
}
