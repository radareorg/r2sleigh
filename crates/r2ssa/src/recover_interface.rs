//! Recovering a function's ABI from the machine code that implements it.
//!
//! A register a function reads before it writes is a value its caller supplied.
//! That is a dataflow fact, not an inference: SSA construction already assigns
//! version 0 to exactly those reads, because there is no prior definition in the
//! function to rename them to.
//!
//! Intersecting those reads with the calling convention's candidate slots yields
//! the parameters, and the convention's result slot yields the return. Nothing
//! here claims a type or a name, both of which compilation genuinely erases.

use std::collections::{BTreeMap, BTreeSet};

use r2il::SpaceId;
use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, ConventionModel, SourceAbiParameterSpec,
    SourceArityFloor, SourceCallArgumentSpec, SourceCallResult, SourceCallSiteIdentity,
    SourceCallSiteInterface, SourceCarrierKind, SourceCarrierProjection, SourceFloorCause,
    SourceFunctionInterface, SourceFunctionReturn, SourceLogicalValue, SourceMachineRoles,
    SourceParameterLocation, SourceResultCause, SourceResultSeed, SourceResultWidth,
    SourceStackSlotSpec, SourceType, SourceTypeGraph, SourceTypeKind, SourceUnprovenCall,
    SourceUnprovenResult, SourceUnstatedCall, StackAddressBase,
};

use r2source::convention::SlotClass;

use crate::body_boundary::{Section, SlotUse};
use crate::function::SSAFunction;
use crate::graph::SsaGraph;
use crate::var::SSAVar;

/// One argument slot the machine code proves the function reads.
///
/// The slot is what the convention names, and the read is what the function
/// actually did with it. They differ whenever a parameter is narrower than the
/// register that carries it: an `int` third argument on amd64 arrives in `rdx`
/// and the callee reads `edx`. Keeping only the slot claimed the function reads
/// all eight bytes, and no value of that width exists, so the parameter was
/// left without a fact and eventually rendered as an unnamed binding or trimmed
/// away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredParameter {
    slot: CanonicalStorageId,
    observed: CanonicalStorageId,
    class: r2source::convention::SlotClass,
    basis: r2source::Basis,
}

impl RecoveredParameter {
    /// The convention's argument register.
    pub const fn slot(&self) -> CanonicalStorageId {
        self.slot
    }

    /// The entry read that satisfied it, never wider than the slot; a hole's is the slot.
    pub const fn observed(&self) -> CanonicalStorageId {
        self.observed
    }

    /// The section's class: a float register's parameter is a float.
    pub const fn class(&self) -> r2source::convention::SlotClass {
        self.class
    }

    /// `Decoded` for a read, `Solved` for a slot handed on, `Convention` for a hole.
    pub const fn basis(&self) -> r2source::Basis {
        self.basis
    }

    /// Where the parameter arrives: a float in its register's low lane, as `place` puts it.
    fn location(&self) -> CanonicalStorageId {
        match self.class {
            r2source::convention::SlotClass::Float => self.observed,
            _ => self.slot,
        }
    }
}

/// One result slot the function proves it fills, and the part it actually fills.
///
/// The convention names the full carrier while the defining operation names the
/// logical width. They differ for an `int` returned in a 64-bit register, just
/// as they do for a narrow parameter arriving in a full argument register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredResult {
    slot: CanonicalStorageId,
    observed: CanonicalStorageId,
    /// The carrier is the float result register, read by callers as a float of the observed width.
    float: bool,
    /// What every return path leaves above the observed bytes (doc/adr-result-side.md, section 2).
    above: r2source::SourceAbove,
}

impl RecoveredResult {
    /// The fill every return path leaves above the observed bytes, `Undefined` where they differ.
    pub const fn above(self) -> r2source::SourceAbove {
        self.above
    }

    /// The convention's result register.
    pub const fn slot(self) -> CanonicalStorageId {
        self.slot
    }

    /// The widest definition that contributes to the result.
    pub const fn observed(self) -> CanonicalStorageId {
        self.observed
    }

    /// Whether the result is a float in the float result register.
    pub const fn float(self) -> bool {
        self.float
    }
}

/// What the body proves it leaves for its caller.
///
/// `Void` is the claim that no return path fills a result carrier. `Unproven`
/// is the absence of a claim: a body nobody read owns the result boundary, so
/// the caller falls back to its convention instead of being told there is
/// nothing there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredFunctionResult {
    Void,
    Register(RecoveredResult),
    /// One value in two registers, the low half in `low` (doc/adr-language-profile.md, item 1).
    Pair {
        low: CanonicalStorageId,
        high: CanonicalStorageId,
    },
    Unproven,
}

impl RecoveredFunctionResult {
    /// The carrier this result names, where it names one.
    pub const fn register(self) -> Option<RecoveredResult> {
        match self {
            Self::Register(result) => Some(result),
            Self::Void | Self::Pair { .. } | Self::Unproven => None,
        }
    }
}

/// One argument slot in the caller's frame the function reads before anything
/// in it writes there, and how much of it the read covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredStackParameter {
    offset: i64,
    slot_bytes: u32,
    observed_bytes: u32,
    /// Unread below a read slot: a parameter by the convention's order alone.
    hole: bool,
}

impl RecoveredStackParameter {
    /// The slot's offset from the stack pointer at entry.
    pub const fn offset(self) -> i64 {
        self.offset
    }

    /// The convention's slot width.
    pub const fn slot_bytes(self) -> u32 {
        self.slot_bytes
    }

    /// The widest read of the slot, rounded to a machine width, never wider
    /// than the slot.
    pub const fn observed_bytes(self) -> u32 {
        self.observed_bytes
    }

    /// Whether no read reaches the slot: a hole below the highest one read.
    pub const fn is_hole(self) -> bool {
        self.hole
    }

    /// `Convention` for a hole, else `Decoded`.
    pub const fn basis(self) -> r2source::Basis {
        match self.hole {
            true => r2source::Basis::Convention,
            false => r2source::Basis::Decoded,
        }
    }
}

/// Where every exit of the function takes its return address from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredReturnMechanism {
    /// A register, or the callee's own save of one.
    Link,
    /// The slot at the entry stack pointer, which the call left there.
    Stacked { slot_bytes: u32 },
}

/// What the machine code proves about a function's interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredInterface {
    parameters: Box<[RecoveredParameter]>,
    stack_parameters: Box<[RecoveredStackParameter]>,
    result: RecoveredFunctionResult,
    /// Whether that result is the return address the caller pushed.
    result_is_return_address: bool,
    return_mechanism: Option<RecoveredReturnMechanism>,
    /// Why the result is unproven, where it is (doc/adr-verified-layers.md, D37).
    unproven_result: Option<SourceUnprovenResult>,
    /// The registers an unproven result may be in, where a caller's read can say which.
    result_carriers: Option<r2source::SourceResultCarriers>,
    /// Why an argument slot past the parameters may be read, or a call's arguments are unproven.
    arity_floor: Option<SourceArityFloor>,
    /// Whether the body saves the argument registers past its parameters to the convention's
    /// register save area: arguments continue past them, which each call counts (`save_area`).
    variadic: bool,
    /// The parameter a tail-consuming loop is bounded by, where the body proves one (`tail_count`).
    tail_count: Option<r2source::SourceTailCount>,
    /// What the closed world decided and this recovery applied, with the premises it rests on.
    closed: Option<r2source::SourceClosedDecision>,
    /// Whether some return hands back a parameter through a merge: an entry input, spelled.
    result_holds_input: bool,
    /// No return path is reached, so the `Void` result states what a call leaves, never a type.
    unreached: bool,
    /// How the body uses each slot and the bytes it leaves in each result lane.
    boundary: crate::body_boundary::BodyBoundary,
    /// Whether the body is a proven `/GS` check (`security_cookie::proves_check`).
    security_check: bool,
}

impl RecoveredInterface {
    /// What the result's closed-world decision takes for granted; none where none was applied.
    pub const fn closed_premises(&self) -> &'static [r2source::Premise] {
        match self.closed {
            Some(decision) => decision.premises(),
            None => &[],
        }
    }

    /// Why the result is unproven, where it is.
    pub const fn unproven_result(&self) -> Option<&SourceUnprovenResult> {
        self.unproven_result.as_ref()
    }

    /// Whether arguments continue past the parameters, as the body's register save area proves.
    pub const fn is_variadic(&self) -> bool {
        self.variadic
    }

    /// Parameter slots in convention order, contiguous from index zero, each
    /// with the entry read that proved it.
    pub const fn parameters(&self) -> &[RecoveredParameter] {
        &self.parameters
    }

    /// Argument-area slots in convention order after the register slots,
    /// contiguous from the first one, each read by the function.
    pub const fn stack_parameters(&self) -> &[RecoveredStackParameter] {
        &self.stack_parameters
    }

    /// What the body proves it returns.
    pub const fn result(&self) -> RecoveredFunctionResult {
        self.result
    }

    /// Whether the result is the return address the caller pushed.
    pub const fn result_is_return_address(&self) -> bool {
        self.result_is_return_address
    }

    /// How the function returns, when every exit agrees.
    pub const fn return_mechanism(&self) -> Option<RecoveredReturnMechanism> {
        self.return_mechanism
    }

    /// What the body states at its boundary, the evidence the parameters were minted from.
    pub const fn boundary(&self) -> &crate::body_boundary::BodyBoundary {
        &self.boundary
    }
}

/// The stack slot every return reloads its control value from, when they agree.
fn return_address_object(
    facts: &crate::semantic::PreparedFunctionFacts,
) -> Option<crate::semantic::ObjectId> {
    let mut found = None;
    for at in facts.boundaries.returns.keys() {
        let object = facts
            .certificates
            .machine_return_controls
            .get(at)?
            .reload_object?;
        if found.is_some_and(|known| known != object) {
            return None;
        }
        found = Some(object);
    }
    found
}

/// Whether what the body leaves in its result carrier is the return address.
///
/// A position-independent thunk is `mov esi, [esp]; ret`: it hands its caller
/// back the address the call pushed. A stacked return mechanism already proves
/// every return takes its control value out of that entry slot, so a result
/// read from the same slot -- in a body that never writes it, which would make
/// the read and the return two different contents -- is the address control
/// goes back to.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "the members of one entity (a certificate, carrier, return or component): a few ids each, where a dense index would cost O(values) per entity"
    )
)]
fn result_is_the_return_address(
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    live_out: &crate::liveout::FunctionLiveOut,
    mechanism: Option<RecoveredReturnMechanism>,
) -> bool {
    let Some(RecoveredReturnMechanism::Stacked { slot_bytes }) = mechanism else {
        return false;
    };
    let Some(object) = return_address_object(facts) else {
        return false;
    };
    let accesses = facts
        .structured
        .memory_accesses
        .values()
        .filter(|access| access.object == object);
    // A write of any width leaves the read and the return two contents apart.
    if accesses.clone().any(|access| access.is_write) {
        return false;
    }
    let read_values = accesses
        .filter(|access| access.width == slot_bytes)
        .filter_map(|access| access.value)
        .collect::<BTreeSet<_>>();
    let proven = !live_out.is_empty()
        && live_out
            .iter()
            .all(|value| read_values.contains(&crate::constant::root_of(graph, value)));
    if proven {
        r2il::refusal_evidence!(
            "interface-recovery",
            "the result is read from {object:?}, the slot every return takes its address from"
        );
    }
    proven
}

/// Where the function's exits take the return address from, when they agree.
///
/// A return whose control value is reloaded from the slot at the entry stack
/// pointer proves the call pushed it there; one that reads a register, or a
/// save of one in the function's own frame, proves a link register. A return
/// with no certified control chain proves nothing, and neither does a body
/// with no return.
fn recovered_return_mechanism(
    facts: &crate::semantic::PreparedFunctionFacts,
) -> Option<RecoveredReturnMechanism> {
    let mut mechanism = None;
    for (at, boundary) in &facts.boundaries.returns {
        let Some(return_address) = boundary.return_address else {
            r2il::refusal_evidence!(
                "interface-recovery",
                "return {at:?} has no return-address fact, so no return mechanism"
            );
            return None;
        };
        let Some(certificate) = facts.certificates.machine_return_controls.get(at) else {
            r2il::refusal_evidence!(
                "interface-recovery",
                "return {at:?} has no certified control chain, so no return mechanism"
            );
            return None;
        };
        r2il::refusal_evidence!(
            "interface-recovery",
            "return {at:?} takes {:?} from {:?}",
            return_address.storage,
            certificate
                .reload_object
                .and_then(|object| facts.objects.object(object))
                .map(|object| object.kind.clone())
        );
        let found = match certificate
            .reload_object
            .and_then(|object| facts.objects.object(object))
            .map(|object| &object.kind)
        {
            None => RecoveredReturnMechanism::Link,
            Some(crate::semantic::ObjectKind::StackSlot {
                base: StackAddressBase::StackPointer,
                offset,
                ..
            }) if *offset < 0 => RecoveredReturnMechanism::Link,
            Some(crate::semantic::ObjectKind::StackSlot {
                base: StackAddressBase::StackPointer,
                offset: 0,
                ..
            }) => RecoveredReturnMechanism::Stacked {
                slot_bytes: return_address.storage.size,
            },
            Some(_) => return None,
        };
        if mechanism.is_some_and(|known| known != found) {
            return None;
        }
        mechanism = Some(found);
    }
    mechanism
}

/// The argument-area slots the function reads and never writes, from the
/// first slot above the return address up to the first one it does not read.
///
/// A read is evidence only when its value reaches a program observation, the
/// same authority the register slots rest on. A slot some store in the body
/// writes is the function's own variable from then on, so its reads say
/// nothing about the caller. A read that crosses a slot boundary describes
/// something wider than one slot and ends the prefix there.
fn recovered_stack_parameters(
    (facts, prep): (
        &crate::semantic::PreparedFunctionFacts,
        Option<&crate::DecompilePrepFacts>,
    ),
    observations: &crate::deadphi::ProvenProgramObservations,
    first_offset: i64,
    slot_bytes: u32,
) -> ArgumentArea {
    if slot_bytes == 0 {
        return ArgumentArea::default();
    }
    // A slot the body writes can still be a parameter: at -O0 a function with
    // no argument registers advances its own argument in place. The argument
    // area above the entry stack pointer is the caller's, so a read of it is a
    // read of what the caller left there whatever the body later stores.
    // The return address is the caller's too, and the return reads it.
    let control = facts
        .certificates
        .machine_return_controls
        .values()
        .flat_map(|certificate| certificate.insts.iter().copied())
        .collect::<crate::dense::IdSet<_>>();
    let mut observed: BTreeMap<u64, Option<u32>> = BTreeMap::new();
    let mut unknown = false;
    for access in facts.structured.memory_accesses.values() {
        if access.is_write || access.space != SpaceId::Ram || control.contains(access.id.inst) {
            continue;
        }
        let (value, relative) = match area_read((facts, prep), observations, access, first_offset) {
            AreaRead::Placed { value, relative } => (value, relative),
            AreaRead::Unplaced => {
                unknown = true;
                continue;
            }
            AreaRead::Elsewhere => continue,
        };
        let Some(relative) = relative
            .checked_sub(first_offset)
            .and_then(|relative| u64::try_from(relative).ok())
        else {
            continue;
        };
        let slot = relative / u64::from(slot_bytes);
        let inside = u32::try_from(relative % u64::from(slot_bytes)).unwrap_or(u32::MAX);
        let end = inside.saturating_add(access.width);
        r2il::refusal_evidence!(
            "interface-recovery",
            "stack slot {slot} at entry offset {}: {value:?} reads {} bytes at +{inside}",
            first_offset.saturating_add(
                i64::try_from(slot)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(i64::from(slot_bytes))
            ),
            access.width
        );
        let entry = observed.entry(slot).or_insert(Some(0));
        match entry {
            Some(bytes) if end <= slot_bytes => *bytes = (*bytes).max(end),
            _ => *entry = None,
        }
    }
    let mut area = argument_area_slots(&observed, first_offset, slot_bytes);
    area.unknown |= unknown;
    area
}

/// What one frame read is to the argument area.
enum AreaRead {
    /// An observed value read at one entry offset.
    Placed {
        value: crate::ValueId,
        relative: i64,
    },
    /// It may be of the area, at no proven place or with no proven observation.
    Unplaced,
    /// Proven unread, or no read of the area.
    Elsewhere,
}

/// Where an object starts from the entry stack pointer, for an object of the entry frame.
fn frame_start(
    facts: &crate::semantic::PreparedFunctionFacts,
    object: crate::ObjectId,
) -> Option<i64> {
    use crate::semantic::ObjectKind::{FrameObject, StackSlot};
    match facts.objects.object(object).map(|object| &object.kind)? {
        StackSlot { base, offset, .. } | FrameObject { base, offset, .. }
            if *base == StackAddressBase::StackPointer =>
        {
            Some(*offset)
        }
        _ => None,
    }
}

/// Classify one read (doc/adr-result-side.md, "S25 as built", finding 8). O(annotations).
fn area_read(
    (facts, prep): (
        &crate::semantic::PreparedFunctionFacts,
        Option<&crate::DecompilePrepFacts>,
    ),
    observations: &crate::deadphi::ProvenProgramObservations,
    access: &crate::semantic::StructuredMemoryAccessFact,
    first_offset: i64,
) -> AreaRead {
    if (access.value).is_some_and(|value| observations.proven_unread(value)) {
        return AreaRead::Elsewhere;
    }
    let start = frame_start(facts, access.object);
    // An address the frame places only up to an index names no one byte of its object.
    let indexed = prep.is_some_and(|prep| {
        prep.stack_address_root_of(access.address).is_none()
            && prep.indexed_stack_address_root_of(access.address).is_some()
    });
    let exact = (access.provenance_complete && !indexed)
        .then(|| start?.checked_add(access.object_offset?))
        .flatten();
    let value = access.value.filter(|value| observations.contains(*value));
    if let Some((value, relative)) = value.zip(exact) {
        return AreaRead::Placed { value, relative };
    }
    // A place the model did not pin to one byte may still lie in the area.
    let annotated = |location: &crate::semantic::MemoryLocation| {
        frame_start(facts, location.object).is_some_and(|start| {
            match location.address.exact_offset() {
                Some(offset) => {
                    start
                        .saturating_add(offset)
                        .saturating_add(i64::from(location.size))
                        > first_offset
                }
                None => start >= first_offset,
            }
        })
    };
    let may = match access.provenance_complete {
        true => exact.or(start).is_some_and(|at| at >= first_offset),
        false => (facts
            .memory
            .uses_by_inst
            .get(access.id.inst)
            .into_iter()
            .flatten())
        .any(|read| annotated(&read.location)),
    };
    if !may {
        return AreaRead::Elsewhere;
    }
    r2il::refusal_evidence!(
        "interface-recovery",
        "a read {:?} that may be of the argument area has no proven place or observation: complete {} object {:?} offset {:?} value {:?}",
        access.id,
        access.provenance_complete,
        access.object,
        access.object_offset,
        access.value
    );
    AreaRead::Unplaced
}

/// Unread slots the argument area may hold below its highest read; past them its slots are a floor.
const HOLE_BUDGET: usize = 64;

/// The argument-area slots as the body reads them, and whether they stop at [`HOLE_BUDGET`].
#[derive(Debug, Clone, Default)]
struct ArgumentArea {
    slots: Vec<RecoveredStackParameter>,
    past_budget: bool,
    /// A read crosses two slots, or may be of the area with no proven place or observation.
    unknown: bool,
}

/// The slots below the highest read, each `observed` its widest read (`None` crossing two), are
/// parameters (rule 4). Work: `O(reads + HOLE_BUDGET)`, whatever offset a read names.
fn argument_area_slots(
    observed: &BTreeMap<u64, Option<u32>>,
    first_offset: i64,
    slot_bytes: u32,
) -> ArgumentArea {
    let highest = observed.keys().next_back().copied();
    let mut area = ArgumentArea::default();
    let parameters = &mut area.slots;
    let mut holes = 0;
    for slot in (0..).take_while(|slot| highest.is_some_and(|highest| *slot <= highest)) {
        if !observed.contains_key(&slot) {
            if holes == HOLE_BUDGET {
                r2il::refusal_evidence!(
                    "interface-recovery",
                    "argument-area slot {slot} is past {HOLE_BUDGET} holes below the read at slot {highest:?}"
                );
                area.past_budget = true;
                break;
            }
            holes += 1;
        }
        let Some(observed_bytes) = observed.get(&slot).map_or(Some(None), |bytes| {
            bytes.map(|bytes| Some(bytes.next_power_of_two().min(slot_bytes)))
        }) else {
            // A read crossing into the next slot places no parameter: the slots below stand.
            r2il::refusal_evidence!(
                "interface-recovery",
                "argument-area slot {slot} is read across its end, so the slots stop below it"
            );
            area.unknown = true;
            break;
        };
        let Some(offset) = i64::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_mul(i64::from(slot_bytes)))
            .and_then(|displacement| first_offset.checked_add(displacement))
        else {
            break;
        };
        parameters.push(RecoveredStackParameter {
            offset,
            slot_bytes,
            observed_bytes: observed_bytes.unwrap_or(slot_bytes),
            hole: observed_bytes.is_none(),
        });
    }
    area
}

/// True when this variable is a value the caller supplied.
///
/// Version 0 means SSA renaming found no prior definition in this function, so
/// the read observes whatever entered. Constants and non-register storage are
/// excluded: only a register can carry an argument under these conventions.
fn is_entry_read(func: &SSAFunction, var: &SSAVar) -> Option<CanonicalStorageId> {
    if var.version != 0 {
        return None;
    }
    let storage = func.canonical_storage_for_var(var)?;
    (storage.space == CanonicalStorageSpace::Register).then_some(storage)
}

/// Storages this function reads before writing and whose values reach a program
/// observation.
///
/// SSA normalization deliberately preserves machine-state joins that symbolic
/// execution still needs. Those joins may mention every incoming convention
/// register even when the native program never observes it, so occurrence in a
/// phi or alias-composition op is not parameter evidence. The upstream positive
/// observation certificate is the authority for admitting an entry read; an
/// unsupported/unknown obligation can cause refusal but cannot prove a parameter.
fn observed_entry_read_storages(
    func: &SSAFunction,
    graph: &SsaGraph,
    observations: &crate::deadphi::ProvenProgramObservations,
    saved: Option<&crate::dense::IdSet<crate::ValueId>>,
) -> Vec<CanonicalStorageId> {
    let mut reads = Vec::new();
    let mut note = |storage: CanonicalStorageId| {
        if !reads.contains(&storage) {
            reads.push(storage);
        }
    };
    let mut lanes = ReadLanes::new(graph, observations);
    for value in &graph.values {
        if observations.contains(value.id)
            && graph.def_inst(value.id).is_none()
            && saved.is_none_or(|saved| !saved.contains(value.id))
            && let Some(root) = (is_entry_read(func, &value.var))
                .or_else(|| graph.formal_projection_storage(value.id))
        {
            // Every register value is its root, so the width the program
            // read is the low lane holding every observed byte, not the
            // register's: bytes two and three of `rdi` are `edi`'s, whether
            // the build rooted the read at `rdi` or at `edi`.
            // A lane is a power of two bytes wide, so the observed run is
            // rounded up to the lane that holds it, as a stack parameter's
            // is: three bytes read through `& 0xffffff` take the four-byte
            // lane, and six take the whole register. Covering a byte the
            // program did not read is the side a formal may err on; a lane
            // no register has would leave the interface unmintable.
            let storage = Some(lanes.lane(value.id))
                .filter(|bytes| *bytes > 0 && *bytes < root.size)
                .map_or(root, |size| CanonicalStorageId { size, ..root });
            // Which observation this parameter rests on is the whole question
            // when the count is wrong, and it is knowable only here.
            let (root, chain) = observations.witness(value.id);
            let steps = chain
                .iter()
                .map(|step| {
                    let op = graph
                        .def_inst(*step)
                        .and_then(|inst| graph.inst(inst))
                        .map(|inst| match &inst.payload {
                            crate::graph::InstPayload::Phi { .. } => "phi".to_string(),
                            crate::graph::InstPayload::Op(op) => {
                                let text = format!("{op:?}");
                                text.split([' ', '(', '{'])
                                    .next()
                                    .unwrap_or("op")
                                    .to_string()
                            }
                        })
                        .unwrap_or_else(|| "entry".to_string());
                    format!("{step:?}:{op}")
                })
                .collect::<Vec<_>>();
            r2il::refusal_evidence!(
                "interface-recovery",
                "entry read {storage:?} ({:?}, bytes {}) is observed from {}: {}",
                value.id,
                observations
                    .observed_bytes(value.id)
                    .unwrap_or(crate::deadphi::ByteMask::NONE),
                root.unwrap_or("?"),
                steps.join(" <- ")
            );
            note(storage);
        }
    }
    reads
}

/// The widest offset-0 lane of an entry value an operation reads whole, which is the width it is
/// read at; the bytes it demands are narrower under a mask (`and edi, 1` reads `edi`; D266).
struct ReadLanes<'a> {
    graph: &'a SsaGraph,
    observations: &'a crate::deadphi::ProvenProgramObservations,
    /// Bytes per value, `UNSEEN` before it is asked and `ASKING` on a cycle through merges.
    lanes: Vec<u32>,
}

impl<'a> ReadLanes<'a> {
    const UNSEEN: u32 = u32::MAX;
    const ASKING: u32 = u32::MAX - 1;

    fn new(
        graph: &'a SsaGraph,
        observations: &'a crate::deadphi::ProvenProgramObservations,
    ) -> Self {
        let lanes = vec![Self::UNSEEN; graph.values.len()];
        Self {
            graph,
            observations,
            lanes,
        }
    }

    /// `value`'s lane in bytes, a power of two that covers every byte observed of it; 0 where
    /// nothing observes it. Each value is answered once: O(uses reached through merges).
    fn lane(&mut self, value: crate::ValueId) -> u32 {
        match self.lanes.get(value.0 as usize).copied() {
            Some(Self::ASKING) | None => return 0,
            Some(Self::UNSEEN) => {}
            Some(known) => return known,
        }
        self.lanes[value.0 as usize] = Self::ASKING;
        let size = self.graph.var(value).size;
        let extent = (self.observations.observed_extent_bytes(value)).unwrap_or(0);
        let mut lane = extent;
        for site in self.graph.use_sites(value).to_vec() {
            lane = lane.max(self.read_at(site, size));
        }
        let lane = match lane {
            0 => 0,
            lane => lane.next_power_of_two().min(size.next_power_of_two()),
        };
        self.lanes[value.0 as usize] = lane;
        lane
    }

    /// The bytes of a `size`-byte value the use at `site` reads beyond what it demands: a merge, a
    /// copy or an offset-0 SUBPIECE reads its output's lane, and a constant mask its output's bytes.
    fn read_at(&mut self, site: crate::graph::UseSite, size: u32) -> u32 {
        let Some(inst) = self.graph.inst(site.inst) else {
            return 0;
        };
        let Some(dst) = inst.output else {
            return 0;
        };
        let op = match &inst.payload {
            crate::graph::InstPayload::Phi { .. } => return self.lane(dst),
            crate::graph::InstPayload::Op(op) => op,
        };
        match op {
            crate::SSAOp::Copy { .. } | crate::SSAOp::Subpiece { offset: 0, .. } => self.lane(dst),
            crate::SSAOp::IntAnd { a, b, .. }
            | crate::SSAOp::IntOr { a, b, .. }
            | crate::SSAOp::IntXor { a, b, .. }
                if self.observations.contains(dst)
                    && [a, b].iter().any(|mask| self.graph.var(**mask).is_const()) =>
            {
                (self.observations.observed_extent_bytes(dst)).map_or(size, |bytes| bytes.min(size))
            }
            _ => 0,
        }
    }
}

/// Storages this function hands to a call without ever defining them.
///
/// A parameter is otherwise proven by an entry read, and a carrier the function
/// only passes on is never read explicitly: a call takes its arguments
/// implicitly, so the ordinary observation scan cannot see it. Depending on
/// register normalization, the boundary may retain that state as
/// `PreservedEntry` or as a producerless version-zero graph value; both are the
/// same exact entry carrier, while a value with a definition is not.
/// The consequence was that the argument had no parameter to name, the call
/// rendered with it dropped, and its obligation could never be discharged --
/// the affected `/bin/ls` calls refuse that way.
///
/// The evidence is the callee's, not a guess about this function. A boundary's
/// arguments come from the callee's own interface, so the argument exists
/// because the callee takes it, and `SourceCallArgumentValue::PreservedEntry`
/// says the value it receives is the one this function was entered with. That
/// is what a parameter is.
fn passed_through_entry_storages(
    boundaries: &crate::semantic::SourceBoundaryFacts,
    graph: &SsaGraph,
    held: impl Fn(
        crate::CallSiteId,
        u32,
        CanonicalStorageId,
        Option<crate::ValueId>,
    ) -> Option<CanonicalStorageId>,
) -> Vec<(CanonicalStorageId, crate::CallSiteId)> {
    let mut storages = Vec::new();
    for boundary in boundaries.calls.values() {
        // A slot the callee leaves a hole is no read of it (rule 1).
        let held = |index, storage, carrier| held(boundary.call_site, index, storage, carrier);
        let arguments = boundary.arguments.iter();
        let passed = (arguments.filter(|argument| !boundary.ignores(argument)))
            .filter_map(|argument| passed_through(graph, argument, &held))
            .map(|storage| (storage, boundary.call_site));
        for passed in passed {
            if !storages.contains(&passed) {
                storages.push(passed);
            }
        }
    }
    storages
}

/// The entry storage one argument hands on: a formal lane the boundary passes is a parameter of its
/// width, and so is an entry carrier handed whole to a callee holding its low lane (ROADMAP D105).
fn passed_through(
    graph: &SsaGraph,
    argument: &crate::semantic::SourceCallArgumentFact,
    held: &dyn Fn(u32, CanonicalStorageId, Option<crate::ValueId>) -> Option<CanonicalStorageId>,
) -> Option<CanonicalStorageId> {
    use crate::semantic::SourceCallArgumentValue::{PreservedEntry, Value};
    let crate::semantic::CallBoundarySlot::Register { index, storage } = argument.slot else {
        return None;
    };
    let entry = |value: crate::ValueId| {
        let held = graph.value(value)?;
        (graph.def_inst(value).is_none() && held.var.version == 0)
            .then_some(held)?
            .canonical_storage
    };
    match argument.value {
        Value(value) if argument.lane_of.is_some() => graph
            .formal_projection_storage(value)
            .or_else(|| entry(value)),
        Value(value) if graph.var(value).size != storage.size || entry(value) != Some(storage) => {
            None
        }
        Value(value) => Some(held(index, storage, Some(value)).unwrap_or(storage)),
        PreservedEntry => Some(held(index, storage, None).unwrap_or(storage)),
    }
}

/// True when a read of `read` observes bytes of the candidate slot.
///
/// A convention slot names the full register; a function may read only its low
/// half (`w0` of `x0`). Both are the same argument, so containment rather than
/// equality decides.
/// What a read observes of a slot: the read itself inside it, or the slot where it is the low lane of the read's root.
fn observed_in_slot(
    read: CanonicalStorageId,
    slot: CanonicalStorageId,
    machine_context: Option<&crate::SourceMachineContext>,
) -> Option<CanonicalStorageId> {
    if read.space != slot.space || read.offset != slot.offset || read.size == 0 {
        return None;
    }
    if read.size <= slot.size {
        return Some(read);
    }
    machine_context
        .is_some_and(|context| context.is_low_lane_of(slot, read))
        .then_some(slot)
}

/// The widest low slice that contributes to a recovered result.
///
/// A full-width base followed by a narrow overlay is still a full-width value,
/// while a function that only defines the low half has a narrow logical result.
/// Requiring every contributing value to belong to the convention's exact
/// location keeps an unrelated register from becoming return-width evidence.
/// What a live-out value says about the result, where a call defined it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReturnedByCall {
    /// A value the program produced, or one a call defines under a boundary that is not complete.
    Produced,
    /// The value a callee's complete boundary states it returns in this register.
    Stated,
    /// The callee returns nothing, so the register holds no value.
    Void,
    /// The callee's result is stated nowhere, so what the register holds is unproven.
    Unstated(crate::semantic::CallSiteId),
    /// A lane the call states nothing of where its callee's unproven result may be (D212, W46).
    Undecided(crate::semantic::CallSiteId),
}

/// Whether a call left this register undefined, unstated, or returned it.
///
/// A `CallDefine` stands for whatever a call may have written. When the
/// boundary proves the callee returns nothing, the register holds no value
/// the program produced, so reaching the exit through one is not a result.
fn returned_by_call(
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    value: crate::ValueId,
) -> ReturnedByCall {
    let Some(inst) = graph.def_inst(value) else {
        return ReturnedByCall::Produced;
    };
    let Some(instruction) = graph.inst(inst) else {
        return ReturnedByCall::Produced;
    };
    if !matches!(
        instruction.payload,
        crate::graph::InstPayload::Op(crate::op::SSAOp::CallDefine { .. })
    ) {
        return ReturnedByCall::Produced;
    }
    // A call and the definitions it stands for are separate instructions, so
    // the site is the nearest call above them in the same block.
    let Some(block) = graph.block(instruction.block) else {
        return ReturnedByCall::Produced;
    };
    let Some(id) = block
        .insts
        .iter()
        .take_while(|candidate| **candidate != inst)
        .filter(|candidate| graph.op(**candidate).is_some_and(crate::op::SSAOp::is_call))
        .last()
        .and_then(|call| facts.call_sites.by_inst.get(*call))
    else {
        return ReturnedByCall::Produced;
    };
    let Some(boundary) = facts.boundaries.calls.get(id) else {
        return ReturnedByCall::Produced;
    };
    r2il::refusal_evidence!(
        "interface-recovery",
        "live-out {value:?} is defined by call {id:?}: complete={} result={:?}",
        boundary.results_complete,
        boundary.result_kind
    );
    // A declared void callee proves no value; a boundary naming no result kind proves nothing either way.
    // A register outside the stated result holds what the callee left there, which is no value either.
    let held = graph.value(value).and_then(|value| value.canonical_storage);
    let outside = |result: crate::SourceCallResult| {
        held.is_some_and(|held| result.storages().all(|storage| !overlaps(storage, held)))
    };
    let unstated =
        held.is_some_and(|held| (boundary.unstated_lanes.iter()).any(|lane| overlaps(*lane, held)));
    let grouped = matches!(
        boundary.result_kind,
        Some(SourceCallResult::Unproven { .. })
    );
    match (boundary.results_complete, boundary.result_kind) {
        (true, Some(_)) if unstated => ReturnedByCall::Undecided(*id),
        (true, Some(result)) if grouped && !outside(result) => ReturnedByCall::Undecided(*id),
        (true, Some(crate::SourceCallResult::Void)) => ReturnedByCall::Void,
        (true, None) => ReturnedByCall::Unstated(*id),
        (true, Some(result)) if outside(result) => ReturnedByCall::Void,
        (true, Some(_)) => ReturnedByCall::Stated,
        _ => ReturnedByCall::Produced,
    }
}

/// Whether two storages share a byte.
fn overlaps(one: CanonicalStorageId, other: CanonicalStorageId) -> bool {
    one.space == other.space
        && one.offset < other.offset + u64::from(other.size)
        && other.offset < one.offset + u64::from(one.size)
}

/// The one carrier a body leaves defined at every exit, where the convention's
/// own result register is not one of them.
///
/// The convention says where a result would be; a body can still prove one
/// elsewhere, and the rule that a body-proven signature wins applies to the
/// result exactly as it does to arity. Two candidates prove nothing, because
/// nothing then says which one a caller reads.
fn body_proven_result(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    machine_context: Option<&crate::SourceMachineContext>,
    slots: &ConventionModel,
) -> Option<(CanonicalStorageId, crate::liveout::FunctionLiveOut)> {
    let machine_context = machine_context?;
    let excluded = [
        machine_context.stack_pointer_carrier(),
        machine_context.return_address_carrier(),
        slots.result(),
    ];
    let mut candidates = graph
        .values
        .iter()
        .filter(|value| graph.def_inst(value.id).is_some())
        .filter_map(|value| value.canonical_storage)
        .filter(|storage| storage.space == crate::CanonicalStorageSpace::Register)
        .filter(|storage| !excluded.contains(&Some(*storage)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|candidate| {
            let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[candidate]);
            (!live_out.is_empty()
                && live_out.unresolved_blocks().next().is_none()
                && !restored_from_its_save(graph, facts, &live_out, candidate))
            .then_some((candidate, live_out))
        });
    let first = candidates.next()?;
    candidates
        .next()
        .is_none()
        .then_some(first)
        .filter(|(candidate, live_out)| {
            recovered_result(func, graph, facts, live_out, *candidate)
                .register()
                .is_some()
        })
}

/// Whether every value `live_out` hands back in `storage` is the caller's own, reloaded from the
/// frame slot the body saved it to (`push rbp` ... `pop rbp`): a preserved register is no result.
fn restored_from_its_save(
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    live_out: &crate::liveout::FunctionLiveOut,
    storage: CanonicalStorageId,
) -> bool {
    let accesses = &facts.structured.memory_accesses;
    let saves_storage = |write: &crate::semantic::StructuredMemoryAccessFact| {
        let saved = write.value.and_then(|value| {
            crate::semantic::exact_copy_chain_to_entry_storage(graph, value, write.width)
        });
        saved.is_some_and(|(saved, ..)| saved == storage)
    };
    live_out.iter().all(|value| {
        let value = crate::constant::root_of(graph, value);
        let Some(read) =
            (accesses.values()).find(|access| !access.is_write && access.value == Some(value))
        else {
            return false;
        };
        let mut writes = (accesses.values())
            .filter(|access| access.object == read.object && access.is_write)
            .peekable();
        writes.peek().is_some()
            && writes.all(|write| {
                write.provenance_complete
                    && (write.width, write.object_offset) == (read.width, read.object_offset)
                    && saves_storage(write)
            })
    })
}

/// The result the returns prove; a walk that reaches no return proves void only where non-returning calls close the body.
///
/// Where the carrier is also an argument slot, the caller fills it, so an untouched one may be returned.
fn returned_result(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    live_out: &crate::liveout::FunctionLiveOut,
    slots: &ConventionModel,
) -> (RecoveredFunctionResult, Returned) {
    let Some(slot) = slots.result() else {
        return (RecoveredFunctionResult::Unproven, Returned::Value);
    };
    let entry_undefined = entry_defines_nothing(graph, slots, slot);
    let input = (slots
        .arguments(r2source::convention::SlotClass::Integer)
        .iter())
    .any(|argument| argument.location() == slot.location());
    let merged_entry = returns_the_callers_value(graph, live_out, slot);
    // A path holding the caller's carrier is untouched, unless its byte defines nothing (case 1)
    // or a merge hands back the parameter in an argument register, a value the text spells.
    let untouched = !entry_undefined
        && (live_out.unresolved_blocks().next().is_some() || (merged_entry && !input));
    let result = if !live_out.has_returns() {
        // A call leaves nothing where control never comes back; the header reads `unreached`.
        if closed_by_calls_that_do_not_return(func) {
            RecoveredFunctionResult::Void
        } else {
            RecoveredFunctionResult::Unproven
        }
    } else if live_out.clobbered_blocks().next().is_some() || untouched {
        // A call nothing states, a supervisor call, or an entry byte of an input leaves it unproven.
        RecoveredFunctionResult::Unproven
    } else {
        // Undefined joined with data is data: void where no return defines a byte.
        let returns = Returns {
            func,
            graph,
            facts,
            live_out,
            entry_undefined,
        };
        recovered_result_over(&returns, slot, false)
    };
    r2il::refusal_evidence!(
        "interface-recovery",
        "result at the returns: returns={} unresolved={} clobbered={} -> {result:?}",
        live_out.has_returns(),
        live_out.unresolved_blocks().count(),
        live_out.clobbered_blocks().count()
    );
    // Unproven only because the carrier may still hold what the caller left: no unstated call
    // touches it, so the register is the result's and the parameters are the body's own.
    let handed_back = result == RecoveredFunctionResult::Unproven
        && live_out.has_returns()
        && live_out.clobbered_blocks().next().is_none()
        && untouched;
    if result.register().is_some() && merged_entry && input {
        return (result, Returned::Input);
    }
    (
        result,
        if handed_back {
            Returned::HandedBack
        } else {
            Returned::Value
        },
    )
}

/// How the returns hold a register result: a value, the caller's own carrier, or a parameter a
/// merge hands back (an entry input, spelled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Returned {
    Value,
    HandedBack,
    Input,
}

/// Whether some return hands back the carrier's entry value, directly or as an
/// arm of the merges that reach it.
///
/// One pass over the live-out values and the phis above them, each visited
/// once.
fn returns_the_callers_value(
    graph: &SsaGraph,
    live_out: &crate::liveout::FunctionLiveOut,
    slot: CanonicalStorageId,
) -> bool {
    let mut seen = crate::dense::IdSet::default();
    let mut pending = live_out.iter().collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
            if graph
                .value(value)
                .and_then(|value| value.canonical_storage)
                .is_some_and(|storage| storage.location() == slot.location())
            {
                return true;
            }
            continue;
        };
        if matches!(inst.payload, crate::graph::InstPayload::Phi { .. }) {
            pending.extend(graph.inputs(inst.id).iter().copied());
        }
    }
    false
}

/// Whether `slot`'s entry byte is no input and the body reads none of it, so it defines no result
/// (doc/adr-scratch-result.md, case 1).
fn entry_defines_nothing(
    graph: &SsaGraph,
    slots: &ConventionModel,
    slot: CanonicalStorageId,
) -> bool {
    let input = (slots
        .arguments(r2source::convention::SlotClass::Integer)
        .iter())
    .any(|argument| argument.location() == slot.location());
    !input && !read_on_entry(graph, slot)
}

/// Whether the body reads a byte of `slot` as it was entered (SysV's `al` vector count): a use
/// past copies and merges, other than a call's or a return's boundary read. O(uses reached).
fn read_on_entry(graph: &SsaGraph, slot: CanonicalStorageId) -> bool {
    let entry = (graph.values.iter())
        .filter(|value| graph.def_inst(value.id).is_none())
        .filter(|value| {
            value
                .canonical_storage
                .is_some_and(|held| overlaps(held, slot))
        });
    let mut pending = entry.map(|value| value.id).collect::<Vec<_>>();
    let mut seen = crate::dense::IdSet::default();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                continue;
            };
            match &inst.payload {
                crate::graph::InstPayload::Phi { .. }
                | crate::graph::InstPayload::Op(
                    crate::op::SSAOp::Copy { .. }
                    | crate::op::SSAOp::IntZExt { .. }
                    | crate::op::SSAOp::Subpiece { .. },
                ) => pending.extend(inst.output),
                crate::graph::InstPayload::Op(
                    crate::op::SSAOp::CallUse { .. } | crate::op::SSAOp::Return { .. },
                ) => {}
                crate::graph::InstPayload::Op(_) => return true,
            }
        }
    }
    false
}

/// Whether every way out of the body is a call its source says does not come back.
fn closed_by_calls_that_do_not_return(func: &SSAFunction) -> bool {
    func.cfg().blocks().all(|block| {
        !block.successors().is_empty()
            || matches!(
                block.terminator,
                crate::cfg::BlockTerminator::Call {
                    fallthrough: None,
                    ..
                } | crate::cfg::BlockTerminator::IndirectCall { fallthrough: None }
            )
    })
}

/// The carrier the answered returns fill, void where none does, unproven where one is stated nowhere.
///
/// Its width is the widest any return path wrote (doc/adr-written-lanes.md):
/// The float result register and its live-out, where an operation of the body reaches a return
/// there through any merge: a call's clobber and the caller's own value are not the body's.
fn float_result_written(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    slots: &ConventionModel,
) -> Option<(CanonicalStorageId, crate::liveout::FunctionLiveOut)> {
    // A lane a callee's unproven result may be in is a carrier, as a body's own write is (D212).
    let float = slots.results().float?;
    result_register_written(func, graph, float, Some(facts), (false, false))
}

/// `slot` and its live-out, where a body's operation, an `Undecided` lane (D212), a `stated` call's
/// result or, with `unstated`, a call stating none reaches a return there through any merge.
fn result_register_written(
    func: &SSAFunction,
    graph: &SsaGraph,
    float: CanonicalStorageId,
    facts: Option<&crate::semantic::PreparedFunctionFacts>,
    (stated, unstated): (bool, bool),
) -> Option<(CanonicalStorageId, crate::liveout::FunctionLiveOut)> {
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[float]);
    let mut seen = crate::dense::IdSet::default();
    let mut pending = live_out.iter().collect::<Vec<_>>();
    // Each value is taken once, so the walk ends after at most every value reaching a return.
    while let Some(value) = pending.pop() {
        if !seen.insert(value) || !graph.written_by_body(value) {
            continue;
        }
        let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
            continue;
        };
        match &inst.payload {
            crate::graph::InstPayload::Phi { .. } => {
                pending.extend(graph.inputs(inst.id).iter().copied())
            }
            crate::graph::InstPayload::Op(crate::op::SSAOp::CallDefine { .. }) => {
                let by = facts.map(|facts| returned_by_call(graph, facts, value));
                if (stated && by == Some(ReturnedByCall::Stated))
                    || matches!(by, Some(ReturnedByCall::Undecided(_)))
                    || (unstated && matches!(by, Some(ReturnedByCall::Unstated(_))))
                {
                    return Some((float, live_out));
                }
            }
            crate::graph::InstPayload::Op(_) => return Some((float, live_out)),
        }
    }
    None
}

/// Why a lane past the typed three, or the float lane's call bytes, hold a result: the supply walk
/// of doc/adr-result-side.md, "S36 as built". O(V + lanes × (V + E)).
fn unheld_lane_written(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    machine_context: &crate::SourceMachineContext,
) -> Option<SourceResultCause> {
    let model = machine_context.convention()?;
    if model.results_complete.is_none() {
        return Some(SourceResultCause::LanesUnbounded);
    }
    let written = (graph.values.iter())
        .filter(|value| graph.def_inst(value.id).is_some())
        .filter_map(|value| value.canonical_storage)
        .collect::<BTreeSet<_>>();
    let walk = |lane: CanonicalStorageId, unstated_only: bool| {
        if !written.iter().any(|storage| overlaps(*storage, lane)) {
            return None;
        }
        lane_supply(func, graph, facts, (machine_context, lane), unstated_only)
    };
    // The float lane's body writes are `float_result_written`'s; a call's bytes there are not yet.
    let typed = model.typed_results();
    if let Some(cause) = typed.float.and_then(|float| walk(float, true)) {
        return Some(cause);
    }
    let typed = [typed.integer, typed.float, typed.second];
    let mut holds = vec![false; model.results.len()];
    for (at, lane) in model.results.iter().enumerate() {
        let first_empty = lane.follows.is_some_and(|first| !holds[first]);
        if typed
            .iter()
            .flatten()
            .any(|held| overlaps(*held, lane.storage))
            || lane.entry == r2source::convention::LaneEntry::Input
            || first_empty
        {
            continue;
        }
        if let Some(cause) = walk(lane.storage, false) {
            holds[at] = true;
            return Some(cause);
        }
    }
    None
}

/// What a return leaves in `lane` past its entry bytes, by copies and merges: a body write
/// (`Written`, unless `unstated_only`) or a call's bytes no contract states. O(V + E).
fn lane_supply(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    (machine_context, lane): (&crate::SourceMachineContext, CanonicalStorageId),
    unstated_only: bool,
) -> Option<SourceResultCause> {
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[lane]);
    let mut seen = crate::dense::IdSet::default();
    let mut pending = live_out.iter().collect::<Vec<_>>();
    // Each value is taken once, so the walk ends after every value reaching a return.
    while let Some(value) = pending.pop() {
        let value = crate::constant::root_of(graph, value);
        if !seen.insert(value) || !graph.written_by_body(value) {
            continue;
        }
        let Some(inst) = graph.def_inst(value).and_then(|inst| graph.inst(inst)) else {
            continue;
        };
        let cause = match &inst.payload {
            crate::graph::InstPayload::Phi { .. } => {
                pending.extend(graph.inputs(inst.id).iter().copied());
                None
            }
            crate::graph::InstPayload::Op(crate::op::SSAOp::CallDefine { .. }) => {
                call_supply(graph, facts, machine_context, value, unstated_only)
            }
            crate::graph::InstPayload::Op(_) => {
                (!unstated_only).then_some(SourceResultCause::Written)
            }
        };
        if cause.is_some() {
            return cause;
        }
    }
    None
}

/// Why a call's bytes at a return are a result; on the float lane, a callee whose carriers leave it
/// out writes none there (scratch-result case 2; per-lane supply is S16's).
fn call_supply(
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    machine_context: &crate::SourceMachineContext,
    value: crate::ValueId,
    unstated_only: bool,
) -> Option<SourceResultCause> {
    let id = match returned_by_call(graph, facts, value) {
        ReturnedByCall::Void => return None,
        ReturnedByCall::Stated | ReturnedByCall::Produced => {
            return (!unstated_only).then_some(SourceResultCause::Written);
        }
        ReturnedByCall::Unstated(id) | ReturnedByCall::Undecided(id) => id,
    };
    let call = facts.call_sites.by_id.get(&id)?;
    let statement =
        (call.direct_target).and_then(|target| machine_context.callee_statement(target));
    if unstated_only
        && statement
            .and_then(|s| s.carriers)
            .is_some_and(|c| c.float.is_none())
    {
        return None;
    }
    let named =
        (call.direct_target).map_or(SourceUnstatedCall::Indirect, SourceUnstatedCall::Direct);
    Some(SourceResultCause::Returned(named))
}

/// `slot`, where every return hands back a value the body wrote there: no path leaves it as the
/// caller left it, and no call nothing states clobbers it.
fn written_on_every_return(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    slot: Option<CanonicalStorageId>,
) -> Option<CanonicalStorageId> {
    let slot = slot?;
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[slot]);
    let whole = live_out.has_returns()
        && live_out.unresolved_blocks().next().is_none()
        && live_out.clobbered_blocks().next().is_none()
        && !returns_the_callers_value(graph, &live_out, slot);
    // A half is the body's on every path: `sete dl` over the caller's other seven bytes is none.
    let written = func.written_or_captured();
    let whole_width = |value: crate::ValueId| {
        let Some(storage) = graph.value(value).and_then(|value| value.canonical_storage) else {
            return false;
        };
        let bytes = written_bytes(&written, graph, value, &mut BTreeSet::new());
        !crate::lanes::keeps_callers(&bytes, storage)
    };
    (whole
        && live_out.iter().all(whole_width)
        && matches!(
            recovered_result(func, graph, facts, &live_out, slot),
            RecoveredFunctionResult::Register(_)
        ))
    .then_some(slot)
}

/// Whether every return hands back in `lane` what a call left there, stated or not. O(V + E).
fn left_by_calls(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    lane: CanonicalStorageId,
) -> bool {
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[lane]);
    live_out.has_returns()
        && live_out.unresolved_blocks().next().is_none()
        && live_out.iter().all(|value| {
            matches!(
                returned_by_call(graph, facts, value),
                ReturnedByCall::Stated | ReturnedByCall::Unstated(_) | ReturnedByCall::Undecided(_)
            )
        })
}

/// The float bytes a closed-world read takes.
fn float_bytes(closed: r2source::SourceClosedResult) -> Option<u8> {
    match closed {
        r2source::SourceClosedResult::Read(r2source::SourceReadLanes::Float { bytes }) => {
            Some(bytes)
        }
        _ => None,
    }
}

/// The low `bytes` of the float slot, where they fit it.
fn float_lane(float: CanonicalStorageId, bytes: u8) -> CanonicalStorageId {
    CanonicalStorageId {
        size: u32::from(bytes).min(float.size),
        ..float
    }
}

/// one past the highest byte some path computed or moved there, as lifted,
/// and the carrier's own where a path wrote none of it.
fn recovered_result(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    live_out: &crate::liveout::FunctionLiveOut,
    slot: CanonicalStorageId,
) -> RecoveredFunctionResult {
    let returns = Returns {
        func,
        graph,
        facts,
        live_out,
        entry_undefined: false,
    };
    recovered_result_over(&returns, slot, false)
}

/// A body, its facts, and the values its returns hand back.
struct Returns<'a> {
    func: &'a SSAFunction,
    graph: &'a SsaGraph,
    facts: &'a crate::semantic::PreparedFunctionFacts,
    live_out: &'a crate::liveout::FunctionLiveOut,
    /// The carrier's entry bytes define nothing (doc/adr-scratch-result.md, case 1).
    entry_undefined: bool,
}

/// `recovered_result`, where `skip_unstated` sets aside the values a call defines and nothing states.
fn recovered_result_over(
    returns: &Returns<'_>,
    slot: CanonicalStorageId,
    skip_unstated: bool,
) -> RecoveredFunctionResult {
    let Returns {
        func,
        graph,
        facts,
        live_out,
        entry_undefined,
    } = *returns;
    let written = func.written_or_captured();
    let mut observed = None;
    // Each path's bytes above its own width; a path that leaves none states no fill.
    let mut above = Vec::new();
    // A return no write reaches leaves the caller's bytes above: no fill is stated.
    let mut every_path_writes = live_out.unresolved_blocks().next().is_none();
    for value in live_out.iter() {
        match returned_by_call(graph, facts, value) {
            ReturnedByCall::Void => {
                every_path_writes = false;
                continue;
            }
            // A seed starts a cycle's fixpoint from its own paths: the calls' reads raise it.
            ReturnedByCall::Unstated(_) | ReturnedByCall::Undecided(_) if skip_unstated => continue,
            ReturnedByCall::Unstated(_) | ReturnedByCall::Undecided(_) => {
                return RecoveredFunctionResult::Unproven;
            }
            ReturnedByCall::Produced | ReturnedByCall::Stated => {}
        }
        let Some(storage) = graph.value(value).and_then(|value| value.canonical_storage) else {
            return RecoveredFunctionResult::Unproven;
        };
        if storage.location() != slot.location() || storage.size == 0 || storage.size > slot.size {
            return RecoveredFunctionResult::Unproven;
        }
        let bytes = written_bytes(&written, graph, value, &mut BTreeSet::new());
        // Undefined joined with data is data; a path of undefined bytes alone leaves no result.
        if crate::lanes::defines_nothing(&bytes, storage, entry_undefined) {
            every_path_writes = false;
            continue;
        }
        // A path that writes no byte of the carrier hands back what the
        // caller left there -- on arm64, the first argument, returned through
        // a spill and reload -- whose width the body does not narrow: the
        // carrier's. Whether that hands-back is a result at all is decided
        // above, by the definitions that reach the return.
        let observed_size = crate::lanes::written_width(&bytes, storage).unwrap_or(storage.size);
        every_path_writes &= storage.size == slot.size;
        above.push(bytes);
        let storage = CanonicalStorageId {
            space: slot.space,
            offset: slot.offset,
            size: observed_size,
        };
        if observed.is_none_or(|current: CanonicalStorageId| storage.size > current.size) {
            observed = Some(storage);
        }
    }
    observed.map_or(RecoveredFunctionResult::Void, |observed| {
        let above = match every_path_writes {
            true => crate::lanes::above(&above, observed.size),
            false => r2source::SourceAbove::Undefined,
        };
        RecoveredFunctionResult::Register(RecoveredResult {
            slot,
            observed,
            float: false,
            above,
        })
    })
}

/// What each byte of a value holds, low byte first: as its definition wrote
/// it when the function was lifted, where the definition is one the lift
/// made; otherwise from what its inputs hold, by the same rules.
///
/// The record is what makes this a fact about the instruction rather than the
/// optimised operation: `ZEXT(EAX ^ EAX)` folds to the literal `0:8`, whose
/// bytes are all data, while the instruction computed four of them. A value
/// defined after the lift -- a lane projection -- is read through its inputs;
/// a cycle among such values, which no record breaks, is data.
#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(
        entity_keyed_map,
        reason = "a walk guard of one query: the few ids one walk visits, where a bitset would cost O(values) per query"
    )
)]
fn written_bytes(
    written: &crate::lanes::Written,
    graph: &SsaGraph,
    value: crate::ValueId,
    visiting: &mut BTreeSet<crate::ValueId>,
) -> crate::lanes::Bytes {
    let Some(held) = graph.value(value) else {
        return Vec::new();
    };
    let size = held.var.size;
    let Some(inst_id) = graph.def_inst(value) else {
        return crate::lanes::entry_bytes(held.canonical_storage, size);
    };
    if let Some(recorded) = graph
        .op_for_inst(inst_id)
        .and_then(|id| written.of(id))
        .filter(|bytes| bytes.len() == size as usize)
    {
        return recorded;
    }
    let Some(inst) = graph.inst(inst_id) else {
        return Vec::new();
    };
    if !visiting.insert(value) {
        return vec![crate::lanes::Byte::Data; size as usize];
    }
    let bytes = match &inst.payload {
        crate::graph::InstPayload::Phi { .. } => {
            let mut joined: Option<crate::lanes::Bytes> = None;
            for source in graph.inputs(inst.id).to_vec() {
                let source = written_bytes(written, graph, source, visiting);
                joined = Some(match joined {
                    None => source,
                    Some(held) => crate::lanes::join(&held, &source),
                });
            }
            joined.unwrap_or_default()
        }
        crate::graph::InstPayload::Op(op) => {
            let facts = |id: &crate::ValueId| crate::op::var_facts(graph.var(*id));
            let inputs = op
                .sources()
                .into_iter()
                .map(|source| {
                    let bytes = match facts(source) {
                        (size, Some(_)) => vec![crate::lanes::Byte::Data; size as usize],
                        _ => written_bytes(written, graph, *source, visiting),
                    };
                    (*source, bytes)
                })
                .collect::<BTreeMap<_, _>>();
            // A definition the lift did not make states no instruction's
            // extension, so none of its fills is the architecture's.
            crate::lanes::transfer(op, false, facts, |source| {
                inputs
                    .get(source)
                    .cloned()
                    .unwrap_or_else(|| vec![crate::lanes::Byte::Data; facts(source).0 as usize])
            })
        }
    };
    visiting.remove(&value);
    bytes
}

/// Recover what the machine code proves about this function's interface.
///
/// Parameters are the longest prefix of the convention's candidate slots that
/// the function reads before writing. The prefix stops at the first slot it does
/// not read: a gap cannot be resolved, because an unread slot is equally
/// consistent with an unused parameter and with the function taking fewer
/// arguments, and claiming either would be a guess. Under-reporting a trailing
/// unused parameter is the safe direction.
///
/// Returns `None` when the convention offers no candidates, which leaves the
/// caller to refuse rather than assume a convention. Production recovers on the
/// preliminary build, before the seal drops the lane record it reads.
#[cfg(test)]
pub(crate) fn recover_interface(
    func: &SSAFunction,
    slots: &ConventionModel,
) -> Option<RecoveredInterface> {
    let stated = Stated::default();
    recover_interface_inner(func, None, slots, None, stated).expect("a test function settles")
}

/// What the program states about a function beside its body: its callers' reads.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Stated {
    closed: Option<r2source::SourceClosedResult>,
    /// Whether that decision rests on a cited slot (`SourceClosedDecision::premises`).
    through_slot: bool,
    /// Whether the walk left a transfer it did not follow: code no read sees may take more arguments.
    unseen: bool,
}

impl Stated {
    pub(crate) fn of(source: &r2source::OwnedFunctionSnapshot) -> Self {
        let function = source.function();
        Self {
            closed: function.closed_result(),
            through_slot: (function.closed_decision()).is_some_and(|decided| decided.through_slot),
            unseen: (source.image().blocks().iter()).any(|block| block.transfer_unresolved()),
        }
    }
}

/// Recover an interface while retaining exact source-owned call boundaries.
///
/// This is the production path. The context is provisional only in that it
/// does not yet contain the function interface being recovered; its call-site
/// identities and interfaces are already final source facts.
///
/// `prep` is the prep facts of `func`, which is prepared and never sealed.
pub(crate) fn recover_interface_with_context(
    func: &SSAFunction,
    prep: &crate::function::Provisional,
    slots: &ConventionModel,
    machine_context: &crate::SourceMachineContext,
    stated: Stated,
) -> Result<Option<RecoveredInterface>, crate::fixpoint::Exhausted> {
    recover_interface_inner(func, Some(prep), slots, Some(machine_context), stated)
}

fn recover_interface_inner(
    func: &SSAFunction,
    provisional: Option<&crate::function::Provisional>,
    slots: &ConventionModel,
    machine_context: Option<&crate::SourceMachineContext>,
    Stated {
        closed,
        through_slot,
        unseen,
    }: Stated,
) -> Result<Option<RecoveredInterface>, crate::fixpoint::Exhausted> {
    // A convention with no argument registers still places its arguments: x86
    // cdecl puts every one on the stack. Only a convention that states neither
    // offers nothing to intersect the body's reads against.
    if slots
        .arguments(r2source::convention::SlotClass::Integer)
        .is_empty()
        && slots.stack_arguments().is_none()
    {
        return Ok(None);
    }
    // Recovery is intentionally a bounded two-phase path used only when the
    // source supplied no exact interface. This provisional O(V + E) fact pass
    // establishes the observation domain; the ordinary preparation pass then
    // seals the recovered interface into the final artifact. A cheaper raw-use
    // scan cannot distinguish program inputs from preserved machine state.
    // The graph the prep facts were read off, or one built here when none came with them.
    let built;
    let (graph, prep) = match provisional {
        Some(provisional) => (&provisional.graph, Some(&provisional.facts)),
        None => {
            built = SsaGraph::from_function(func);
            (&built, None)
        }
    };
    let facts = if let Some(machine_context) = machine_context {
        crate::semantic::PreparedFunctionFacts::collect_for_recovery(
            func,
            prep,
            graph,
            machine_context,
        )?
    } else {
        crate::semantic::PreparedFunctionFacts::collect(func, graph)?
    };
    if !facts.obligations.is_complete() {
        r2il::refusal_evidence!(
            "interface-recovery",
            "the obligation inventory is incomplete, so no interface is recovered and \
             every ABI question about this function answers `unavailable`"
        );
        return Ok(None);
    }

    let lanes = r2source::convention::TypedResults {
        integer: slots.result(),
        float: slots.results().float,
        second: slots.results().second,
    };
    let tail = match tail_result_storage(func, &facts, lanes) {
        TailResult::NoTailBoundary => TailResult::NoTailBoundary,
        TailResult::Exact(result) => TailResult::Exact(result),
        // The body hands control to a callee it names nothing about, and
        // that callee's result is this function's result on that path. A
        // register the body never wrote is not evidence of a void result
        // here; it is evidence that the answer lives in a body not read.
        // Claiming void from it gave every caller of an import thunk a
        // callee that returns nothing, and the caller then read the return
        // register as a value no statement had assigned.
        // A body that returns a value on a path of its own answers the
        // boundary the tail transfer leaves open. `shape_mutual_even` ends
        // one arm with `return accumulator ^ ...` and tails to its partner on
        // the other; the convention gives both the same result register, so
        // the arm that writes it says what the function returns. An import
        // thunk has no such arm and still refuses.
        TailResult::Unproven
            if direct_return_result(func, graph, &facts, lanes.integer).is_some() =>
        {
            let slot = slots.result();
            r2il::refusal_evidence!(
                "interface-recovery",
                "a tail transfer owns one path and a direct return owns another; \
                 the direct return's {slot:?} is the result"
            );
            TailResult::Exact(slot.map_or(SourceCallResult::Void, SourceCallResult::register))
        }
        TailResult::Unproven => {
            r2il::refusal_evidence!(
                "interface-recovery",
                "a tail transfer to a target without a complete prototype owns the result \
                 boundary, so the result is unproven; tails {:?}",
                facts
                    .call_sites
                    .by_id
                    .values()
                    .filter(|call| call.transfer == crate::CallSiteTransfer::TailCall)
                    .map(|call| {
                        let boundary = facts.boundaries.calls.get(&call.id);
                        (
                            call.id,
                            call.at,
                            call.direct_target,
                            boundary.map(|boundary| boundary.complete),
                            boundary.and_then(|boundary| boundary.result_kind),
                        )
                    })
                    .collect::<Vec<_>>()
            );
            TailResult::Unproven
        }
    };
    // Why the direct returns beside void tails leave the result unproven, where they do.
    let mut beside_void_tails = None;
    let mut result = match tail {
        // A group states no exact tail result (`stated_result`).
        TailResult::Unproven
        | TailResult::Exact(
            SourceCallResult::Unproven { .. } | SourceCallResult::Unstated { .. },
        ) => RecoveredFunctionResult::Unproven,
        // The tail callee's value is this function's, at the width the callee states.
        TailResult::Exact(SourceCallResult::Register {
            storage: slot,
            width,
        }) => {
            let narrow = CanonicalStorageId {
                size: u32::from(width.logical),
                ..slot
            };
            let (observed, above) = match width.fills(slot) {
                true => (slot, r2source::SourceAbove::Undefined),
                false => joined_with_direct_returns(func, graph, &facts, (slot, narrow), width),
            };
            RecoveredFunctionResult::Register(RecoveredResult {
                slot,
                observed,
                float: false,
                above,
            })
        }
        TailResult::Exact(SourceCallResult::Pair { low, high }) => {
            RecoveredFunctionResult::Pair { low, high }
        }
        // A void tail leaves nothing; a direct return that defines a byte is still a result.
        TailResult::Exact(SourceCallResult::Void) => {
            let (result, cause) = direct_returns_beside_void_tails(func, graph, &facts, slots);
            beside_void_tails = cause;
            result
        }
        TailResult::NoTailBoundary => RecoveredFunctionResult::Void,
    };
    let no_tail_boundary = matches!(tail, TailResult::NoTailBoundary);
    let tail_unproven = matches!(tail, TailResult::Unproven);
    let mut result_causes = BTreeSet::new();
    result_causes.extend(beside_void_tails);
    let mut live_out = crate::liveout::FunctionLiveOut::default();
    let mut result_carriers = None;
    let read = |lanes: r2source::SourceReadLanes| {
        closed == Some(r2source::SourceClosedResult::Read(lanes))
    };
    let mut applied = None;
    let mut result_holds_input = false;
    let mut unreached = false;
    // An exact tail-call interface owns this boundary. Looking at the value
    // present before the branch would instead mistake a call argument for the
    // value the callee returns into the same register.
    if no_tail_boundary && let Some(candidate) = slots.result() {
        let mut candidate_live_out =
            crate::liveout::FunctionLiveOut::compute(func, graph, &[candidate]);
        let (recovered, returned) =
            returned_result(func, graph, &facts, &candidate_live_out, slots);
        result = recovered;
        unreached = !candidate_live_out.has_returns();
        let handed_back = returned == Returned::HandedBack;
        result_holds_input = returned == Returned::Input;
        if result == RecoveredFunctionResult::Unproven {
            let causes = [
                (!candidate_live_out.has_returns()).then_some(SourceResultCause::NoReturn),
                (candidate_live_out.clobbered_blocks().next().is_some())
                    .then_some(SourceResultCause::Clobbered),
                handed_back.then_some(SourceResultCause::HandedBack),
            ];
            result_causes.extend(causes.into_iter().flatten());
        }
        if handed_back {
            result_carriers = Some(r2source::SourceResultCarriers {
                integer: candidate,
                float: None,
                second: None,
                integer_undefined: false,
                float_second: None,
            });
        }
        // A body that writes both result registers on its way out hands back one of them: the
        // callers' reads say which, where they agree (doc/adr-resolved-bodies.md, "Caller reads").
        if result.register().is_some()
            && let Some((float, float_live_out)) = float_result_written(func, graph, &facts, slots)
        {
            let float_read = (closed.and_then(float_bytes)).map(|bytes| float_lane(float, bytes));
            match closed {
                Some(r2source::SourceClosedResult::Read(r2source::SourceReadLanes::Integer)) => {
                    applied = closed;
                }
                // The carrier is the lane the reads take, as a declared float's is (`low_lane`):
                // AArch64's float slot is all of q0, and a double is d0.
                _ if float_read.is_some() => {
                    let observed = float_read.expect("checked");
                    result = RecoveredFunctionResult::Register(RecoveredResult {
                        slot: observed,
                        observed,
                        float: true,
                        above: r2source::SourceAbove::Undefined,
                    });
                    candidate_live_out = float_live_out;
                    applied = closed;
                }
                _ => {
                    result_carriers = Some(r2source::SourceResultCarriers {
                        integer: candidate,
                        float: Some(float),
                        second: None,
                        integer_undefined: false,
                        float_second: None,
                    });
                    result = RecoveredFunctionResult::Unproven;
                    result_causes.insert(SourceResultCause::Ambiguous);
                }
            }
        }
        // An integer register holding nothing the body computed leaves the float one, which the body
        // or a callee's stated result fills, as the result where every reading call reads it there.
        let integer_unheld = handed_back || result == RecoveredFunctionResult::Void;
        if integer_unheld
            && let Some(float) = slots.results().float
            && let Some((float, float_live_out)) =
                result_register_written(func, graph, float, Some(&facts), (true, true))
        {
            match (closed.and_then(float_bytes)).map(|bytes| float_lane(float, bytes)) {
                Some(observed) => {
                    result = RecoveredFunctionResult::Register(RecoveredResult {
                        slot: observed,
                        observed,
                        float: true,
                        above: r2source::SourceAbove::Undefined,
                    });
                    result_carriers = None;
                    candidate_live_out = float_live_out;
                    applied = closed;
                }
                // A written float lane is a carrier no read decided: never void (D200). One an unstated
                // call fills is that call's (`result_calls`).
                None if result == RecoveredFunctionResult::Void => {
                    result = RecoveredFunctionResult::Unproven;
                    // What feeds the written lane is observed: its inputs are parameters.
                    candidate_live_out = float_live_out;
                    if result_register_written(func, graph, float, Some(&facts), (true, false))
                        .is_some()
                    {
                        result_causes.insert(SourceResultCause::Written);
                    }
                    result_carriers = Some(r2source::SourceResultCarriers {
                        integer: candidate,
                        float: Some(float),
                        second: None,
                        integer_undefined: true,
                        float_second: None,
                    });
                }
                // An argument handed back beside a written float: the callers' reads choose.
                None if handed_back => {
                    result_carriers = Some(r2source::SourceResultCarriers {
                        integer: candidate,
                        float: Some(float),
                        second: None,
                        integer_undefined: false,
                        float_second: None,
                    });
                }
                None => {}
            }
        }
        // An integer result whose second register the body also writes on every return is one
        // value in both where every reading call reads the second (doc/adr-language-profile.md,
        // item 1); unasked, it asks them.
        if let RecoveredFunctionResult::Register(low) = result
            && !low.float()
            && let Some(high) = written_on_every_return(func, graph, &facts, slots.results().second)
        {
            let both =
                || crate::liveout::FunctionLiveOut::compute(func, graph, &[low.slot(), high]);
            // One closed-world call reading the second register is evidence the value spans both.
            if read(r2source::SourceReadLanes::Pair) {
                result = RecoveredFunctionResult::Pair {
                    low: low.slot(),
                    high,
                };
                candidate_live_out = both();
                applied = closed;
            } else if !read(r2source::SourceReadLanes::Integer) {
                // The second register is a carrier a reading call may take; what feeds it is observed.
                result_carriers = Some(r2source::SourceResultCarriers {
                    integer: low.slot(),
                    float: None,
                    second: Some(high),
                    integer_undefined: false,
                    float_second: None,
                });
                candidate_live_out = both();
            }
        }
        if !candidate_live_out.is_empty()
            && (candidate_live_out.unresolved_blocks().next().is_none()
                || result.register().is_some()
                || matches!(result, RecoveredFunctionResult::Pair { .. }))
        {
            live_out = candidate_live_out;
        }
    }
    // A body may prove a result the convention does not name: a position-
    // independent code thunk returns the address a call pushed, in whichever
    // register its name says. Only one carrier may qualify, or the body has
    // proven nothing about which of them a caller reads.
    // An unproven convention carrier may be what the caller reads, so no other carrier is the one result.
    if no_tail_boundary && result == RecoveredFunctionResult::Void {
        let mut proven = body_proven_result(func, graph, &facts, machine_context, slots);
        if let Some((candidate, candidate_live_out)) = proven.take() {
            result = recovered_result(func, graph, &facts, &candidate_live_out, candidate);
            live_out = candidate_live_out;
        }
    }
    // An entry byte of the float lane, an input, may be the result where the integer one holds none.
    if !tail_unproven
        && result == RecoveredFunctionResult::Void
        && let Some(float) = slots.results().float
    {
        let tails = owned_tail_blocks(func, graph, &facts, float);
        let float_live_out =
            crate::liveout::FunctionLiveOut::compute(func, graph, &[float]).without(&tails);
        // A path that never writes the lane reaches the entry unresolved, or through a merge's arm.
        if float_live_out.has_returns()
            && (float_live_out.unresolved_blocks().next().is_some()
                || returns_the_callers_value(graph, &float_live_out, float))
        {
            result = RecoveredFunctionResult::Unproven;
            result_causes.insert(SourceResultCause::HandedBack);
            result_carriers = (slots.result()).map(|integer| r2source::SourceResultCarriers {
                integer,
                float: Some(float),
                second: None,
                integer_undefined: true,
                float_second: None,
            });
        }
    }
    // A forwarder's carriers are the lanes its calls leave at its returns, so the open read the
    // decision reads names them though no callee is resolved there (D317).
    if no_tail_boundary
        && result == RecoveredFunctionResult::Unproven
        && result_carriers.is_none()
        && let Some(integer) = slots.result()
    {
        let float = (slots.results().float).filter(|lane| {
            result_register_written(func, graph, *lane, Some(&facts), (true, true)).is_some()
        });
        let second =
            (slots.results().second).filter(|lane| left_by_calls(func, graph, &facts, *lane));
        if float.is_some() || second.is_some() {
            result_carriers = Some(r2source::SourceResultCarriers {
                integer,
                float,
                second,
                integer_undefined: false,
                float_second: None,
            });
        }
    }
    // The lane after the float one, written at a return, makes a float result one group with it.
    if let Some(carriers) = &mut result_carriers
        && let (Some(_), Some(context)) = (carriers.float, machine_context)
    {
        let results = convention_results(context.convention());
        let lanes = crate::site_boundary::ResultLanes::of(slots, &results);
        let model = context.convention().map(|model| &model.results[..]);
        carriers.float_second = model
            .and_then(|model| lanes.after_float(model))
            .filter(|(lane, _)| lane_supply(func, graph, &facts, (context, *lane), false).is_some())
            .and_then(|(_, id)| u8::try_from(id).ok());
    }
    // Void only where every lane of the return set holds nothing (S36): asked only of a `Void` the
    // body or the closed world would decide, whose cause then keeps it `Unproven`.
    let deciding_void = result == RecoveredFunctionResult::Void
        || (result == RecoveredFunctionResult::Unproven
            && closed == Some(r2source::SourceClosedResult::Void));
    let unheld = deciding_void
        .then(|| unheld_lane_written(func, graph, &facts, machine_context?))
        .flatten();
    if let Some(cause) = unheld {
        result = RecoveredFunctionResult::Unproven;
        result_causes.insert(cause);
    }
    // The closed world's held decision, a stated input applied as stated (doc/adr-result-side.md).
    match closed {
        Some(r2source::SourceClosedResult::Read(_)) => applied = closed,
        // A decided `void` yields to a lane the walk finds written: no `Void` unless every lane holds none.
        Some(r2source::SourceClosedResult::Void) if unheld.is_some() => {
            r2il::refusal_evidence!(
                "interface-recovery",
                "a closed-world void yields to {unheld:?}"
            );
        }
        // A cited `void` slot is the C type every way in calls it through: a written lane is no result (S30).
        Some(
            r2source::SourceClosedResult::Void | r2source::SourceClosedResult::DeclaredVoid(_),
        ) => {
            result = RecoveredFunctionResult::Void;
            live_out = crate::liveout::FunctionLiveOut::default();
            result_carriers = None;
            result_causes.clear();
            applied = closed;
        }
        Some(
            cause @ (r2source::SourceClosedResult::Unread
            | r2source::SourceClosedResult::ForwardCycle),
        ) => {
            if result == RecoveredFunctionResult::Unproven {
                result_causes.insert(match cause {
                    r2source::SourceClosedResult::Unread => SourceResultCause::Unread,
                    _ => SourceResultCause::ForwardCycle,
                });
            }
            applied = closed;
        }
        None => {}
    }
    r2il::refusal_evidence!(
        "interface-recovery",
        "observation roots: live_out={} unresolved_blocks={} positive obligations={}",
        live_out.len(),
        live_out.unresolved_blocks().count(),
        facts
            .obligations
            .obligations()
            .values()
            .filter(|obligation| obligation.id.kind.is_positive_observation_root())
            .count()
    );
    let Some(observations) =
        crate::deadphi::ProvenProgramObservations::find(graph, &live_out, &facts, machine_context)
    else {
        r2il::refusal_evidence!(
            "interface-recovery",
            "no proven program observations: result_slot={:?} live_out={} unresolved_blocks={}",
            slots.result(),
            live_out.len(),
            live_out.unresolved_blocks().count()
        );
        return Ok(None);
    };
    // A variadic prologue's saves to the register save area are its tail, not parameter reads.
    let mut cursor_count = None;
    let mut save_area = prep
        .and_then(|prep| crate::save_area::register_save_area(graph, prep, slots, &observations))
        .or_else(|| {
            let (prep, machine) = prep.zip(machine_context)?;
            let homes = (graph, prep);
            crate::save_area::home_va_list(homes, &facts, slots, machine, &observations)
        })
        .or_else(|| {
            // A home the body walks itself is a tail only where its count is proven.
            let (prep, machine) = prep.zip(machine_context)?;
            let area = crate::save_area::home_cursor((graph, prep), machine, &observations)?;
            let tail = (&area, &observations);
            cursor_count = Some(crate::tail_count::tail_count(
                func, graph, prep, slots, tail,
            )?);
            Some(area)
        });
    // A carrier passed straight to a call is read by that call: the callee's statement reads it.
    // Each entry carrier's widest read, found once for every argument that asks (D105).
    let held_widths = std::cell::OnceCell::new();
    let held = |call: crate::CallSiteId, index: u32, storage: CanonicalStorageId, carrier| {
        let identity = facts.call_sites.by_id.get(&call)?.raw_identity?;
        let context = machine_context?;
        let interface = context.call_site_interface(identity)?;
        let lane = crate::semantic::callee_held_lane(interface, index, storage)?;
        let views = prep.map(|prep| &prep.views);
        let widths =
            held_widths.get_or_init(|| crate::semantic::HeldLaneWidths::of(graph, context));
        let admitted = |carrier| widths.admits(graph, views, carrier, lane.size);
        Option::<crate::ValueId>::is_none_or(carrier, admitted).then_some(lane)
    };
    let handed = passed_through_entry_storages(&facts.boundaries, graph, held);
    let observed_reads = |saved: Option<&crate::dense::IdSet<crate::ValueId>>| {
        observed_entry_read_storages(func, graph, &observations, saved)
    };
    let mut observed = observed_reads(save_area.as_ref().map(|area| &area.saved));
    let read_at = |reads: &[CanonicalStorageId], slot: CanonicalStorageId| {
        (reads.iter()).any(|read| observed_in_slot(*read, slot, machine_context).is_some())
    };
    let handed_storages = handed
        .iter()
        .map(|(storage, _)| *storage)
        .collect::<Vec<_>>();
    // A tail slot read past its save contradicts the area.
    if let Some(area) = &save_area
        && slots.arguments(r2source::convention::SlotClass::Integer)[area.named..]
            .iter()
            .any(|slot| read_at(&observed, *slot) || read_at(&handed_storages, *slot))
    {
        r2il::refusal_evidence!(
            "interface-recovery",
            "a register past the {} named slots is read beside its save, so no save area is proven",
            area.named
        );
        save_area = None;
        observed = observed_reads(None);
    }
    // A call's read of a register its certified boundary does not pass is no read (`liveness`).
    let ignored_reads = crate::function::unpassed_call_reads(graph, machine_context);
    // The call of unproven arity a `CallUse` at `inst` reads for: the first after it in its block.
    let handed_to = |inst: crate::InstId| {
        let used = graph.inst(inst)?;
        let call = (facts.boundaries.calls.values())
            .filter_map(|boundary| Some((boundary, graph.inst(boundary.at)?)))
            .filter(|(_, at)| at.block == used.block && at.ordinal > used.ordinal)
            .min_by_key(|(_, at)| at.ordinal)?
            .0;
        (call.may_read_unlisted()).then(|| unproven_call(&facts, machine_context, call.call_site))
    };
    // Each register's entry values and the lanes minted for them, found in one pass. O(V log V).
    let mut entry_values = BTreeMap::<_, Vec<crate::ValueId>>::new();
    for value in &graph.values {
        let entry = graph.def_inst(value.id).is_none() && value.var.version == 0;
        if let Some(storage) = (value.canonical_storage)
            .filter(|_| entry || graph.formal_projection_storage(value.id).is_some())
        {
            entry_values
                .entry(storage.location())
                .or_default()
                .push(value.id);
        }
    }
    // An escaped address that may reach a homed argument or the argument area lets code outside
    // read them (FrameReach); a body with no prep facts places no frame address (tests only).
    let escapes_incoming = prep.is_some_and(|prep| {
        let model = machine_context.and_then(crate::SourceMachineContext::convention);
        argument_place_escapes((graph, prep), &facts, model)
    });
    // Each register slot's use (doc/adr-call-boundary.md, rule 3).
    let use_of = |slot: CanonicalStorageId| {
        // The prologue saves every vector register under the count it is handed, and the area
        // records no float save apart from a named float's read: no float is named here.
        if save_area.is_some()
            && slots
                .arguments(r2source::convention::SlotClass::Float)
                .contains(&slot)
        {
            return SlotUse::SaveArea;
        }
        let widest = |reads: &[CanonicalStorageId]| {
            (reads.iter())
                .filter_map(|read| observed_in_slot(*read, slot, machine_context))
                .max_by_key(|read| read.size)
        };
        let entries = entry_values
            .get(&slot.location())
            .map_or(&[][..], Vec::as_slice);
        let saved = save_area.as_ref().is_some_and(|area| {
            (slots
                .arguments(r2source::convention::SlotClass::Integer)
                .get(area.named..))
            .is_some_and(|tail| tail.contains(&slot))
        });
        let home = (machine_context.and_then(crate::SourceMachineContext::convention))
            .zip(shared_position(slots, slot))
            .and_then(|(model, position)| model.home(position));
        if let Some(home) = home.filter(|_| !saved)
            && homed_in_its_home(graph, &facts, &observations, home, (entries, &handed_to))
        {
            return SlotUse::Homed {
                loaded: false,
                escapes: escapes_incoming,
            };
        }
        if let Some(read) = widest(&observed) {
            return SlotUse::Read {
                bytes: low_bytes(read.size),
            };
        }
        if let Some(read) = widest(&handed_storages) {
            let mut to = (handed.iter())
                .filter(|(storage, _)| observed_in_slot(*storage, slot, machine_context).is_some())
                .map(|(_, call)| *call)
                .collect::<Vec<_>>();
            to.sort_unstable();
            to.dedup();
            return SlotUse::HandedOn {
                bytes: low_bytes(read.size),
                to: to.into_boxed_slice(),
            };
        }
        if saved {
            return SlotUse::SaveArea;
        }
        match unobserved_use(
            (graph, &facts),
            (&ignored_reads, &observations),
            &handed_to,
            entries,
        ) {
            SlotUse::Homed { loaded, .. } => SlotUse::Homed {
                loaded,
                escapes: escapes_incoming,
            },
            used => used,
        }
    };
    // The register sections in convention order: each slot's class and register, and its use.
    let (mut registers, mut uses, mut spans) = (Vec::new(), Vec::new(), Vec::new());
    if slots.shares_positions() {
        // Microsoft x64 shares positions: a position is a float where only its float register is read.
        for (position, integer) in slots
            .arguments(r2source::convention::SlotClass::Integer)
            .iter()
            .enumerate()
        {
            let integer_use = use_of(*integer);
            let float = (slots
                .arguments(r2source::convention::SlotClass::Float)
                .get(position))
            .map(|float| (*float, use_of(*float)));
            match float {
                Some((float, float_use)) if float_use.proves() && !integer_use.proves() => {
                    registers.push((SlotClass::Float, float));
                    uses.push(float_use);
                }
                _ => {
                    registers.push((SlotClass::Integer, *integer));
                    uses.push(integer_use);
                }
            }
        }
        spans.push((Section::Shared, 0..registers.len()));
    } else {
        for (section, class, section_slots) in [
            (
                Section::Integer,
                SlotClass::Integer,
                slots.arguments(r2source::convention::SlotClass::Integer),
            ),
            (
                Section::Float,
                SlotClass::Float,
                slots.arguments(r2source::convention::SlotClass::Float),
            ),
        ] {
            let start = registers.len();
            for slot in section_slots {
                registers.push((class, *slot));
                uses.push(use_of(*slot));
            }
            spans.push((section, start..registers.len()));
        }
    }
    // The variadic tail starts at the first unnamed slot, so each slot below it is a parameter.
    let named = save_area.as_ref().map_or(0, |area| area.named);
    // Rule 1 per section; the slot past a section's parameters may be handed to a call of unproven
    // arity (D37), and only the calls it reaches are named.
    let mut counts = Vec::new();
    let mut causes = Vec::new();
    for (section, range) in spans {
        let (count, mut past) = crate::body_boundary::section_rule(&uses[range.clone()]);
        // Only the first slot past the parameters names the calls it reaches (D37's probe below),
        // which the `aa` fixpoint's arity height counts; a float section nothing reads names none.
        past.retain(|cause| !matches!(cause, SourceFloorCause::HandedOn(_)));
        if section == Section::Float && count == 0 {
            past.clear();
        }
        let count = match section {
            Section::Float => count,
            _ => count.max(named.min(range.len())),
        };
        causes.extend(past);
        // A hole a call of unproven arity may be handed is a parameter the caller must pass.
        for at in range.start..range.start + count {
            if matches!(uses[at], SlotUse::Unread | SlotUse::Homed { .. })
                && let Some(first) = (unproven_calls_reached(
                    func,
                    prep,
                    graph,
                    &facts,
                    machine_context,
                    registers[at].1,
                ))
                .first()
            {
                uses[at] = SlotUse::Unknown(SourceFloorCause::HandedOn(*first));
            }
        }
        let probed = section != Section::Float || count > 0;
        if probed && count < range.len() && save_area.is_none() {
            let at = range.start + count;
            let reached =
                unproven_calls_reached(func, prep, graph, &facts, machine_context, registers[at].1);
            if let Some(first) = reached.first() {
                uses[at] = SlotUse::Unknown(SourceFloorCause::HandedOn(*first));
            }
            causes.extend(reached.into_iter().map(SourceFloorCause::HandedOn));
        }
        counts.push((section, range, count));
    }
    let parameters = (counts.iter())
        .flat_map(|(_, range, count)| range.start..range.start + count)
        .map(|at| {
            let (class, slot) = registers[at];
            let read = (observed.iter().chain(&handed_storages))
                .filter_map(|read| observed_in_slot(*read, slot, machine_context))
                .max_by_key(|read| read.size);
            // A hole spells its class's residual type: a float register's at a double's width.
            let observed = match (read, class) {
                (Some(read), _) => read,
                (None, SlotClass::Float) => CanonicalStorageId {
                    size: slot.size.min(8),
                    ..slot
                },
                (None, _) => slot,
            };
            RecoveredParameter {
                slot,
                observed,
                class,
                basis: uses[at].basis(),
            }
        })
        .collect::<Vec<_>>();
    let tail_count = save_area.as_ref().zip(prep).and_then(|(area, prep)| {
        cursor_count.or_else(|| {
            crate::tail_count::tail_count(func, graph, prep, slots, (area, &observations))
        })
    });
    let return_mechanism = recovered_return_mechanism(&facts);
    let result_is_return_address = result.register().is_some()
        && result_is_the_return_address(graph, &facts, &live_out, return_mechanism);
    // The argument area as the body reads it, or `None` where the exits do not agree on where it is.
    let argument_area = {
        // A convention with no argument registers takes its step from the
        // stack entry the specification declares instead.
        let slot_bytes = slots
            .arguments(r2source::convention::SlotClass::Integer)
            .first()
            .map_or_else(
                || {
                    slots
                        .stack_arguments()
                        .map_or(0, |placement| placement.stride_bytes())
                },
                |slot| slot.size,
            );
        // The area starts where the convention's stack section does: past Microsoft x64's home.
        let first = (slots.stack_arguments()).map_or(0, |placement| placement.first_offset());
        match return_mechanism {
            Some(RecoveredReturnMechanism::Link) => Some(recovered_stack_parameters(
                (&facts, prep),
                &observations,
                first,
                slot_bytes,
            )),
            Some(RecoveredReturnMechanism::Stacked { slot_bytes: spent }) => {
                Some(recovered_stack_parameters(
                    (&facts, prep),
                    &observations,
                    i64::from(spent) + first,
                    slot_bytes,
                ))
            }
            None => {
                r2il::refusal_evidence!(
                    "interface-recovery",
                    "the exits do not agree on a return mechanism, so the argument area is not read"
                );
                None
            }
        }
    };
    // Rule 4: a stack slot is a parameter only behind a register section it overflows from that is
    // full, since SysV and AAPCS64 reach the stack with registers of another class still free.
    let full = registers.is_empty()
        || (counts.iter()).any(|(_, range, count)| !range.is_empty() && *count == range.len());
    let stack_parameters = match (full, &argument_area) {
        (true, Some(area)) => area.slots.clone(),
        _ => Vec::new(),
    };
    // Past the registers, a read of the argument area, or an area no exit places, is a floor; a
    // variadic tail continues there.
    let area = match (save_area.is_none(), full, &argument_area) {
        (true, true, None) => Some(SourceFloorCause::ArgumentAreaUnplaced),
        (true, false, Some(area)) if !area.slots.is_empty() => {
            Some(SourceFloorCause::ArgumentAreaRead)
        }
        // A read no slot places bounds nothing: the parameters below it are a floor.
        (true, _, Some(area)) if area.unknown => Some(SourceFloorCause::ArgumentAreaRead),
        _ => None,
    };
    let past_budget = (argument_area.as_ref()).is_some_and(|area| area.past_budget);
    // A proven variadic tail is that escape: its cursor walks the homes and the area.
    let escapes = save_area.is_none() && escapes_incoming;
    // A supervisor call reads registers no operation names, so what it is handed is no read here.
    let enters_supervisor = (graph.insts.iter()).any(|inst| {
        matches!(&inst.payload, crate::graph::InstPayload::Op(op) if func.enters_supervisor(op))
    });
    causes.extend(
        [
            unseen.then_some(SourceFloorCause::UnresolvedTransfer),
            enters_supervisor.then_some(SourceFloorCause::SupervisorEntry),
            area,
            past_budget.then_some(SourceFloorCause::ArgumentAreaPastBudget),
            escapes.then_some(SourceFloorCause::ArgumentAreaEscapes),
        ]
        .into_iter()
        .flatten(),
    );
    let arity_floor = SourceArityFloor::of(causes);
    r2il::refusal_evidence!(
        "interface-recovery",
        "register parameters {:?} from uses {:?}; a floor: {:?}",
        parameters
            .iter()
            .map(|parameter| (
                parameter.slot.offset,
                parameter.observed.size,
                parameter.basis
            ))
            .collect::<Vec<_>>(),
        uses,
        arity_floor
    );
    let boundary = crate::body_boundary::BodyBoundary {
        locations: slot_locations(&counts, &registers, &stack_parameters),
        slots: crate::dense::IdVec::from_fn(uses.len() + stack_parameters.len(), |id| {
            let at = crate::dense::DenseId::index(id);
            match uses.get(at) {
                Some(used) => used.clone(),
                None => match stack_parameters[at - uses.len()] {
                    parameter if parameter.is_hole() => SlotUse::Unread,
                    parameter => SlotUse::Read {
                        bytes: low_bytes(parameter.observed_bytes()),
                    },
                },
            }
        }),
        floor: arity_floor.clone(),
    };
    let unproven_result = match result {
        RecoveredFunctionResult::Unproven => {
            let calls = result_calls(func, graph, &facts, lanes, tail_unproven);
            result_causes.extend(calls);
            if result_causes.is_empty() {
                result_causes.insert(SourceResultCause::Undefined);
            }
            let only_returned = result_causes
                .iter()
                .all(|cause| matches!(cause, SourceResultCause::Returned(_)));
            let seed = (only_returned && no_tail_boundary)
                .then(|| seed_result(func, graph, &facts, slots))
                .flatten();
            SourceUnprovenResult::of(result_causes, seed)
        }
        _ => None,
    };

    Ok(Some(RecoveredInterface {
        parameters: parameters.into_boxed_slice(),
        stack_parameters: stack_parameters.into_boxed_slice(),
        result,
        result_is_return_address,
        return_mechanism,
        unproven_result,
        result_carriers,
        arity_floor,
        variadic: save_area.is_some(),
        tail_count,
        closed: applied.map(|result| r2source::SourceClosedDecision {
            result,
            through_slot,
        }),
        result_holds_input,
        unreached: unreached && result == RecoveredFunctionResult::Void,
        boundary,
        security_check: machine_context
            .is_some_and(|machine| crate::security_cookie::proves_check(func, machine)),
    }))
}

/// The calls of unproven arity `slot` may be handed (D37): those it reaches untouched, or all where
/// the body keeps a read of it (gcc -O2's `mov rbp, rsi`). O(calls x block).
fn unproven_calls_reached(
    func: &SSAFunction,
    prep: Option<&crate::DecompilePrepFacts>,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    machine_context: Option<&crate::SourceMachineContext>,
    slot: CanonicalStorageId,
) -> Vec<SourceUnprovenCall> {
    let unproven =
        (facts.boundaries.calls.values()).filter(|boundary| boundary.may_read_unlisted());
    let kept = graph.values.iter().any(|value| {
        graph.caller_supplied(value.id)
            && value
                .canonical_storage
                .is_some_and(|storage| overlaps(storage, slot))
            && read_beyond_merges(graph, value.id)
    });
    let reached = unproven.filter(|boundary| {
        kept || machine_context.is_some_and(|context| {
            arrives_untouched((func, prep, graph, context), boundary.at, slot)
        })
    });
    let mut calls = reached
        .map(|boundary| unproven_call(facts, machine_context, boundary.call_site))
        .collect::<Vec<_>>();
    calls.sort_unstable();
    calls.dedup();
    calls
}

/// Whether the call at `at` may be handed `slot` as the function entered with it: unseen there, or
/// a value the body did not write.
fn arrives_untouched(
    (func, prep, graph, context): (
        &SSAFunction,
        Option<&crate::DecompilePrepFacts>,
        &SsaGraph,
        &crate::SourceMachineContext,
    ),
    at: crate::InstId,
    slot: CanonicalStorageId,
) -> bool {
    let Some((block_addr, op_index)) = graph.walk_start(at) else {
        return false;
    };
    let reached = crate::semantic::reaching_abi_value_in_block_with_policy(
        func, prep, graph, context, block_addr, op_index, slot, false,
    );
    reached.is_none_or(|state| match state {
        crate::semantic::ReachingAbiState::PreservedEntry => true,
        crate::semantic::ReachingAbiState::Value(value) => !graph.written_by_body(value),
    })
}

/// Whether an operation reads `value`, directly or through the merges it flows into: a merge alone
/// reads nothing. Each value is taken once, so the walk ends.
fn read_beyond_merges(graph: &SsaGraph, value: crate::ValueId) -> bool {
    let mut seen = crate::dense::IdSet::default();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        for site in graph.use_sites(value) {
            match graph.inst(site.inst) {
                Some(inst) if matches!(inst.payload, crate::graph::InstPayload::Phi { .. }) => {
                    pending.extend(inst.output);
                }
                Some(_) => return true,
                None => {}
            }
        }
    }
    false
}

/// One call of unproven arity, as its callee's statement leaves it (D37).
fn unproven_call(
    facts: &crate::semantic::PreparedFunctionFacts,
    context: Option<&crate::SourceMachineContext>,
    call: crate::CallSiteId,
) -> SourceUnprovenCall {
    let Some((call, target)) =
        (facts.call_sites.by_id.get(&call)).and_then(|call| Some((call, call.direct_target?)))
    else {
        return SourceUnprovenCall::Indirect;
    };
    let declared = (call.raw_identity.zip(context))
        .is_some_and(|(identity, context)| context.call_site_interface(identity).is_some());
    match context.and_then(|context| context.callee_statement(target)) {
        Some(statement) if !statement.arity.is_exact() => SourceUnprovenCall::Floor(target),
        Some(_) => SourceUnprovenCall::Stated(target),
        None if declared => SourceUnprovenCall::Stated(target),
        None => SourceUnprovenCall::Unstated(target),
    }
}

/// Bytes `size` low bytes of a register cover.
fn low_bytes(size: u32) -> crate::site_boundary::ByteMask {
    crate::site_boundary::ByteMask(match size {
        0 => 0,
        128.. => u128::MAX,
        size => (1u128 << size) - 1,
    })
}

/// The shared position a register is a location of (Microsoft x64), integer or float.
fn shared_position(slots: &ConventionModel, slot: CanonicalStorageId) -> Option<u8> {
    if !slots.shares_positions() {
        return None;
    }
    let at = |section: &[CanonicalStorageId]| section.iter().position(|of| *of == slot);
    let position = at(slots.arguments(r2source::convention::SlotClass::Integer))
        .or_else(|| at(slots.arguments(r2source::convention::SlotClass::Float)))?;
    u8::try_from(position).ok()
}

/// Rule 3 under Microsoft x64: an entry value read only by stores to its own home, which no load
/// reads and whose address does not escape, is homed. O(objects + accesses + uses).
fn homed_in_its_home(
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    observations: &crate::deadphi::ProvenProgramObservations,
    home: std::ops::Range<i64>,
    (entries, handed): (
        &[crate::ValueId],
        &dyn Fn(crate::InstId) -> Option<SourceUnprovenCall>,
    ),
) -> bool {
    let objects = (facts.objects.entry_stack_roots.iter())
        .filter(|(_, root)| {
            root.base == StackAddressBase::StackPointer && home.contains(&root.offset)
        })
        .map(|(object, _)| *object)
        .collect::<Vec<_>>();
    let reach = &facts.objects.frame_reach;
    if objects.is_empty() || objects.iter().any(|object| reach.escapes_directly(*object)) {
        return false;
    }
    let mut stores = crate::dense::IdSet::new(graph.insts.len());
    let accesses = facts.structured.memory_accesses.values();
    for access in accesses.filter(|access| objects.contains(&access.object)) {
        if !access.is_write {
            return false;
        }
        stores.insert(access.id.inst);
    }
    // A call that may read past its listed arguments may read the register, so it is no home only.
    let taken = |call_use| handed(call_use).is_some();
    !stores.is_empty()
        && (entries.iter()).all(|value| {
            crate::save_area::read_only_by(graph, *value, &stores, (observations, &taken))
        })
}

/// Whether an escaped address may point at an argument's place: a stack argument, a home holding
/// its position's entry register, or no place known. O(escaped offsets x homes + stores).
fn argument_place_escapes(
    (graph, prep): (&SsaGraph, &crate::DecompilePrepFacts),
    facts: &crate::semantic::PreparedFunctionFacts,
    model: Option<&r2source::ConventionModel>,
) -> bool {
    let Some(escaped) = facts.objects.frame_reach.escaped_incoming() else {
        return true;
    };
    let homes = (0..=u8::MAX)
        .map_while(|position| Some((position, model?.home(position)?)))
        .collect::<Vec<_>>();
    // Whether the home holds the entry value of a register passed at its position.
    let homed = |position: u8, home: &std::ops::Range<i64>| {
        let registers = [SlotClass::Integer, SlotClass::Float]
            .map(|class| model.and_then(|model| model.argument(class, usize::from(position))));
        let in_home = |object| {
            (facts.objects.entry_stack_roots.get(&object)).is_some_and(|root| {
                root.base == StackAddressBase::StackPointer && home.contains(&root.offset)
            })
        };
        (facts.structured.memory_accesses.values())
            .filter(|access| access.is_write && in_home(access.object))
            .filter_map(|access| graph.value(prep.views.copy_root(access.value?)))
            .any(|stored| {
                stored.var.version == 0
                    && graph.caller_supplied(stored.id)
                    && registers.iter().flatten().any(|register| {
                        (stored.canonical_storage)
                            .is_some_and(|storage| storage.location() == register.location())
                    })
            })
    };
    escaped.iter().any(|offset| {
        let home = homes.iter().find(|(_, home)| home.contains(offset));
        home.is_none_or(|(position, home)| homed(*position, home))
    })
}

/// `slot`'s use where no observation reads it (rule 3; doc/adr-result-side.md, "Parameter side"):
/// `Unknown` reaching an unproven call or not proven `dead`, `Homed` only copied, else `Unread`.
fn unobserved_use(
    (graph, facts): (&SsaGraph, &crate::semantic::PreparedFunctionFacts),
    (ignored, observations): (
        &BTreeSet<crate::graph::UseSite>,
        &crate::deadphi::ProvenProgramObservations,
    ),
    handed: &dyn Fn(crate::InstId) -> Option<SourceUnprovenCall>,
    entries: &[crate::ValueId],
) -> SlotUse {
    let (mut moved, mut used) = (false, false);
    let mut seen = crate::dense::IdSet::default();
    let mut pending = entries.to_vec();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                continue;
            };
            if let crate::graph::InstPayload::Op(crate::SSAOp::CallUse { .. }) = &inst.payload
                && let Some(call) = handed(site.inst)
            {
                return SlotUse::Unknown(SourceFloorCause::HandedOn(call));
            }
            match (&inst.payload, inst.output) {
                _ if ignored.contains(site) => {}
                // A copy nothing reads is where the dropped home store was; a lane projection
                // nothing reads is the build's own (`xor ecx, ecx` folds the lane it read).
                (crate::graph::InstPayload::Op(op), Some(output)) if moves(graph, output) => {
                    moved |= matches!(op, crate::SSAOp::Copy { .. })
                        && graph.use_sites(output).is_empty();
                    pending.push(output);
                }
                (crate::graph::InstPayload::Op(op), _) if folds_to_constant(graph, op) => {}
                (_, output) => {
                    used = true;
                    pending.extend(output);
                }
            }
        }
    }
    // `Unread` is a proof: an operation with no modelled semantics may read what nothing observes.
    if let Some(alive) = (entries.iter()).find(|value| !observations.proven_unread(**value)) {
        r2il::refusal_evidence!(
            "interface-recovery",
            "entry value {alive:?} is neither observed nor proven dead: {}",
            unproven_readers(graph, facts, *alive)
        );
        return SlotUse::Unknown(SourceFloorCause::RegisterRead);
    }
    match moved && !used {
        true => SlotUse::Homed {
            loaded: false,
            escapes: false,
        },
        false => SlotUse::Unread,
    }
}

/// The unmodelled instructions that may read `value`, for the trace. O(values reached).
fn unproven_readers(
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    value: crate::ValueId,
) -> String {
    let mut seen = crate::dense::IdSet::default();
    let mut pending = vec![value];
    let mut names = BTreeSet::new();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        for inst in (graph.use_sites(value).iter()).filter_map(|site| graph.inst(site.inst)) {
            if facts.obligations.unmodelled().contains(inst.id) {
                let text = format!("{:?}", inst.payload);
                names.insert(text.split([' ', '{']).next().unwrap_or("op").to_string());
            }
            pending.extend(inst.output);
        }
    }
    names.into_iter().collect::<Vec<_>>().join(",")
}

/// Whether `op` computes a constant whatever its inputs hold: `x ^ x`, `x - x`, `x & 0`.
fn folds_to_constant(graph: &SsaGraph, op: &crate::SSAOp<crate::ValueId>) -> bool {
    let zero = |value: &crate::ValueId| graph.var(*value).constant_bits() == Some(0);
    match op {
        crate::SSAOp::IntXor { a, b, .. } | crate::SSAOp::IntSub { a, b, .. } => a == b,
        crate::SSAOp::IntAnd { a, b, .. } => zero(a) || zero(b),
        _ => false,
    }
}

/// Whether `value` is a copy or a low lane of another, as `mov [rbp-4], edi` stores `rdi`'s.
fn moves(graph: &SsaGraph, value: crate::ValueId) -> bool {
    (graph.def_inst(value).and_then(|inst| graph.inst(inst))).is_some_and(|inst| {
        matches!(
            &inst.payload,
            crate::graph::InstPayload::Op(
                crate::SSAOp::Copy { .. } | crate::SSAOp::Subpiece { offset: 0, .. }
            )
        )
    })
}

/// Each slot's section, position and location: the register sections, then the stack slots read.
fn slot_locations(
    counts: &[(Section, std::ops::Range<usize>, usize)],
    registers: &[(SlotClass, CanonicalStorageId)],
    stack: &[RecoveredStackParameter],
) -> crate::dense::IdVec<crate::body_boundary::SlotId, crate::body_boundary::Slot> {
    let registers = counts.iter().flat_map(|(section, range, _)| {
        range.clone().map(move |at| crate::body_boundary::Slot {
            section: *section,
            position: u16::try_from(at - range.start).unwrap_or(u16::MAX),
            location: SourceParameterLocation::Register(registers[at].1),
        })
    });
    let stack = stack
        .iter()
        .enumerate()
        .map(|(position, parameter)| crate::body_boundary::Slot {
            section: Section::Stack,
            position: u16::try_from(position).unwrap_or(u16::MAX),
            location: SourceParameterLocation::Stack {
                offset: parameter.offset(),
                size_bytes: parameter.slot_bytes(),
                callee_offset: parameter.offset(),
            },
        });
    let all = registers.chain(stack).collect::<Vec<_>>();
    crate::dense::IdVec::from_fn(all.len(), |id| all[crate::dense::DenseId::index(id)])
}

/// The calls an unproven result waits on: a tail transfer to a target no prototype describes, or
/// a call whose unstated result reaches an exit. O(live-out + calls).
fn result_calls(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    lanes: r2source::convention::TypedResults,
    tails_unproven: bool,
) -> BTreeSet<SourceResultCause> {
    let named = |call: &crate::semantic::CallSiteFact| {
        call.direct_target
            .map_or(SourceUnstatedCall::Indirect, SourceUnstatedCall::Direct)
    };
    let unstated = |call: &crate::semantic::CallSiteFact| {
        let boundary = facts.boundaries.calls.get(&call.id);
        !boundary.is_some_and(|boundary| stated_result(boundary, lanes.float).is_some())
    };
    let tails = owned_tails(func, facts, lanes);
    let mut causes: BTreeSet<SourceResultCause> = tails
        .filter(|call| unstated(call))
        .map(|call| SourceResultCause::Tailed(named(call)))
        .collect();
    if tails_unproven && causes.is_empty() {
        causes.insert(SourceResultCause::TailsDisagree);
    }
    for slot in [lanes.integer, lanes.float].into_iter().flatten() {
        let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[slot]);
        for value in live_out.iter() {
            if let ReturnedByCall::Unstated(id) | ReturnedByCall::Undecided(id) =
                returned_by_call(graph, facts, value)
                && let Some(call) = facts.call_sites.by_id.get(&id)
            {
                causes.insert(SourceResultCause::Returned(named(call)));
            }
        }
    }
    causes
}

/// What the paths that return a value of their own prove of an unproven result, were the calls
/// that define the carrier to return what the paths return: `None` where no path returns one.
fn seed_result(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    slots: &ConventionModel,
) -> Option<SourceResultSeed> {
    let slot = slots.result()?;
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[slot]);
    if !live_out.has_returns()
        || live_out.unresolved_blocks().next().is_some()
        || returns_the_callers_value(graph, &live_out, slot)
    {
        return None;
    }
    let returns = Returns {
        func,
        graph,
        facts,
        live_out: &live_out,
        entry_undefined: false,
    };
    let result = recovered_result_over(&returns, slot, true).register()?;
    let bits = storage_bits(result.observed())?;
    (storage_bits(result.slot()).is_some()).then_some(SourceResultSeed {
        slot: result.slot(),
        bits,
        above: result.above(),
    })
}

/// What the function's tail transfers say about its result.
enum TailResult {
    /// No exit is a tail transfer; ordinary live-out recovery answers.
    NoTailBoundary,
    /// Every tail transfer names a complete prototype and they agree on its result.
    Exact(SourceCallResult),
    /// Some tail transfer reaches a body whose prototype is unknown or
    /// incomplete, or two tail transfers disagree. The result is owned by a
    /// body not read here, so nothing can be recovered for it.
    Unproven,
}

/// The result carrier licensed by every source-proven tail boundary.
/// The result a return path of this body's own proves, when the function also
/// leaves through a tail transfer nothing describes.
///
/// A block that ends in a tail branch is a returning block with no write of
/// the result register on its own path, so the ordinary live-out walk reports
/// it unresolved. What the other paths write is still a fact about this
/// function: the convention gives the tail callee the same result register, so
/// a path that fills it says the function has a result and where it is.
fn direct_return_result(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    candidate: Option<CanonicalStorageId>,
) -> Option<CanonicalStorageId> {
    let candidate = candidate?;
    let tail_blocks = owned_tail_blocks(func, graph, facts, candidate);
    if tail_blocks.is_empty() {
        return None;
    }
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[candidate]);
    if live_out.is_empty() {
        return None;
    }
    // Every path the walk could not answer has to be one a tail transfer owns,
    // and at least one path has to have answered.
    if live_out
        .unresolved_blocks()
        .any(|block| !tail_blocks.contains(&block))
    {
        return None;
    }
    // A direct return answers only where it defines a byte: a canary's residue defines none (D200).
    let direct = live_out.without(&tail_blocks);
    let returns = Returns {
        func,
        graph,
        facts,
        live_out: &direct,
        entry_undefined: false,
    };
    let defines = recovered_result_over(&returns, candidate, false)
        .register()
        .is_some();
    (direct.by_return().next().is_some() && defines).then_some(candidate)
}

/// The tail callee's `narrow` width joined with every direct return's written width (an unknown
/// one keeps the whole `slot`), and the fill above that the tail and every direct return state alike.
fn joined_with_direct_returns(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    (slot, narrow): (CanonicalStorageId, CanonicalStorageId),
    tail: SourceResultWidth,
) -> (CanonicalStorageId, r2source::SourceAbove) {
    let undefined = r2source::SourceAbove::Undefined;
    let tails = owned_tail_blocks(func, graph, facts, slot);
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[slot]).without(&tails);
    if live_out.unresolved_blocks().next().is_some() {
        return (slot, undefined);
    }
    if !live_out.has_returns() {
        return (narrow, tail.above);
    }
    let returns = Returns {
        func,
        graph,
        facts,
        live_out: &live_out,
        entry_undefined: false,
    };
    match recovered_result_over(&returns, slot, false) {
        RecoveredFunctionResult::Void => (narrow, undefined),
        RecoveredFunctionResult::Register(direct) if !direct.float() => {
            match direct.observed().size.cmp(&narrow.size) {
                std::cmp::Ordering::Greater => (direct.observed(), undefined),
                std::cmp::Ordering::Equal if direct.above() == tail.above => (narrow, tail.above),
                _ => (narrow, undefined),
            }
        }
        _ => (slot, undefined),
    }
}

/// What the direct returns beside tail transfers to void callees leave: void where none defines a
/// byte, unproven, with its cause, where one is clobbered or hands back the caller's input.
fn direct_returns_beside_void_tails(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    slots: &ConventionModel,
) -> (RecoveredFunctionResult, Option<SourceResultCause>) {
    let Some(slot) = slots.result() else {
        return (RecoveredFunctionResult::Void, None);
    };
    let tails = owned_tail_blocks(func, graph, facts, slot);
    let live_out = crate::liveout::FunctionLiveOut::compute(func, graph, &[slot]).without(&tails);
    let entry_undefined = entry_defines_nothing(graph, slots, slot);
    let untouched = live_out.unresolved_blocks().next().is_some()
        || returns_the_callers_value(graph, &live_out, slot);
    if live_out.clobbered_blocks().next().is_some() {
        let cause = SourceResultCause::Clobbered;
        return (RecoveredFunctionResult::Unproven, Some(cause));
    }
    if untouched && !entry_undefined {
        let cause = SourceResultCause::HandedBack;
        return (RecoveredFunctionResult::Unproven, Some(cause));
    }
    let returns = Returns {
        func,
        graph,
        facts,
        live_out: &live_out,
        entry_undefined,
    };
    (recovered_result_over(&returns, slot, false), None)
}

/// What a declared body's returns leave in its integer and float result lanes, default deny: `None`
/// and `Written` are proven, else `Open` (D331). O(blocks + values reaching a return) per lane.
pub(crate) fn body_result_lanes(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    model: &r2source::ConventionModel,
) -> r2source::SourceBodyResult {
    use r2source::SourceBodyLane as Lane;
    use r2source::convention::Location;
    let arguments = (model.sections.iter()).flat_map(|section| section.locations.iter());
    let inputs = arguments
        .filter_map(|location| match location {
            Location::Register { storage, .. } => Some(*storage),
            _ => None,
        })
        .collect::<Vec<_>>();
    let read = |slot: CanonicalStorageId| {
        // A tail whose callee may write the lane proves nothing of it.
        if !owned_tail_blocks(func, graph, facts, slot).is_empty() {
            return Lane::Open;
        }
        let reach = crate::liveout::FunctionLiveOut::over_every_return(func, graph, slot);
        if !reach.returns || reach.clobbered {
            return Lane::Open;
        }
        // The lane's entry byte at a return is the caller's, unless it defines nothing (case 1).
        let input = inputs.iter().any(|input| overlaps(*input, slot));
        let entry_undefined = !input && !read_on_entry(graph, slot);
        if reach.unwritten && !entry_undefined {
            return Lane::Open;
        }
        let walk = LaneWalk {
            slot,
            inputs: &inputs,
            entry_undefined,
        };
        let lane = lane_at_returns(func, graph, facts, &reach, &walk);
        r2il::refusal_evidence!("declared-body-result", "{slot:?}: {lane:?}");
        lane
    };
    let lanes = model.typed_results();
    r2source::SourceBodyResult {
        integer: lanes.integer.map(|slot| (slot, read(slot))),
        float: lanes.float.map(|slot| (slot, read(slot))),
    }
}

/// What reaches a return in one lane, read by `lane_at_returns`.
struct LaneWalk<'a> {
    slot: CanonicalStorageId,
    /// The convention's argument registers: an entry value in one is a parameter.
    inputs: &'a [CanonicalStorageId],
    /// The lane's own entry byte defines nothing (doc/adr-scratch-result.md, case 1).
    entry_undefined: bool,
}

/// One lane over each value a return's bytes come from, once: `Written` by a stated call, a
/// parameter or a computed byte, `None` by none, `Open` at anything unstated. O(values reached).
fn lane_at_returns(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    reach: &crate::liveout::LaneReach,
    walk: &LaneWalk<'_>,
) -> r2source::SourceBodyLane {
    use crate::bytes::Rule;
    use crate::graph::InstPayload;
    use r2source::SourceBodyLane as Lane;
    // The seal keeps no per-operation record, so a check's residue would read as data.
    let checked = func.has_compiler_inserted_writes();
    let written = func.written();
    let var_facts = |id: &crate::ValueId| crate::op::var_facts(graph.var(*id));
    // `defined`: some byte is a C value. `moved`: a slice, concat or insert may hide which.
    let (mut defined, mut moved) = (false, false);
    let mut seen = crate::dense::IdSet::default();
    let mut pending = reach.values.iter().collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        if !seen.insert(value) {
            continue;
        }
        if var_facts(&value).1.is_some() {
            defined = true;
            continue;
        }
        let storage = graph.value(value).and_then(|value| value.canonical_storage);
        let inst = graph.def_inst(value).and_then(|inst| graph.inst(inst));
        let Some(inst) = inst.filter(|_| graph.written_by_body(value)) else {
            // The caller's value: the lane's own entry byte, a parameter, or nothing stated.
            let own = storage.is_some_and(|held| overlaps(held, walk.slot));
            let parameter =
                storage.is_some_and(|held| walk.inputs.iter().any(|input| overlaps(*input, held)));
            match (own, parameter) {
                (true, _) if walk.entry_undefined => {}
                (false, true) => defined = true,
                _ => return Lane::Open,
            }
            continue;
        };
        let op = match &inst.payload {
            InstPayload::Phi { .. } => {
                pending.extend(graph.inputs(inst.id).iter().copied());
                continue;
            }
            InstPayload::Op(crate::op::SSAOp::CallDefine { .. }) => {
                match returned_by_call(graph, facts, value) {
                    ReturnedByCall::Void => {}
                    ReturnedByCall::Stated => defined = true,
                    _ => return Lane::Open,
                }
                continue;
            }
            InstPayload::Op(op) => op,
        };
        if checked {
            return Lane::Open;
        }
        let sources = op.sources();
        let conventional = graph
            .op_for_inst(inst.id)
            .is_some_and(|id| written.is_conventional_extension(id));
        // An operation that moves bytes hands on its sources'; any other computes data.
        match crate::bytes::rule(op, var_facts) {
            Rule::Copy => pending.extend(sources.first().copied()),
            Rule::Extend { .. } if conventional => pending.extend(sources.first().copied()),
            Rule::Slice { .. } => {
                moved = true;
                pending.extend(sources.first().copied());
            }
            Rule::Concat { .. } | Rule::Insert { .. } => {
                moved = true;
                pending.extend(sources.iter().take(2).copied());
            }
            _ => defined = true,
        }
    }
    match (defined, moved) {
        (false, _) => Lane::None,
        (true, false) => Lane::Written,
        (true, true) => Lane::Open,
    }
}

/// The tail transfers that own the result: every one but a tail to a callee that leaves each result
/// lane as it found it (D212), whose block hands back what reaches it, as a return does.
fn owned_tails<'f>(
    func: &'f SSAFunction,
    facts: &'f crate::semantic::PreparedFunctionFacts,
    lanes: r2source::convention::TypedResults,
) -> impl Iterator<Item = &'f crate::semantic::CallSiteFact> + 'f {
    let lanes = [lanes.integer, lanes.float, lanes.second];
    let passes = move |target: u64| {
        (lanes.iter().flatten()).all(|lane| func.call_passes(target, *lane))
            && lanes.iter().any(Option::is_some)
    };
    (facts.call_sites.by_id.values())
        .filter(|call| call.transfer == crate::CallSiteTransfer::TailCall)
        .filter(move |call| !call.direct_target.is_some_and(passes))
}

/// The blocks that leave by a tail transfer whose callee may change `lane`; one that passes it
/// hands it back as a return does (`liveout::passing_tail`).
fn owned_tail_blocks(
    func: &SSAFunction,
    graph: &SsaGraph,
    facts: &crate::semantic::PreparedFunctionFacts,
    lane: CanonicalStorageId,
) -> BTreeSet<u64> {
    (facts.call_sites.by_id.values())
        .filter(|call| call.transfer == crate::CallSiteTransfer::TailCall)
        .filter(|call| !(call.direct_target).is_some_and(|target| func.call_passes(target, lane)))
        .filter_map(|call| graph.block_addr_of(call.at))
        .collect()
}

fn tail_result_storage(
    func: &SSAFunction,
    facts: &crate::semantic::PreparedFunctionFacts,
    lanes: r2source::convention::TypedResults,
) -> TailResult {
    let mut results = owned_tails(func, facts, lanes)
        .map(|call| {
            // What the tail callee returns is the prototype's claim, and an
            // argument count the body cannot prove -- a variadic import thunk
            // forwards a tail it never sees -- says nothing about the result.
            stated_result(facts.boundaries.calls.get(&call.id)?, lanes.float)
        })
        .peekable();
    if results.peek().is_none() {
        return TailResult::NoTailBoundary;
    }
    let Some(Some(mut first)) = results.next() else {
        return TailResult::Unproven;
    };
    for result in results {
        // Tails into one register agree; the result is as wide as the widest of them.
        first = match (first, result) {
            (
                SourceCallResult::Register { storage, width },
                Some(SourceCallResult::Register {
                    storage: other,
                    width: wider,
                }),
            ) if storage == other => SourceCallResult::Register {
                storage,
                width: width.join(wider),
            },
            (first, Some(result)) if result == first => first,
            _ => return TailResult::Unproven,
        };
    }
    TailResult::Exact(first)
}

/// What a call's complete boundary states it returns, where no float lane it states nothing of may
/// hold its result instead (D212).
fn stated_result(
    boundary: &crate::semantic::SourceCallBoundaryFact,
    float: Option<CanonicalStorageId>,
) -> Option<SourceCallResult> {
    let open = (boundary.unstated_lanes.iter())
        .any(|lane| float.is_some_and(|float| overlaps(*lane, float)));
    let result = boundary.result_kind?;
    let grouped = matches!(result, SourceCallResult::Unproven { .. });
    (boundary.results_complete && !open && !grouped).then_some(result)
}

/// The width of a register storage, where it is one an integer type can have.
fn storage_bits(storage: CanonicalStorageId) -> Option<u32> {
    let bits = storage.size.checked_mul(8)?;
    matches!(bits, 8 | 16 | 32 | 64).then_some(bits)
}

/// Build a source interface from what the machine code proves.
///
/// Every parameter is an unsigned integer of the register's own width. That is
/// not a claim about the source type, which compilation erased: it is the same
/// convention the renderer already applies to every machine value, where a
/// value is an unsigned bit pattern and signedness comes from the operations
/// applied to it. Signedness, pointer-ness and names are never asserted.
///
/// The return-address and stack-pointer carriers come from the machine roles,
/// which the source resolves without any recovered prototype. Certification
/// requires both, so a source lacking either yields no interface rather than a
/// half-formed one.
pub fn mint_recovered_interface(
    recovered: &RecoveredInterface,
    roles: &SourceMachineRoles,
    revision_identity: &[u8],
    convention: r2source::ConventionId,
    model: Option<&r2source::ConventionModel>,
) -> Option<SourceFunctionInterface> {
    let minted = placed(recovered, model)
        .and_then(|()| {
            mint_recovered_interface_inner(recovered, roles, revision_identity, convention)
        })
        .map(|interface| match &recovered.arity_floor {
            Some(floor) => interface.with_arity_floor(floor.clone()),
            None => interface,
        })
        .map(|interface| match recovered.variadic {
            true => interface.with_variadic_tail(),
            false => interface,
        })
        .map(|interface| match recovered.tail_count {
            Some(count) => match interface.clone().with_tail_count(count) {
                Ok(counted) => counted,
                Err(why) => {
                    r2il::refusal_evidence!("tail-count", "the proven count is refused: {why}");
                    interface
                }
            },
            None => interface,
        })
        .map(|interface| match recovered.result_carriers {
            Some(carriers) => interface.with_result_carriers(carriers),
            None => interface,
        })
        .map(|interface| match recovered.closed {
            Some(closed) => interface.with_closed_result(closed),
            None => interface,
        })
        .map(|interface| match recovered.result_holds_input {
            true => interface.with_result_holding_input(),
            false => interface,
        })
        .map(|interface| match recovered.unreached {
            true => interface.with_no_return_reached(),
            false => interface,
        })
        .map(|interface| match &recovered.unproven_result {
            Some(result) => interface.with_unproven_result(result.clone()),
            None => interface,
        });
    if minted.is_none() {
        r2il::refusal_evidence!(
            "interface-minting",
            "return_address={:?} stack_pointer={:?} identity={} convention={:?} \
             parameters={:?} result={:?}",
            roles.return_address_storage(),
            roles.stack_pointer_storage(),
            revision_identity.len(),
            convention,
            recovered
                .parameters()
                .iter()
                .map(|parameter| (parameter.slot().size, parameter.observed().size))
                .collect::<Vec<_>>(),
            recovered
                .result()
                .register()
                .map(|result| (result.slot().size, result.observed().size))
        );
    }
    minted
}

/// `place` puts each recovered parameter where the body read it; a disagreement mints nothing.
fn placed(recovered: &RecoveredInterface, model: Option<&r2source::ConventionModel>) -> Option<()> {
    let Some(model) = model else {
        return Some(());
    };
    let bytes = |size: u32| {
        u8::try_from(size)
            .ok()
            .map(crate::place::ParamClass::Integer)
    };
    let class = |parameter: &RecoveredParameter| match parameter.class() {
        SlotClass::Float => u8::try_from(parameter.observed().size)
            .ok()
            .map(crate::place::ParamClass::Float),
        _ => bytes(parameter.slot().size),
    };
    let classes = (recovered.parameters().iter())
        .map(class)
        .chain((recovered.stack_parameters().iter()).map(|parameter| bytes(parameter.slot_bytes())))
        .collect::<Option<Vec<_>>>()?;
    let read = (recovered.parameters().iter())
        .map(|parameter| SourceParameterLocation::Register(parameter.location()))
        .chain(recovered.stack_parameters().iter().map(|parameter| {
            SourceParameterLocation::Stack {
                offset: parameter.offset(),
                size_bytes: parameter.slot_bytes(),
                callee_offset: parameter.offset(),
            }
        }));
    let placement = crate::place::place(model, &classes);
    if placement.is_whole() && read.eq(placement.locations) {
        return Some(());
    }
    r2il::refusal_evidence!(
        "interface-minting",
        "the convention places the recovered parameters elsewhere than the body reads them"
    );
    None
}

/// A float result's own type node, after the integers in `types`: its id and width.
fn float_type(
    recovered: &RecoveredInterface,
    types: &mut Vec<SourceType>,
) -> Option<Option<(u32, u32)>> {
    let Some(result) = recovered
        .result()
        .register()
        .filter(|result| result.float())
    else {
        return Some(None);
    };
    let bits = storage_bits(result.observed())?;
    let id = u32::try_from(types.len()).ok()?;
    let (size, align) = (u64::from(bits), u64::from(bits));
    types.push(SourceType::new(id, SourceTypeKind::Float, size, align));
    Some(Some((id, bits)))
}

/// Each parameter's logical width, as read, and the float widths among them; `note` records each
/// integer width for the type graph.
fn parameter_widths(
    recovered: &RecoveredInterface,
    note: &mut dyn FnMut(u32),
) -> Option<(Vec<u32>, Vec<u32>)> {
    let (mut all, mut floats) = (Vec::new(), Vec::new());
    for parameter in recovered.parameters() {
        let bits = storage_bits(parameter.observed())?;
        match parameter.class() {
            SlotClass::Float if matches!(bits, 32 | 64) => floats.push(bits),
            SlotClass::Float => return None,
            _ => note(bits),
        }
        all.push(bits);
    }
    for parameter in recovered.stack_parameters() {
        let bits = parameter.observed_bytes().checked_mul(8)?;
        if !matches!(bits, 8 | 16 | 32 | 64) {
            return None;
        }
        note(bits);
        all.push(bits);
    }
    Some((all, floats))
}

/// Each float parameter's width as a type node of its own, after the integers; the result's where
/// it is as wide: each width and its node.
fn float_nodes(
    mut floats: Vec<u32>,
    result: Option<(u32, u32)>,
    types: &mut Vec<SourceType>,
) -> Option<Vec<(u32, u32)>> {
    floats.sort_unstable();
    floats.dedup();
    let node = |bits: u32, types: &mut Vec<SourceType>| {
        let id = u32::try_from(types.len()).ok()?;
        let (size, align) = (u64::from(bits), u64::from(bits));
        types.push(SourceType::new(id, SourceTypeKind::Float, size, align));
        Some(id)
    };
    (floats.into_iter())
        .map(|bits| match result {
            Some((id, result_bits)) if result_bits == bits => Some((bits, id)),
            _ => Some((bits, node(bits, types)?)),
        })
        .collect()
}

/// A float result's return: its own type node `id`, read at the low `bits` of its slot.
fn float_return(
    result: RecoveredResult,
    (id, bits): (u32, u32),
) -> Option<(SourceFunctionReturn, Option<SourceLogicalValue>)> {
    let kind = if bits < result.slot().size.checked_mul(8)? {
        SourceCarrierKind::LowBits
    } else {
        SourceCarrierKind::Full
    };
    let logical =
        SourceLogicalValue::new(id, SourceCarrierProjection::new(kind, 0, u64::from(bits)));
    let storage = result.slot();
    Some((SourceFunctionReturn::Register { storage }, Some(logical)))
}

fn mint_recovered_interface_inner(
    recovered: &RecoveredInterface,
    roles: &SourceMachineRoles,
    revision_identity: &[u8],
    convention: r2source::ConventionId,
) -> Option<SourceFunctionInterface> {
    let return_address_storage = roles.return_address_storage()?;
    let stack_pointer_storage = roles.stack_pointer_storage()?;
    if revision_identity.is_empty() {
        return None;
    }

    // One integer type per distinct width the interface actually uses, so the
    // graph describes exactly what is referenced and nothing more. The
    // constructor enforces that literally: a graph carrying a type no logical
    // value names is rejected outright.
    // Every integer is unsigned: its C sign is r2types' to state from the body (D265, RULING 1.7).
    let mut widths: Vec<u32> = Vec::new();
    fn note_bits(widths: &mut Vec<u32>, bits: u32) {
        if !widths.contains(&bits) {
            widths.push(bits);
        }
    }
    // The logical value is typed by what the function read, not by the size of
    // the register the convention put it in; a hole's is its slot's, its basis `Convention`.
    let (parameter_widths, floats) = parameter_widths(recovered, &mut |bits| {
        note_bits(&mut widths, bits);
    })?;
    // The slot's width decides whether the read covers the whole carrier or
    // only its low half, and nothing else. It names no logical value, so it
    // must not put a type in the graph: an `int` parameter arriving in a
    // sixty-four-bit register is read as thirty-two bits, and registering the
    // carrier's width added a type nothing referenced and made the constructor
    // reject the interface. The function was then left with no ABI at all --
    // every question about its return kind answering `unavailable`, its return
    // boundary incomplete, and the renderer refusing. That was the largest
    // single refusal cause in the corpus, and it fires for any function taking
    // a parameter narrower than the register that carries it.
    let parameter_slot_widths = recovered
        .parameters()
        .iter()
        .map(|parameter| storage_bits(parameter.location()))
        .chain(
            recovered
                .stack_parameters()
                .iter()
                .map(|parameter| parameter.slot_bytes().checked_mul(8)),
        )
        .collect::<Option<Vec<_>>>()?;
    let result_width = match recovered.result() {
        RecoveredFunctionResult::Register(result) if !result.float() => {
            let bits = storage_bits(result.observed())?;
            note_bits(&mut widths, bits);
            Some(bits)
        }
        // One integer as wide as both halves (doc/adr-language-profile.md, item 1).
        RecoveredFunctionResult::Pair { low, high } => {
            let half = storage_bits(low).filter(|bits| Some(*bits) == storage_bits(high))?;
            let bits = half.checked_mul(2)?;
            note_bits(&mut widths, bits);
            Some(bits)
        }
        _ => None,
    };
    widths.sort_unstable();

    let mut types = widths
        .iter()
        .enumerate()
        .map(|(index, bits)| {
            SourceType::new(
                u32::try_from(index).ok()?,
                SourceTypeKind::UnsignedInteger,
                u64::from(*bits),
                u64::from(*bits),
            )
            .into()
        })
        .collect::<Option<Vec<SourceType>>>()?;
    let float_type = float_type(recovered, &mut types)?;
    let float_ids = float_nodes(floats, float_type, &mut types)?;
    let type_graph = SourceTypeGraph::new(types, []).ok()?;
    let type_id = |bits: u32| -> Option<u32> {
        widths
            .iter()
            .position(|candidate| *candidate == bits)
            .and_then(|index| u32::try_from(index).ok())
    };
    // `Full` where the read is the whole register, `LowBits` where it is the
    // register's low half. The second is what an `int` parameter looks like in
    // a 64-bit argument register, and it is the projection the parameter-fact
    // collector already knows how to narrow.
    let logical = |bits: u32, carrier_bits: u32| -> Option<SourceLogicalValue> {
        let kind = if bits < carrier_bits {
            SourceCarrierKind::LowBits
        } else {
            SourceCarrierKind::Full
        };
        Some(SourceLogicalValue::new(
            type_id(bits)?,
            SourceCarrierProjection::new(kind, 0, u64::from(bits)),
        ))
    };

    let register_count = recovered.parameters().len();
    // Each parameter is at the boundary slot of its location. O(parameters x slots).
    let slot = |location: SourceParameterLocation, class, basis| {
        let (id, _) =
            (recovered.boundary().locations.iter()).find(|(_, at)| at.location == location)?;
        Some(r2source::SourceSlot {
            id: id.0,
            class,
            basis,
        })
    };
    let parameters = recovered
        .parameters()
        .iter()
        .enumerate()
        .map(|(index, parameter)| {
            let slotted = SourceParameterLocation::Register(parameter.slot());
            Some(SourceAbiParameterSpec::new(
                u32::try_from(index).ok()?,
                parameter.location(),
                slot(slotted, parameter.class(), parameter.basis())?,
            ))
        })
        .chain(
            recovered
                .stack_parameters()
                .iter()
                .enumerate()
                .map(|(index, parameter)| {
                    let location = SourceParameterLocation::Stack {
                        offset: parameter.offset(),
                        size_bytes: parameter.slot_bytes(),
                        callee_offset: parameter.offset(),
                    };
                    Some(SourceAbiParameterSpec::with_location(
                        u32::try_from(register_count.checked_add(index)?).ok()?,
                        location,
                        slot(location, SlotClass::Stack, parameter.basis())?,
                    ))
                }),
        )
        .collect::<Option<Vec<_>>>()?;
    // A stack parameter is its own slot, declared at the width it was read,
    // as a source would declare `int` in an eight-byte slot.
    let stack_slots = recovered
        .stack_parameters()
        .iter()
        .enumerate()
        .map(|(index, parameter)| {
            Some(SourceStackSlotSpec::new_parameter(
                StackAddressBase::StackPointer,
                stack_pointer_storage,
                parameter.offset(),
                parameter.observed_bytes(),
                u32::try_from(register_count.checked_add(index)?).ok()?,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let float_logical = |bits: u32| {
        let (_, id) = float_ids.iter().find(|(width, _)| *width == bits)?;
        Some(SourceLogicalValue::new(
            *id,
            SourceCarrierProjection::new(SourceCarrierKind::Full, 0, u64::from(bits)),
        ))
    };
    let classes = (recovered.parameters().iter())
        .map(|parameter| parameter.class())
        .chain(
            recovered
                .stack_parameters()
                .iter()
                .map(|_| SlotClass::Stack),
        );
    let parameter_logical_values = parameter_widths
        .iter()
        .zip(parameter_slot_widths.iter())
        .zip(classes)
        .map(|((bits, carrier_bits), class)| match class {
            SlotClass::Float => float_logical(*bits).map(Some),
            _ => logical(*bits, *carrier_bits).map(Some),
        })
        .collect::<Option<Vec<_>>>()?;
    let (return_kind, return_logical_value) = match (recovered.result(), result_width) {
        (RecoveredFunctionResult::Register(result), Some(bits)) => (
            SourceFunctionReturn::Register {
                storage: result.slot(),
            },
            Some(logical(bits, result.slot().size.checked_mul(8)?)?),
        ),
        (RecoveredFunctionResult::Register(result), None) if result.float() => {
            float_return(result, float_type?)?
        }
        (RecoveredFunctionResult::Pair { low, high }, Some(bits)) => (
            SourceFunctionReturn::Pair { low, high },
            Some(logical(bits, bits)?),
        ),
        // A pair is typed or the interface is not minted: no half of it stands for the whole.
        (RecoveredFunctionResult::Pair { .. }, None) => return None,
        // A body nobody read owns this result, so nothing is claimed for it.
        (RecoveredFunctionResult::Unproven, _) => (SourceFunctionReturn::Unproven, None),
        _ => (SourceFunctionReturn::Void, None),
    };

    // Exact: every stack slot here is a parameter's own, so the roles are
    // complete, which certification requires before it will trust the model.
    let interface = SourceFunctionInterface::new_exact_with_logical_types(
        revision_identity.to_vec(),
        convention,
        parameters,
        return_kind,
        stack_slots,
        parameter_logical_values,
        return_logical_value,
        Some(type_graph),
    )
    .inspect_err(|error| {
        r2il::refusal_evidence!("interface-minting", "constructor rejected it: {error:?}");
    })
    .ok()?
    .with_return_address_storage(return_address_storage)
    .ok()?
    .with_stack_pointer_storage(stack_pointer_storage)
    .ok()?
    // The carriers as the roles spell them: the trusted lift restates every
    // carrier in its own architecture's numbering by looking it up by name,
    // and an interface naming none had both storages cleared there while its
    // stacked return still stood -- a mechanism with no carriers, refused as
    // a conflict with the machine.
    .with_role_register_names(roles.role_register_names())
    .with_types(r2source::Confidence::of(r2source::Basis::CarrierWidth));
    let above = (recovered.result().register())
        .map_or(r2source::SourceAbove::Undefined, |held| held.above());
    let interface = interface.with_result_above(above);
    let interface = if recovered.result_is_return_address() {
        interface.with_body_proven_return_address().ok()?
    } else {
        interface
    };
    let interface = match recovered.security_check {
        true => interface.with_security_check(),
        false => interface,
    };
    with_stacked_return(recovered, interface)
}

/// A stacked return names the slot the call spent, which places the argument area at a call site;
/// a stack parameter without it would be read at the wrong offset, so no interface is minted.
fn with_stacked_return(
    recovered: &RecoveredInterface,
    interface: SourceFunctionInterface,
) -> Option<SourceFunctionInterface> {
    let Some(RecoveredReturnMechanism::Stacked { slot_bytes }) = recovered.return_mechanism()
    else {
        return Some(interface);
    };
    match interface
        .clone()
        .with_exact_stacked_return(0, slot_bytes, slot_bytes, slot_bytes)
    {
        Ok(interface) => Some(interface),
        Err(error) => {
            r2il::refusal_evidence!(
                "interface-minting",
                "the stacked return the body proves is rejected: {error:?}"
            );
            recovered.stack_parameters().is_empty().then_some(interface)
        }
    }
}

/// The lanes of a call to a callee whose result is unproven (D212): what the call states, and the
/// lanes left `Unproven`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallLanes {
    pub(crate) result: SourceCallResult,
    pub(crate) unproven: Vec<CanonicalStorageId>,
}

/// Each lane of `results` at a call to `callee`, default deny: `PassThrough`, `None` or `Unproven`;
/// `Void` needs no `Unproven` lane (doc/adr-call-boundary.md, "S16 as built").
pub(crate) fn call_lanes(
    callee: &SourceFunctionInterface,
    passes: Option<&BTreeSet<CanonicalStorageId>>,
    results: &[CanonicalStorageId],
) -> Option<CallLanes> {
    let carriers = callee.result_carriers()?;
    let passed = |lane| passes.is_some_and(|kept| crate::semantic::covers(kept, lane));
    let integer =
        (!carriers.integer_undefined && !passed(carriers.integer)).then_some(carriers.integer);
    let none = |lane: CanonicalStorageId| {
        carriers.integer_undefined
            && [Some(carriers.integer), carriers.second]
                .into_iter()
                .flatten()
                .any(|held| overlaps(held, lane))
    };
    let float = carriers.float.filter(|float| !passed(*float));
    if integer.is_some() && carriers.second.is_some_and(|second| !passed(second)) {
        return None;
    }
    let unproven = |result: SourceCallResult| {
        let stated = |lane: CanonicalStorageId| result.storages().any(|held| overlaps(held, lane));
        let lanes = results.iter().copied().chain(carriers.float);
        (lanes.chain([carriers.integer]))
            .filter(|lane| !stated(*lane) && !passed(*lane) && !none(*lane))
            .collect::<BTreeSet<_>>()
    };
    let result = match (integer, float) {
        // Two written carriers stay one unproven group: no constructor picks one.
        (Some(integer), Some(float)) => SourceCallResult::Unproven { integer, float },
        (Some(lane), None) | (None, Some(lane)) => SourceCallResult::register(lane),
        (None, None) if !results.is_empty() && unproven(SourceCallResult::Void).is_empty() => {
            SourceCallResult::Void
        }
        // An input handed back as found is the caller's own bytes in that register, as stated.
        (None, None) if !carriers.integer_undefined => SourceCallResult::register(carriers.integer),
        (None, None) => return None,
    };
    Some(CallLanes {
        result,
        unproven: unproven(result).into_iter().collect(),
    })
}

/// The storages of the convention's result lanes; none without a model.
pub(crate) fn convention_results(
    model: Option<&r2source::ConventionModel>,
) -> Vec<CanonicalStorageId> {
    (model.into_iter())
        .flat_map(|model| model.results.iter().map(|lane| lane.storage))
        .collect()
}

/// Mint a call-site interface from an interface recovered for the callee.
///
/// radare2 reports a prototype for a call only when it has one. For a local
/// function it usually has none: it correctly declines to assert a return type
/// it never inferred, and the snapshot carries that absence faithfully. The
/// call site is then left with no interface at all, its boundary never
/// completes, and every use of the call's result in the caller is refused.
///
/// But the callee's body arrives in the same capture, and its interface is
/// already recovered from its own SSA by `recover_interface` -- which is a
/// stronger fact than a prototype, because it is derived from the code rather
/// than declared about it. So where the source names no prototype and we hold
/// the callee, the call site is described from what the callee does.
///
/// The carriers come from the callee; the identity, revision and convention
/// come from the call site, so the result is indistinguishable from a
/// source-supplied interface to everything downstream and passes the same
/// admission gates.
pub fn mint_recovered_call_site_interface(
    callee: &SourceFunctionInterface,
    passes: Option<&BTreeSet<CanonicalStorageId>>,
    results: &[CanonicalStorageId],
    identity: SourceCallSiteIdentity,
    revision_identity: &[u8],
) -> Option<SourceCallSiteInterface> {
    // A stack parameter is named from the callee's entry stack pointer; the
    // call site names the same slot from its own stack pointer before the
    // transfer spends the return-address slot the callee's mechanism states.
    if !callee.arity().is_exact() {
        r2il::refusal_evidence!(
            "call-site-minting",
            "the callee reads an argument slot past its {} parameters, so its arity is no call's contract",
            callee.parameters().len()
        );
        return None;
    }
    let arguments = (callee.parameters().iter())
        .map(|parameter| {
            let location = callee.at_call_site(parameter.location())?;
            Some(SourceCallArgumentSpec::with_location(
                parameter.index(),
                location,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    // One result per callee at every call (D62): a call that does not read the high half of a pair
    // reads the low half; an unproven result with one carrier is that register.
    let result = match callee.return_kind() {
        SourceFunctionReturn::Void => SourceCallResult::Void,
        // The callee's width is complete: its declaration's, or its body's on every return.
        SourceFunctionReturn::Register { storage } => SourceCallResult::Register {
            storage,
            width: (callee.result_width()).unwrap_or(SourceResultWidth::whole(storage)),
        },
        SourceFunctionReturn::Pair { low, high } => SourceCallResult::Pair { low, high },
        SourceFunctionReturn::Unproven => match (
            callee.unstated_carrier(),
            call_lanes(callee, passes, results),
        ) {
            (Some(carrier), _) => SourceCallResult::Unstated { carrier },
            (None, Some(lanes)) => lanes.result,
            (None, None) => {
                r2il::refusal_evidence!(
                    "call-site-minting",
                    "the callee's result is unproven ({:?}), so its body describes no call contract",
                    callee.result_carriers()
                );
                return None;
            }
        },
    };
    let interface = SourceCallSiteInterface::new(
        revision_identity.to_vec(),
        identity,
        true,
        callee.convention(),
        arguments,
        callee.is_variadic(),
        false,
        result,
    )
    .and_then(|interface| interface.with_exact_callee_interface(callee.clone()))
    .ok()?;
    // The format the declaration names counts the tail at each call, else the one the callee's
    // body forwards; without either, a variadic call's tail is residualized, never dropped.
    match (
        callee.declared_format_parameter(),
        callee.body_proven_format_parameter(),
    ) {
        (Some(index), _) => interface.with_radare2_format_parameter(index).ok(),
        (None, Some(index)) => interface.with_body_proven_format_parameter(index).ok(),
        (None, None) => Some(interface),
    }
}

#[cfg(test)]
mod tests {
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, Varnode};
    use r2source::SourceCallSiteInterfaceError;

    use super::*;

    const AAPCS64: r2source::ConventionId = r2source::ConventionId::Aapcs64;

    fn arch() -> crate::Arch {
        crate::Arch::new(arch_spec())
    }

    fn arch_spec() -> ArchSpec {
        let mut arch = ArchSpec::new("aarch64");
        arch.addr_size = 8;
        arch.add_register(RegisterDef::new("x0", 0, 8));
        arch.add_register(RegisterDef::new("w0", 0, 4));
        arch.add_register(RegisterDef::new("x1", 8, 8));
        arch.add_register(RegisterDef::new("x2", 16, 8));
        arch
    }

    fn register(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    /// Recovery under a context, over a function prepared and never sealed,
    /// with the prep facts its preparation gives it.
    fn recover_in_context(
        function: &SSAFunction,
        context: &crate::SourceMachineContext,
    ) -> Option<RecoveredInterface> {
        recover_interface_with_context(
            function,
            &function.prep_facts_for_test(),
            &candidates(),
            context,
            Stated::default(),
        )
        .expect("settles")
    }

    fn candidate_model() -> r2source::convention::testing::Model {
        r2source::convention::testing::model(AAPCS64)
            .arguments(
                r2source::convention::SlotClass::Integer,
                [register(0, 8), register(8, 8), register(16, 8)],
            )
            .result(r2source::convention::SlotClass::Integer, register(0, 8))
    }

    fn candidates() -> std::sync::Arc<ConventionModel> {
        candidate_model().build()
    }

    fn recovered(mut block: R2ILBlock) -> RecoveredInterface {
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let arch = arch();
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch)).expect("ssa");
        recover_interface(&func, &candidates()).expect("recovery")
    }

    /// A body writing x0 and x1 on every return, proven a pair by a call reading x1, is one register
    /// at a call reading only x0 (doc/adr-language-profile.md).
    #[test]
    fn a_call_reading_only_the_first_register_of_a_pair_takes_that_register() {
        let mut block = R2ILBlock::new(0x1000, 8);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(8, 8),
            a: Varnode::register(0, 8),
            b: Varnode::constant(2, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(0, 8),
            a: Varnode::register(0, 8),
            b: Varnode::constant(1, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch())).expect("ssa");
        let slots = candidate_model()
            .result(r2source::convention::SlotClass::Integer, register(8, 8))
            .build();
        let stated = Stated {
            closed: Some(r2source::SourceClosedResult::Read(
                r2source::SourceReadLanes::Pair,
            )),
            ..Stated::default()
        };
        let recovered = recover_interface_inner(&func, None, &slots, None, stated)
            .expect("settles")
            .expect("recovery");
        let (low, high) = (register(0, 8), register(8, 8));
        assert_eq!(
            recovered.result(),
            RecoveredFunctionResult::Pair { low, high }
        );
        let names = r2source::SourceRoleRegisterNames::new(Some("x30"), Some("sp"), None);
        let roles = SourceMachineRoles::new(Some(register(0x80, 8)), Some(register(0x88, 8)))
            .expect("machine roles")
            .with_role_register_names(names);
        let interface =
            mint_recovered_interface(&recovered, &roles, b"pair", AAPCS64, None).expect("a pair");
        let identity = SourceCallSiteIdentity::new(
            0x2003,
            CanonicalStorageId {
                space: CanonicalStorageSpace::Constant,
                offset: 0x1000,
                size: 8,
            },
        );
        // The pair is the callee's: every call takes it, read whole or not (D62).
        let site = mint_recovered_call_site_interface(&interface, None, &[], identity, b"pair")
            .expect("a call site");
        assert_eq!(site.result(), SourceCallResult::Pair { low, high });
        assert_eq!(site.exact_callee_interface(), Some(&interface));
    }

    fn lane_interface(carriers: r2source::SourceResultCarriers) -> SourceFunctionInterface {
        SourceFunctionInterface::new(
            b"lanes".to_vec(),
            AAPCS64,
            [],
            SourceFunctionReturn::Unproven,
            [],
        )
        .expect("an unproven interface")
        .with_result_carriers(carriers)
    }

    /// Each lane at a call, default deny (D212): `Void` only where every lane of the set passes or is
    /// none, two written carriers one group, and with no lane set no `Void`.
    #[test]
    fn a_call_states_void_only_where_every_lane_passes_or_is_none() {
        let (x0, x1, q0) = (register(0, 8), register(8, 8), register(0x5000, 16));
        let handed_back = r2source::SourceResultCarriers {
            integer: x0,
            float: Some(q0),
            second: None,
            integer_undefined: true,
            float_second: None,
        };
        let callee = lane_interface(handed_back);
        let every = BTreeSet::from([x0, x1, q0]);
        let lanes = call_lanes(&callee, Some(&every), &[x0, x1, q0]).expect("lanes");
        assert_eq!(lanes.result, SourceCallResult::Void);
        assert!(lanes.unproven.is_empty());
        // x1 may change and nothing proves it holds no value: no `Void`.
        let some = BTreeSet::from([x0, q0]);
        assert_eq!(call_lanes(&callee, Some(&some), &[x0, x1, q0]), None);
        // No lane set: no `Void`.
        assert_eq!(call_lanes(&callee, Some(&every), &[]), None);
        // Two written carriers are one group: no lane is picked.
        let written = r2source::SourceResultCarriers {
            integer_undefined: false,
            ..handed_back
        };
        let lanes = call_lanes(&lane_interface(written), None, &[x0, x1, q0]).expect("lanes");
        assert_eq!(
            lanes.result,
            SourceCallResult::Unproven {
                integer: x0,
                float: q0
            }
        );
        assert_eq!(lanes.unproven, vec![x1]);
    }

    fn call_boundary_with(
        arguments: Vec<crate::semantic::SourceCallArgumentFact>,
    ) -> crate::semantic::SourceBoundaryFacts {
        let mut boundaries = crate::semantic::SourceBoundaryFacts::default();
        boundaries.calls.insert(
            crate::semantic::CallSiteId(0),
            crate::semantic::SourceCallBoundaryFact {
                call_site: crate::semantic::CallSiteId(0),
                at: crate::graph::InstId(0),
                convention: None,
                variadic: None,
                noreturn: None,
                result_kind: None,
                unstated_lanes: Box::default(),
                unstated_carrier: None,
                fixed_argument_count: Some(arguments.len()),
                ignored: Box::default(),
                reads_stated: true,
                variadic_argument_count_evidence: None,
                variadic_argument_count_refusal: None,
                arguments,
                results: Vec::new(),
                complete: true,
                arguments_complete: true,
                results_complete: true,
                arguments_proven: true,
                refusal: None,
            },
        );
        boundaries
    }

    fn graph_for(mut block: R2ILBlock) -> SsaGraph {
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let arch = arch();
        let function = SSAFunction::from_blocks_with_arch(&[block], Some(&arch)).expect("ssa");
        SsaGraph::from_function(&function)
    }

    fn register_argument(
        index: u32,
        storage: CanonicalStorageId,
        value: crate::semantic::SourceCallArgumentValue,
    ) -> crate::semantic::SourceCallArgumentFact {
        crate::semantic::SourceCallArgumentFact {
            slot: crate::semantic::CallBoundarySlot::Register { index, storage },
            value,
            lane_of: None,
        }
    }

    #[test]
    fn a_carrier_passed_straight_to_a_call_counts_as_read() {
        // The callee's own interface says the argument exists and
        // `PreservedEntry` says the value is the one this function was entered
        // with, so it is a parameter even though nothing here reads it: a call
        // takes its arguments implicitly and leaves no explicit read behind.
        let boundaries = call_boundary_with(vec![register_argument(
            0,
            register(0, 8),
            crate::semantic::SourceCallArgumentValue::PreservedEntry,
        )]);
        let graph = graph_for(R2ILBlock::new(0x1000, 4));
        assert_eq!(
            passed_through_entry_storages(&boundaries, &graph, |_, _, _, _| None),
            vec![(register(0, 8), crate::CallSiteId(0))]
        );
    }

    #[test]
    fn a_producerless_boundary_value_is_the_same_passed_entry_carrier() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::register(0, 8),
        });
        let graph = graph_for(block);
        let entry = graph
            .values
            .iter()
            .find(|value| {
                value.canonical_storage == Some(register(0, 8))
                    && graph.def_inst(value.id).is_none()
            })
            .expect("producerless x0 entry value")
            .id;
        let boundaries = call_boundary_with(vec![register_argument(
            0,
            register(0, 8),
            crate::semantic::SourceCallArgumentValue::Value(entry),
        )]);

        assert_eq!(
            passed_through_entry_storages(&boundaries, &graph, |_, _, _, _| None),
            vec![(register(0, 8), crate::CallSiteId(0))]
        );
    }

    #[test]
    fn contextual_recovery_promotes_a_preserved_call_carrier() {
        let arch = arch();
        let target = Varnode::constant(0x401000, 8);
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Call {
            target: target.clone(),
        });
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        block.stamp_instruction(0, 0x1000);
        let blocks = [block];
        let call_interface = SourceCallSiteInterface::new(
            b"contextual-preserved-entry".to_vec(),
            SourceCallSiteIdentity::new(0x1000, CanonicalStorageId::from_varnode(&target)),
            true,
            AAPCS64,
            [SourceCallArgumentSpec::new(0, register(0, 8))],
            false,
            false,
            SourceCallResult::register(register(0, 8)),
        )
        .expect("exact callsite interface");
        // A call clobbers the argument registers, so the carrier reaches the call only from entry.
        let clobbered = [register(0, 8), register(8, 8), register(16, 8)];
        let machine_context = crate::SourceMachineContext::from_blocks_with_interfaces(
            &blocks,
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(candidate_model().killed(clobbered).conventions()),
            vec![call_interface],
        );
        let function = SSAFunction::for_decompile_under(&blocks, Some(&arch), &machine_context)
            .expect("decompile-normalized ssa");
        let recovered =
            recover_in_context(&function, &machine_context).expect("contextual recovery");

        assert_eq!(recovered.parameters().len(), 1);
        assert_eq!(recovered.parameters()[0].slot(), register(0, 8));
    }

    #[test]
    fn a_result_register_defined_at_the_return_is_the_result() {
        let mut block = R2ILBlock::new(0x2000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(7, 8),
        });
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let arch = arch();
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch)).expect("ssa");
        let observed = recover_interface(&func, &candidates()).expect("recovery");
        assert!(
            observed.result().register().is_some(),
            "the defined result register is live out"
        );
    }

    #[test]
    fn an_argument_this_function_computed_is_not_a_passed_through_carrier() {
        // A value defined here already has a producer and an SSA value naming
        // it, so it needs no help from this rule and must not be reported as an
        // entry read: that would claim a parameter the function may not have.
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(7, 8),
        });
        let graph = graph_for(block);
        let defined = graph
            .inst_spelled_at(0x1000, 0)
            .and_then(|inst| graph.inst(inst))
            .and_then(|inst| inst.output)
            .expect("defined x0 value");
        let boundaries = call_boundary_with(vec![register_argument(
            0,
            register(0, 8),
            crate::semantic::SourceCallArgumentValue::Value(defined),
        )]);
        assert!(passed_through_entry_storages(&boundaries, &graph, |_, _, _, _| None).is_empty());
    }

    #[test]
    fn a_register_read_before_any_write_is_a_parameter() {
        let mut block = R2ILBlock::new(0x1000, 4);
        // reads x0 and x1 without defining them first
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(0, 8),
            a: Varnode::register(0, 8),
            b: Varnode::register(8, 8),
        });
        let interface = recovered(block);
        assert_eq!(
            interface
                .parameters()
                .iter()
                .map(RecoveredParameter::slot)
                .collect::<Vec<_>>(),
            &[register(0, 8), register(8, 8)]
        );
        // x0 was written, so the result carrier is defined
        assert_eq!(
            interface.result(),
            RecoveredFunctionResult::Register(RecoveredResult {
                slot: register(0, 8),
                observed: register(0, 8),
                float: false,
                above: r2source::SourceAbove::Undefined,
            })
        );
    }

    #[test]
    fn a_narrow_result_keeps_the_full_slot_and_mints_its_observed_width() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 4),
            src: Varnode::constant(7, 4),
        });
        block.push(R2ILOp::IntZExt {
            dst: Varnode::register(0, 8),
            src: Varnode::register(0, 4),
        });
        let recovered = recovered(block);
        let result = recovered
            .result()
            .register()
            .expect("recovered narrow result");
        assert_eq!(result.slot(), register(0, 8));
        assert_eq!(result.observed(), register(0, 4));

        let names = r2source::SourceRoleRegisterNames::new(Some("x30"), Some("sp"), None);
        let roles = SourceMachineRoles::new(Some(register(0x80, 8)), Some(register(0x88, 8)))
            .expect("machine roles")
            .with_role_register_names(names);
        let interface =
            mint_recovered_interface(&recovered, &roles, b"narrow-return-revision", AAPCS64, None)
                .expect("minted narrow return interface");
        // The lift restates carriers by name; an interface minted without the
        // roles' names had its carriers cleared there.
        assert_eq!(interface.role_register_names(), names);
        assert_eq!(
            interface.return_kind(),
            SourceFunctionReturn::Register {
                storage: register(0, 8),
            }
        );
        let logical = interface
            .return_logical_value()
            .expect("logical return projection");
        assert_eq!(logical.carrier().kind(), SourceCarrierKind::LowBits);
        assert_eq!(logical.carrier().size_bits(), 32);
        let source_type = &interface.type_graph().expect("return type graph").types()
            [usize::try_from(logical.type_id()).expect("type index")];
        assert_eq!(source_type.kind(), SourceTypeKind::UnsignedInteger);
        assert_eq!(source_type.size_bits(), 32);

        let callsite = mint_recovered_call_site_interface(
            &interface,
            None,
            &[],
            SourceCallSiteIdentity::new(
                0x2003,
                CanonicalStorageId {
                    space: CanonicalStorageSpace::Constant,
                    offset: 0x4000,
                    size: 8,
                },
            ),
            b"narrow-return-revision",
        )
        .expect("callsite with recovered callee interface");
        assert_eq!(callsite.exact_callee_interface(), Some(&interface));

        let incompatible = SourceCallSiteInterface::new(
            b"narrow-return-revision".to_vec(),
            callsite.identity(),
            true,
            AAPCS64,
            [],
            false,
            false,
            SourceCallResult::Void,
        )
        .expect("physically valid void callsite")
        .with_exact_callee_interface(interface);
        assert_eq!(
            incompatible,
            Err(SourceCallSiteInterfaceError::IncompatibleCalleeInterface)
        );
    }

    #[test]
    fn a_register_written_before_it_is_read_is_not_a_parameter() {
        let mut block = R2ILBlock::new(0x1000, 4);
        // x0 is defined from a constant, then read: the read observes this
        // function's own value, not the caller's
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(7, 8),
        });
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(8, 8),
            a: Varnode::register(0, 8),
            b: Varnode::constant(1, 8),
        });
        let interface = recovered(block);
        assert!(interface.parameters().is_empty());
    }

    #[test]
    fn an_unread_slot_below_a_read_one_is_a_hole_not_the_end_of_the_parameters() {
        let mut block = R2ILBlock::new(0x1000, 4);
        // Reads x0 and x2, never x1: the old prefix stopped at x1 and dropped x2 (W12). Rule 2
        // makes x1 a hole at `Convention`, so a caller still places x2 where the body reads it.
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(0, 8),
            a: Varnode::register(0, 8),
            b: Varnode::register(16, 8),
        });
        let interface = recovered(block);
        let parameters = interface.parameters();
        assert_eq!(
            parameters
                .iter()
                .map(|parameter| (parameter.slot(), parameter.basis()))
                .collect::<Vec<_>>(),
            [
                (register(0, 8), r2source::Basis::Decoded),
                (register(8, 8), r2source::Basis::Convention),
                (register(16, 8), r2source::Basis::Decoded),
            ]
        );
        // Every register slot is a parameter, so an argument area no exit places is the floor.
        assert_eq!(
            interface.arity_floor.as_ref().map(SourceArityFloor::causes),
            Some(&[SourceFloorCause::ArgumentAreaUnplaced][..])
        );
        assert_eq!(
            interface.boundary().slots[crate::body_boundary::SlotId(1)],
            SlotUse::Unread
        );
    }

    #[test]
    fn a_narrow_read_still_names_the_whole_candidate_slot() {
        let mut block = R2ILBlock::new(0x1000, 4);
        // reads w0, the low half of x0: same argument, narrower view
        block.push(R2ILOp::IntZExt {
            dst: Varnode::register(0, 8),
            src: Varnode::register(0, 4),
        });
        let interface = recovered(block);
        assert_eq!(
            interface
                .parameters()
                .iter()
                .map(RecoveredParameter::slot)
                .collect::<Vec<_>>(),
            &[register(0, 8)]
        );
    }

    #[test]
    fn an_untouched_result_carrier_that_is_also_an_argument_is_unproven() {
        let mut block = R2ILBlock::new(0x1000, 4);
        // x0 is only read, so the caller may read back the argument it passed: neither a result nor void is proven
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::register(0, 8),
        });
        let interface = recovered(block);
        assert_eq!(interface.result(), RecoveredFunctionResult::Unproven);
    }

    #[test]
    fn a_dead_entry_read_is_not_promoted_to_a_parameter() {
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(0, 8),
            a: Varnode::register(0, 8),
            b: Varnode::register(8, 8),
        });
        // x2 is a convention candidate and is genuinely read at the machine
        // level, but this pure result reaches no effect or return. Its presence
        // cannot prove a third source parameter.
        block.push(R2ILOp::IntAdd {
            dst: Varnode::register(16, 8),
            a: Varnode::register(16, 8),
            b: Varnode::constant(1, 8),
        });
        let interface = recovered(block);
        assert_eq!(
            interface
                .parameters()
                .iter()
                .map(RecoveredParameter::slot)
                .collect::<Vec<_>>(),
            &[register(0, 8), register(8, 8)]
        );
    }

    #[test]
    fn a_convention_without_candidates_recovers_nothing() {
        let arch = arch();
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::register(0, 8),
        });
        let func = SSAFunction::from_blocks_with_arch(&[block], Some(&arch)).expect("ssa");
        let empty = r2source::convention::testing::model(r2source::ConventionId::SysVAmd64).build();
        assert!(recover_interface(&func, &empty).is_none());
    }

    #[test]
    fn a_tail_transfer_to_an_unknown_target_leaves_the_result_unproven() {
        // An import thunk: load the relocated slot, jump through it. The body
        // writes no register, which says nothing about what the target
        // returns.
        let arch = arch();
        let slot = 0x4000u64;
        let slot_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Ram,
            offset: slot,
            size: 8,
        };
        let loaded = Varnode::unique(0x100, 8);
        let mut block = R2ILBlock::new(0x1000, 8);
        block.push(R2ILOp::Load {
            dst: loaded.clone(),
            space: r2il::SpaceId::Ram,
            addr: Varnode::constant(slot, 8),
        });
        block.push(R2ILOp::BranchInd { target: loaded });
        block.stamp_instruction(1, 0x1001);
        let identity = SourceCallSiteIdentity::new(0x1001, slot_storage);
        let function =
            SSAFunction::from_blocks_for_decompile(std::slice::from_ref(&block), Some(&arch))
                .expect("thunk ssa");

        let unknown = crate::SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            std::slice::from_ref(&block),
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(candidate_model().conventions()),
            Vec::new(),
            vec![identity],
        );
        let unproven = recover_in_context(&function, &unknown)
            .expect("an unproven result is still an interface");
        assert_eq!(
            unproven.result(),
            RecoveredFunctionResult::Unproven,
            "a body that hands its result to an unknown target proves nothing about it"
        );
        let roles = SourceMachineRoles::new(Some(register(0x80, 8)), Some(register(0x88, 8)))
            .expect("machine roles");
        let minted = mint_recovered_interface(&unproven, &roles, b"thunk-revision", AAPCS64, None)
            .expect("an unproven result mints an interface");
        assert_eq!(minted.return_kind(), SourceFunctionReturn::Unproven);
        // Nothing this body proves describes a call to it, arguments included.
        assert!(
            mint_recovered_call_site_interface(&minted, None, &[], identity, b"thunk-revision")
                .is_none(),
            "an unproven result cannot be a call site's exact contract"
        );

        // The same body behind a complete prototype recovers that prototype's
        // result.
        let interface = SourceCallSiteInterface::new(
            b"thunk-prototype".to_vec(),
            identity,
            true,
            AAPCS64,
            [SourceCallArgumentSpec::new(0, register(0, 8))],
            false,
            false,
            SourceCallResult::register(register(0, 8)),
        )
        .expect("exact tail interface");
        let known = crate::SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            std::slice::from_ref(&block),
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(candidate_model().conventions()),
            vec![interface],
            vec![identity],
        );
        let recovered =
            recover_in_context(&function, &known).expect("a proven tail boundary owns the result");
        assert_eq!(
            recovered.result().register().map(|result| result.slot()),
            Some(register(0, 8))
        );
    }

    #[test]
    fn a_direct_return_owns_the_result_a_tail_transfer_leaves_open() {
        // One arm returns a value of its own, the other tails to a target
        // nothing describes -- the shape of a mutually recursive pair whose
        // partner has no prototype yet. The arm that returns says where the
        // result is.
        let arch = arch();
        let slot = 0x4000u64;
        let slot_storage = CanonicalStorageId {
            space: CanonicalStorageSpace::Ram,
            offset: slot,
            size: 8,
        };
        let mut entry = R2ILBlock::new(0x1000, 4);
        entry.push(R2ILOp::IntEqual {
            dst: Varnode::register(24, 1),
            a: Varnode::register(0, 8),
            b: Varnode::constant(0, 8),
        });
        entry.push(R2ILOp::CBranch {
            target: Varnode::ram(0x1008, 8),
            cond: Varnode::register(24, 1),
        });

        let mut tail = R2ILBlock::new(0x1004, 4);
        let loaded = Varnode::unique(0x100, 8);
        tail.push(R2ILOp::Load {
            dst: loaded.clone(),
            space: r2il::SpaceId::Ram,
            addr: Varnode::constant(slot, 8),
        });
        tail.push(R2ILOp::BranchInd { target: loaded });
        tail.stamp_instruction(1, 0x1005);

        let mut direct = R2ILBlock::new(0x1008, 4);
        direct.push(R2ILOp::IntXor {
            dst: Varnode::register(0, 8),
            a: Varnode::register(8, 8),
            b: Varnode::constant(0xa5a5_a5a5, 8),
        });
        direct.push(R2ILOp::Return {
            target: Varnode::register(16, 8),
        });

        let blocks = [entry, tail, direct];
        let identity = SourceCallSiteIdentity::new(0x1005, slot_storage);
        let function = SSAFunction::from_blocks_for_decompile(&blocks, Some(&arch))
            .expect("mutual recursion ssa");
        let context = crate::SourceMachineContext::from_blocks_with_interfaces_and_tail_calls(
            &blocks,
            Some(&arch),
            None,
            SourceMachineRoles::default(),
            Some(candidate_model().conventions()),
            Vec::new(),
            vec![identity],
        );
        let recovered = recover_in_context(&function, &context)
            .expect("a direct return answers the boundary the tail leaves open");
        assert_eq!(
            recovered.result().register().map(|result| result.slot()),
            Some(register(0, 8))
        );
    }

    #[test]
    fn a_body_whose_walk_reaches_no_return_proves_no_void() {
        let mut block = R2ILBlock::new(0x1000, 4);
        let target = Varnode::unique(0x100, 8);
        block.push(R2ILOp::Load {
            dst: target.clone(),
            space: r2il::SpaceId::Ram,
            addr: Varnode::register(8, 8),
        });
        block.push(R2ILOp::BranchInd { target });
        let arch = arch();
        let function = SSAFunction::from_blocks_with_arch(&[block], Some(&arch)).expect("ssa");
        let recovered = recover_interface(&function, &candidates()).expect("recovery");
        assert_eq!(recovered.result(), RecoveredFunctionResult::Unproven);
    }
}

/// One stack slot the body proves a role for, in entry-stack-pointer
/// coordinates.
///
/// A capture that states these is stating what preparation already proved, so
/// the spill into a parameter's home stops being a memory access and becomes
/// the parameter again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredStackSlot {
    pub offset: i64,
    pub size_bytes: u32,
    /// The parameter this slot homes, where the body proves it is one.
    pub parameter: Option<u32>,
}

/// The stack slots one prepared body proves, with the parameter each homes.
///
/// Preparation already certifies every stack slot: where it sits, how wide it
/// is, and which values were stored into it. This reads those certificates
/// rather than re-deriving them from the memory accesses, because a second
/// derivation is a second answer -- and the weaker one, since the certificate
/// knows about indexed access, callee-written extents and the frame carriers
/// this body manages for itself.
///
/// A home is a slot a formal parameter was stored into. Which formal a value
/// is is the preparation's answer too, so a parameter copied or narrowed
/// before the spill is still recognised.
pub fn recovered_stack_slots(prepared: &crate::SsaArtifact) -> Vec<RecoveredStackSlot> {
    let facts = prepared.decompile_prep_facts();
    let mut slots = Vec::new();
    for (object, certificate) in &prepared.certificates().stack_slots {
        // The frame carriers a function manages for itself are not the
        // source's to declare, and a slot with no stated extent is not a slot.
        if !prepared.declarable_stack_object(*object) {
            continue;
        }
        let (Some(size_bytes), StackAddressBase::StackPointer) =
            (certificate.size, certificate.base)
        else {
            continue;
        };
        let parameter = prepared.proved_parameter_home(*object).or_else(|| {
            certificate
                .stored_values
                .iter()
                .find_map(|value| facts.formal_parameter_of(value))
                .and_then(|index| u32::try_from(index).ok())
        });
        slots.push(RecoveredStackSlot {
            offset: certificate.offset,
            size_bytes,
            parameter,
        });
    }
    slots.sort_by_key(|slot| slot.offset);
    r2il::refusal_evidence!(
        "recovered-stack-slots",
        "{} certified slots, {} declarable ({} homes)",
        prepared.certificates().stack_slots.len(),
        slots.len(),
        slots.iter().filter(|slot| slot.parameter.is_some()).count()
    );
    slots
}
