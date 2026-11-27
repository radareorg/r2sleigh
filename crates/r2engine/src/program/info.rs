//! What one function is, read off the analysis that renders it.
//!
//! Nothing here is analysed afresh: the blocks and instructions are the
//! prepared artifact's, the calls are its call-site certificates, and the
//! arguments and locals are the type analysis's certified entities. A number
//! radare2 prints that none of these proves is left for the shell to omit.

use std::collections::BTreeSet;

use r2source::confidence::{Basis, Fact};
use r2types::{CTypeLike, CertifiedEntity, SourceOwnedFunctionFacts};

pub use r2ssa::StackAddressBase as StackBase;

/// One function, as `afi` and `afv` report it.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionInfo {
    pub entry: u64,
    /// The function's blocks by address, each with a byte extent.
    pub blocks: Vec<Block>,
    /// Where each call site transfers, where the instruction states it.
    pub calls: Vec<Option<u64>>,
    /// The convention the function's interface states, where it has one.
    pub convention: Option<r2abi::ConventionId>,
    pub arguments: Vec<Argument>,
    /// Whether arguments continue past `arguments`: a variadic tail the interface states.
    pub variadic: bool,
    /// Where the interface states only a floor of parameters, why: `arguments` are then at least
    /// the parameters (D37).
    pub floor: Option<r2source::SourceArityFloor>,
    pub locals: Vec<Local>,
    /// The frame array the rendering declares its members in, where one holds a listed local (D633).
    pub frame: Option<FrameArray>,
    /// What a definition of it declares it returns, and what that rests on: the decided type, or
    /// the result carrier a caller reads, on the convention alone, where the value is unproven
    /// (none where C has no carrier that wide). Absent where r2types refuses a type.
    pub returns: Option<Fact<Option<CTypeLike>>>,
    /// Where the result is unproven: the convention's carrier and why (doc/adr-scratch-result.md).
    pub unproven: Option<UnprovenResult>,
    /// What a proven result's closed decision takes for granted (`result_premises`, D592); empty
    /// where it rests on nothing or is unproven (D566).
    pub result_premises: Vec<r2source::Premise>,
    /// Why control never comes back from it, and what that takes for granted: a proof, or a bound
    /// such as a walk that reached no return (D380). `None` where nothing says it never does.
    pub noreturn: Option<r2source::Never>,
    /// Why there is no analysis, where there is none: the blocks are then the walk's, and
    /// the calls, convention, parameters, locals and return are unknown, not empty (ROADMAP D29).
    pub refused: Option<crate::native::NativeRefusal>,
}

/// An unproven result: the register a caller reads it from, and the cause the proof line names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnprovenResult {
    pub carrier: Option<r2ssa::CanonicalStorageId>,
    pub cause: Option<r2types::UnprovenCause>,
    /// The carrier's width, where the header spells it `r2sleigh_result_uN`.
    pub bits: Option<u32>,
}

impl UnprovenResult {
    /// The cause as the proof line spells it.
    pub fn cause_name(self) -> &'static str {
        crate::query::ResultStanding::cause_name(self.cause)
    }
}

/// One basic block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub addr: u64,
    pub size: u64,
    pub instructions: usize,
    pub successors: usize,
}

/// One parameter, in the slot the boundary proved it arrives in.
#[derive(Debug, Clone, PartialEq)]
pub struct Argument {
    pub slot: u32,
    /// The storage it arrives in, where the entry value names one.
    pub storage: Option<r2ssa::CanonicalStorageId>,
    /// Its type, and what that rests on: the interface's types, the body's solve, or only the
    /// width of the carrier it arrives in.
    pub ty: Fact<CTypeLike>,
    /// Its one name (r2types `FunctionFacts::parameter_name`).
    pub name: String,
}

/// One stack object in the function's own frame, frame management excluded.
#[derive(Debug, Clone, PartialEq)]
pub struct Local {
    /// What the rendering calls it (`SourceOwnedFunctionFacts::stack_object_name`).
    pub name: String,
    pub base: StackBase,
    pub offset: i64,
    /// The type it is declared at, as C spells it.
    pub ty: String,
    /// What the frame model proves became of it, where it proves one (D633).
    pub fate: Option<Fate>,
}

/// What became of a frame slot, as `afv` states it beside the slot (D633).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fate {
    /// Promotion took it out of memory; `reads` is the parameter whose value it holds throughout.
    Promoted { reads: Option<String> },
    /// The save of a preserved register's entry value.
    Save { storage: r2ssa::CanonicalStorageId },
    /// The home of a parameter, named as the rendering names it, at its byte in the frame array
    /// where `afv` lists the array.
    Home { parameter: String, at: Option<u32> },
    /// A member of the frame array at this byte.
    InFrame { at: u32 },
}

/// The one byte array the rendering declares the frame's members in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameArray {
    /// The entry-stack offset of its byte 0.
    pub offset: i64,
    pub bytes: u32,
}

impl Argument {
    /// This parameter declared under a name, as C spells the declaration.
    pub fn declared_as(&self, name: &str) -> String {
        r2types::c_object_declaration(&self.ty.value, name)
    }
}

impl FunctionInfo {
    /// Read one prepared function and the type analysis sealed from it, over the walk's blocks.
    pub(crate) fn read(
        entry: u64,
        artifact: &r2ssa::SsaArtifact,
        sealed: &SourceOwnedFunctionFacts,
        noreturn: Option<r2source::Never>,
        blocks: Vec<Block>,
    ) -> Self {
        let facts = sealed.report();
        let certificates = artifact.certificates();
        let arguments = arguments(artifact, sealed);
        let entities = facts
            .render()
            .map(|render| render.certified_entities.values().collect::<Vec<_>>())
            .unwrap_or_default();
        let (locals, frame) = locals(artifact, sealed, &entities);
        Self {
            entry,
            blocks,
            calls: certificates
                .callsites
                .values()
                .map(|site| site.direct_target)
                .collect(),
            convention: (artifact.machine_context().function_interface())
                .map(r2source::SourceFunctionInterface::convention),
            arguments,
            variadic: (artifact.machine_context().function_interface())
                .is_some_and(r2source::SourceFunctionInterface::is_variadic),
            floor: (artifact.machine_context().function_interface())
                .and_then(|interface| interface.arity_floor().cloned()),
            returns: returns(artifact, sealed),
            unproven: (sealed.return_type())
                .filter(|fact| fact.is_unproven())
                .map(|fact| UnprovenResult {
                    carrier: artifact.machine_context().return_value_carrier(),
                    cause: fact.unproven_cause(),
                    bits: match fact.declared() {
                        Some(CTypeLike::Int { bits, .. }) => Some(*bits),
                        _ => None,
                    },
                }),
            result_premises: match sealed.return_type() {
                Some(fact) if !fact.is_unproven() => {
                    (artifact.function().result_premises().iter().copied()).collect()
                }
                _ => Vec::new(),
            },
            locals,
            frame,
            noreturn,
            refused: None,
        }
    }

    /// A function whose analysis refused: the walk's blocks, as `afb` lists them, and why.
    pub(crate) fn refused(
        entry: u64,
        walked: &[super::GraphBlock],
        noreturn: Option<r2source::Never>,
        refusal: crate::native::NativeRefusal,
    ) -> Self {
        let blocks = (walked.iter())
            .map(|block| Block {
                addr: block.address,
                size: block.size,
                instructions: block.lines.len(),
                successors: block.edges.len(),
            })
            .collect();
        Self {
            entry,
            blocks,
            calls: Vec::new(),
            convention: None,
            arguments: Vec::new(),
            variadic: false,
            floor: None,
            locals: Vec::new(),
            frame: None,
            returns: None,
            unproven: None,
            result_premises: Vec::new(),
            noreturn,
            refused: Some(refusal),
        }
    }

    /// The lowest address any block covers.
    pub fn min_addr(&self) -> u64 {
        self.blocks
            .iter()
            .map(|block| block.addr)
            .min()
            .unwrap_or(self.entry)
    }

    /// One past the highest address any block covers.
    pub fn max_addr(&self) -> u64 {
        let end = self.blocks.iter().map(|block| block.addr + block.size);
        end.max().unwrap_or(self.entry)
    }

    /// The bytes the blocks cover, holes excluded.
    pub fn real_size(&self) -> u64 {
        self.blocks.iter().map(|block| block.size).sum()
    }

    pub fn instructions(&self) -> usize {
        self.blocks.iter().map(|block| block.instructions).sum()
    }

    pub fn edges(&self) -> usize {
        self.blocks.iter().map(|block| block.successors).sum()
    }

    /// Blocks control leaves the function from.
    pub fn exits(&self) -> usize {
        let exits = self.blocks.iter().filter(|block| block.successors == 0);
        exits.count()
    }

    /// McCabe's `E - N + 2P`, with each exit block a component as radare2 counts it.
    pub fn complexity(&self) -> i64 {
        let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
        count(self.edges()) - count(self.blocks.len()) + 2 * count(self.exits())
    }

    /// Whether the blocks tile one run of bytes from the entry with no gap.
    pub fn is_lineal(&self) -> bool {
        self.min_addr() == self.entry && self.max_addr() - self.entry == self.real_size()
    }

    /// Whether some call site states this function's own entry as its target.
    pub fn is_recursive(&self) -> bool {
        self.calls.contains(&Some(self.entry))
    }

    /// Call sites whose target the instruction states.
    pub fn direct_calls(&self) -> usize {
        self.calls.iter().flatten().count()
    }
}

/// Every formal parameter of the one list `pdd` declares (r2ssa's formal facts), named by the one
/// name owner and typed as r2types declares that slot, else as storage of its width.
fn arguments(artifact: &r2ssa::SsaArtifact, sealed: &SourceOwnedFunctionFacts) -> Vec<Argument> {
    (artifact.facts().boundaries.parameters.values())
        .map(|formal| {
            let width_bits = formal.bytes() * 8;
            let slot = formal.index as usize;
            Argument {
                slot: formal.index,
                storage: formal.register().map(|(_, lane)| lane),
                name: sealed.report().parameter_name(slot),
                ty: (sealed.parameter_declaration_fact(slot, width_bits))
                    .unwrap_or_else(|| carrier_typed(width_bits)),
            }
        })
        .collect()
}

/// A type that is only the width of the carrier a value arrives in.
fn carrier_typed(width_bits: u32) -> Fact<CTypeLike> {
    Fact::new(CTypeLike::machine_bits(width_bits), Basis::CarrierWidth)
}

/// The decided return, spelled as a rendering declares it.
fn returns(
    artifact: &r2ssa::SsaArtifact,
    sealed: &SourceOwnedFunctionFacts,
) -> Option<Fact<Option<CTypeLike>>> {
    let bits = artifact
        .machine_context()
        .memory_model()
        .default_address_bits();
    let fact = sealed.return_type()?;
    let declared = fact
        .declared()
        .map(|ty| r2types::spellable_c_type_like(ty, bits));
    Some(Fact::new(declared, fact.basis(artifact)?))
}

/// Every declarable stack object and every promoted frame slot, each with its fate: the frame model
/// `afv` lists for either pipeline; and the frame array, where a listed member is in it.
fn locals(
    artifact: &r2ssa::SsaArtifact,
    sealed: &SourceOwnedFunctionFacts,
    entities: &[&CertifiedEntity],
) -> (Vec<Local>, Option<FrameArray>) {
    let layout = r2ssa::FrameLayout::of(artifact);
    let fates = artifact.slot_fates(layout.as_ref());
    let objects = entities
        .iter()
        .filter_map(|entity| object(artifact, sealed, entity, &fates))
        .collect::<Vec<_>>();
    let held = objects
        .iter()
        .map(|local| local.offset)
        .collect::<BTreeSet<_>>();
    // A parameter's name is the one the rendering reads; another value's name is r2dec's own.
    let named = |index: usize| sealed.report().parameter_name(index);
    let reads = |value: r2ssa::ValueId| {
        let index = artifact.decompile_prep_facts().formal_parameter_of(value)?;
        Some(named(index))
    };
    let promoted = (artifact.promoted_slots().into_iter())
        .filter(|slot| !held.contains(&slot.offset))
        .map(|slot| Local {
            name: r2ssa::frame_object_name(slot.offset),
            base: StackBase::StackPointer,
            offset: slot.offset,
            ty: CTypeLike::machine_bits(slot.size * 8).to_string(),
            fate: Some(fate(slot.fate, &reads, &named)),
        });
    let mut locals = objects.into_iter().chain(promoted).collect::<Vec<_>>();
    locals.sort_by_key(|local| local.offset);
    let member = (locals.iter()).any(|local| matches!(local.fate, Some(Fate::InFrame { .. })));
    let frame = layout.filter(|_| member).map(|layout| FrameArray {
        offset: layout.start(),
        bytes: layout.bytes(),
    });
    // A home's byte in the array is stated only where the array is listed.
    for local in locals.iter_mut().filter(|_| frame.is_none()) {
        if let Some(Fate::Home { at, .. }) = &mut local.fate {
            *at = None;
        }
    }
    (locals, frame)
}

/// A fate r2ssa proves, as `afv` states it.
fn fate(
    fate: r2ssa::SlotFate,
    reads: &impl Fn(r2ssa::ValueId) -> Option<String>,
    named: &impl Fn(usize) -> String,
) -> Fate {
    match fate {
        r2ssa::SlotFate::Promoted { holds } => Fate::Promoted {
            reads: holds.and_then(reads),
        },
        r2ssa::SlotFate::Save { storage } => Fate::Save { storage },
        r2ssa::SlotFate::Home { parameter, index } => Fate::Home {
            parameter: named(parameter as usize),
            at: index,
        },
        r2ssa::SlotFate::Member { index } => Fate::InFrame { at: index },
    }
}

/// A stack object the rendering can declare, typed as declared or by its width.
fn object(
    artifact: &r2ssa::SsaArtifact,
    sealed: &SourceOwnedFunctionFacts,
    entity: &CertifiedEntity,
    fates: &r2ssa::dense::IdVec<r2ssa::ObjectId, Option<r2ssa::SlotFate>>,
) -> Option<Local> {
    let CertifiedEntity::StackSlot {
        object,
        base,
        offset,
        size,
        ty,
        ..
    } = entity
    else {
        return None;
    };
    // The caller's storage -- a return address, a stack-passed value -- is no local of this body.
    if !artifact.declarable_stack_object(*object) || artifact.caller_stack_object(*object) {
        return None;
    }
    let storage = CTypeLike::machine_bits(size.unwrap_or_default() * 8);
    Some(Local {
        name: sealed.stack_object_name(*object, *offset),
        base: *base,
        offset: *offset,
        ty: ty.clone().unwrap_or(storage).to_string(),
        fate: (fates.get(*object).copied().flatten()).map(|found| {
            fate(found, &|_| None, &|index| {
                sealed.report().parameter_name(index)
            })
        }),
    })
}
