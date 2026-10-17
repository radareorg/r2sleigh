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
    /// The calling convention the type analysis settled on, where it did.
    pub convention: Option<String>,
    pub arguments: Vec<Argument>,
    /// Whether arguments continue past `arguments`: a variadic tail the interface states.
    pub variadic: bool,
    pub locals: Vec<Local>,
    /// What a definition of it declares it returns, and what that rests on: the decided type, or
    /// the result carrier a caller reads, on the convention alone, where the value is unproven
    /// (none where C has no carrier that wide). Absent where r2types refuses a type.
    pub returns: Option<Fact<Option<CTypeLike>>>,
    /// Whether control never comes back from it, and what that takes for granted: nothing where
    /// the whole program proves it, a premise where a runtime model says it. `None` where it may.
    pub noreturn: Option<std::collections::BTreeSet<r2source::Premise>>,
    /// Why there is no analysis, where there is none: the blocks are then the walk's, and
    /// the calls, convention, parameters, locals and return are unknown, not empty (ROADMAP D29).
    pub refused: Option<crate::native::NativeRefusal>,
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
    /// What the source calls it, where the source names it.
    pub name: Option<String>,
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
}

impl Argument {
    /// This parameter declared under a name, as C spells the declaration.
    pub fn declared_as(&self, name: &str) -> String {
        r2types::c_object_declaration(&self.ty.value, name)
    }
}

impl FunctionInfo {
    /// Read one prepared function and the type analysis sealed from it.
    pub(crate) fn read(
        entry: u64,
        artifact: &r2ssa::SsaArtifact,
        sealed: &SourceOwnedFunctionFacts,
        noreturn: Option<std::collections::BTreeSet<r2source::Premise>>,
    ) -> Self {
        let facts = sealed.report();
        let certificates = artifact.certificates();
        let entities = facts
            .render()
            .map(|render| render.certified_entities.values().collect::<Vec<_>>())
            .unwrap_or_default();
        Self {
            entry,
            blocks: blocks(artifact),
            calls: certificates
                .callsites
                .values()
                .map(|site| site.direct_target)
                .collect(),
            convention: facts.type_facts().callconv.clone(),
            arguments: arguments(artifact, sealed, &entities),
            variadic: (artifact.machine_context().function_interface())
                .is_some_and(r2source::SourceFunctionInterface::is_variadic),
            returns: returns(artifact, sealed),
            locals: locals(artifact, sealed, &entities),
            noreturn,
            refused: None,
        }
    }

    /// A function whose analysis refused: the walk's blocks, as `afb` lists them, and why.
    pub(crate) fn refused(
        entry: u64,
        walked: &[super::GraphBlock],
        noreturn: Option<std::collections::BTreeSet<r2source::Premise>>,
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
            locals: Vec::new(),
            returns: None,
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

/// Every block with bytes, the blocks a decided check or branch removed among them, and the instructions
/// whose spans start inside it.
fn blocks(artifact: &r2ssa::SsaArtifact) -> Vec<Block> {
    let function = artifact.function();
    let starts = artifact
        .obligations()
        .native_spans()
        .values()
        .map(|span| span.instruction_addr())
        .collect::<BTreeSet<_>>();
    let removed = (function.compiler_removed_edges().iter())
        .chain(function.decided_dead_edges())
        .copied()
        .collect::<BTreeSet<_>>();
    let block = |addr: u64, size: u32| {
        let edges = removed.range((addr, 0)..=(addr, u64::MAX)).count();
        Block {
            addr,
            size: u64::from(size),
            instructions: starts.range(addr..addr + u64::from(size)).count(),
            successors: function.successors(addr).len() + edges,
        }
    };
    let graph = (artifact.graph().blocks.iter()).map(|held| (held.addr, held.size));
    let gone = (function.compiler_inserted_blocks().iter()).chain(function.decided_dead_blocks());
    let mut blocks = (graph.chain(gone.map(|(addr, size)| (*addr, *size))))
        .filter(|(_, size)| *size > 0)
        .map(|(addr, size)| block(addr, size))
        .collect::<Vec<_>>();
    blocks.sort_unstable_by_key(|block| block.addr);
    blocks
}

/// Every certified parameter, typed as r2types declares that slot, else as storage of its width.
fn arguments(
    artifact: &r2ssa::SsaArtifact,
    sealed: &SourceOwnedFunctionFacts,
    entities: &[&CertifiedEntity],
) -> Vec<Argument> {
    let graph = artifact.graph();
    let mut arguments = entities
        .iter()
        .filter_map(|entity| {
            let CertifiedEntity::Parameter {
                slot,
                entry_values,
                carrier_width,
                ..
            } = entity
            else {
                return None;
            };
            // A declared lane of a wider register is a formal of its own, with its own storage.
            let storage = entry_values.iter().find_map(|value| {
                graph
                    .formal_projection_storage(*value)
                    .or(graph.value(*value)?.canonical_storage)
            });
            let width_bits = storage.map_or(*carrier_width, |storage| storage.size) * 8;
            Some(Argument {
                slot: *slot,
                storage,
                name: sealed
                    .report()
                    .display_names()
                    .parameter(*slot as usize)
                    .map(str::to_owned),
                ty: (sealed.parameter_declaration_fact(*slot as usize, width_bits))
                    .unwrap_or_else(|| carrier_typed(width_bits)),
            })
        })
        .collect::<Vec<_>>();
    // The interface owns arity: a formal the body never reads is still one of its parameters.
    let interface = artifact.machine_context().function_interface();
    for (slot, width_bytes) in sealed.interface_parameter_widths() {
        if arguments.iter().any(|argument| argument.slot == slot) {
            continue;
        }
        let width_bits = width_bytes * 8;
        let storage = interface
            .and_then(|interface| interface.parameters().iter().find(|p| p.index() == slot))
            .and_then(|parameter| parameter.register_storage());
        arguments.push(Argument {
            slot,
            storage,
            name: sealed
                .report()
                .display_names()
                .parameter(slot as usize)
                .map(str::to_owned),
            ty: (sealed.parameter_declaration_fact(slot as usize, width_bits))
                .unwrap_or_else(|| carrier_typed(width_bits)),
        });
    }
    arguments.sort_unstable_by_key(|argument| argument.slot);
    arguments
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

/// Every declarable stack object, and every frame slot promotion took out of memory: the frame
/// model `afv` lists for either pipeline.
fn locals(
    artifact: &r2ssa::SsaArtifact,
    sealed: &SourceOwnedFunctionFacts,
    entities: &[&CertifiedEntity],
) -> Vec<Local> {
    let objects = entities
        .iter()
        .filter_map(|entity| object(artifact, sealed, entity))
        .collect::<Vec<_>>();
    // A frame-management slot is no local: a slot promotion holds the value a return reads as its
    // return address in is that address's save (r2ssa's return boundary names the value).
    let graph = artifact.graph();
    let mut returns_to = r2ssa::dense::IdSet::new(graph.values.len());
    for boundary in artifact.facts().boundaries.returns.values() {
        if let Some(address) = &boundary.return_address {
            returns_to.insert(address.value);
        }
    }
    let saves_return_address = |value: r2ssa::ValueId| {
        matches!(
            graph.def_inst(value).and_then(|def| graph.inst(def)),
            Some(r2ssa::GraphInst {
                payload: r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { src, .. }),
                ..
            }) if returns_to.contains(*src)
        )
    };
    let held = objects
        .iter()
        .map(|local| local.offset)
        .collect::<BTreeSet<_>>();
    let promoted = graph
        .values
        .iter()
        .filter(|value| !saves_return_address(value.id))
        .filter_map(|value| value.canonical_storage)
        .filter_map(|storage| Some((r2ssa::promoted_slot_offset(&storage)?, storage.size)))
        .filter(|(offset, _)| !r2ssa::SsaArtifact::caller_frame_offset(*offset))
        .filter(|(offset, _)| !held.contains(offset))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(offset, bytes)| Local {
            name: r2ssa::frame_object_name(offset),
            base: StackBase::StackPointer,
            offset,
            ty: CTypeLike::machine_bits(bytes * 8).to_string(),
        });
    let mut locals = objects.into_iter().chain(promoted).collect::<Vec<_>>();
    locals.sort_by_key(|local| local.offset);
    locals
}

/// A stack object the rendering can declare, typed as declared or by its width.
fn object(
    artifact: &r2ssa::SsaArtifact,
    sealed: &SourceOwnedFunctionFacts,
    entity: &CertifiedEntity,
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
    })
}
