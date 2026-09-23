//! What one function is, read off the analysis that renders it.
//!
//! Nothing here is analysed afresh: the blocks and instructions are the
//! prepared artifact's, the calls are its call-site certificates, and the
//! arguments and locals are the type analysis's certified entities. A number
//! radare2 prints that none of these proves is left for the shell to omit.

use std::collections::BTreeSet;

use r2types::{CTypeLike, CertifiedEntity, FunctionFacts};

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
    pub locals: Vec<Local>,
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
    pub ty: CTypeLike,
}

/// One stack object in the function's own frame, frame management excluded.
#[derive(Debug, Clone, PartialEq)]
pub struct Local {
    pub base: StackBase,
    pub offset: i64,
    /// The declared type, or else storage of the width its accesses agree on.
    pub ty: CTypeLike,
}

impl FunctionInfo {
    /// Read one prepared function and the type analysis made of it.
    pub(crate) fn read(entry: u64, artifact: &r2ssa::SsaArtifact, facts: &FunctionFacts) -> Self {
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
            arguments: arguments(artifact, facts, &entities),
            locals: locals(artifact, &entities),
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

/// Every block with bytes, and the instructions whose spans start inside it.
fn blocks(artifact: &r2ssa::SsaArtifact) -> Vec<Block> {
    let function = artifact.function();
    let starts = artifact
        .obligations()
        .native_spans()
        .values()
        .map(|span| span.instruction_addr())
        .collect::<BTreeSet<_>>();
    let mut blocks = function
        .blocks()
        .iter()
        .filter(|block| block.size > 0)
        .map(|block| {
            let end = block.addr + u64::from(block.size);
            Block {
                addr: block.addr,
                size: u64::from(block.size),
                instructions: starts.range(block.addr..end).count(),
                successors: function.successors(block.addr).len(),
            }
        })
        .collect::<Vec<_>>();
    blocks.sort_unstable_by_key(|block| block.addr);
    blocks
}

/// Every certified parameter, typed as the declaration, the signature, or its carrier says.
fn arguments(
    artifact: &r2ssa::SsaArtifact,
    facts: &FunctionFacts,
    entities: &[&CertifiedEntity],
) -> Vec<Argument> {
    let signature = facts.type_facts().render_authorized_signature();
    let graph = artifact.graph();
    let mut arguments = entities
        .iter()
        .filter_map(|entity| {
            let CertifiedEntity::Parameter {
                slot,
                entry_values,
                carrier_width,
                ty,
                ..
            } = entity
            else {
                return None;
            };
            let signed = signature
                .and_then(|signature| signature.params.get(*slot as usize))
                .and_then(|param| param.ty.clone());
            // A declared lane of a wider register is a formal of its own, with its own storage.
            let storage = entry_values.iter().find_map(|value| {
                graph
                    .formal_projection_storage(*value)
                    .or(graph.value(*value)?.canonical_storage)
            });
            Some(Argument {
                slot: *slot,
                storage,
                ty: ty
                    .clone()
                    .or(signed)
                    .unwrap_or_else(|| CTypeLike::machine_bits(*carrier_width)),
            })
        })
        .collect::<Vec<_>>();
    arguments.sort_unstable_by_key(|argument| argument.slot);
    arguments
}

/// Every declarable stack object, and every frame slot promotion took out of memory.
fn locals(artifact: &r2ssa::SsaArtifact, entities: &[&CertifiedEntity]) -> Vec<Local> {
    let objects = entities
        .iter()
        .filter_map(|entity| object(artifact, entity));
    let promoted = artifact
        .graph()
        .values
        .iter()
        .filter_map(|value| value.canonical_storage)
        .filter_map(|storage| Some((r2ssa::promoted_slot_offset(&storage)?, storage.size)))
        .filter(|(offset, _)| !r2ssa::SsaArtifact::caller_frame_offset(*offset))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(offset, bytes)| Local {
            base: StackBase::StackPointer,
            offset,
            ty: CTypeLike::machine_bits(bytes * 8),
        });
    let mut locals = objects.chain(promoted).collect::<Vec<_>>();
    locals.sort_by_key(|local| local.offset);
    locals
}

/// A stack object the rendering can declare, typed as declared or by its width.
fn object(artifact: &r2ssa::SsaArtifact, entity: &CertifiedEntity) -> Option<Local> {
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
        base: *base,
        offset: *offset,
        ty: ty.clone().unwrap_or(storage),
    })
}
