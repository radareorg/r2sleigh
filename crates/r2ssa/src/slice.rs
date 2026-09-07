//! Deterministic backward slices of canonical SSA and prepared memory versions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::semantic::memory_locations_may_alias;
use crate::{InstId, InstPayload, MemoryLocation, MemoryVersion, SsaArtifact, SsaGraph, ValueId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceSeed {
    Value(ValueId),
    Instruction(InstId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceError {
    InvalidValue(ValueId),
    InvalidInstruction(InstId),
    InvalidSyntax(String),
    NotFound(String),
    AmbiguousName {
        name: String,
        values: BTreeSet<ValueId>,
    },
}

impl fmt::Display for SliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(id) => write!(f, "value v{} is not in this artifact", id.0),
            Self::InvalidInstruction(id) => {
                write!(f, "instruction i{} is not in this artifact", id.0)
            }
            Self::InvalidSyntax(text) => write!(
                f,
                "invalid slice seed {text:?}; expected v123, an SSA name, or 0x4e3a:7"
            ),
            Self::NotFound(text) => {
                write!(f, "slice seed {text:?} does not resolve in this artifact")
            }
            Self::AmbiguousName { name, values } => {
                write!(f, "SSA name {name:?} is ambiguous: {values:?}")
            }
        }
    }
}

impl std::error::Error for SliceError {}

/// Resolve an exact displayed SSA name, decimal value id, or hexadecimal block:decimal-op site.
pub fn resolve_slice_seed(artifact: &SsaArtifact, text: &str) -> Result<SliceSeed, SliceError> {
    let text = text.trim();
    let graph = artifact.graph();
    if let Some(digits) = text.strip_prefix('v')
        && !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        let id = ValueId(
            digits
                .parse()
                .map_err(|_| SliceError::InvalidSyntax(text.into()))?,
        );
        return graph
            .value(id)
            .map(|_| SliceSeed::Value(id))
            .ok_or(SliceError::InvalidValue(id));
    }
    let values: BTreeSet<_> = graph
        .values
        .iter()
        .filter(|value| value.var.display_name() == text)
        .map(|value| value.id)
        .collect();
    if values.len() > 1 {
        return Err(SliceError::AmbiguousName {
            name: text.into(),
            values,
        });
    }
    if let Some(value) = values.first() {
        return Ok(SliceSeed::Value(*value));
    }
    if let Some(site) = text.strip_prefix("0x") {
        let (addr, op) = site
            .split_once(':')
            .ok_or_else(|| SliceError::InvalidSyntax(text.into()))?;
        let addr =
            u64::from_str_radix(addr, 16).map_err(|_| SliceError::InvalidSyntax(text.into()))?;
        let op = op
            .parse::<usize>()
            .map_err(|_| SliceError::InvalidSyntax(text.into()))?;
        return graph
            .inst_id_for_op_site(addr, op)
            .map(SliceSeed::Instruction)
            .ok_or_else(|| SliceError::NotFound(text.into()));
    }
    if text.is_empty() {
        return Err(SliceError::InvalidSyntax(text.into()));
    }
    Err(SliceError::NotFound(text.into()))
}

/// An owned diagnostic snapshot; obligations describe source requirements, not downstream refusal verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slice {
    lines: Vec<String>,
    pub error: Option<SliceError>,
}

impl fmt::Display for Slice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        if let Some(error) = &self.error {
            writeln!(f, "depth=0 error: {error}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Instruction(InstId),
    Entry(ValueId),
    Memory(MemoryVersion, MemoryLocation),
}

fn value_node(graph: &SsaGraph, value: ValueId) -> Node {
    graph
        .def_inst(value)
        .map(Node::Instruction)
        .unwrap_or(Node::Entry(value))
}

fn value_label(graph: &SsaGraph, value: ValueId) -> String {
    match graph.value(value) {
        Some(value) => format!("v{}({})", value.id.0, value.var),
        None => format!("v{}(missing-value)", value.0),
    }
}

/// Expand each instruction at most once, with ordered version indexes and a breadth-first frontier.
/// Cost is O((facts + visited edges) log(facts + values + instructions)), plus matching-version alias checks.
pub fn backward_slice(artifact: &SsaArtifact, seed: SliceSeed) -> Slice {
    let graph = artifact.graph();
    let mut slice = Slice {
        lines: Vec::new(),
        error: None,
    };
    let root = match seed {
        SliceSeed::Value(value) if graph.value(value).is_some() => value_node(graph, value),
        SliceSeed::Instruction(inst) if graph.inst(inst).is_some() => Node::Instruction(inst),
        SliceSeed::Value(value) => {
            slice.error = Some(SliceError::InvalidValue(value));
            return slice;
        }
        SliceSeed::Instruction(inst) => {
            slice.error = Some(SliceError::InvalidInstruction(inst));
            return slice;
        }
    };
    let facts = artifact.facts();
    let mut defs = BTreeMap::<_, BTreeSet<_>>::new();
    for (inst, definitions) in &facts.memory.defs_by_inst {
        for def in definitions {
            defs.entry(def.next_version)
                .or_default()
                .insert((*inst, &def.location));
        }
    }
    let mut phis = BTreeMap::<_, Vec<_>>::new();
    for (block, merges) in &facts.memory.phis_by_block {
        for phi in merges {
            phis.entry(phi.output_version)
                .or_default()
                .push((*block, phi));
        }
    }
    let mut pending = BTreeSet::from([(0usize, root.clone())]);
    let mut discovered = BTreeSet::from([root]);
    let mut expanded_instructions = 0;
    while let Some((depth, node)) = pending.pop_first() {
        let mut dependencies = BTreeSet::new();
        let detail =
            match node {
                Node::Instruction(id) => {
                    if expanded_instructions >= graph.insts.len() {
                        slice
                            .lines
                            .push(format!("depth={depth} instruction-budget-exhausted"));
                        break;
                    }
                    expanded_instructions += 1;
                    let Some(inst) = graph.inst(id) else {
                        slice.error = Some(SliceError::InvalidInstruction(id));
                        break;
                    };
                    dependencies.extend(inst.inputs.iter().map(|value| value_node(graph, *value)));
                    if let Some(uses) = facts.memory.uses_by_inst.get(&id) {
                        dependencies.extend(uses.iter().map(|use_fact| {
                            Node::Memory(use_fact.version, use_fact.location.clone())
                        }));
                    }
                    render_instruction(artifact, id)
                }
                Node::Entry(value) => format!(
                    "entry {} (no defining instruction)",
                    value_label(graph, value)
                ),
                Node::Memory(version, location) => {
                    for (inst, definition) in defs.get(&version).into_iter().flatten() {
                        if memory_locations_may_alias(&facts.objects, &location, definition) {
                            dependencies.insert(Node::Instruction(*inst));
                        }
                    }
                    let mut merge_sites = BTreeSet::new();
                    for (block, phi) in phis.get(&version).into_iter().flatten() {
                        if memory_locations_may_alias(&facts.objects, &location, &phi.location) {
                            merge_sites.insert(format!("0x{block:x}"));
                            dependencies.extend(
                                phi.inputs
                                    .iter()
                                    .map(|(_, input)| Node::Memory(*input, location.clone())),
                            );
                        }
                    }
                    let cause = if !merge_sites.is_empty() {
                        format!(
                            "phi=[{}]",
                            merge_sites.into_iter().collect::<Vec<_>>().join(", ")
                        )
                    } else if !dependencies.is_empty() {
                        "reaching-definition".into()
                    } else if version.version == 0 {
                        "entry-memory (no defining instruction)".into()
                    } else {
                        "unresolved-memory (no aliasing definition or phi for version)".into()
                    };
                    format!(
                        "memory object={:?} version={} location={location:?} {cause}",
                        version.object, version.version
                    )
                }
            };
        slice.lines.push(format!("depth={depth} {detail}"));
        for dependency in dependencies {
            if discovered.insert(dependency.clone()) {
                pending.insert((depth + 1, dependency));
            }
        }
    }
    slice
}

fn operation_kind(op: &crate::SSAOp) -> &'static str {
    macro_rules! kinds {
        ($($kind:ident),* $(,)?) => {
            match op {
                $(crate::SSAOp::$kind { .. } => stringify!($kind),)*
                crate::SSAOp::Nop => "Nop",
                crate::SSAOp::Unimplemented => "Unimplemented",
                crate::SSAOp::Breakpoint => "Breakpoint",
            }
        };
    }
    kinds!(
        Phi,
        Copy,
        Load,
        Store,
        Fence,
        LoadLinked,
        StoreConditional,
        AtomicCAS,
        LoadGuarded,
        StoreGuarded,
        IntAdd,
        IntSub,
        IntMult,
        IntDiv,
        IntSDiv,
        IntRem,
        IntSRem,
        IntNegate,
        IntCarry,
        IntSCarry,
        IntSBorrow,
        IntAnd,
        IntOr,
        IntXor,
        IntNot,
        IntLeft,
        IntRight,
        IntSRight,
        IntEqual,
        IntNotEqual,
        IntLess,
        IntSLess,
        IntLessEqual,
        IntSLessEqual,
        IntZExt,
        IntSExt,
        BoolNot,
        BoolAnd,
        BoolOr,
        BoolXor,
        Piece,
        Subpiece,
        PopCount,
        Lzcount,
        Branch,
        CBranch,
        BranchInd,
        Call,
        CallInd,
        CallDefine,
        CallRestore,
        Return,
        FloatAdd,
        FloatSub,
        FloatMult,
        FloatDiv,
        FloatNeg,
        FloatAbs,
        FloatSqrt,
        FloatCeil,
        FloatFloor,
        FloatRound,
        FloatNaN,
        FloatEqual,
        FloatNotEqual,
        FloatLess,
        FloatLessEqual,
        Int2Float,
        Float2Int,
        FloatFloat,
        Trunc,
        CallOther,
        CpuId,
        PtrAdd,
        PtrSub,
        SegmentOp,
        New,
        Cast,
        Extract,
        Insert,
        Select,
    )
}

fn render_instruction(artifact: &SsaArtifact, id: InstId) -> String {
    let graph = artifact.graph();
    let Some(inst) = graph.inst(id) else {
        return format!("i{} missing-instruction", id.0);
    };
    let site = match graph.op_site_for_inst(id) {
        Some((block, op)) => format!("0x{block:x}:{op}"),
        None => match graph.block(inst.block) {
            Some(block) => format!("0x{:x}:phi:{}", block.addr, inst.ordinal),
            None => "missing-block".into(),
        },
    };
    let operation = match &inst.payload {
        InstPayload::Phi { .. } => "PHI".into(),
        InstPayload::Op(op) => format!("{}: {op}", operation_kind(op)),
    };
    let output = inst
        .output
        .map(|value| value_label(graph, value))
        .unwrap_or_else(|| "-".into());
    let inputs = inst
        .inputs
        .iter()
        .map(|value| value_label(graph, *value))
        .collect::<Vec<_>>()
        .join(", ");
    let obligations = artifact
        .obligations()
        .obligations_for_inst(id)
        .map(|obligation| obligation.id.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut memory = BTreeSet::new();
    let start = crate::StructuredAccessId {
        inst: id,
        ordinal: 0,
    };
    let end = crate::StructuredAccessId {
        inst: id,
        ordinal: u32::MAX,
    };
    for (_, access) in artifact.structured().memory_accesses.range(start..=end) {
        memory.insert(format!(
            "object={:?} address={} indexed={} write={}",
            access.object,
            value_label(graph, access.address),
            artifact.facts().objects.address_is_indexed(access.address),
            access.is_write
        ));
    }
    format!(
        "{site} i{} op=[{operation}] output={output} inputs=[{inputs}] obligations=[{obligations}] memory=[{}]",
        id.0,
        memory.into_iter().collect::<Vec<_>>().join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn copy_artifact() -> Result<SsaArtifact, Box<dyn std::error::Error>> {
        let mut arch = ArchSpec::new("slice");
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.add_register(RegisterDef::new("RBX", 8, 8));
        arch.add_register(RegisterDef::new("RCX", 16, 8));
        let mut block = R2ILBlock::new(0x1000, 4);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(8, 8),
            src: Varnode::register(0, 8),
        });
        block.push(R2ILOp::Copy {
            dst: Varnode::register(16, 8),
            src: Varnode::register(8, 8),
        });
        SsaArtifact::raw(&[block], Some(&arch))
            .ok_or_else(|| "copy artifact preparation failed".into())
    }

    #[test]
    fn slice_register_copy_chain() -> TestResult {
        let artifact = copy_artifact()?;
        let seed = resolve_slice_seed(&artifact, "0x1000:1")?;
        let slice = backward_slice(&artifact, seed);
        let text = slice.to_string();
        assert!(slice.error.is_none());
        assert_eq!(text.lines().count(), 3);
        assert!(
            text.lines()
                .next()
                .is_some_and(|line| line.starts_with("depth=0 0x1000:1"))
        );
        assert!(
            text.lines()
                .nth(1)
                .is_some_and(|line| line.starts_with("depth=1 0x1000:0"))
        );
        assert!(
            text.lines()
                .nth(2)
                .is_some_and(|line| line.starts_with("depth=2 entry") && line.contains("RAX_0"))
        );
        assert_eq!(text, backward_slice(&artifact, seed).to_string());
        assert_eq!(text, backward_slice(&copy_artifact()?, seed).to_string());
        println!("{text}");
        Ok(())
    }

    #[test]
    fn slice_store_and_reload() -> TestResult {
        let mut block = R2ILBlock::new(0x2000, 4);
        block.push(R2ILOp::Store {
            space: SpaceId::Ram,
            addr: Varnode::constant(0x4000, 8),
            val: Varnode::register(0, 8),
        });
        block.push(R2ILOp::Load {
            dst: Varnode::register(8, 8),
            space: SpaceId::Ram,
            addr: Varnode::constant(0x4000, 8),
        });
        let artifact =
            SsaArtifact::raw(&[block], None).ok_or("memory artifact preparation failed")?;
        let slice = backward_slice(&artifact, resolve_slice_seed(&artifact, "0x2000:1")?);
        let text = slice.to_string();
        assert!(slice.error.is_none());
        assert!(text.contains("depth=0 0x2000:1"));
        assert!(text.contains("depth=2 0x2000:0"));
        assert!(text.contains("reaching-definition"));
        assert!(text.contains("memory-read"));
        assert!(text.contains("memory-write"));
        assert!(text.contains("indexed=false"));
        assert!(text.contains("object=ObjectId("));
        assert!(text.contains("entry") && text.contains("reg:0_0"));
        Ok(())
    }

    #[test]
    fn slice_terminates_at_entry_value() -> TestResult {
        let artifact = copy_artifact()?;
        let seed = resolve_slice_seed(&artifact, "RAX_0")?;
        let SliceSeed::Value(value) = seed else {
            return Err("name did not resolve to value".into());
        };
        assert_eq!(
            resolve_slice_seed(&artifact, &format!("v{}", value.0))?,
            seed
        );
        let text = backward_slice(&artifact, seed).to_string();
        assert_eq!(
            text,
            format!(
                "depth=0 entry v{}(RAX_0) (no defining instruction)\n",
                value.0
            )
        );
        Ok(())
    }

    #[test]
    fn slice_rejects_unresolved_seeds() -> TestResult {
        let artifact = copy_artifact()?;
        for text in ["", "0x1000:no", "0x1000:999", "RAX_999", "v4294967296"] {
            assert!(resolve_slice_seed(&artifact, text).is_err(), "{text}");
        }
        assert_eq!(
            resolve_slice_seed(&artifact, "v4294967295"),
            Err(SliceError::InvalidValue(ValueId(u32::MAX)))
        );
        let invalid = backward_slice(&artifact, SliceSeed::Instruction(InstId(u32::MAX)));
        assert_eq!(
            invalid.error,
            Some(SliceError::InvalidInstruction(InstId(u32::MAX)))
        );
        assert!(invalid.to_string().contains("not in this artifact"));
        Ok(())
    }

    #[test]
    fn slice_phi_inputs_and_cycle_are_bounded() -> TestResult {
        let accumulator = Varnode::register(0, 8);
        let mut entry = R2ILBlock::new(0x3000, 4);
        entry.push(R2ILOp::Copy {
            dst: accumulator.clone(),
            src: Varnode::constant(0, 8),
        });
        entry.push(R2ILOp::Branch {
            target: Varnode::ram(0x3010, 8),
        });
        let mut header = R2ILBlock::new(0x3010, 4);
        header.push(R2ILOp::CBranch {
            target: Varnode::ram(0x3020, 8),
            cond: Varnode::register(16, 1),
        });
        let mut exit = R2ILBlock::new(0x3014, 4);
        exit.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let mut latch = R2ILBlock::new(0x3020, 4);
        latch.push(R2ILOp::IntAdd {
            dst: accumulator.clone(),
            a: accumulator,
            b: Varnode::constant(1, 8),
        });
        latch.push(R2ILOp::Branch {
            target: Varnode::ram(0x3010, 8),
        });
        let artifact = SsaArtifact::raw(&[entry, header, exit, latch], None)
            .ok_or("loop artifact preparation failed")?;
        let phi = artifact
            .graph()
            .insts
            .iter()
            .find(|inst| matches!(inst.payload, InstPayload::Phi { .. }))
            .ok_or("fixture needs a phi")?;
        assert_eq!(phi.inputs.len(), 2);
        let slice = backward_slice(&artifact, SliceSeed::Instruction(phi.id));
        let text = slice.to_string();
        assert!(slice.error.is_none());
        assert_eq!(text.matches("op=[PHI]").count(), 1);
        assert!(text.contains("depth=1 0x3000:0"));
        assert!(text.contains("depth=1 0x3020:0"));
        for input in &phi.inputs {
            assert!(text.contains(&format!("output={}", value_label(artifact.graph(), *input))));
        }
        assert!(!text.contains("budget-exhausted"));
        assert!(
            text.lines().count() <= artifact.graph().insts.len() + artifact.graph().values.len()
        );
        Ok(())
    }

    #[test]
    fn slice_memory_phi_reaches_both_stores() -> TestResult {
        let mut entry = R2ILBlock::new(0x4000, 4);
        entry.push(R2ILOp::CBranch {
            target: Varnode::ram(0x4010, 8),
            cond: Varnode::register(16, 1),
        });
        let arm = |addr, value| {
            let mut block = R2ILBlock::new(addr, 4);
            block.push(R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::constant(0x8000, 8),
                val: Varnode::constant(value, 8),
            });
            block.push(R2ILOp::Branch {
                target: Varnode::ram(0x4020, 8),
            });
            block
        };
        let mut merge = R2ILBlock::new(0x4020, 4);
        merge.push(R2ILOp::Load {
            dst: Varnode::register(0, 8),
            space: SpaceId::Ram,
            addr: Varnode::constant(0x8000, 8),
        });
        let artifact = SsaArtifact::raw(&[entry, arm(0x4004, 1), arm(0x4010, 2), merge], None)
            .ok_or("memory phi artifact preparation failed")?;
        assert!(!artifact.facts().memory.phis_by_block.is_empty());
        let seed = resolve_slice_seed(&artifact, "0x4020:0")?;
        let slice = backward_slice(&artifact, seed);
        let text = slice.to_string();
        assert!(slice.error.is_none());
        assert!(text.contains("phi=[0x4020]"));
        assert!(text.contains("depth=3 0x4004:0"));
        assert!(text.contains("depth=3 0x4010:0"));
        assert_eq!(text, backward_slice(&artifact, seed).to_string());
        Ok(())
    }
}
