//! Interprocedural semantic summaries built on top of prepared SSA.
//!
//! This layer stays summary-based on purpose. It reuses the canonical
//! intraprocedural facts in [`SsaArtifact`] and solves a deterministic
//! fixpoint over direct-call reachable functions without introducing a second
//! whole-program SSA graph.

mod dependence;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2il::{ArchSpec, MemoryOrdering, SpaceId};
use serde::{Deserialize, Serialize};

use crate::abi::AbiProfile;
use crate::function::SsaArtifact;
use crate::graph::{InstPayload, UseSite, ValueId};
use crate::op::SSAOp;
use crate::semantic::ObjectKind;
use crate::{CallSiteId, SSAVar};

/// Current serialized interprocedural report schema.
///
/// Version 1 denotes the historical unversioned encoding. Version 2 is the
/// first encoding that carries and mirrors an explicit schema stamp at both
/// the report-set and per-function levels.
pub const INTERPROC_SUMMARY_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterprocSummarySchemaError {
    ReportSchemaVersion {
        found: u32,
    },
    FunctionSchemaVersion {
        id: InterprocFunctionId,
        found: u32,
    },
    FunctionIdentityMismatch {
        key: InterprocFunctionId,
        summary_id: InterprocFunctionId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InterprocFunctionId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummaryMemoryEffectKind {
    Read,
    Write,
    Escape,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummaryMemoryRegion {
    Arg { index: usize },
    Global { address: u64 },
    HeapReturn,
    Unknown,
}

/// How far a callee reaches through one pointer argument.
///
/// A constant reach is a span the caller can use as it stands. A scaled reach
/// is one the callee states per index -- `base + stride * <its own argument>`
/// -- and only the caller knows how far the index goes, so it is carried in
/// this form until a call site can multiply it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummaryArgumentReach {
    Bytes(u64),
    Scaled {
        argument: usize,
        stride: i64,
        base: i64,
        width: u32,
    },
}

impl SummaryArgumentReach {
    /// The bytes this reaches when the scaling argument runs up to `bound`.
    pub fn bytes(self, mut bound: impl FnMut(usize) -> Option<u64>) -> Option<u64> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::Scaled {
                argument,
                stride,
                base,
                width,
            } => {
                // The last index reaches `stride * bound`, and the element
                // there occupies `width` bytes, so that is where the object
                // ends. Counting `bound + 1` elements and adding the width on
                // top of them measures one element too many.
                let last = stride.checked_mul(i64::try_from(bound(argument)?).ok()?)?;
                u64::try_from(base.checked_add(last)?.checked_add(i64::from(width))?).ok()
            }
        }
    }
}

/// An offset that grows with one of the callee's own arguments.
///
/// `indirect_load(base, index)` reads at `base + 8 * index`. The stride is a
/// fact about the callee and nothing about the caller decides it; how far the
/// read actually goes is a fact about the caller, which knows what it passed
/// for `index`. Carrying the stride is what lets the two be multiplied at the
/// call site: without it the reach is only "somewhere through argument 0",
/// which sizes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryScaledOffset {
    /// Which of the callee's arguments the offset scales with.
    pub argument: usize,
    pub stride: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryMemoryRange {
    pub offset_lo: i64,
    pub offset_hi: i64,
    pub width: Option<u32>,
    /// Set when the offset is not constant but affine in an argument.
    pub scaled_by: Option<SummaryScaledOffset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryMemoryLocation {
    pub region: SummaryMemoryRegion,
    pub range: Option<SummaryMemoryRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryMemoryEffect {
    pub kind: SummaryMemoryEffectKind,
    pub location: SummaryMemoryLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummaryTransferLength {
    Arg(usize),
    Const(u64),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryTransferEffect {
    pub dst: SummaryMemoryLocation,
    pub src: SummaryMemoryLocation,
    pub len: SummaryTransferLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryAllocationEffect {
    pub size_arg: Option<usize>,
    pub zeroed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummaryLifetimeOp {
    Free,
    Retain,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryLifetimeEffect {
    pub arg: usize,
    pub op: SummaryLifetimeOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummarySyncOp {
    Lock,
    Unlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummarySyncEffect {
    pub arg: usize,
    pub op: SummarySyncOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummaryAtomicOp {
    LoadLinked,
    StoreConditional,
    CompareExchange,
    Fence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SummaryAtomicOrdering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SummaryAtomicEffect {
    pub op: SummaryAtomicOp,
    pub location: SummaryMemoryLocation,
    pub ordering: SummaryAtomicOrdering,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryArgEffect {
    pub read: bool,
    pub write: bool,
    pub escape: bool,
    pub free: bool,
}

impl SummaryArgEffect {
    fn merge_from(&mut self, other: &Self) -> bool {
        let before = self.clone();
        self.read |= other.read;
        self.write |= other.write;
        self.escape |= other.escape;
        self.free |= other.free;
        *self != before
    }

    fn mark_read(&mut self) {
        self.read = true;
    }

    fn mark_write(&mut self) {
        self.write = true;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SummaryReturnRelation {
    Unknown,
    Void,
    Arg(usize),
    Const(u64),
    HeapAlloc,
    Global(u64),
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum FunctionSemanticLinkage {
    #[default]
    Unknown,
    Internal,
    Imported,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSemanticSummary {
    pub schema_version: u32,
    pub id: InterprocFunctionId,
    pub name: Option<String>,
    pub linkage: FunctionSemanticLinkage,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub arg_count_hint: Option<usize>,
    pub direct_callees: BTreeSet<u64>,
    pub callsite_count: usize,
    pub has_unknown_calls: bool,
    pub arg_effects: BTreeMap<usize, SummaryArgEffect>,
    pub memory_effects: Vec<SummaryMemoryEffect>,
    pub transfer_effects: Vec<SummaryTransferEffect>,
    pub allocation_effects: Vec<SummaryAllocationEffect>,
    pub lifetime_effects: Vec<SummaryLifetimeEffect>,
    pub sync_effects: Vec<SummarySyncEffect>,
    pub atomic_effects: Vec<SummaryAtomicEffect>,
    pub return_relation: SummaryReturnRelation,
    pub reads_global_memory: bool,
    pub writes_global_memory: bool,
    pub touches_unknown_memory: bool,
}

impl FunctionSemanticSummary {
    /// Whether this report uses the current non-authoritative wire schema.
    pub const fn has_current_schema(&self) -> bool {
        self.schema_version == INTERPROC_SUMMARY_SCHEMA_VERSION
    }

    pub fn unknown(id: InterprocFunctionId, name: Option<String>) -> Self {
        Self {
            schema_version: INTERPROC_SUMMARY_SCHEMA_VERSION,
            id,
            name,
            linkage: FunctionSemanticLinkage::Unknown,
            arg_count_hint: None,
            direct_callees: BTreeSet::new(),
            callsite_count: 0,
            has_unknown_calls: false,
            arg_effects: BTreeMap::new(),
            memory_effects: Vec::new(),
            transfer_effects: Vec::new(),
            allocation_effects: Vec::new(),
            lifetime_effects: Vec::new(),
            sync_effects: Vec::new(),
            atomic_effects: Vec::new(),
            return_relation: SummaryReturnRelation::Unknown,
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        }
    }

    /// The seed for a bodiless callee named bare or marked. The names table
    /// spells an import bare; having no body is the externality the seed
    /// table asks the name to carry.
    pub(crate) fn seed_for_callee_name(id: InterprocFunctionId, name: &str) -> Option<Self> {
        if name.contains("imp.") || name.contains("reloc.") {
            Self::seed_for_name(id, name)
        } else {
            Self::seed_for_name(id, &format!("sym.imp.{name}"))
        }
    }

    fn seed_for_name(id: InterprocFunctionId, name: &str) -> Option<Self> {
        let normalized = normalize_seed_name(name)?;
        // The normalized spelling selects the model; it does not rename the
        // callee. `_Exit` is not `exit`, and a rendering that says so names a
        // function the program does not call.
        let called = import_basename(name).to_owned();
        let mut arg_effects = BTreeMap::new();
        let mut effect = |idx: usize, read: bool, write: bool, escape: bool, free: bool| {
            arg_effects.insert(
                idx,
                SummaryArgEffect {
                    read,
                    write,
                    escape,
                    free,
                },
            );
        };
        let mut memory_effects = Vec::new();
        let mut transfer_effects = Vec::new();
        let mut allocation_effects = Vec::new();
        let mut lifetime_effects = Vec::new();
        let mut sync_effects = Vec::new();
        let atomic_effects = Vec::new();

        let return_relation = match normalized {
            "malloc" => {
                effect(0, true, false, false, false);
                allocation_effects.push(SummaryAllocationEffect {
                    size_arg: Some(0),
                    zeroed: false,
                });
                SummaryReturnRelation::HeapAlloc
            }
            "calloc" => {
                effect(0, true, false, false, false);
                effect(1, true, false, false, false);
                allocation_effects.push(SummaryAllocationEffect {
                    size_arg: Some(1),
                    zeroed: true,
                });
                SummaryReturnRelation::HeapAlloc
            }
            "free" => {
                effect(0, false, false, true, true);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Free,
                    location: arg_location(0, None, None),
                });
                lifetime_effects.push(SummaryLifetimeEffect {
                    arg: 0,
                    op: SummaryLifetimeOp::Free,
                });
                SummaryReturnRelation::Void
            }
            "memcpy" | "memmove" => {
                effect(0, false, true, true, false);
                effect(1, true, false, false, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Write,
                    location: arg_location(0, None, None),
                });
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Read,
                    location: arg_location(1, None, None),
                });
                transfer_effects.push(SummaryTransferEffect {
                    dst: arg_location(0, None, None),
                    src: arg_location(1, None, None),
                    len: SummaryTransferLength::Arg(2),
                });
                SummaryReturnRelation::Arg(0)
            }
            "copyin" | "copyout" => {
                effect(0, true, false, false, false);
                effect(1, false, true, true, false);
                effect(2, true, false, false, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Read,
                    location: arg_location(0, None, None),
                });
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Write,
                    location: arg_location(1, None, None),
                });
                transfer_effects.push(SummaryTransferEffect {
                    dst: arg_location(1, None, None),
                    src: arg_location(0, None, None),
                    len: SummaryTransferLength::Arg(2),
                });
                SummaryReturnRelation::Unknown
            }
            "memset" => {
                effect(0, false, true, true, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Write,
                    location: arg_location(0, None, None),
                });
                transfer_effects.push(SummaryTransferEffect {
                    dst: arg_location(0, None, None),
                    src: SummaryMemoryLocation {
                        region: SummaryMemoryRegion::Unknown,
                        range: None,
                    },
                    len: SummaryTransferLength::Arg(2),
                });
                SummaryReturnRelation::Arg(0)
            }
            // The `n`-bounded writers: at most `n` bytes land in the destination.
            "snprintf" | "vsnprintf" => {
                effect(0, false, true, true, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Write,
                    location: arg_location(0, None, None),
                });
                transfer_effects.push(SummaryTransferEffect {
                    dst: arg_location(0, None, None),
                    src: SummaryMemoryLocation {
                        region: SummaryMemoryRegion::Unknown,
                        range: None,
                    },
                    len: SummaryTransferLength::Arg(1),
                });
                SummaryReturnRelation::Unknown
            }
            // `__snprintf_chk(s, maxlen, flag, slen, format, ...)` on glibc and
            // Apple alike: the write is bounded by `maxlen`; `slen` is the
            // object size the check compares it against.
            "snprintf_chk" => {
                effect(0, false, true, true, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Write,
                    location: arg_location(0, None, None),
                });
                transfer_effects.push(SummaryTransferEffect {
                    dst: arg_location(0, None, None),
                    src: SummaryMemoryLocation {
                        region: SummaryMemoryRegion::Unknown,
                        range: None,
                    },
                    len: SummaryTransferLength::Arg(1),
                });
                SummaryReturnRelation::Unknown
            }
            "strncpy" => {
                effect(0, false, true, true, false);
                effect(1, true, false, false, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Write,
                    location: arg_location(0, None, None),
                });
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Read,
                    location: arg_location(1, None, None),
                });
                transfer_effects.push(SummaryTransferEffect {
                    dst: arg_location(0, None, None),
                    src: arg_location(1, None, None),
                    len: SummaryTransferLength::Arg(2),
                });
                SummaryReturnRelation::Arg(0)
            }
            "strlen" => {
                effect(0, true, false, false, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Read,
                    location: arg_location(0, None, None),
                });
                SummaryReturnRelation::Unknown
            }
            "strcmp" | "memcmp" => {
                effect(0, true, false, false, false);
                effect(1, true, false, false, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Read,
                    location: arg_location(0, None, None),
                });
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Read,
                    location: arg_location(1, None, None),
                });
                SummaryReturnRelation::Unknown
            }
            "puts" | "printf" => {
                effect(0, true, false, false, false);
                memory_effects.push(SummaryMemoryEffect {
                    kind: SummaryMemoryEffectKind::Read,
                    location: arg_location(0, None, None),
                });
                SummaryReturnRelation::Unknown
            }
            "retain" => {
                effect(0, true, false, true, false);
                lifetime_effects.push(SummaryLifetimeEffect {
                    arg: 0,
                    op: SummaryLifetimeOp::Retain,
                });
                SummaryReturnRelation::Arg(0)
            }
            "release" => {
                effect(0, false, false, true, false);
                lifetime_effects.push(SummaryLifetimeEffect {
                    arg: 0,
                    op: SummaryLifetimeOp::Release,
                });
                SummaryReturnRelation::Void
            }
            "lock" => {
                effect(0, false, false, true, false);
                sync_effects.push(SummarySyncEffect {
                    arg: 0,
                    op: SummarySyncOp::Lock,
                });
                SummaryReturnRelation::Void
            }
            "unlock" => {
                effect(0, false, false, true, false);
                sync_effects.push(SummarySyncEffect {
                    arg: 0,
                    op: SummarySyncOp::Unlock,
                });
                SummaryReturnRelation::Void
            }
            "exit" => SummaryReturnRelation::Void,
            _ => return None,
        };

        Some(Self {
            schema_version: INTERPROC_SUMMARY_SCHEMA_VERSION,
            id,
            name: Some(called),
            linkage: FunctionSemanticLinkage::Unknown,
            arg_count_hint: Some(match normalized {
                "malloc" | "free" | "strlen" | "puts" | "printf" | "exit" | "retain"
                | "release" | "lock" | "unlock" => 1,
                "calloc" => 2,
                "strcmp" | "memcmp" => 2,
                "memcpy" | "memmove" | "copyin" | "copyout" | "memset" | "strncpy" | "snprintf"
                | "vsnprintf" => 3,
                "snprintf_chk" => 5,
                _ => 0,
            }),
            direct_callees: BTreeSet::new(),
            callsite_count: 0,
            has_unknown_calls: false,
            arg_effects,
            memory_effects,
            transfer_effects,
            allocation_effects,
            lifetime_effects,
            sync_effects,
            atomic_effects,
            return_relation,
            reads_global_memory: false,
            writes_global_memory: false,
            touches_unknown_memory: false,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterprocSummaryDiagnostics {
    pub iterations: usize,
    pub max_iterations: usize,
    pub converged: bool,
    pub scope_size: usize,
    pub scc_count: usize,
    pub max_scc_size: usize,
}

/// Serializable interprocedural report data.
///
/// This value does not retain an SSA owner and therefore is not authority for
/// type facts or certification. Consumers that need source-owned evidence
/// must use [`PreparedInterprocSummarySet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterprocSummarySet {
    pub schema_version: u32,
    pub root: Option<InterprocFunctionId>,
    pub summaries: BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
    pub diagnostics: InterprocSummaryDiagnostics,
}

impl Default for InterprocSummarySet {
    fn default() -> Self {
        Self {
            schema_version: INTERPROC_SUMMARY_SCHEMA_VERSION,
            root: None,
            summaries: BTreeMap::new(),
            diagnostics: InterprocSummaryDiagnostics::default(),
        }
    }
}

impl InterprocSummarySet {
    /// Validate the complete report projection against the current wire
    /// schema. This never upgrades or normalizes older report data.
    pub fn validate_current_schema(&self) -> Result<(), InterprocSummarySchemaError> {
        if self.schema_version != INTERPROC_SUMMARY_SCHEMA_VERSION {
            return Err(InterprocSummarySchemaError::ReportSchemaVersion {
                found: self.schema_version,
            });
        }
        validate_function_summary_map(&self.summaries)
    }

    /// Validate the complete report projection against the current wire
    /// schema, including each nested function summary and its map identity.
    pub fn has_current_schema(&self) -> bool {
        self.validate_current_schema().is_ok()
    }
}

fn validate_function_summary_map(
    summaries: &BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) -> Result<(), InterprocSummarySchemaError> {
    for (key, summary) in summaries {
        if summary.schema_version != INTERPROC_SUMMARY_SCHEMA_VERSION {
            return Err(InterprocSummarySchemaError::FunctionSchemaVersion {
                id: *key,
                found: summary.schema_version,
            });
        }
        if *key != summary.id {
            return Err(InterprocSummarySchemaError::FunctionIdentityMismatch {
                key: *key,
                summary_id: summary.id,
            });
        }
    }
    Ok(())
}

/// Source-owned interprocedural evidence sealed to one exact SSA allocation.
///
/// The private fields deliberately prevent promoting a serialized
/// [`InterprocSummarySet`] back into authoritative evidence.
#[derive(Debug, Clone)]
pub struct PreparedInterprocSummarySet {
    root: InterprocFunctionId,
    owners: BTreeMap<InterprocFunctionId, Arc<SsaArtifact>>,
    /// Every function this evidence was derived from a body for, whether or
    /// not that body's allocation is still retained. Retention is a memory
    /// decision; which functions contributed evidence is a fact about the
    /// evidence, and a consumer asking "was there a body for this callee"
    /// is asking the second question.
    bodies: BTreeSet<InterprocFunctionId>,
    report: InterprocSummarySet,
}

impl PreparedInterprocSummarySet {
    /// Borrow the exact immutable SSA owner used to produce this evidence.
    pub fn root(&self) -> &Arc<SsaArtifact> {
        self.owners
            .get(&self.root)
            .expect("prepared interproc root owner is retained")
    }

    /// Borrow every exact immutable SSA owner used to produce this evidence.
    pub fn owners(&self) -> &BTreeMap<InterprocFunctionId, Arc<SsaArtifact>> {
        &self.owners
    }

    /// Borrow one exact immutable SSA owner by its function identity.
    pub fn owner(&self, id: InterprocFunctionId) -> Option<&Arc<SsaArtifact>> {
        self.owners.get(&id)
    }

    /// Whether this evidence was derived from a body for `id`.
    pub fn has_body(&self, id: InterprocFunctionId) -> bool {
        self.bodies.contains(&id)
    }

    /// Every function a body contributed evidence for.
    pub fn bodies(&self) -> &BTreeSet<InterprocFunctionId> {
        &self.bodies
    }

    /// Borrow the report projection produced from the retained root.
    pub fn report(&self) -> &InterprocSummarySet {
        &self.report
    }

    /// Return whether `root` is the exact retained SSA allocation.
    pub fn matches_root(&self, root: &Arc<SsaArtifact>) -> bool {
        Arc::ptr_eq(self.root(), root)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparedInterprocSummaryError {
    MissingRoot,
    DuplicateRoot,
    MislabeledRoot,
    ForeignRoot,
    DuplicateFunction,
    MislabeledFunction,
    ManualFunction,
    UnknownOrIncoherentMachineContext,
    ArchitectureMismatch,
    ManualRootWithHelpers,
    FunctionBlockRangeOverflow,
    OverlappingFunctionBlockRanges,
    NonConverged,
}

#[derive(Debug, Clone)]
pub struct InterprocFunctionInput<'a> {
    pub id: InterprocFunctionId,
    pub name: Option<String>,
    pub prepared: &'a SsaArtifact,
}

/// One exact owned input to an authoritative interprocedural solve.
///
/// Unlike [`InterprocFunctionInput`], this form retains the caller's `Arc`, so
/// every helper contributing evidence remains alive for the lifetime of the
/// returned [`PreparedInterprocSummarySet`].
#[derive(Debug, Clone)]
pub struct PreparedInterprocFunctionInput<'a> {
    pub id: InterprocFunctionId,
    pub name: Option<String>,
    pub prepared: &'a Arc<SsaArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SummaryOperand {
    Arg(usize),
    Const(u64),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallArgObservation {
    Arg(usize),
    Const(u64),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SummaryValueObservation {
    Arg(usize),
    Const(u64),
    Global(u64),
    Call(CallObservation),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallObservation {
    target: u64,
    args: Vec<SummaryOperand>,
    result_storage: Option<crate::CanonicalStorageId>,
}

#[derive(Debug, Clone)]
struct LocalSummaryFacts {
    arg_count_hint: Option<usize>,
    direct_callees: BTreeSet<u64>,
    callsite_count: usize,
    has_unknown_calls: bool,
    arg_effects: BTreeMap<usize, SummaryArgEffect>,
    memory_effects: BTreeSet<SummaryMemoryEffect>,
    transfer_effects: BTreeSet<SummaryTransferEffect>,
    allocation_effects: BTreeSet<SummaryAllocationEffect>,
    lifetime_effects: BTreeSet<SummaryLifetimeEffect>,
    sync_effects: BTreeSet<SummarySyncEffect>,
    atomic_effects: BTreeSet<SummaryAtomicEffect>,
    return_observations: Vec<SummaryValueObservation>,
    call_observations: BTreeMap<CallSiteId, CallObservation>,
    call_carriers_converged: bool,
    /// The arguments the body itself loads or stores through: proof, where
    /// `arg_effects` also holds what an unknown call is assumed to do.
    dereferenced_args: BTreeSet<usize>,
    /// The formals something the summary cannot place could reach through,
    /// as `dependence` bits: an access at no stated place, a call, a formal
    /// stored into memory. Their reach is unbounded; every other formal's is
    /// what the accesses through it state.
    unplaced_reach: u64,
}

#[derive(Debug)]
struct CallArgumentState {
    by_call: BTreeMap<CallSiteId, Vec<SummaryOperand>>,
    converged: bool,
}

fn require_converged_call_carriers(
    local: &LocalSummaryFacts,
) -> Result<(), PreparedInterprocSummaryError> {
    local
        .call_carriers_converged
        .then_some(())
        .ok_or(PreparedInterprocSummaryError::NonConverged)
}

fn require_converged_summary_report(
    report: &InterprocSummarySet,
) -> Result<(), PreparedInterprocSummaryError> {
    report
        .diagnostics
        .converged
        .then_some(())
        .ok_or(PreparedInterprocSummaryError::NonConverged)
}

fn exact_range(offset: i64, size: u32) -> Option<SummaryMemoryRange> {
    if size == 0 {
        return None;
    }
    Some(SummaryMemoryRange {
        offset_lo: offset,
        offset_hi: offset.saturating_add(size as i64).saturating_sub(1),
        width: Some(size),
        scaled_by: None,
    })
}

/// The reach through one argument at `stride * <argument>`, for a callee that
/// indexes what it was handed.
fn scaled_arg_location(
    index: usize,
    scaled: SummaryScaledOffset,
    offset: i64,
    width: Option<u32>,
) -> SummaryMemoryLocation {
    SummaryMemoryLocation {
        region: SummaryMemoryRegion::Arg { index },
        range: Some(SummaryMemoryRange {
            offset_lo: offset,
            offset_hi: offset,
            width,
            scaled_by: Some(scaled),
        }),
    }
}

fn arg_location(index: usize, offset: Option<i64>, width: Option<u32>) -> SummaryMemoryLocation {
    SummaryMemoryLocation {
        region: SummaryMemoryRegion::Arg { index },
        range: match (offset, width) {
            (Some(offset), Some(width)) => exact_range(offset, width),
            _ => None,
        },
    }
}

fn global_location(address: u64, offset: Option<i64>, width: Option<u32>) -> SummaryMemoryLocation {
    SummaryMemoryLocation {
        region: SummaryMemoryRegion::Global { address },
        range: match (offset, width) {
            (Some(offset), Some(width)) => exact_range(offset, width),
            _ => None,
        },
    }
}

fn unknown_location() -> SummaryMemoryLocation {
    SummaryMemoryLocation {
        region: SummaryMemoryRegion::Unknown,
        range: None,
    }
}

fn prepared_obligations_require_unknown_effects(prepared: &SsaArtifact) -> bool {
    let inventory = prepared.obligations();
    !inventory.is_complete()
        || inventory.obligations().values().any(|obligation| {
            obligation.id.kind == crate::SemanticObligationKind::VolatileOrUnknownEffect
                && !only_variadic_tail_unproven(prepared, obligation.id.instruction)
        })
}

/// A direct variadic call whose one gap is the count of its tail composes
/// exactly: the callee summary names argument positions, and the solve maps
/// each position from its own carrier state, declaring unknown what it cannot
/// follow. Only the rendering needs the count, not the effect.
fn only_variadic_tail_unproven(
    prepared: &SsaArtifact,
    instruction: crate::CanonicalInstructionId,
) -> bool {
    let crate::CanonicalInstructionSite::Op(ordinal) = instruction.site else {
        return false;
    };
    prepared.certificates().callsites.values().any(|site| {
        site.block_addr == instruction.block_addr
            && site.op_index as u64 == ordinal
            && site.direct_target.is_some()
            && site.variadic
            && site.variadic_argument_count_refusal.is_some()
            && site.results_complete
    })
}

fn unknown_call_argument_state(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    converged: bool,
) -> CallArgumentState {
    CallArgumentState {
        by_call: prepared
            .call_sites()
            .by_id
            .keys()
            .map(|call_id| (*call_id, unknown_call_arguments(prepared, abi, *call_id)))
            .collect(),
        converged,
    }
}

fn mark_unknown_call_effects(
    has_unknown_calls: &mut bool,
    arg_effects: &mut BTreeMap<usize, SummaryArgEffect>,
    memory_effects: &mut BTreeSet<SummaryMemoryEffect>,
    args: Option<&[SummaryOperand]>,
) {
    *has_unknown_calls = true;
    if let Some(args) = args {
        for actual in args {
            let SummaryOperand::Arg(idx) = actual else {
                continue;
            };
            let effect = arg_effects.entry(*idx).or_default();
            effect.mark_read();
            effect.mark_write();
            effect.escape = true;
            for kind in [
                SummaryMemoryEffectKind::Read,
                SummaryMemoryEffectKind::Write,
                SummaryMemoryEffectKind::Escape,
            ] {
                memory_effects.insert(SummaryMemoryEffect {
                    kind,
                    location: arg_location(*idx, None, None),
                });
            }
        }
    }
    for kind in [
        SummaryMemoryEffectKind::Read,
        SummaryMemoryEffectKind::Write,
        SummaryMemoryEffectKind::Escape,
    ] {
        memory_effects.insert(SummaryMemoryEffect {
            kind,
            location: unknown_location(),
        });
    }
}

fn summary_atomic_ordering(ordering: MemoryOrdering) -> SummaryAtomicOrdering {
    match ordering {
        MemoryOrdering::Relaxed => SummaryAtomicOrdering::Relaxed,
        MemoryOrdering::Acquire => SummaryAtomicOrdering::Acquire,
        MemoryOrdering::Release => SummaryAtomicOrdering::Release,
        MemoryOrdering::AcqRel => SummaryAtomicOrdering::AcqRel,
        MemoryOrdering::SeqCst => SummaryAtomicOrdering::SeqCst,
        MemoryOrdering::Unknown => SummaryAtomicOrdering::Unknown,
    }
}

fn shifted_range(
    range: Option<SummaryMemoryRange>,
    delta: i64,
    width: u32,
) -> Option<SummaryMemoryRange> {
    match range {
        Some(range) => Some(SummaryMemoryRange {
            offset_lo: range.offset_lo.saturating_add(delta),
            offset_hi: range.offset_hi.saturating_add(delta),
            width: range.width.or(Some(width)),
            scaled_by: range.scaled_by,
        }),
        None => exact_range(delta, width),
    }
}

fn bump_arg_count_hint(hint: &mut Option<usize>, index: usize) {
    let count = index.saturating_add(1);
    match hint {
        Some(current) => *current = (*current).max(count),
        None => *hint = Some(count),
    }
}

fn bump_arg_count_hint_for_location(hint: &mut Option<usize>, location: SummaryMemoryLocation) {
    if let SummaryMemoryRegion::Arg { index } = location.region {
        bump_arg_count_hint(hint, index);
    }
}

struct SummaryArgCountInputs<'a> {
    base: Option<usize>,
    arg_effects: &'a BTreeMap<usize, SummaryArgEffect>,
    memory_effects: &'a BTreeSet<SummaryMemoryEffect>,
    transfer_effects: &'a BTreeSet<SummaryTransferEffect>,
    allocation_effects: &'a BTreeSet<SummaryAllocationEffect>,
    lifetime_effects: &'a BTreeSet<SummaryLifetimeEffect>,
    sync_effects: &'a BTreeSet<SummarySyncEffect>,
    atomic_effects: &'a BTreeSet<SummaryAtomicEffect>,
    return_relation: &'a SummaryReturnRelation,
}

fn summary_arg_count_hint(inputs: SummaryArgCountInputs<'_>) -> Option<usize> {
    let mut hint = inputs.base;
    for index in inputs.arg_effects.keys().copied() {
        bump_arg_count_hint(&mut hint, index);
    }
    for effect in inputs.memory_effects {
        bump_arg_count_hint_for_location(&mut hint, effect.location);
    }
    for effect in inputs.transfer_effects {
        bump_arg_count_hint_for_location(&mut hint, effect.dst);
        bump_arg_count_hint_for_location(&mut hint, effect.src);
        if let SummaryTransferLength::Arg(index) = effect.len {
            bump_arg_count_hint(&mut hint, index);
        }
    }
    for effect in inputs.allocation_effects {
        if let Some(index) = effect.size_arg {
            bump_arg_count_hint(&mut hint, index);
        }
    }
    for effect in inputs.lifetime_effects {
        bump_arg_count_hint(&mut hint, effect.arg);
    }
    for effect in inputs.sync_effects {
        bump_arg_count_hint(&mut hint, effect.arg);
    }
    for effect in inputs.atomic_effects {
        bump_arg_count_hint_for_location(&mut hint, effect.location);
    }
    if let SummaryReturnRelation::Arg(index) = inputs.return_relation {
        bump_arg_count_hint(&mut hint, *index);
    }
    hint
}

/// Solve serializable report data without retaining source authority.
///
/// This entrypoint remains useful for simulation and reporting. Its result
/// must not authorize type facts or certification.
pub fn solve_interproc_summary_set(
    functions: &[InterprocFunctionInput<'_>],
    arch: Option<&ArchSpec>,
    root: Option<InterprocFunctionId>,
    seed_summaries: &BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) -> Result<InterprocSummarySet, InterprocSummarySchemaError> {
    validate_function_summary_map(seed_summaries)?;
    let abi = AbiProfile::from_arch(arch);
    let mut locals = BTreeMap::new();
    let mut current = seed_summaries.clone();

    for function in functions {
        let local = collect_local_summary_facts(function.prepared, &abi);
        current
            .entry(function.id)
            .or_insert_with(|| initial_summary(function.id, function.name.clone(), &local));
        locals.insert(function.id, (function.name.clone(), local));
    }

    Ok(solve_interproc_summary_set_from_locals(
        locals,
        current,
        root,
        functions.len(),
    ))
}

fn solve_interproc_summary_set_from_locals(
    locals: BTreeMap<InterprocFunctionId, (Option<String>, LocalSummaryFacts)>,
    mut current: BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
    root: Option<InterprocFunctionId>,
    scope_size: usize,
) -> InterprocSummarySet {
    let sccs = compute_summary_sccs(&locals);
    // Convergence is proven by a pass that changes nothing, so a fixpoint needs
    // one pass to compute a summary and a second to confirm it. A budget of one
    // can only ever end mid-change, which reports every summary as unconverged
    // no matter how simple the function is.
    let mut iterations = 0usize;
    let mut converged = true;
    let mut max_scc_size = 0usize;
    let mut max_iterations = 0usize;

    for scc in &sccs {
        max_scc_size = max_scc_size.max(scc.len());
        // Rounds enough to reach the fixed point, from the facts rather than
        // from a policy. `resolve_summary` rebuilds a summary from the
        // function's own facts plus its callees', combining them only by set
        // insertion and boolean `or`, and remapping never invents a region,
        // range or nesting that was not already there. So the universe of
        // facts an SCC can derive is fixed before the loop starts, every
        // summary ascends in it, and a round that reports a change moved at
        // least one fact into at least one summary. Bound the rounds by how
        // many such moves exist, plus the round that observes no change.
        let scc_bound = scc_fixpoint_round_bound(scc, &locals, &current);
        max_iterations = max_iterations.max(scc_bound);
        let mut scc_converged = false;
        for _ in 0..scc_bound {
            iterations += 1;
            let mut changed = false;
            for function_id in scc {
                let Some((name, local)) = locals.get(function_id) else {
                    continue;
                };
                let next = resolve_summary(*function_id, name.clone(), local, &current);
                if current.get(function_id) != Some(&next) {
                    current.insert(*function_id, next);
                    changed = true;
                }
            }
            if !changed {
                scc_converged = true;
                break;
            }
        }
        if !scc_converged {
            r2il::refusal_evidence!(
                "interproc-summary-cap",
                "an SCC of {} functions did not settle in {scc_bound} rounds",
                scc.len()
            );
        }
        converged &= scc_converged;
    }

    InterprocSummarySet {
        schema_version: INTERPROC_SUMMARY_SCHEMA_VERSION,
        root,
        summaries: current,
        diagnostics: InterprocSummaryDiagnostics {
            iterations,
            max_iterations,
            converged,
            scope_size,
            scc_count: sccs.len(),
            max_scc_size,
        },
    }
}

fn validate_prepared_interproc_block_ranges(
    functions: &[PreparedInterprocFunctionInput<'_>],
) -> Result<(), PreparedInterprocSummaryError> {
    validate_interproc_block_ranges(functions.iter().flat_map(|function| {
        function
            .prepared
            .function()
            .blocks()
            .iter()
            .map(move |block| (function.id, block.addr, block.size))
    }))
}

fn validate_interproc_block_ranges(
    blocks: impl IntoIterator<Item = (InterprocFunctionId, u64, u32)>,
) -> Result<(), PreparedInterprocSummaryError> {
    let mut ranges = blocks
        .into_iter()
        .map(|(owner, start, size)| {
            start
                .checked_add(u64::from(size))
                .map(|end| (start, end, owner))
                .ok_or(PreparedInterprocSummaryError::FunctionBlockRangeOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ranges.sort_unstable();
    for (index, &(start, end, owner)) in ranges.iter().enumerate() {
        for &(other_start, _, other_owner) in &ranges[index + 1..] {
            if other_start >= end {
                break;
            }
            if owner != other_owner && start < end {
                return Err(PreparedInterprocSummaryError::OverlappingFunctionBlockRanges);
            }
        }
    }
    Ok(())
}

fn require_trusted_root_for_helper_scope(
    root_provenance: crate::SsaArtifactProvenanceKind,
    scope_size: usize,
) -> Result<(), PreparedInterprocSummaryError> {
    if scope_size > 1 && root_provenance != crate::SsaArtifactProvenanceKind::TrustedSource {
        return Err(PreparedInterprocSummaryError::ManualRootWithHelpers);
    }
    Ok(())
}

/// Solve interprocedural evidence owned by one exact prepared SSA root.
///
/// Exactly one input must identify the root by function id, entry, and
/// artifact authority. Independently rebuilt, omitted, duplicated, or
/// mislabeled roots are refused before any report is sealed. Every helper id
/// must equal its prepared entry and be unique. This authoritative path is
/// deliberately seedless; external and name-derived seeds remain report-only.
/// One callee's whole contribution to a caller's interprocedural solve.
///
/// Everything here is derived from that callee's own prepared body and
/// nothing else: the local effect summary the fixpoint iterates over, and the
/// facts the caller checks it against. So it can be derived once for a
/// function and used by every caller of it, which is what lets a caller reuse
/// the work without keeping the callee's whole SSA allocation alive to redo
/// it from.
#[derive(Debug, Clone)]
pub struct PreparedCalleeSummary {
    id: InterprocFunctionId,
    architecture_family: crate::MachineArchitectureFamily,
    blocks: Vec<(u64, u32)>,
    local: LocalSummaryFacts,
    /// Names of the bodiless callees this body reaches: a PLT stub's slot.
    callee_names: BTreeMap<u64, String>,
}

impl PreparedCalleeSummary {
    /// Derive a callee's contribution from the body that owns it. The body is
    /// read here and not retained.
    ///
    /// No name is taken. Names supplied by a scope are presentation advice
    /// rather than evidence the prepared owner retains, and an authoritative
    /// summary is invariant to them.
    pub fn derive(
        id: InterprocFunctionId,
        prepared: &Arc<SsaArtifact>,
    ) -> Result<Self, PreparedInterprocSummaryError> {
        if id.0 != prepared.function().entry {
            return Err(PreparedInterprocSummaryError::MislabeledFunction);
        }
        if prepared.provenance_kind() != crate::SsaArtifactProvenanceKind::TrustedSource {
            return Err(PreparedInterprocSummaryError::ManualFunction);
        }
        let abi = AbiProfile::from_machine_context(prepared.machine_context())
            .ok_or(PreparedInterprocSummaryError::UnknownOrIncoherentMachineContext)?;
        let local = collect_source_owned_summary_facts(prepared, &abi);
        require_converged_call_carriers(&local)?;
        let callee_names = prepared
            .display_names()
            .functions()
            .iter()
            .filter(|(addr, _)| local.direct_callees.contains(*addr))
            .map(|(addr, name)| (*addr, name.clone()))
            .collect();
        Ok(Self {
            id,
            architecture_family: prepared.machine_context().architecture_family(),
            blocks: prepared
                .function()
                .blocks()
                .iter()
                .map(|block| (block.addr, block.size))
                .collect(),
            local,
            callee_names,
        })
    }

    pub const fn id(&self) -> InterprocFunctionId {
        self.id
    }

    /// The arguments this body itself loads or stores through, by index.
    ///
    /// Only accesses the body performs: an argument handed to a call nothing
    /// can see is assumed read and written in `arg_effects`, which is a
    /// conservative guess about effects rather than proof the value is an address.
    pub const fn dereferenced_arguments(&self) -> &BTreeSet<usize> {
        &self.local.dereferenced_args
    }

    /// Each argument this body passes on unchanged to a direct callee: the
    /// callee, the argument it arrives as there, and the argument it was here.
    pub fn forwarded_arguments(&self) -> Vec<(u64, usize, usize)> {
        let mut forwarded = self
            .local
            .call_observations
            .values()
            .flat_map(|call| {
                call.args
                    .iter()
                    .enumerate()
                    .filter_map(move |(there, operand)| match operand {
                        SummaryOperand::Arg(here) => Some((call.target, there, *here)),
                        SummaryOperand::Const(_) | SummaryOperand::Unknown => None,
                    })
            })
            .collect::<Vec<_>>();
        forwarded.sort_unstable();
        forwarded.dedup();
        forwarded
    }

    /// How far this body is proven to touch through each pointer argument it
    /// is handed, in bytes from that argument.
    ///
    /// A caller that hands over a frame address learns from this that the
    /// bytes it covers are one object: the callee reaches them all through one
    /// pointer, so a position inside them is a member of what it was given
    /// rather than a neighbouring local. An argument the body hands on to
    /// something the summary cannot see, or accesses at a place it cannot
    /// state, has no entry -- an unbounded reach is not a span.
    /// `argument_bounds` is the greatest value the caller passes for each
    /// argument, where it knows one. An offset that scales with an argument
    /// reaches `stride * (bound + 1)`, and is unbounded without a bound, which
    /// is what an empty map says.
    pub fn argument_touch_reach(&self) -> BTreeMap<usize, SummaryArgumentReach> {
        let mut scaled = BTreeMap::<usize, SummaryArgumentReach>::new();
        let mut reach = BTreeMap::<usize, u64>::new();
        let mut unbounded = BTreeSet::<usize>::new();
        for effect in &self.local.memory_effects {
            let SummaryMemoryRegion::Arg { index } = effect.location.region else {
                continue;
            };
            match effect.kind {
                SummaryMemoryEffectKind::Read | SummaryMemoryEffectKind::Write => {}
                SummaryMemoryEffectKind::Escape | SummaryMemoryEffectKind::Free => {
                    unbounded.insert(index);
                    continue;
                }
            }
            let Some(range) = effect.location.range else {
                unbounded.insert(index);
                continue;
            };
            if let Some(term) = range.scaled_by {
                // Stated per index; the caller multiplies it out.
                scaled.insert(
                    index,
                    SummaryArgumentReach::Scaled {
                        argument: term.argument,
                        stride: term.stride,
                        base: range.offset_lo,
                        width: range.width.unwrap_or(0),
                    },
                );
                continue;
            }
            let Some(end) = range
                .offset_hi
                .checked_add(1)
                .and_then(|end| u64::try_from(end).ok())
            else {
                unbounded.insert(index);
                continue;
            };
            reach
                .entry(index)
                .and_modify(|known| *known = (*known).max(end))
                .or_insert(end);
        }
        for transfer in &self.local.transfer_effects {
            for location in [transfer.dst, transfer.src] {
                let SummaryMemoryRegion::Arg { index } = location.region else {
                    continue;
                };
                match transfer.len {
                    SummaryTransferLength::Const(length) => {
                        reach
                            .entry(index)
                            .and_modify(|known| *known = (*known).max(length))
                            .or_insert(length);
                    }
                    SummaryTransferLength::Arg(_) | SummaryTransferLength::Unknown => {
                        unbounded.insert(index);
                    }
                }
            }
        }
        // An access or a call nothing places could reach through exactly the
        // formals its address or its arguments are computed from, and no
        // others: an unknown call handed only an index leaves a pointer's
        // reach alone, and an indexed read of a table at a constant address
        // poisons no pointer at all.
        let unplaced = self.local.unplaced_reach;
        let bounded = |index: &usize| {
            !unbounded.contains(index) && !dependence::names_formal(unplaced, *index)
        };
        reach.retain(|index, _| bounded(index));
        scaled.retain(|index, _| bounded(index));
        let mut proven = scaled;
        for (index, bytes) in reach {
            // A constant span and a scaled one through the same argument both
            // hold; the constant is the one this body states on its own.
            proven.insert(index, SummaryArgumentReach::Bytes(bytes));
        }
        r2il::refusal_evidence!(
            "argument-reach",
            "{:#x}: reach={proven:?} unbounded={unbounded:?} unplaced={unplaced:#x} unknown_calls={} effects={:?}",
            self.id.0,
            self.local.has_unknown_calls,
            self.local
                .memory_effects
                .iter()
                .map(|effect| (effect.kind, effect.location))
                .collect::<Vec<_>>()
        );
        proven
    }
}

/// Solve the summary set for one root against callee contributions already
/// derived from their own bodies.
///
/// The root still arrives as its exact allocation, because the evidence is
/// sealed to it. A callee arrives as what it contributes, which is all the
/// solve reads of it.
/// The helpers whose blocks nothing else in the scope claims.
///
/// The root's own blocks always win: it is the function being rendered, and a
/// helper is only there to lend its signature. A helper that overlaps the root
/// or an earlier helper is left out, and says so.
fn attributable_callees(
    root: &SsaArtifact,
    root_id: InterprocFunctionId,
    callees: &[PreparedCalleeSummary],
) -> Vec<PreparedCalleeSummary> {
    let mut claimed: Vec<(u64, u64)> = root
        .function()
        .blocks()
        .iter()
        .filter_map(|block| {
            block
                .addr
                .checked_add(u64::from(block.size))
                .map(|end| (block.addr, end))
        })
        .collect();
    let overlaps = |claimed: &[(u64, u64)], start: u64, end: u64| {
        claimed
            .iter()
            .any(|(other_start, other_end)| start < *other_end && *other_start < end)
    };
    let mut kept = Vec::with_capacity(callees.len());
    for callee in callees {
        let ranges = callee
            .blocks
            .iter()
            .filter_map(|(addr, size)| addr.checked_add(u64::from(*size)).map(|end| (*addr, end)))
            .collect::<Vec<_>>();
        if ranges.len() != callee.blocks.len()
            || ranges
                .iter()
                .any(|(start, end)| overlaps(&claimed, *start, *end))
        {
            r2il::refusal_evidence!(
                "interproc-scope",
                "{:#x}: helper {:#x} shares blocks with the scope and is left out",
                root_id.0,
                callee.id.0
            );
            continue;
        }
        claimed.extend(ranges);
        kept.push(callee.clone());
    }
    kept
}

pub fn solve_prepared_interproc_summary_set_from_callee_summaries(
    root: Arc<SsaArtifact>,
    callees: &[PreparedCalleeSummary],
) -> Result<PreparedInterprocSummarySet, PreparedInterprocSummaryError> {
    let root_id = InterprocFunctionId(root.function().entry);
    let mut seen = BTreeSet::new();
    seen.insert(root_id);
    for callee in callees {
        if callee.id == root_id {
            return Err(PreparedInterprocSummaryError::DuplicateRoot);
        }
        if !seen.insert(callee.id) {
            return Err(PreparedInterprocSummaryError::DuplicateFunction);
        }
    }

    let root_family = root.machine_context().architecture_family();
    if root.machine_context().function_interface().is_none() {
        return Err(PreparedInterprocSummaryError::UnknownOrIncoherentMachineContext);
    }
    let root_abi = AbiProfile::from_machine_context(root.machine_context())
        .ok_or(PreparedInterprocSummaryError::UnknownOrIncoherentMachineContext)?;

    // A body kept across roots carries the revision of its own capture; the
    // set is consistent by construction, each body current by the analysis
    // epochs when the root was read, so no revision is compared here.
    for callee in callees {
        if callee.architecture_family != root_family {
            return Err(PreparedInterprocSummaryError::ArchitectureMismatch);
        }
    }
    // A helper whose blocks the root also claims is dropped rather than
    // refused over. Two functions sharing a tail is a fact about the binary --
    // `ld` merges them -- and it makes the ownership of those blocks
    // ambiguous, not the root's signature unknowable. Refusing the set lost
    // the root as well, which is a whole function for a helper's sake.
    let callees = &attributable_callees(&root, root_id, callees);
    validate_interproc_block_ranges(
        root.function()
            .blocks()
            .iter()
            .map(|block| (root_id, block.addr, block.size))
            .chain(callees.iter().flat_map(|callee| {
                callee
                    .blocks
                    .iter()
                    .map(move |(addr, size)| (callee.id, *addr, *size))
            })),
    )?;

    let root_local = collect_source_owned_summary_facts(&root, &root_abi);
    require_converged_call_carriers(&root_local)?;
    require_trusted_root_for_helper_scope(root.provenance_kind(), callees.len() + 1)?;

    let mut owners = BTreeMap::new();
    let mut bodies = BTreeSet::new();
    let mut locals = BTreeMap::new();
    let mut current = BTreeMap::new();
    owners.insert(root_id, Arc::clone(&root));
    bodies.insert(root_id);
    current.insert(root_id, initial_summary(root_id, None, &root_local));
    locals.insert(root_id, (None, root_local));
    for callee in callees {
        bodies.insert(callee.id);
        current.insert(callee.id, initial_summary(callee.id, None, &callee.local));
        locals.insert(callee.id, (None, callee.local.clone()));
    }

    let mut names = root.display_names().functions().clone();
    for callee in callees {
        for (addr, name) in &callee.callee_names {
            names.entry(*addr).or_insert_with(|| name.clone());
        }
    }
    seed_named_callees(&names, &locals, &mut current);
    let report =
        solve_interproc_summary_set_from_locals(locals, current, Some(root_id), callees.len() + 1);
    require_converged_summary_report(&report)?;
    Ok(PreparedInterprocSummarySet {
        root: root_id,
        owners,
        bodies,
        report,
    })
}

/// A callee with no body but a known name is what its model says: an import
/// the seed table describes enters the set as a fixed summary, so a call to
/// `snprintf` is a bounded write rather than an unknown call.
fn seed_named_callees(
    names: &BTreeMap<u64, String>,
    locals: &BTreeMap<InterprocFunctionId, (Option<String>, LocalSummaryFacts)>,
    current: &mut BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) {
    let callees = locals
        .values()
        .flat_map(|(_, local)| local.direct_callees.iter().copied())
        .collect::<BTreeSet<_>>();
    for callee in callees {
        let id = InterprocFunctionId(callee);
        if current.contains_key(&id) {
            continue;
        }
        let seed = names
            .get(&callee)
            .and_then(|name| FunctionSemanticSummary::seed_for_callee_name(id, name));
        r2il::refusal_evidence!(
            "summary-seed",
            "callee {callee:#x} name={:?} seeded={}",
            names.get(&callee),
            seed.is_some()
        );
        let Some(seed) = seed else {
            continue;
        };
        current.insert(id, seed);
    }
}

/// Solve from whole prepared bodies. Each non-root body is reduced to its
/// contribution first, which is all the solve reads of it.
pub fn solve_prepared_interproc_summary_set(
    root: Arc<SsaArtifact>,
    functions: &[PreparedInterprocFunctionInput<'_>],
) -> Result<PreparedInterprocSummarySet, PreparedInterprocSummaryError> {
    let root_id = InterprocFunctionId(root.function().entry);
    let mut function_ids = BTreeSet::new();
    for function in functions {
        if function.id.0 != function.prepared.function().entry {
            return Err(if function.prepared.authority() == root.authority() {
                PreparedInterprocSummaryError::MislabeledRoot
            } else {
                PreparedInterprocSummaryError::MislabeledFunction
            });
        }
        if !function_ids.insert(function.id) {
            return Err(if function.id == root_id {
                PreparedInterprocSummaryError::DuplicateRoot
            } else {
                PreparedInterprocSummaryError::DuplicateFunction
            });
        }
    }
    let root_candidates = functions
        .iter()
        .filter(|function| {
            function.id == root_id
                || function.prepared.function().entry == root.function().entry
                || function.prepared.authority() == root.authority()
        })
        .collect::<Vec<_>>();

    if root_candidates.len() > 1 {
        return Err(PreparedInterprocSummaryError::DuplicateRoot);
    }
    let Some(root_input) = root_candidates.first() else {
        return Err(PreparedInterprocSummaryError::MissingRoot);
    };
    if root_input.id != root_id || root_input.prepared.function().entry != root.function().entry {
        return Err(PreparedInterprocSummaryError::MislabeledRoot);
    }
    if !Arc::ptr_eq(root_input.prepared, &root) {
        return Err(PreparedInterprocSummaryError::ForeignRoot);
    }
    // Refuse in the order this entry point always has. A body that is not
    // source-owned cannot contribute at all, but a scope that is the wrong
    // architecture or whose functions overlap is wrong about every body in
    // it, so those answers come first.
    let root_family = root.machine_context().architecture_family();
    for function in functions {
        if function.prepared.machine_context().architecture_family() != root_family {
            return Err(PreparedInterprocSummaryError::ArchitectureMismatch);
        }
    }
    validate_prepared_interproc_block_ranges(functions)?;

    let mut callees = Vec::new();
    for function in functions {
        if function.id == root_id {
            continue;
        }
        callees.push(PreparedCalleeSummary::derive(
            function.id,
            function.prepared,
        )?);
    }
    let mut set = solve_prepared_interproc_summary_set_from_callee_summaries(root, &callees)?;
    // This entry point was handed the bodies, so it can retain them.
    for function in functions {
        set.owners
            .insert(function.id, Arc::clone(function.prepared));
    }
    Ok(set)
}

fn compute_summary_sccs(
    locals: &BTreeMap<InterprocFunctionId, (Option<String>, LocalSummaryFacts)>,
) -> Vec<Vec<InterprocFunctionId>> {
    let node_ids: Vec<InterprocFunctionId> = locals.keys().copied().collect();
    let node_set: BTreeSet<InterprocFunctionId> = node_ids.iter().copied().collect();
    let mut succs = BTreeMap::<InterprocFunctionId, Vec<InterprocFunctionId>>::new();
    let mut rev = BTreeMap::<InterprocFunctionId, Vec<InterprocFunctionId>>::new();

    for node in &node_ids {
        succs.entry(*node).or_default();
        rev.entry(*node).or_default();
    }
    for (node, (_, local)) in locals {
        let mut out = local
            .direct_callees
            .iter()
            .map(|target| InterprocFunctionId(*target))
            .filter(|target| node_set.contains(target))
            .collect::<Vec<_>>();
        out.sort_unstable();
        out.dedup();
        succs.insert(*node, out.clone());
        for succ in out {
            rev.entry(succ).or_default().push(*node);
        }
    }
    for preds in rev.values_mut() {
        preds.sort_unstable();
        preds.dedup();
    }

    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for node in &node_ids {
        dfs_summary_postorder(*node, &succs, &mut visited, &mut order);
    }

    visited.clear();
    let mut sccs = Vec::new();
    while let Some(node) = order.pop() {
        if visited.contains(&node) {
            continue;
        }
        let mut component = Vec::new();
        dfs_summary_component(node, &rev, &mut visited, &mut component);
        component.sort_unstable();
        sccs.push(component);
    }

    // Edges point caller -> callee, but summary propagation wants callee SCCs
    // solved before dependent caller SCCs when the graph is acyclic.
    sccs.reverse();

    sccs
}

fn dfs_summary_postorder(
    node: InterprocFunctionId,
    succs: &BTreeMap<InterprocFunctionId, Vec<InterprocFunctionId>>,
    visited: &mut BTreeSet<InterprocFunctionId>,
    order: &mut Vec<InterprocFunctionId>,
) {
    let mut stack = vec![(node, false)];
    while let Some((node, expanded)) = stack.pop() {
        if expanded {
            order.push(node);
            continue;
        }
        if !visited.insert(node) {
            continue;
        }
        stack.push((node, true));
        if let Some(children) = succs.get(&node) {
            for &succ in children.iter().rev() {
                stack.push((succ, false));
            }
        }
    }
}

fn dfs_summary_component(
    node: InterprocFunctionId,
    rev: &BTreeMap<InterprocFunctionId, Vec<InterprocFunctionId>>,
    visited: &mut BTreeSet<InterprocFunctionId>,
    component: &mut Vec<InterprocFunctionId>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if !visited.insert(node) {
            continue;
        }
        component.push(node);
        if let Some(preds) = rev.get(&node) {
            for &pred in preds.iter().rev() {
                stack.push(pred);
            }
        }
    }
}

fn initial_summary(
    id: InterprocFunctionId,
    name: Option<String>,
    local: &LocalSummaryFacts,
) -> FunctionSemanticSummary {
    let (reads_global_memory, writes_global_memory, touches_unknown_memory) =
        summarize_memory_effect_flags(&local.memory_effects);
    let return_relation = resolve_return_relation(&local.return_observations, &BTreeMap::new());
    let arg_count_hint = summary_arg_count_hint(SummaryArgCountInputs {
        base: local.arg_count_hint,
        arg_effects: &local.arg_effects,
        memory_effects: &local.memory_effects,
        transfer_effects: &local.transfer_effects,
        allocation_effects: &local.allocation_effects,
        lifetime_effects: &local.lifetime_effects,
        sync_effects: &local.sync_effects,
        atomic_effects: &local.atomic_effects,
        return_relation: &return_relation,
    });
    FunctionSemanticSummary {
        schema_version: INTERPROC_SUMMARY_SCHEMA_VERSION,
        id,
        name,
        linkage: FunctionSemanticLinkage::Unknown,
        arg_count_hint,
        direct_callees: local.direct_callees.clone(),
        callsite_count: local.callsite_count,
        has_unknown_calls: local.has_unknown_calls,
        arg_effects: local.arg_effects.clone(),
        memory_effects: local.memory_effects.iter().copied().collect(),
        transfer_effects: local.transfer_effects.iter().copied().collect(),
        allocation_effects: local.allocation_effects.iter().copied().collect(),
        lifetime_effects: local.lifetime_effects.iter().copied().collect(),
        sync_effects: local.sync_effects.iter().copied().collect(),
        atomic_effects: local.atomic_effects.iter().copied().collect(),
        return_relation,
        reads_global_memory,
        writes_global_memory,
        touches_unknown_memory,
    }
}

/// How many rounds an SCC can take to reach its fixed point.
///
/// One move per (function, fact) pair, where a fact is one entry a summary can
/// gain: an argument effect, a memory, transfer, allocation, lifetime, sync or
/// atomic effect, the unknown-call flag, or one call observation resolving from
/// absent to present. Plus the round that observes no change.
///
/// A member's summary also gains whatever its callees outside this SCC already
/// hold. Those callees are resolved before the SCC runs, so their facts arrive
/// in the first round, but they then travel round the cycle like any other, so
/// the universe counts them. Undercounting fails by refusing with
/// `NonConverged`, which is why this over-approximates rather than assuming
/// imported facts settle at once.
fn scc_fixpoint_round_bound(
    scc: &[InterprocFunctionId],
    locals: &BTreeMap<InterprocFunctionId, (Option<String>, LocalSummaryFacts)>,
    resolved: &BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) -> usize {
    let local_facts = |local: &LocalSummaryFacts| {
        local.arg_effects.len()
            + local.memory_effects.len()
            + local.transfer_effects.len()
            + local.allocation_effects.len()
            + local.lifetime_effects.len()
            + local.sync_effects.len()
            + local.atomic_effects.len()
            + local.call_observations.len()
            + 1
    };
    let imported_facts = |summary: &FunctionSemanticSummary| {
        summary.arg_effects.len()
            + summary.memory_effects.len()
            + summary.transfer_effects.len()
            + summary.allocation_effects.len()
            + summary.lifetime_effects.len()
            + summary.sync_effects.len()
            + summary.atomic_effects.len()
            + 1
    };
    let universe: usize = scc
        .iter()
        .filter_map(|id| locals.get(id))
        .map(|(_, local)| {
            let imported: usize = local
                .call_observations
                .values()
                .filter_map(|call| resolved.get(&InterprocFunctionId(call.target)))
                .map(imported_facts)
                .sum();
            local_facts(local).saturating_add(imported)
        })
        .sum();
    scc.len().saturating_mul(universe).saturating_add(1).max(2)
}

fn resolve_summary(
    id: InterprocFunctionId,
    name: Option<String>,
    local: &LocalSummaryFacts,
    current: &BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) -> FunctionSemanticSummary {
    let mut has_unknown_calls = local.has_unknown_calls;
    let mut arg_effects = local.arg_effects.clone();
    let mut memory_effects = local.memory_effects.clone();
    let mut transfer_effects = local.transfer_effects.clone();
    let mut allocation_effects = local.allocation_effects.clone();
    let mut lifetime_effects = local.lifetime_effects.clone();
    let mut sync_effects = local.sync_effects.clone();
    let mut atomic_effects = local.atomic_effects.clone();
    let mut has_unresolved_direct_call = false;
    for call in local.call_observations.values() {
        let Some(callee) = current.get(&InterprocFunctionId(call.target)) else {
            has_unresolved_direct_call = true;
            mark_unknown_call_effects(
                &mut has_unknown_calls,
                &mut arg_effects,
                &mut memory_effects,
                Some(&call.args),
            );
            continue;
        };
        has_unknown_calls |= callee.has_unknown_calls;
        for (idx, effect) in &callee.arg_effects {
            let Some(actual) = call.args.get(*idx) else {
                continue;
            };
            let SummaryOperand::Arg(caller_idx) = actual else {
                continue;
            };
            arg_effects
                .entry(*caller_idx)
                .or_default()
                .merge_from(effect);
        }
        for effect in &callee.memory_effects {
            memory_effects.insert(remap_memory_effect(effect, &call.args));
        }
        for effect in &callee.transfer_effects {
            transfer_effects.insert(remap_transfer_effect(effect, &call.args));
        }
        allocation_effects.extend(callee.allocation_effects.iter().copied());
        for effect in &callee.lifetime_effects {
            if let Some(effect) = remap_lifetime_effect(effect, &call.args) {
                lifetime_effects.insert(effect);
            }
        }
        for effect in &callee.sync_effects {
            if let Some(effect) = remap_sync_effect(effect, &call.args) {
                sync_effects.insert(effect);
            }
        }
        for effect in &callee.atomic_effects {
            atomic_effects.insert(remap_atomic_effect(effect, &call.args));
        }
    }
    let (reads_global_memory, writes_global_memory, touches_unknown_memory) =
        summarize_memory_effect_flags(&memory_effects);
    let return_relation = if local.has_unknown_calls || has_unresolved_direct_call {
        SummaryReturnRelation::Unknown
    } else {
        resolve_return_relation_with_wrapper_fallback(local, current)
    };
    let arg_count_hint = summary_arg_count_hint(SummaryArgCountInputs {
        base: local.arg_count_hint,
        arg_effects: &arg_effects,
        memory_effects: &memory_effects,
        transfer_effects: &transfer_effects,
        allocation_effects: &allocation_effects,
        lifetime_effects: &lifetime_effects,
        sync_effects: &sync_effects,
        atomic_effects: &atomic_effects,
        return_relation: &return_relation,
    });

    FunctionSemanticSummary {
        schema_version: INTERPROC_SUMMARY_SCHEMA_VERSION,
        id,
        name,
        linkage: FunctionSemanticLinkage::Unknown,
        arg_count_hint,
        direct_callees: local.direct_callees.clone(),
        callsite_count: local.callsite_count,
        has_unknown_calls,
        arg_effects,
        memory_effects: memory_effects.iter().copied().collect(),
        transfer_effects: transfer_effects.iter().copied().collect(),
        allocation_effects: allocation_effects.iter().copied().collect(),
        lifetime_effects: lifetime_effects.iter().copied().collect(),
        sync_effects: sync_effects.iter().copied().collect(),
        atomic_effects: atomic_effects.iter().copied().collect(),
        return_relation,
        reads_global_memory,
        writes_global_memory,
        touches_unknown_memory,
    }
}

fn summarize_memory_effect_flags(effects: &BTreeSet<SummaryMemoryEffect>) -> (bool, bool, bool) {
    let mut reads_global_memory = false;
    let mut writes_global_memory = false;
    let mut touches_unknown_memory = false;
    for effect in effects {
        match (effect.kind, effect.location.region) {
            (SummaryMemoryEffectKind::Read, SummaryMemoryRegion::Global { .. }) => {
                reads_global_memory = true
            }
            (
                SummaryMemoryEffectKind::Write
                | SummaryMemoryEffectKind::Escape
                | SummaryMemoryEffectKind::Free,
                SummaryMemoryRegion::Global { .. },
            ) => writes_global_memory = true,
            (_, SummaryMemoryRegion::Unknown) => touches_unknown_memory = true,
            _ => {}
        }
    }
    (
        reads_global_memory,
        writes_global_memory,
        touches_unknown_memory,
    )
}

fn remap_memory_effect(
    effect: &SummaryMemoryEffect,
    args: &[SummaryOperand],
) -> SummaryMemoryEffect {
    SummaryMemoryEffect {
        kind: effect.kind,
        location: remap_memory_location(effect.location, args),
    }
}

fn remap_memory_location(
    location: SummaryMemoryLocation,
    args: &[SummaryOperand],
) -> SummaryMemoryLocation {
    match location.region {
        SummaryMemoryRegion::Arg { index } => match args.get(index) {
            Some(SummaryOperand::Arg(caller_idx)) => SummaryMemoryLocation {
                region: SummaryMemoryRegion::Arg { index: *caller_idx },
                range: location.range,
            },
            Some(SummaryOperand::Const(value)) => SummaryMemoryLocation {
                region: SummaryMemoryRegion::Global { address: *value },
                range: location.range,
            },
            _ => SummaryMemoryLocation {
                region: SummaryMemoryRegion::Unknown,
                range: None,
            },
        },
        other => SummaryMemoryLocation {
            region: other,
            range: location.range,
        },
    }
}

fn remap_transfer_effect(
    effect: &SummaryTransferEffect,
    args: &[SummaryOperand],
) -> SummaryTransferEffect {
    SummaryTransferEffect {
        dst: remap_memory_location(effect.dst, args),
        src: remap_memory_location(effect.src, args),
        len: remap_transfer_len(effect.len, args),
    }
}

fn remap_transfer_len(
    len: SummaryTransferLength,
    args: &[SummaryOperand],
) -> SummaryTransferLength {
    match len {
        SummaryTransferLength::Arg(index) => match args.get(index) {
            Some(SummaryOperand::Arg(caller_idx)) => SummaryTransferLength::Arg(*caller_idx),
            Some(SummaryOperand::Const(value)) => SummaryTransferLength::Const(*value),
            _ => SummaryTransferLength::Unknown,
        },
        other => other,
    }
}

fn remap_lifetime_effect(
    effect: &SummaryLifetimeEffect,
    args: &[SummaryOperand],
) -> Option<SummaryLifetimeEffect> {
    let Some(SummaryOperand::Arg(caller_arg)) = args.get(effect.arg) else {
        return None;
    };
    Some(SummaryLifetimeEffect {
        arg: *caller_arg,
        op: effect.op,
    })
}

fn remap_sync_effect(
    effect: &SummarySyncEffect,
    args: &[SummaryOperand],
) -> Option<SummarySyncEffect> {
    let Some(SummaryOperand::Arg(caller_arg)) = args.get(effect.arg) else {
        return None;
    };
    Some(SummarySyncEffect {
        arg: *caller_arg,
        op: effect.op,
    })
}

fn remap_atomic_effect(
    effect: &SummaryAtomicEffect,
    args: &[SummaryOperand],
) -> SummaryAtomicEffect {
    SummaryAtomicEffect {
        op: effect.op,
        location: remap_memory_location(effect.location, args),
        ordering: effect.ordering,
    }
}

fn resolve_return_relation(
    observations: &[SummaryValueObservation],
    current: &BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) -> SummaryReturnRelation {
    if observations.is_empty() {
        return SummaryReturnRelation::Unknown;
    }
    let mut relation: Option<SummaryReturnRelation> = None;
    for observation in observations {
        let next = match observation {
            SummaryValueObservation::Arg(idx) => SummaryReturnRelation::Arg(*idx),
            SummaryValueObservation::Const(value) => SummaryReturnRelation::Const(*value),
            SummaryValueObservation::Global(address) => SummaryReturnRelation::Global(*address),
            SummaryValueObservation::Unknown => SummaryReturnRelation::Unknown,
            SummaryValueObservation::Call(call) => {
                let Some(callee) = current.get(&InterprocFunctionId(call.target)) else {
                    return SummaryReturnRelation::Unknown;
                };
                match &callee.return_relation {
                    SummaryReturnRelation::Arg(idx) => match call.args.get(*idx) {
                        Some(SummaryOperand::Arg(arg_idx)) => SummaryReturnRelation::Arg(*arg_idx),
                        Some(SummaryOperand::Const(value)) => SummaryReturnRelation::Const(*value),
                        _ => SummaryReturnRelation::Unknown,
                    },
                    SummaryReturnRelation::Const(value) => SummaryReturnRelation::Const(*value),
                    SummaryReturnRelation::HeapAlloc => SummaryReturnRelation::HeapAlloc,
                    SummaryReturnRelation::Global(address) => {
                        SummaryReturnRelation::Global(*address)
                    }
                    SummaryReturnRelation::Void => SummaryReturnRelation::Void,
                    SummaryReturnRelation::Unknown => SummaryReturnRelation::Unknown,
                }
            }
        };

        match &relation {
            None => relation = Some(next),
            Some(current) if *current == next => {}
            _ => return SummaryReturnRelation::Unknown,
        }
    }

    relation.unwrap_or(SummaryReturnRelation::Unknown)
}

fn resolve_single_call_wrapper_return_relation(
    local: &LocalSummaryFacts,
    current: &BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) -> Option<SummaryReturnRelation> {
    if local.has_unknown_calls || local.call_observations.len() != 1 {
        return None;
    }
    if !local
        .return_observations
        .iter()
        .all(|observation| matches!(observation, SummaryValueObservation::Unknown))
    {
        return None;
    }

    let call = local.call_observations.values().next()?;
    call.result_storage?;
    let callee = current.get(&InterprocFunctionId(call.target))?;
    match &callee.return_relation {
        SummaryReturnRelation::Arg(idx) => match call.args.get(*idx) {
            Some(SummaryOperand::Arg(arg_idx)) => Some(SummaryReturnRelation::Arg(*arg_idx)),
            Some(SummaryOperand::Const(value)) => Some(SummaryReturnRelation::Const(*value)),
            _ => None,
        },
        SummaryReturnRelation::Const(value) => Some(SummaryReturnRelation::Const(*value)),
        SummaryReturnRelation::HeapAlloc => Some(SummaryReturnRelation::HeapAlloc),
        SummaryReturnRelation::Global(address) => Some(SummaryReturnRelation::Global(*address)),
        SummaryReturnRelation::Void | SummaryReturnRelation::Unknown => None,
    }
}

fn resolve_return_relation_with_wrapper_fallback(
    local: &LocalSummaryFacts,
    current: &BTreeMap<InterprocFunctionId, FunctionSemanticSummary>,
) -> SummaryReturnRelation {
    match resolve_return_relation(&local.return_observations, current) {
        SummaryReturnRelation::Unknown => {
            resolve_single_call_wrapper_return_relation(local, current)
                .unwrap_or(SummaryReturnRelation::Unknown)
        }
        relation => relation,
    }
}

fn exact_call_result_storage(
    prepared: &SsaArtifact,
    call_site: CallSiteId,
) -> Option<crate::CanonicalStorageId> {
    let interface = prepared.call_site_interface(call_site)?;
    if !interface.is_complete() {
        return None;
    }
    match interface.result() {
        crate::SourceCallResult::Register { storage }
            if Some(storage) == exact_function_return_storage(prepared) =>
        {
            Some(storage)
        }
        crate::SourceCallResult::Register { .. } => None,
        crate::SourceCallResult::Void => None,
    }
}

fn exact_function_return_storage(prepared: &SsaArtifact) -> Option<crate::CanonicalStorageId> {
    match prepared
        .machine_context()
        .function_interface()?
        .return_kind()
    {
        crate::SourceFunctionReturn::Register { storage } => Some(storage),
        crate::SourceFunctionReturn::Void | crate::SourceFunctionReturn::Unproven => None,
    }
}

fn collect_local_summary_facts(prepared: &SsaArtifact, abi: &AbiProfile) -> LocalSummaryFacts {
    collect_local_summary_facts_with_obligation_authority(prepared, abi, false)
}

fn collect_source_owned_summary_facts(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
) -> LocalSummaryFacts {
    collect_local_summary_facts_with_obligation_authority(prepared, abi, true)
}

fn collect_local_summary_facts_with_obligation_authority(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    source_owned: bool,
) -> LocalSummaryFacts {
    let function = prepared.function();
    let source_requires_unknown_effects =
        source_owned && prepared_obligations_require_unknown_effects(prepared);
    r2il::refusal_evidence!(
        "summary-local",
        "{:#x}: source_owned={source_owned} unknown_effects={source_requires_unknown_effects} complete={} volatile_or_unknown={:?} calls={} sites={:?}",
        function.entry,
        prepared.obligations().is_complete(),
        prepared
            .obligations()
            .obligations()
            .values()
            .filter(|obligation| {
                obligation.id.kind == crate::SemanticObligationKind::VolatileOrUnknownEffect
            })
            .map(|obligation| obligation.id.to_string())
            .collect::<Vec<_>>(),
        prepared.call_sites().by_id.len(),
        prepared
            .certificates()
            .callsites
            .values()
            .map(|site| (
                site.block_addr,
                site.op_index,
                site.variadic,
                site.variadic_argument_count_refusal,
                site.results_complete,
                site.fixed_argument_count,
                site.argument_values.len()
            ))
            .collect::<Vec<_>>()
    );
    let observed_call_argument_state = collect_call_arg_state(prepared, abi);
    let call_argument_state = if source_requires_unknown_effects {
        unknown_call_argument_state(prepared, abi, observed_call_argument_state.converged)
    } else {
        observed_call_argument_state
    };
    let state_by_call = &call_argument_state.by_call;
    let mut has_volatile_or_unknown_effects = source_requires_unknown_effects;
    let mut out = LocalSummaryFacts {
        arg_count_hint: Some(0),
        direct_callees: BTreeSet::new(),
        callsite_count: prepared.call_sites().by_id.len(),
        has_unknown_calls: false,
        arg_effects: BTreeMap::new(),
        memory_effects: BTreeSet::new(),
        transfer_effects: BTreeSet::new(),
        allocation_effects: BTreeSet::new(),
        lifetime_effects: BTreeSet::new(),
        sync_effects: BTreeSet::new(),
        atomic_effects: BTreeSet::new(),
        return_observations: Vec::new(),
        call_observations: BTreeMap::new(),
        call_carriers_converged: call_argument_state.converged,
        dereferenced_args: BTreeSet::new(),
        unplaced_reach: 0,
    };
    // Which formals each value is computed from, and so which formals an
    // access or a call this summary cannot place could reach through.
    let dependence = dependence::FormalDependence::of(prepared, abi);
    out.unplaced_reach |= dependence.passed_to_calls();
    if source_requires_unknown_effects {
        out.unplaced_reach = u64::MAX;
    }
    let bits_of_var = |var: &SSAVar| {
        prepared
            .graph()
            .value_id_for_var(var)
            .map_or(0, |value| dependence.bits_of(value))
    };
    // A formal stored into the frame has escaped exactly where the place it
    // was stored at is exposed: a frame object whose address leaves the
    // body, or a place at or above one. Anything the address reached can
    // read it back and write through it. A private place is read only by
    // this body's own loads, which carry the formal on in the dependence.
    let stored_in_frame = |block: u64, op: usize, stored: u64| {
        if dependence.frame_store_is_exposed(prepared, block, op) {
            stored
        } else {
            0
        }
    };
    // An access that names no argument region at a stated place could touch
    // any formal's object its address is computed from.
    let unplaced = |location: &SummaryMemoryLocation, addr: &SSAVar| match location.region {
        SummaryMemoryRegion::Unknown => bits_of_var(addr),
        SummaryMemoryRegion::Arg { .. } if location.range.is_none() => bits_of_var(addr),
        _ => 0,
    };

    if source_requires_unknown_effects {
        let formal_arguments = (0..abi.argument_count())
            .map(SummaryOperand::Arg)
            .collect::<Vec<_>>();
        mark_unknown_call_effects(
            &mut out.has_unknown_calls,
            &mut out.arg_effects,
            &mut out.memory_effects,
            Some(&formal_arguments),
        );
    }

    for (call_id, call) in &prepared.call_sites().by_id {
        match call.direct_target {
            Some(target) => {
                out.direct_callees.insert(target);
                let args = state_by_call
                    .get(call_id)
                    .cloned()
                    .unwrap_or_else(|| unknown_call_arguments(prepared, abi, *call_id));
                out.call_observations.insert(
                    *call_id,
                    CallObservation {
                        target,
                        args,
                        result_storage: exact_call_result_storage(prepared, *call_id),
                    },
                );
            }
            None => {
                r2il::refusal_evidence!(
                    "summary-local",
                    "{:#x}: call {call_id:?} has no direct target",
                    function.entry
                );
                mark_unknown_call_effects(
                    &mut out.has_unknown_calls,
                    &mut out.arg_effects,
                    &mut out.memory_effects,
                    state_by_call.get(call_id).map(Vec::as_slice),
                );
            }
        }
    }

    for block in function.blocks() {
        for (op_idx, op) in block.ops.iter().enumerate() {
            match op {
                SSAOp::Load { addr, dst, space }
                | SSAOp::LoadLinked {
                    addr, dst, space, ..
                }
                | SSAOp::LoadGuarded {
                    addr, dst, space, ..
                } => {
                    if memory_access_is_local_stack(prepared, addr, *space) {
                        continue;
                    }
                    let location =
                        classify_memory_access_location(prepared, abi, addr, *space, dst.size);
                    out.unplaced_reach |= unplaced(&location, addr);
                    mark_location_access(&mut out, location, true, false);
                    out.memory_effects.insert(SummaryMemoryEffect {
                        kind: SummaryMemoryEffectKind::Read,
                        location,
                    });
                    if let SSAOp::LoadLinked { ordering, .. } = op {
                        out.atomic_effects.insert(SummaryAtomicEffect {
                            op: SummaryAtomicOp::LoadLinked,
                            location,
                            ordering: summary_atomic_ordering(*ordering),
                        });
                    }
                }
                SSAOp::AtomicCAS(swap) => {
                    let (addr, expected, space) = (&swap.addr, &swap.expected, swap.space);
                    let stored = bits_of_var(&swap.replacement);
                    if memory_access_is_local_stack(prepared, addr, space) {
                        out.unplaced_reach |= stored_in_frame(block.addr, op_idx, stored);
                        continue;
                    }
                    let location =
                        classify_memory_access_location(prepared, abi, addr, space, expected.size);
                    out.unplaced_reach |= unplaced(&location, addr) | stored;
                    mark_location_access(&mut out, location, true, true);
                    out.memory_effects.insert(SummaryMemoryEffect {
                        kind: SummaryMemoryEffectKind::Read,
                        location,
                    });
                    out.memory_effects.insert(SummaryMemoryEffect {
                        kind: SummaryMemoryEffectKind::Write,
                        location,
                    });
                    out.atomic_effects.insert(SummaryAtomicEffect {
                        op: SummaryAtomicOp::CompareExchange,
                        location,
                        ordering: if let SSAOp::AtomicCAS(swap) = op {
                            summary_atomic_ordering(swap.ordering)
                        } else {
                            SummaryAtomicOrdering::Unknown
                        },
                    });
                }
                SSAOp::StoreConditional {
                    addr, val, space, ..
                } => {
                    let stored = bits_of_var(val);
                    if memory_access_is_local_stack(prepared, addr, *space) {
                        out.unplaced_reach |= stored_in_frame(block.addr, op_idx, stored);
                        continue;
                    }
                    let location =
                        classify_memory_access_location(prepared, abi, addr, *space, val.size);
                    out.unplaced_reach |= unplaced(&location, addr) | stored;
                    mark_location_access(&mut out, location, true, true);
                    out.memory_effects.insert(SummaryMemoryEffect {
                        kind: SummaryMemoryEffectKind::Read,
                        location,
                    });
                    out.memory_effects.insert(SummaryMemoryEffect {
                        kind: SummaryMemoryEffectKind::Write,
                        location,
                    });
                    out.atomic_effects.insert(SummaryAtomicEffect {
                        op: SummaryAtomicOp::StoreConditional,
                        location,
                        ordering: if let SSAOp::StoreConditional { ordering, .. } = op {
                            summary_atomic_ordering(*ordering)
                        } else {
                            SummaryAtomicOrdering::Unknown
                        },
                    });
                }
                SSAOp::Fence { ordering } => {
                    out.atomic_effects.insert(SummaryAtomicEffect {
                        op: SummaryAtomicOp::Fence,
                        location: unknown_location(),
                        ordering: summary_atomic_ordering(*ordering),
                    });
                }
                SSAOp::Store { addr, val, space }
                | SSAOp::StoreGuarded {
                    addr, val, space, ..
                } => {
                    let stored = bits_of_var(val);
                    if memory_access_is_local_stack(prepared, addr, *space) {
                        out.unplaced_reach |= stored_in_frame(block.addr, op_idx, stored);
                        continue;
                    }
                    let location =
                        classify_memory_access_location(prepared, abi, addr, *space, val.size);
                    // A formal's pointer stored where this function does not
                    // own the memory has escaped: whatever reads it later can
                    // reach its object.
                    out.unplaced_reach |= unplaced(&location, addr) | stored;
                    mark_location_access(&mut out, location, false, true);
                    out.memory_effects.insert(SummaryMemoryEffect {
                        kind: SummaryMemoryEffectKind::Write,
                        location,
                    });
                }
                SSAOp::Return { target } => {
                    out.return_observations.push(classify_return_target(
                        prepared,
                        block.addr,
                        op_idx,
                        target,
                        &out.call_observations,
                    ));
                }
                SSAOp::CallOther { inputs, .. } => {
                    has_volatile_or_unknown_effects = true;
                    out.unplaced_reach |= inputs
                        .iter()
                        .map(&bits_of_var)
                        .fold(0, |left, right| left | right);
                    let args = inputs
                        .iter()
                        .map(|input| classify_var_operand(prepared, input))
                        .collect::<Vec<_>>();
                    mark_unknown_call_effects(
                        &mut out.has_unknown_calls,
                        &mut out.arg_effects,
                        &mut out.memory_effects,
                        Some(&args),
                    );
                }
                op if has_volatile_or_unknown_effect(op) => {
                    has_volatile_or_unknown_effects = true;
                    // An operation whose effect nothing describes could read
                    // or write through any register.
                    out.unplaced_reach = u64::MAX;
                    mark_unknown_call_effects(
                        &mut out.has_unknown_calls,
                        &mut out.arg_effects,
                        &mut out.memory_effects,
                        None,
                    );
                }
                _ => {}
            }
        }
    }

    if has_volatile_or_unknown_effects {
        out.return_observations.clear();
        out.return_observations
            .push(SummaryValueObservation::Unknown);
    }

    out
}

/// Keep this classification aligned with the operations for which obligation
/// collection emits `VolatileOrUnknownEffect`. None of these operations carry
/// exact preservation authority for call carriers or observable memory.
fn has_volatile_or_unknown_effect(op: &SSAOp) -> bool {
    matches!(
        op,
        SSAOp::CallOther { .. } | SSAOp::Unimplemented | SSAOp::CpuId { .. } | SSAOp::New { .. }
    )
}

fn apply_call_carrier_transfer(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    state: &mut CallCarrierMap,
    op: &SSAOp,
) {
    // A user operation writes only its named output.
    let clobbers_every_carrier = !matches!(op, SSAOp::CallOther { .. })
        && (matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. })
            || has_volatile_or_unknown_effect(op));
    if clobbers_every_carrier {
        state
            .values_mut()
            .for_each(|value| *value = CallCarrierState::Unknown);
    } else if let Some(dst) = op.dst() {
        update_call_carrier_state(prepared, abi, state, dst);
    }
}

fn memory_access_is_local_stack(prepared: &SsaArtifact, addr: &SSAVar, space: SpaceId) -> bool {
    prepared
        .object_for_var(addr, space)
        .and_then(|object| prepared.objects().object(object))
        .is_some_and(|object| {
            matches!(
                object.kind,
                ObjectKind::StackSlot { .. } | ObjectKind::FrameObject { .. }
            )
        })
}

/// A load or store the body performs, through an argument where the location is one.
fn mark_location_access(
    out: &mut LocalSummaryFacts,
    location: SummaryMemoryLocation,
    read: bool,
    write: bool,
) {
    let SummaryMemoryRegion::Arg { index } = location.region else {
        return;
    };
    out.dereferenced_args.insert(index);
    let effect = out.arg_effects.entry(index).or_default();
    if read {
        effect.mark_read();
    }
    if write {
        effect.mark_write();
    }
}

fn classify_memory_access_location(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    addr: &SSAVar,
    space: SpaceId,
    width: u32,
) -> SummaryMemoryLocation {
    if space != SpaceId::Ram {
        return unknown_location();
    }
    let Some(value_id) = prepared.graph().value_id_for_var(addr) else {
        return unknown_location();
    };
    classify_memory_access_location_value(prepared, abi, value_id, space, width)
}

/// Which of the callee's own arguments a scaling value is, if it is one.
///
/// The value is usually not the argument as it arrived: at `-O0` the index is
/// spilled to its home slot in the prologue and the indexing reads it back, so
/// the question is answered from the formal-identity fact rather than from the
/// value's storage, which is the slot's.
fn scaled_argument_index(prepared: &SsaArtifact, value: ValueId) -> Option<usize> {
    let var = prepared.value_var(value)?;
    prepared
        .function()
        .decompile_prep_facts()?
        .formal_parameter_of(var)
}

/// Where an access through `value_id` lands, as a summary region.
///
/// The address is read the way the value view reads it: a copy or a zero
/// extension is the same address (the representative and the same-integer
/// root are both asked), while a lane at an offset, a truncation or a sign
/// extension is a different value and no address the walk follows. A constant
/// displacement is followed back to its base, one step per definition --
/// definitions are acyclic outside phis, and no phi is stepped through -- so
/// the walk needs no depth bound.
fn classify_memory_access_location_value(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    value_id: ValueId,
    space: SpaceId,
    width: u32,
) -> SummaryMemoryLocation {
    let mut value = value_id;
    let mut delta = 0i64;
    loop {
        if let Some(location) = classify_address_root(prepared, abi, value, space, width) {
            let mut location = location;
            if delta != 0 {
                location.range = shifted_range(location.range, delta, width);
            }
            return location;
        }
        match displacement_step(prepared, value) {
            Some(Displacement::Base { base, offset }) => {
                let Some(next) = delta.checked_add(offset) else {
                    return unknown_location();
                };
                value = base;
                delta = next;
            }
            // A table at a constant address read at an index: the index is
            // scaled or widened from a narrower integer, which no pointer is,
            // so the constant is the object and the index a place inside it.
            Some(Displacement::IndexedGlobal { address }) => {
                return global_location(address.wrapping_add(delta as u64), None, None);
            }
            None => return unknown_location(),
        }
    }
}

/// What a value names on its own: an argument's object, a global, the heap.
fn classify_address_root(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    value_id: ValueId,
    space: SpaceId,
    width: u32,
) -> Option<SummaryMemoryLocation> {
    for candidate in address_candidates(prepared, value_id) {
        if let Some(expression) = prepared.addresses().parameter_expression(candidate) {
            let parameter = match expression
                .parameter_storage
                .and_then(|storage| abi.exact_argument_index_for_storage(storage))
            {
                Some(parameter) => parameter,
                None if abi.is_source_owned() => return Some(unknown_location()),
                None => expression.parameter,
            };
            r2il::refusal_evidence!(
                "summary-location",
                "parameter {parameter} expression for {candidate:?}: offset={} terms={:?}",
                expression.offset,
                expression.terms
            );
            if expression.terms.is_empty() {
                return Some(arg_location(
                    parameter,
                    Some(expression.offset),
                    Some(width),
                ));
            }
            // One term scaled by another argument is an indexed read of what
            // this one points at, and the stride is the fact the caller needs:
            // it knows what it passed for the index and so how far the read
            // goes. Discarding it left the reach merely "through argument n".
            if let [term] = expression.terms.as_slice()
                && let Some(index) = scaled_argument_index(prepared, term.value)
            {
                return Some(scaled_arg_location(
                    parameter,
                    SummaryScaledOffset {
                        argument: index,
                        stride: term.coefficient,
                    },
                    expression.offset,
                    Some(width),
                ));
            }
            return Some(arg_location(parameter, None, None));
        }
        if let Some(address) = crate::constant::value_of(prepared.graph(), candidate) {
            return Some(global_location(address, Some(0), Some(width)));
        }
        let Some(object) = prepared
            .objects()
            .object_for_value(candidate, space)
            .and_then(|object| prepared.objects().object(object))
        else {
            continue;
        };
        match object.kind {
            ObjectKind::Parameter { index, .. } => {
                if abi.is_source_owned() {
                    return Some(unknown_location());
                }
                return Some(arg_location(index, None, None));
            }
            ObjectKind::Global { address, .. } => {
                return Some(global_location(address, Some(0), Some(width)));
            }
            ObjectKind::HeapAlloc { .. } => {
                return Some(SummaryMemoryLocation {
                    region: SummaryMemoryRegion::HeapReturn,
                    range: exact_range(0, width),
                });
            }
            _ => {}
        }
    }
    None
}

/// The values that are `value_id`'s address: itself, its same-bits
/// representative, and the value it zero-extends.
fn address_candidates(prepared: &SsaArtifact, value_id: ValueId) -> Vec<ValueId> {
    let mut candidates = vec![value_id];
    let graph = prepared.graph();
    if let (Some(facts), Some(var)) = (
        prepared.function().decompile_prep_facts(),
        prepared.value_var(value_id),
    ) {
        for root in [facts.canonical_root(var), facts.same_integer_root(var)] {
            if let Some(root) = graph.value_id_for_var(root)
                && !candidates.contains(&root)
            {
                candidates.push(root);
            }
        }
    }
    candidates
}

/// One constant displacement an address is formed by.
enum Displacement {
    /// `base + offset`.
    Base { base: ValueId, offset: i64 },
    /// A constant address plus an index that is no pointer.
    IndexedGlobal { address: u64 },
}

fn displacement_step(prepared: &SsaArtifact, value_id: ValueId) -> Option<Displacement> {
    let graph = prepared.graph();
    let (inst, op) = address_candidates(prepared, value_id)
        .into_iter()
        .find_map(|candidate| {
            let inst = graph.inst(graph.def_inst(candidate)?)?;
            match &inst.payload {
                InstPayload::Op(op) => Some((inst, op)),
                InstPayload::Phi { .. } => None,
            }
        })?;
    let (sign, scale) = match op {
        SSAOp::IntAdd { .. } => (1i64, 1i64),
        SSAOp::IntSub { .. } => (-1, 1),
        SSAOp::PtrAdd { element_size, .. } => (1, i64::from(*element_size)),
        SSAOp::PtrSub { element_size, .. } => (-1, i64::from(*element_size)),
        _ => return None,
    };
    let (&left, &right) = (inst.inputs.first()?, inst.inputs.get(1)?);
    let constant = |value| summary_const_value(prepared, value);
    let offset = |k: u64| (k as i64).checked_mul(scale)?.checked_mul(sign);
    match (constant(left), constant(right)) {
        (_, Some(k)) if constant(left).is_none() => Some(Displacement::Base {
            base: left,
            offset: offset(k)?,
        }),
        (Some(k), None) if sign > 0 && scale == 1 && is_an_index(prepared, right) => {
            Some(Displacement::IndexedGlobal { address: k })
        }
        (Some(k), None) if sign > 0 => Some(Displacement::Base {
            base: right,
            offset: offset(k)?,
        }),
        _ => None,
    }
}

/// Whether a value is an integer index rather than an address: scaled by a
/// constant other than one, or widened from an integer narrower than itself.
/// A pointer is neither on any machine this lifts.
fn is_an_index(prepared: &SsaArtifact, value_id: ValueId) -> bool {
    let graph = prepared.graph();
    let Some(inst) = graph.def_inst(value_id).and_then(|inst| graph.inst(inst)) else {
        return false;
    };
    let InstPayload::Op(op) = &inst.payload else {
        return false;
    };
    let constant = |index: usize| {
        inst.inputs
            .get(index)
            .and_then(|value| summary_const_value(prepared, *value))
    };
    match op {
        SSAOp::IntMult { .. } => [constant(0), constant(1)]
            .into_iter()
            .flatten()
            .any(|factor| factor > 1),
        SSAOp::IntLeft { .. } => constant(1).is_some_and(|places| places > 0),
        SSAOp::IntZExt { dst, src } | SSAOp::IntSExt { dst, src } => src.size < dst.size,
        _ => false,
    }
}

fn summary_const_value(prepared: &SsaArtifact, value_id: ValueId) -> Option<u64> {
    match classify_value_operand(prepared, value_id) {
        SummaryOperand::Const(value) => Some(value),
        _ => None,
    }
}

/// The iterations this dataflow can take, from the data rather than a guess.
///
/// The carrier lattice is flat: a cell is absent, then a specific entry
/// argument or value, then `Unknown`, and a join with anything leaves
/// `Unknown` where it is. So each of a block's carrier cells advances at most
/// twice, and the block's own in-state and out-state each appear once, which
/// is what the first pass reports as a change. Every round that reports a
/// change made at least one of those moves, so bound the rounds by how many
/// exist and add the round that reports none.
fn call_arg_state_iteration_bound(prepared: &SsaArtifact, abi: &AbiProfile) -> usize {
    let blocks = prepared.function().block_addrs().len();
    let carriers = tracked_call_carriers(prepared, abi).len();
    blocks
        .saturating_mul(carriers.saturating_mul(2).saturating_add(2))
        .saturating_add(1)
}

fn collect_call_arg_state(prepared: &SsaArtifact, abi: &AbiProfile) -> CallArgumentState {
    let bound = call_arg_state_iteration_bound(prepared, abi);
    collect_call_arg_state_with_iteration_limit(prepared, abi, bound)
}

fn collect_call_arg_state_with_iteration_limit(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    max_iterations: usize,
) -> CallArgumentState {
    let function = prepared.function();
    let tracked = tracked_call_carriers(prepared, abi);
    let entry_state = tracked
        .iter()
        .map(|carrier| {
            let CallCarrierKey::Storage(storage) = carrier;
            let value = prepared
                .machine_context()
                .abi_model()
                .argument_registers()
                .iter()
                .find(|slot| slot.storage() == *storage)
                .map(|slot| CallCarrierState::EntryArg(slot.index() as usize))
                .unwrap_or(CallCarrierState::Unknown);
            (*carrier, value)
        })
        .collect::<BTreeMap<_, _>>();
    let unknown_state = tracked
        .iter()
        .map(|storage| (*storage, CallCarrierState::Unknown))
        .collect::<BTreeMap<_, _>>();
    let mut in_states = BTreeMap::<u64, CallCarrierMap>::new();
    let mut out_states = BTreeMap::<u64, CallCarrierMap>::new();
    let mut changed = true;
    let mut iterations = 0usize;
    while changed && iterations < max_iterations.max(1) {
        iterations += 1;
        changed = false;
        for &block_addr in function.block_addrs() {
            let preds = function.predecessors(block_addr);
            let mut state = if block_addr == function.entry {
                if preds.is_empty() {
                    entry_state.clone()
                } else {
                    let merged = merge_pred_states(&out_states, &preds, &tracked);
                    merge_call_carrier_states(&entry_state, &merged, &tracked)
                }
            } else if preds.is_empty() {
                unknown_state.clone()
            } else {
                merge_pred_states(&out_states, &preds, &tracked)
            };
            let Some(block) = function.get_block(block_addr) else {
                continue;
            };
            for phi in &block.phis {
                update_call_carrier_state(prepared, abi, &mut state, &phi.dst);
            }
            let old = in_states.insert(block_addr, state.clone());
            if old.as_ref() != Some(&state) {
                changed = true;
            }

            for op in &block.ops {
                apply_call_carrier_transfer(prepared, abi, &mut state, op);
            }
            let new_state = state;
            let old = out_states.insert(block_addr, new_state.clone());
            if old.as_ref() != Some(&new_state) {
                changed = true;
            }
        }
    }

    if changed {
        return unknown_call_argument_state(prepared, abi, false);
    }

    let mut by_call = BTreeMap::new();
    for (&call_id, call) in &prepared.call_sites().by_id {
        let Some((block_addr, call_op_idx)) = prepared.inst_op_site(call.at) else {
            continue;
        };
        let Some(block) = function.get_block(block_addr) else {
            continue;
        };
        let mut state = in_states.get(&block_addr).cloned().unwrap_or_default();
        for phi in &block.phis {
            update_call_carrier_state(prepared, abi, &mut state, &phi.dst);
        }
        for (op_idx, op) in block.ops.iter().enumerate() {
            if op_idx == call_op_idx {
                let args = call_argument_carriers(prepared, abi, call_id)
                    .map(|carriers| {
                        carriers
                            .into_iter()
                            .map(|carrier| match state.get(&carrier) {
                                Some(CallCarrierState::EntryArg(index)) => {
                                    SummaryOperand::Arg(*index)
                                }
                                Some(CallCarrierState::Value(value_id)) => {
                                    classify_value_operand(prepared, *value_id)
                                }
                                Some(CallCarrierState::Unknown) | None => SummaryOperand::Unknown,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|| unknown_call_arguments(prepared, abi, call_id));
                by_call.insert(call_id, args);
                break;
            }
            apply_call_carrier_transfer(prepared, abi, &mut state, op);
        }
    }

    for call_id in prepared.call_sites().by_id.keys() {
        by_call
            .entry(*call_id)
            .or_insert_with(|| unknown_call_arguments(prepared, abi, *call_id));
    }

    CallArgumentState {
        by_call,
        converged: true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallCarrierState {
    EntryArg(usize),
    Value(ValueId),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CallCarrierKey {
    Storage(crate::CanonicalStorageId),
}

type CallCarrierMap = BTreeMap<CallCarrierKey, CallCarrierState>;

fn tracked_call_carriers(prepared: &SsaArtifact, abi: &AbiProfile) -> BTreeSet<CallCarrierKey> {
    if !abi.is_source_owned() {
        return BTreeSet::new();
    }
    prepared
        .machine_context()
        .abi_model()
        .argument_registers()
        .iter()
        .map(|slot| CallCarrierKey::Storage(slot.storage()))
        .chain(
            prepared
                .machine_context()
                .call_site_interfaces()
                .values()
                .flat_map(|interface| interface.arguments())
                .filter_map(|argument| argument.register_storage().map(CallCarrierKey::Storage)),
        )
        .collect()
}

fn storages_overlap(left: crate::CanonicalStorageId, right: crate::CanonicalStorageId) -> bool {
    if left.space != right.space || left.size == 0 || right.size == 0 {
        return false;
    }
    left.offset
        .checked_add(u64::from(left.size))
        .zip(right.offset.checked_add(u64::from(right.size)))
        .is_none_or(|(left_end, right_end)| left.offset < right_end && right.offset < left_end)
}

fn update_call_carrier_state(
    prepared: &SsaArtifact,
    _abi: &AbiProfile,
    state: &mut CallCarrierMap,
    var: &SSAVar,
) {
    let Some(value_id) = prepared.graph().value_id_for_var(var) else {
        return;
    };
    let storage = prepared
        .graph()
        .value(value_id)
        .and_then(|value| value.canonical_storage);
    for (carrier, value) in state.iter_mut() {
        match *carrier {
            CallCarrierKey::Storage(carrier) => {
                if storage == Some(carrier) {
                    *value = CallCarrierState::Value(value_id);
                } else if storage.is_some_and(|storage| storages_overlap(carrier, storage)) {
                    *value = CallCarrierState::Unknown;
                }
            }
        }
    }
}

fn call_argument_carriers(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    call_id: CallSiteId,
) -> Option<Vec<CallCarrierKey>> {
    if !abi.is_source_owned() {
        return None;
    }
    let interface = prepared.call_site_interface(call_id)?;
    interface.is_complete().then(|| {
        interface
            .arguments()
            .iter()
            .filter_map(|argument| argument.register_storage().map(CallCarrierKey::Storage))
            .collect()
    })
}

fn unknown_call_arguments(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
    call_id: CallSiteId,
) -> Vec<SummaryOperand> {
    let count = prepared
        .call_site_interface(call_id)
        .map(|interface| interface.arguments().len())
        .unwrap_or_else(|| abi.argument_count());
    (0..count).map(|_| SummaryOperand::Unknown).collect()
}

pub fn observe_call_arguments(
    prepared: &SsaArtifact,
    abi: &AbiProfile,
) -> BTreeMap<CallSiteId, Vec<CallArgObservation>> {
    collect_call_arg_state(prepared, abi)
        .by_call
        .into_iter()
        .map(|(call_id, args)| {
            let args = args
                .into_iter()
                .map(|arg| match arg {
                    SummaryOperand::Arg(idx) => CallArgObservation::Arg(idx),
                    SummaryOperand::Const(value) => CallArgObservation::Const(value),
                    SummaryOperand::Unknown => CallArgObservation::Unknown,
                })
                .collect();
            (call_id, args)
        })
        .collect()
}

fn merge_pred_states(
    in_states: &BTreeMap<u64, CallCarrierMap>,
    preds: &[u64],
    tracked: &BTreeSet<CallCarrierKey>,
) -> CallCarrierMap {
    let unknown = tracked
        .iter()
        .map(|storage| (*storage, CallCarrierState::Unknown))
        .collect::<CallCarrierMap>();
    let mut states = preds
        .iter()
        .map(|pred| in_states.get(pred).unwrap_or(&unknown));
    let Some(first) = states.next() else {
        return unknown;
    };
    states.fold(first.clone(), |merged, state| {
        merge_call_carrier_states(&merged, state, tracked)
    })
}

fn merge_call_carrier_states(
    left: &CallCarrierMap,
    right: &CallCarrierMap,
    tracked: &BTreeSet<CallCarrierKey>,
) -> CallCarrierMap {
    tracked
        .iter()
        .map(|storage| {
            let left = left
                .get(storage)
                .copied()
                .unwrap_or(CallCarrierState::Unknown);
            let right = right
                .get(storage)
                .copied()
                .unwrap_or(CallCarrierState::Unknown);
            (
                *storage,
                if left == right {
                    left
                } else {
                    CallCarrierState::Unknown
                },
            )
        })
        .collect()
}

fn classify_return_target(
    prepared: &SsaArtifact,
    block_addr: u64,
    return_op_idx: usize,
    target: &SSAVar,
    calls: &BTreeMap<CallSiteId, CallObservation>,
) -> SummaryValueObservation {
    if let Some(return_inst) = exact_return_address_use(prepared, block_addr, return_op_idx, target)
        && let Some(observation) = exact_return_boundary_observation(prepared, return_inst, calls)
    {
        return observation;
    }
    match classify_var_operand(prepared, target) {
        SummaryOperand::Arg(idx) => SummaryValueObservation::Arg(idx),
        SummaryOperand::Const(value) => SummaryValueObservation::Const(value),
        SummaryOperand::Unknown => SummaryValueObservation::Unknown,
    }
}

fn exact_return_address_use(
    prepared: &SsaArtifact,
    block_addr: u64,
    return_op_idx: usize,
    target: &SSAVar,
) -> Option<crate::graph::InstId> {
    let graph = prepared.graph();
    let inst = graph.inst_id_for_op_site(block_addr, return_op_idx)?;
    let boundary = prepared.facts().boundaries.returns.get(&inst)?;
    let return_address = boundary.return_address?;
    let target_value = graph.value_id_for_var(target)?;
    let use_site = UseSite { inst, input_idx: 0 };
    (return_address.value == target_value
        && graph
            .inst(inst)
            .and_then(|return_inst| return_inst.inputs.first())
            == Some(&target_value)
        && graph.use_sites(target_value).contains(&use_site))
    .then_some(inst)
}

fn exact_return_boundary_observation(
    prepared: &SsaArtifact,
    return_inst: crate::graph::InstId,
    calls: &BTreeMap<CallSiteId, CallObservation>,
) -> Option<SummaryValueObservation> {
    let expected_storage = exact_function_return_storage(prepared)?;
    let boundary = prepared.facts().boundaries.returns.get(&return_inst)?;
    if !boundary.complete {
        return None;
    }
    let values = boundary
        .values
        .iter()
        .filter_map(|value| match value.slot {
            crate::semantic::CallBoundarySlot::Register { storage, .. }
                if storage == expected_storage =>
            {
                Some(value.value)
            }
            crate::semantic::CallBoundarySlot::Register { .. }
            | crate::semantic::CallBoundarySlot::Stack(_) => None,
        })
        .collect::<Vec<_>>();
    let [value] = values.as_slice() else {
        return None;
    };
    Some(classify_value_observation(prepared, *value, calls))
}

fn classify_value_observation(
    prepared: &SsaArtifact,
    value_id: ValueId,
    calls: &BTreeMap<CallSiteId, CallObservation>,
) -> SummaryValueObservation {
    match classify_value_operand(prepared, value_id) {
        SummaryOperand::Arg(idx) => SummaryValueObservation::Arg(idx),
        SummaryOperand::Const(value) => SummaryValueObservation::Const(value),
        SummaryOperand::Unknown => {
            if let Some(call_id) = return_call_site_for_value(prepared, value_id, calls)
                && let Some(call) = calls.get(&call_id)
            {
                SummaryValueObservation::Call(call.clone())
            } else if let Some(address) = global_address_for_value_id(prepared, value_id) {
                SummaryValueObservation::Global(address)
            } else {
                SummaryValueObservation::Unknown
            }
        }
    }
}

fn return_call_site_for_value(
    prepared: &SsaArtifact,
    value_id: ValueId,
    calls: &BTreeMap<CallSiteId, CallObservation>,
) -> Option<CallSiteId> {
    let single_call_site = || {
        (prepared.call_sites().by_id.len() == 1)
            .then(|| prepared.call_sites().by_id.keys().next().copied())
            .flatten()
    };
    let graph = prepared.graph();
    let return_storage = exact_function_return_storage(prepared)?;
    if graph.value(value_id)?.canonical_storage != Some(return_storage) {
        return None;
    }

    let exact_result_matches = |call_site: CallSiteId| {
        let result = calls.get(&call_site)?.result_storage?;
        let value_storage = graph.value(value_id)?.canonical_storage?;
        (result == value_storage).then_some(call_site)
    };

    let Some(def_inst) = graph.def_inst(value_id) else {
        return single_call_site().and_then(exact_result_matches);
    };
    let Some(inst) = graph.inst(def_inst) else {
        return single_call_site().and_then(exact_result_matches);
    };
    let Some(block) = graph.blocks.get(inst.block.0 as usize) else {
        return single_call_site().and_then(exact_result_matches);
    };
    let Some(inst_pos) = block.insts.iter().position(|id| *id == def_inst) else {
        return single_call_site().and_then(exact_result_matches);
    };

    for scan_pos in (0..=inst_pos).rev() {
        let scan_inst_id = block.insts[scan_pos];
        let Some(scan_inst) = graph.inst(scan_inst_id) else {
            continue;
        };
        let InstPayload::Op(op) = &scan_inst.payload else {
            continue;
        };
        match op {
            SSAOp::Call { .. } | SSAOp::CallInd { .. } => {
                return prepared
                    .call_sites()
                    .by_inst
                    .get(&scan_inst_id)
                    .copied()
                    .and_then(exact_result_matches);
            }
            SSAOp::CallDefine { .. } => continue,
            _ => break,
        }
    }

    single_call_site().and_then(exact_result_matches)
}

/// What a summary says an operand is: a constant, an argument, or neither.
///
/// Both questions are already answered once during preparation. A constant is
/// what the value folds to. An argument is what the address facts propagated:
/// they carry a parameter through copies, widenings, same-width lane
/// projections, spill slots and affine arithmetic, which is exactly the
/// derivation this used to re-walk here with its own depth limit and its own
/// op set.
fn classify_var_operand(prepared: &SsaArtifact, var: &SSAVar) -> SummaryOperand {
    let Some(value_id) = prepared.graph().value_id_for_var(var) else {
        return SummaryOperand::Unknown;
    };
    classify_value_operand(prepared, value_id)
}

fn classify_value_operand(prepared: &SsaArtifact, value_id: ValueId) -> SummaryOperand {
    let rooted = canonical_root_value(prepared, value_id);
    for candidate in [value_id, rooted] {
        if let Some(bits) = crate::constant::folded_value(prepared.graph(), candidate) {
            return SummaryOperand::Const(bits);
        }
        if let Some(expression) = prepared.addresses().parameter_expression(candidate) {
            return SummaryOperand::Arg(expression.parameter);
        }
    }
    SummaryOperand::Unknown
}

fn canonical_root_value(prepared: &SsaArtifact, value_id: ValueId) -> ValueId {
    crate::function::canonical_root_value_id(prepared, value_id)
}

fn global_address_for_value_id(prepared: &SsaArtifact, value_id: ValueId) -> Option<u64> {
    let object = prepared
        .objects()
        .object_for_value(value_id, SpaceId::Ram)?;
    let object = prepared.objects().object(object)?;
    match object.kind {
        ObjectKind::Global { address, .. } => Some(address),
        _ => None,
    }
}

/// The name the program links against, with radare2's namespace removed.
fn import_basename(name: &str) -> &str {
    let mut bare = name.trim();
    for prefix in ["sym.imp.", "sym.", "imp.", "reloc.", "dbg."] {
        while let Some(rest) = bare.strip_prefix(prefix) {
            bare = rest;
        }
    }
    bare.split_once('@').map_or(bare, |(base, _)| base)
}

fn normalize_seed_name(name: &str) -> Option<&'static str> {
    let normalized_owned = name.trim().to_ascii_lowercase();
    let mut normalized = normalized_owned.as_str();
    let has_external_marker = ["sym.imp.", "imp.", "reloc."]
        .iter()
        .any(|prefix| normalized.strip_prefix(prefix).is_some())
        || normalized.ends_with("@plt")
        || normalized.ends_with(".plt");
    if !has_external_marker {
        return None;
    }
    for prefix in ["sym.imp.", "sym.", "imp.", "reloc.", "dbg."] {
        while let Some(rest) = normalized.strip_prefix(prefix) {
            normalized = rest;
        }
    }
    while let Some(rest) = normalized.strip_suffix("@plt") {
        normalized = rest;
    }
    while let Some(rest) = normalized.strip_suffix(".plt") {
        normalized = rest;
    }
    if let Some((base, _)) = normalized.split_once('@') {
        normalized = base;
    }
    if let Some(rest) = normalized.strip_prefix("__isoc99_") {
        normalized = rest;
    }
    if let Some(rest) = normalized.strip_prefix("__gi_") {
        normalized = rest;
    }
    while let Some(rest) = normalized.strip_prefix('_') {
        normalized = rest;
    }
    match normalized {
        // Names arrive with their leading underscores already stripped, so
        // the fortified variants match by their bare spelling. Those that keep
        // the plain layout share a model; the ones that insert the object size
        // before the length get their own.
        "strlen" | "strlen_chk" => Some("strlen"),
        "strcmp" => Some("strcmp"),
        "memcmp" => Some("memcmp"),
        "memcpy" => Some("memcpy"),
        "memmove" => Some("memmove"),
        "copyin" => Some("copyin"),
        "copyout" => Some("copyout"),
        "memset" => Some("memset"),
        "snprintf" => Some("snprintf"),
        "vsnprintf" => Some("vsnprintf"),
        "snprintf_chk" | "vsnprintf_chk" => Some("snprintf_chk"),
        "strncpy" => Some("strncpy"),
        "malloc" | "__libc_malloc" | "__gi___libc_malloc" => Some("malloc"),
        "calloc" | "__libc_calloc" => Some("calloc"),
        "free" => Some("free"),
        "os_ref_retain" | "osobject_retain" => Some("retain"),
        "os_ref_release" | "osobject_release" => Some("release"),
        "lck_mtx_lock" | "lck_rw_lock_shared" | "lck_rw_lock_exclusive" => Some("lock"),
        "lck_mtx_unlock" | "lck_rw_unlock_shared" | "lck_rw_unlock_exclusive" => Some("unlock"),
        "puts" => Some("puts"),
        "printf" | "__printf_chk" => Some("printf"),
        "exit" | "_exit" => Some("exit"),
        _ => None,
    }
}
