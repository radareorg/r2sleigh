//! Ownership-safe machine expression representation.
//!
//! This module is the semantic boundary between prepared SSA and renderers. It
//! deliberately excludes presentation names and output-tree positions. Source
//! values are identified by artifact-local [`ValueId`] plus an explicit width;
//! persistent provenance is carried by canonical instruction and obligation IDs.

mod lowering;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::function::{SsaArtifact, StackAddressBase};
use crate::graph::{
    BlockId, GraphInst, GraphValue, InstId, InstPayload, SsaGraph, UseSite, ValueId,
};
use crate::machine_context::{MachineMemoryEndianness, MachineRegisterGeometryState};
use crate::obligation::CanonicalInstructionId;
use crate::op::SSAOp;
use crate::semantic::{
    ObjectId, ObjectKind, ObjectModel, StructuredAccessId, StructuredMemoryAccessFact,
};
use crate::{CanonicalStorageId, CanonicalStorageSpace};

fn memory_access_authorities_match(
    graph: &SsaGraph,
    objects: &ObjectModel,
    graph_op: &SSAOp,
    prepared_op: &SSAOp,
    context_space: r2il::SpaceId,
    fact: &StructuredMemoryAccessFact,
    member_run: Option<&crate::MemberRunStoreCertificate>,
) -> bool {
    // A decomposed wide store is one access per member, so the ordinal picks
    // the member rather than being the store's only access.
    let member =
        member_run.and_then(|run| run.members.iter().find(|member| member.access == fact.id));
    // Each term names a different layer to look at, so each says so.
    let no = |why: &str| {
        r2il::refusal_evidence!("memory-access-authority", "{:?}: {why}", fact.id);
        false
    };
    if graph.op_site_for_inst(fact.id.inst) != Some((fact.block_addr, fact.op_index)) {
        return no("the instruction does not stand where the access says");
    }
    // A conditional store performs two: it reads to test the monitor and
    // writes where the monitor held, and both are its own.
    let records_several = matches!(graph_op, SSAOp::StoreConditional { .. });
    if fact.id.ordinal != 0 && member.is_none() && !records_several {
        return no("a later access of an instruction that stores no member run");
    }
    if fact.space != context_space {
        return no("the access and the context name different spaces");
    }
    if graph
        .inst(fact.id.inst)
        .is_none_or(|inst| !matches!(&inst.payload, InstPayload::Op(op) if op == graph_op))
    {
        return no("the graph instruction is not this operation");
    }
    if graph_op != prepared_op {
        return no("the graph and the prepared function spell it differently");
    }
    if graph_op.memory_space() != Some(context_space) {
        return no("the operation names another space than the context");
    }
    if objects.object_for_value(fact.address, context_space) != Some(fact.object) {
        return no("the address reaches another object than the access names");
    }
    if objects
        .object(fact.object)
        .is_none_or(|object| object.kind.space() != context_space)
    {
        return no("the object is not in this space");
    }

    match graph_op {
        SSAOp::Load { dst, addr, .. }
        | SSAOp::LoadLinked { dst, addr, .. }
        | SSAOp::LoadGuarded { dst, addr, .. } => {
            !fact.is_write
                && graph.value_id_for_var(addr) == Some(fact.address)
                && fact.value == graph.value_id_for_var(dst)
                && fact.width == dst.size
        }
        // A conditional store reads to test the monitor and writes where the
        // monitor held. The read names no value, because what it reads is not
        // a value the program takes; the write names what was stored.
        SSAOp::StoreConditional { addr, val, .. } => {
            graph.value_id_for_var(addr) == Some(fact.address)
                && fact.width == val.size
                && match fact.is_write {
                    false => fact.id.ordinal == 0 && fact.value.is_none(),
                    true => fact.id.ordinal == 1 && fact.value == graph.value_id_for_var(val),
                }
        }
        SSAOp::StoreGuarded { addr, val, .. } => {
            fact.is_write
                && graph.value_id_for_var(addr) == Some(fact.address)
                && fact.value == graph.value_id_for_var(val)
                && fact.width == val.size
        }
        SSAOp::Store { addr, val, .. } => {
            let addressed = fact.is_write && graph.value_id_for_var(addr) == Some(fact.address);
            match member {
                Some(member) => {
                    let lane = match member.source {
                        crate::MemberRunSource::Constant(_) => None,
                        crate::MemberRunSource::Lane(value) => Some(value),
                    };
                    addressed
                        && fact.value == lane
                        && fact.width == member.width
                        && fact.object_offset == i64::try_from(member.offset).ok()
                        && member_run.is_some_and(|run| {
                            run.address == fact.address
                                && Some(run.value) == graph.value_id_for_var(val)
                                && run.object == fact.object
                        })
                }
                None => {
                    addressed && fact.value == graph.value_id_for_var(val) && fact.width == val.size
                }
            }
        }
        _ => false,
    }
}

/// Whether a read names exactly the operands its kind has.
///
/// A plain or linked read names its address and nothing else; a guarded one
/// names its condition after it.
fn read_operands_are_exact(op: Option<&SSAOp>, inputs: &[ValueId], address: ValueId) -> bool {
    match op {
        Some(SSAOp::LoadGuarded { .. }) => inputs.len() == 2 && inputs.first() == Some(&address),
        Some(_) => inputs == [address],
        None => false,
    }
}

/// The operation an instruction performs, where it performs one.
fn source_op_of(inst: &GraphInst) -> Option<&SSAOp> {
    match &inst.payload {
        InstPayload::Op(op) => Some(op),
        InstPayload::Phi { .. } => None,
    }
}

/// Opaque, artifact-local handle into a [`MachineExprArena`].
///
/// This is an ownership handle, not a persistent semantic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MachineExprId(u32);

impl MachineExprId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Name-independent reference to one prepared SSA value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MachineValueBinding {
    value: ValueId,
    width_bits: u32,
}

impl MachineValueBinding {
    pub const fn value(self) -> ValueId {
        self.value
    }

    pub const fn width_bits(self) -> u32 {
        self.width_bits
    }
}

/// Exact geometry of one register-backed SSA value in its canonical carrier.
///
/// The carrier is retained as source-owned storage, not reconstructed from a
/// register spelling. Its location is derived from that storage so the two
/// answers cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MachineRegisterValueGeometry {
    carrier: CanonicalStorageId,
    bit_offset: u32,
    value_width_bits: u32,
    carrier_width_bits: u32,
}

impl MachineRegisterValueGeometry {
    pub const fn carrier_storage(self) -> CanonicalStorageId {
        self.carrier
    }

    pub const fn carrier_location(self) -> r2source::CanonicalLocation {
        self.carrier.location()
    }

    pub const fn bit_offset(self) -> u32 {
        self.bit_offset
    }

    pub const fn value_width_bits(self) -> u32 {
        self.value_width_bits
    }

    pub const fn carrier_width_bits(self) -> u32 {
        self.carrier_width_bits
    }
}

/// Exact direct geometry for a value that is not register-backed.
///
/// Synthetic SSA values have no source storage, but still receive this explicit
/// disposition and width. `None` therefore means "source-owned direct value
/// without storage", never "geometry was not computed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MachineDirectValueGeometry {
    storage: Option<CanonicalStorageId>,
    value_width_bits: u32,
}

impl MachineDirectValueGeometry {
    pub const fn storage(self) -> Option<CanonicalStorageId> {
        self.storage
    }

    pub const fn location(self) -> Option<r2source::CanonicalLocation> {
        match self.storage {
            Some(storage) => Some(storage.location()),
            None => None,
        }
    }

    pub const fn value_width_bits(self) -> u32 {
        self.value_width_bits
    }
}

/// Why one register-backed value has no honest canonical-carrier geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineValueGeometryRefusal {
    MissingRegisterGeometry,
    MalformedRegisterGeometry,
    RegisterGeometry(r2il::RegisterProjectionRefusal),
    InvalidBitRange,
}

/// Complete dense geometry disposition for one [`ValueId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineValueGeometryDisposition {
    ExactRegister(MachineRegisterValueGeometry),
    Direct(MachineDirectValueGeometry),
    Refused(MachineValueGeometryRefusal),
}

/// Exact use of one artifact-local machine value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MachineValueUse {
    binding: MachineValueBinding,
    ty: MachineType,
    constant: Option<MachineBitVector>,
    producer: Option<CanonicalInstructionId>,
    memory_access: Option<StructuredAccessId>,
}

impl MachineValueUse {
    pub fn from_artifact(
        artifact: &SsaArtifact,
        value: ValueId,
    ) -> Result<Self, MachineBuildError> {
        let graph_value = artifact
            .graph()
            .value(value)
            .ok_or(MachineBuildError::MissingGraphValue(value))?;
        let binding = binding_for_value(graph_value)?;
        Self::from_artifact_with_type(
            artifact,
            value,
            integer_type(binding.width_bits, MachineSignedness::Unsigned),
            None,
        )
    }

    /// Derive the exact typed address use for one structured memory access.
    pub fn memory_address_for_access(
        artifact: &SsaArtifact,
        access: StructuredAccessId,
    ) -> Result<Self, MachineBuildError> {
        let fact = artifact
            .facts()
            .structured
            .memory_accesses
            .get(&access)
            .filter(|fact| {
                fact.id == access
                    && fact.provenance_complete
                    && artifact.graph().op_site_for_inst(access.inst)
                        == Some((fact.block_addr, fact.op_index))
                    && artifact.objects().object(fact.object).is_some()
            })
            .ok_or_else(|| {
                // Which of the four terms failed is which layer to look at.
                let fact = artifact.facts().structured.memory_accesses.get(&access);
                r2il::refusal_evidence!(
                    "memory-access-entity",
                    "{access:?}: fact={:?} site={:?} object_known={}",
                    fact.map(|fact| (fact.block_addr, fact.op_index, fact.provenance_complete)),
                    artifact.graph().op_site_for_inst(access.inst),
                    fact.is_some_and(|fact| artifact.objects().object(fact.object).is_some())
                );
                MachineBuildError::EntityMismatch(access.inst)
            })?;
        let source_space = artifact
            .machine_context()
            .memory_space_at(fact.block_addr, fact.op_index)
            .ok_or(MachineBuildError::MachineContextMismatch)?;
        let source_op = match &artifact
            .graph()
            .inst(access.inst)
            .ok_or(MachineBuildError::EntityMismatch(access.inst))?
            .payload
        {
            InstPayload::Op(op) => op,
            _ => return Err(MachineBuildError::EntityMismatch(access.inst)),
        };
        let prepared_op = artifact
            .function()
            .get_block(fact.block_addr)
            .and_then(|block| block.ops.get(fact.op_index))
            .ok_or_else(|| {
                r2il::refusal_evidence!(
                    "memory-access-entity",
                    "{access:?}: no prepared operation at {:#x}:{}",
                    fact.block_addr,
                    fact.op_index
                );
                MachineBuildError::EntityMismatch(access.inst)
            })?;
        if !memory_access_authorities_match(
            artifact.graph(),
            artifact.objects(),
            source_op,
            prepared_op,
            source_space,
            fact,
            artifact
                .facts()
                .structured
                .member_run_stores
                .get(&access.inst),
        ) {
            r2il::refusal_evidence!(
                "memory-access-entity",
                "{access:?}: {source_op:?} and the access at {:#x}:{} do not describe one another",
                fact.block_addr,
                fact.op_index
            );
            return Err(MachineBuildError::EntityMismatch(access.inst));
        }
        let model = artifact.machine_context().memory_model();
        let space_model = model
            .space(source_space)
            .filter(|space| {
                model.is_available()
                    && model.is_coherent()
                    && space.address_bits() > 0
                    && space.word_size_bytes() > 0
            })
            .ok_or(MachineBuildError::MachineContextMismatch)?;
        let space = MachineAddressSpace::from(source_space);
        Self::from_artifact_with_type(
            artifact,
            fact.address,
            MachineType::Address {
                width_bits: space_model.address_bits(),
                space,
                provenance: machine_address_provenance(artifact, fact.object),
            },
            Some(access),
        )
    }

    /// Derive the exact typed address projection for one graph use.
    ///
    /// Memory operands are contextual: the same SSA value is an integer in an
    /// arithmetic use but an address with object provenance at a certified
    /// load/store use. Keeping this lookup keyed by [`UseSite`] prevents a
    /// renderer from classifying `rsp`/`rbp` spellings or applying one address
    /// interpretation to every use of the value.
    pub fn memory_address_for_use(
        artifact: &SsaArtifact,
        site: UseSite,
    ) -> Result<Option<Self>, MachineBuildError> {
        let inst = artifact
            .graph()
            .inst(site.inst)
            .ok_or(MachineBuildError::MissingUseDisposition(site))?;
        let used_value = *inst
            .inputs
            .get(site.input_idx)
            .ok_or(MachineBuildError::MissingUseDisposition(site))?;
        let is_memory_address = site.input_idx == 0
            && matches!(
                &inst.payload,
                InstPayload::Op(SSAOp::Load { .. } | SSAOp::Store { .. })
            );
        if !is_memory_address {
            return Ok(None);
        }
        let access = StructuredAccessId {
            inst: site.inst,
            ordinal: 0,
        };
        let projected = Self::memory_address_for_access(artifact, access)?;
        if projected.binding().value() != used_value || projected.memory_access() != Some(access) {
            return Err(MachineBuildError::UseDispositionMismatch(site));
        }
        Ok(Some(projected))
    }

    fn from_artifact_with_type(
        artifact: &SsaArtifact,
        value: ValueId,
        ty: MachineType,
        memory_access: Option<StructuredAccessId>,
    ) -> Result<Self, MachineBuildError> {
        let graph_value = artifact
            .graph()
            .value(value)
            .ok_or(MachineBuildError::MissingGraphValue(value))?;
        let binding = binding_for_value(graph_value)?;
        if binding.width_bits != ty.width_bits() {
            return Err(MachineBuildError::InvalidExpressionType {
                expr: MachineExprId(u32::MAX),
            });
        }
        let constant = graph_value
            .var
            .constant_bits()
            .map(|bits| bit_vector(value, binding.width_bits, bits))
            .transpose()?;
        let producer = artifact
            .graph()
            .def_inst(value)
            .map(|inst| {
                artifact
                    .obligations()
                    .instruction_for_inst(inst)
                    .map(|instruction| instruction.id)
                    .ok_or(MachineBuildError::MissingInstructionDisposition(inst))
            })
            .transpose()?;
        Ok(Self {
            binding,
            ty,
            constant,
            producer,
            memory_access,
        })
    }

    pub const fn binding(&self) -> MachineValueBinding {
        self.binding
    }

    pub const fn ty(&self) -> &MachineType {
        &self.ty
    }

    pub const fn constant(&self) -> Option<MachineBitVector> {
        self.constant
    }

    pub const fn producer(&self) -> Option<CanonicalInstructionId> {
        self.producer
    }

    pub const fn memory_access(&self) -> Option<StructuredAccessId> {
        self.memory_access
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineSignedness {
    Unsigned,
    Signed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineAddressSpace {
    Ram,
    Register,
    Unique,
    Constant,
    Custom(u32),
}

impl From<r2il::SpaceId> for MachineAddressSpace {
    fn from(space: r2il::SpaceId) -> Self {
        match space {
            r2il::SpaceId::Ram => Self::Ram,
            r2il::SpaceId::Register => Self::Register,
            r2il::SpaceId::Unique => Self::Unique,
            r2il::SpaceId::Const => Self::Constant,
            r2il::SpaceId::Custom(id) => Self::Custom(id),
        }
    }
}

/// Prepared origin annotation for an address value.
///
/// This is not standalone lvalue or memory-access proof. Object association is
/// artifact-local and certification must additionally validate the exact
/// structured access, typed address space, and machine-memory policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineAddressProvenance {
    Unknown,
    Parameter { index: u32 },
    Stack { base: MachineStackBase, offset: i64 },
    Global { address: u64 },
    Derived { base: MachineValueBinding },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineStackBase {
    FramePointer,
    StackPointer,
    Realigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineType {
    Bool {
        storage_bits: u32,
    },
    Integer {
        width_bits: u32,
        signedness: MachineSignedness,
    },
    Address {
        width_bits: u32,
        space: MachineAddressSpace,
        provenance: MachineAddressProvenance,
    },
    /// An IEEE binary32 or binary64 value.
    Float {
        width_bits: u32,
    },
}

impl MachineType {
    pub const fn width_bits(&self) -> u32 {
        match self {
            Self::Bool { storage_bits } => *storage_bits,
            Self::Integer { width_bits, .. }
            | Self::Address { width_bits, .. }
            | Self::Float { width_bits } => *width_bits,
        }
    }

    pub const fn signedness(&self) -> Option<MachineSignedness> {
        match self {
            Self::Integer { signedness, .. } => Some(*signedness),
            Self::Bool { .. } | Self::Address { .. } | Self::Float { .. } => None,
        }
    }

    pub const fn is_float(&self) -> bool {
        matches!(self, Self::Float { .. })
    }
}

/// The widths a floating value may have: the two IEEE formats C spells.
pub const fn float_width_is_supported(width_bits: u32) -> bool {
    matches!(width_bits, 32 | 64)
}

/// The widest constant a C integer literal can spell.
const MAX_SPELLABLE_CONSTANT_BITS: u32 = 128;

/// Whether a constant of this width has a C spelling.
///
/// A literal reaches 128 bits. Above that the value still has one wherever the
/// bit-vector prelude carries the width, because a `u64` payload is spelled as
/// its zero extension into the carrier -- which is exactly what a wider
/// constant in this model is: a narrow value the lift gave a wide varnode.
const fn constant_width_is_spellable(width_bits: u32) -> bool {
    width_bits <= MAX_SPELLABLE_CONSTANT_BITS || matches!(width_bits, 256 | 512)
}

/// Exact bitvector constant carried by prepared SSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MachineBitVector {
    width_bits: u32,
    bits: u64,
}

impl MachineBitVector {
    /// The widest constant whose bits this type can hold whole.
    pub const MAX_LITERAL_BITS: u32 = 64;

    /// A constant of `width_bits` holding `bits`, masked to that width.
    ///
    /// Refuses a zero width and anything wider than the bits can hold, so a
    /// caller that folds arithmetic at a width never spells a value the width
    /// cannot represent.
    pub const fn new(width_bits: u32, bits: u64) -> Option<Self> {
        if width_bits == 0 || width_bits > Self::MAX_LITERAL_BITS {
            return None;
        }
        let mask = if width_bits == Self::MAX_LITERAL_BITS {
            u64::MAX
        } else {
            (1u64 << width_bits) - 1
        };
        Some(Self {
            width_bits,
            bits: bits & mask,
        })
    }

    pub const fn zero(width_bits: u32) -> Option<Self> {
        if width_bits == 0 || !constant_width_is_spellable(width_bits) {
            return None;
        }
        Some(Self {
            width_bits,
            bits: 0,
        })
    }

    pub const fn width_bits(self) -> u32 {
        self.width_bits
    }

    pub const fn bits(self) -> u64 {
        self.bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineArithmeticOp {
    Add,
    Subtract,
    Multiply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineArithmeticMode {
    Wrapping,
    Checked,
}

/// A binary IEEE operation under the default rounding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineFloatOp {
    Add,
    Subtract,
    Multiply,
    Divide,
}

/// A unary IEEE operation; `IsNan` yields a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineFloatUnaryOp {
    Negate,
    Absolute,
    SquareRoot,
    Ceiling,
    Floor,
    Round,
    IsNan,
}

/// Result policy when an integer divisor is zero.
///
/// Raw p-code division and remainder do not model a processor trap or choose a
/// result for this case. Keeping that absence explicit prevents a consumer from
/// silently inheriting its host language's divide-by-zero behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineZeroDivisorBehavior {
    Undefined,
}

/// Exact carry/overflow predicate produced by a fixed-width machine operation.
///
/// These are boolean results over the input bit patterns. They are distinct
/// from comparisons: signed carry and signed borrow describe overflow of the
/// corresponding wrapping arithmetic operation, not ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineArithmeticFlagOp {
    UnsignedCarry,
    SignedCarry,
    SignedBorrow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineBitwiseOp {
    And,
    Or,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineBooleanOp {
    And,
    Or,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineShiftKind {
    Left,
    LogicalRight,
    ArithmeticRight,
}

/// Machine behavior when a shift count is at least the value width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineOvershiftBehavior {
    Zero,
    SignFill,
    MaskCount,
    Checked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineComparisonOp {
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum MachineCastKind {
    ZeroExtend,
    SignExtend,
    BitReinterpret,
    IntegerToAddress,
    AddressToInteger,
    /// A signed integer converted to the nearest floating value.
    IntegerToFloat,
    /// A floating value converted to a signed integer, rounding toward zero.
    FloatToInteger,
    /// A floating value converted to the other floating width.
    FloatToFloat,
}

/// A typed conversion applied after selecting the exact source bit slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MachineUseConversion {
    kind: MachineCastKind,
    to_width_bits: u32,
}

impl MachineUseConversion {
    pub const fn kind(self) -> MachineCastKind {
        self.kind
    }

    pub const fn to_width_bits(self) -> u32 {
        self.to_width_bits
    }
}

/// Exact canonical-carrier bits consumed at one dense [`UseSite`] table position.
///
/// Register-backed values are expressed relative to the register geometry's
/// canonical carrier, and `carrier_width_bits` is that carrier's full extent.
/// Other values are expressed relative to their own width. Thus neither the
/// carrier extent nor the coordinate space may be inferred from the selected
/// slice alone.
/// The site and source value are deliberately not repeated here: the table
/// position is the canonical site, and the owning graph is the canonical
/// `UseSite -> ValueId` binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MachineUseSlice {
    bit_offset: u32,
    width_bits: u32,
    carrier_width_bits: u32,
    conversion: Option<MachineUseConversion>,
}

impl MachineUseSlice {
    /// A slice for a test of something that consumes one.
    ///
    /// Production slices are built only here, from the source geometry, so
    /// that a consumer cannot present an arbitrary selection as a certified
    /// one; a test of the consumer still has to hand it a slice.
    #[doc(hidden)]
    pub const fn for_test(
        bit_offset: u32,
        width_bits: u32,
        carrier_width_bits: u32,
        conversion: Option<MachineUseConversion>,
    ) -> Self {
        Self {
            bit_offset,
            width_bits,
            carrier_width_bits,
            conversion,
        }
    }

    pub const fn bit_offset(self) -> u32 {
        self.bit_offset
    }

    pub const fn width_bits(self) -> u32 {
        self.width_bits
    }

    pub const fn carrier_width_bits(self) -> u32 {
        self.carrier_width_bits
    }

    pub const fn conversion(self) -> Option<MachineUseConversion> {
        self.conversion
    }
}

/// Why one graph use has no honest machine slice projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineUseRefusal {
    /// A load/store address exists, but its source-owned memory model cannot
    /// certify the contextual address type and object provenance.
    MissingMemoryContext,
    MissingRegisterGeometry,
    MalformedRegisterGeometry,
    RegisterGeometry(r2il::RegisterProjectionRefusal),
    InvalidBitRange,
    /// The value-producing instruction is outside the machine vocabulary.
    UnsupportedOperation,
    /// Operand counts, widths, or slices were internally incoherent.
    IncoherentOperation,
}

/// One use's disposition as the dense table holds it.
///
/// `MachineUseDisposition::MemoryAddress` carries a `MachineValueUse`, which is
/// a hundred and twelve bytes wide and so set the width of a cell that every
/// graph input of every instruction has one of. A structured access address is
/// a small minority of a function's uses, so the certificates live in their own
/// vector and the cell holds the twenty-four bytes the other two dispositions
/// need. The disposition a caller sees is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum PackedUseDisposition {
    Exact(MachineUseSlice),
    MemoryAddress(u32),
    Refused(MachineUseRefusal),
}

/// Complete disposition for one graph use, keyed only by its dense table cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineUseDisposition {
    Exact(MachineUseSlice),
    /// The exact structured load/store address interpretation for this use.
    ///
    /// Address interpretation is contextual: the same SSA value may be an
    /// integer elsewhere.  Keeping the existing source-owned value-use
    /// certificate in the dense `UseSite` cell prevents a renderer from
    /// replacing a certified stack/object access with a register spelling or
    /// from reporting that it rendered a bit slice instead.
    MemoryAddress(MachineValueUse),
    Refused(MachineUseRefusal),
}

/// Exact effect one surviving definition has on its source-owned carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineWriteProjection {
    /// The definition replaces every bit of its carrier; the definition's
    /// output width is the carrier width.
    Full,
    /// A full-carrier definition zero-extends an exact narrower input;
    /// `to_width_bits` is the carrier width.
    ZeroExtend {
        from_width_bits: u32,
        to_width_bits: u32,
    },
}

/// Why one surviving definition has no honest carrier write projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineWriteRefusal {
    MissingRegisterGeometry,
    MalformedRegisterGeometry,
    RegisterGeometry(r2il::RegisterProjectionRefusal),
    InvalidBitRange,
    UnsupportedOperation,
    IncoherentOperation,
}

/// Complete write disposition for one output-producing [`InstId`] table cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MachineWriteDisposition {
    Exact(MachineWriteProjection),
    Refused(MachineWriteRefusal),
}

/// One immutable machine expression node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MachineExprKind {
    Source {
        binding: MachineValueBinding,
        /// The machine location this value came from, when it has one. A
        /// consumer needs it to recognise that a value is a narrower read of a
        /// location it already knows, such as the low half of an argument
        /// register.
        storage: Option<CanonicalStorageId>,
    },
    Constant {
        binding: MachineValueBinding,
        value: MachineBitVector,
    },
    MemoryRead {
        access: StructuredAccessId,
        object: ObjectId,
        space: MachineAddressSpace,
        endianness: MachineMemoryEndianness,
        word_size_bytes: u32,
        address: MachineExprId,
        width_bits: u32,
    },
    Copy {
        input: MachineExprId,
    },
    Arithmetic {
        op: MachineArithmeticOp,
        mode: MachineArithmeticMode,
        left: MachineExprId,
        right: MachineExprId,
    },
    ArithmeticFlag {
        op: MachineArithmeticFlagOp,
        left: MachineExprId,
        right: MachineExprId,
    },
    /// Quotient of two bit patterns read at the stated interpretation.
    ///
    /// Division is the arithmetic that has to know how its operands are read:
    /// the same bits divide to different quotients signed and unsigned. The
    /// interpretation is therefore the operation's, as it is for a comparison.
    Divide {
        interpretation: MachineSignedness,
        zero_divisor: MachineZeroDivisorBehavior,
        dividend: MachineExprId,
        divisor: MachineExprId,
    },
    Remainder {
        interpretation: MachineSignedness,
        zero_divisor: MachineZeroDivisorBehavior,
        dividend: MachineExprId,
        divisor: MachineExprId,
    },
    Negate {
        mode: MachineArithmeticMode,
        input: MachineExprId,
    },
    PopulationCount {
        input: MachineExprId,
    },
    Bitwise {
        op: MachineBitwiseOp,
        left: MachineExprId,
        right: MachineExprId,
    },
    BitwiseNot {
        input: MachineExprId,
    },
    BooleanNot {
        input: MachineExprId,
    },
    Boolean {
        op: MachineBooleanOp,
        left: MachineExprId,
        right: MachineExprId,
    },
    Shift {
        kind: MachineShiftKind,
        overshift: MachineOvershiftBehavior,
        value: MachineExprId,
        count: MachineExprId,
    },
    Compare {
        op: MachineComparisonOp,
        interpretation: MachineSignedness,
        left: MachineExprId,
        right: MachineExprId,
    },
    Cast {
        kind: MachineCastKind,
        input: MachineExprId,
    },
    Extract {
        input: MachineExprId,
        lsb_bits: u32,
    },
    Concat {
        high: MachineExprId,
        low: MachineExprId,
    },
    /// `root` with `lane` written over its bits `lsb_bits..lsb_bits+width_bits`.
    InsertLane {
        root: MachineExprId,
        lane: MachineExprId,
        /// The constant operand carrying `lsb_bits`, kept so the operands
        /// stay one-to-one with the instruction's.
        position: MachineExprId,
        lsb_bits: u32,
        width_bits: u32,
    },
    FloatArithmetic {
        op: MachineFloatOp,
        left: MachineExprId,
        right: MachineExprId,
    },
    FloatUnary {
        op: MachineFloatUnaryOp,
        input: MachineExprId,
    },
    FloatCompare {
        op: MachineComparisonOp,
        left: MachineExprId,
        right: MachineExprId,
    },
    Select {
        condition: MachineExprId,
        if_true: MachineExprId,
        if_false: MachineExprId,
    },
    Phi {
        inputs: Box<[MachineExprId]>,
    },
    /// The read this instruction performs where its guard holds.
    ///
    /// A predicated load reads memory only under its condition, so the read
    /// itself carries that condition. What the destination holds otherwise is
    /// what it held before, which the selection the lift writes beside this
    /// states; here the claim is only about the access.
    GuardedRead {
        access: StructuredAccessId,
        object: ObjectId,
        space: MachineAddressSpace,
        endianness: MachineMemoryEndianness,
        word_size_bytes: u32,
        address: MachineExprId,
        guard: MachineExprId,
        width_bits: u32,
    },
    /// Whether the conditional store at this instruction took.
    ///
    /// The one value on a machine that is not a function of its operands: two
    /// runs of the same instruction on the same address and the same value
    /// answer differently, because what decides it is whether anything else
    /// wrote between the linked load and here. It is still exactly stated --
    /// this store, of this value, through this address -- which is what makes
    /// the branch that reads it renderable.
    ExclusiveStoreSucceeded {
        address: MachineExprId,
        value: MachineExprId,
    },
}

impl MachineExprKind {
    /// The expressions this one is built from.
    pub fn children(&self) -> Vec<MachineExprId> {
        match self {
            Self::Source { .. } | Self::Constant { .. } => Vec::new(),
            Self::MemoryRead { address, .. } => vec![*address],
            Self::Copy { input }
            | Self::BitwiseNot { input }
            | Self::BooleanNot { input }
            | Self::Negate { input, .. }
            | Self::PopulationCount { input }
            | Self::Cast { input, .. }
            | Self::FloatUnary { input, .. }
            | Self::Extract { input, .. } => vec![*input],
            Self::Arithmetic { left, right, .. }
            | Self::ArithmeticFlag { left, right, .. }
            | Self::Bitwise { left, right, .. }
            | Self::Boolean { left, right, .. }
            | Self::Compare { left, right, .. }
            | Self::FloatArithmetic { left, right, .. }
            | Self::FloatCompare { left, right, .. } => vec![*left, *right],
            Self::Divide {
                dividend, divisor, ..
            }
            | Self::Remainder {
                dividend, divisor, ..
            } => vec![*dividend, *divisor],
            Self::Concat { high, low } => vec![*high, *low],
            Self::InsertLane {
                root,
                lane,
                position,
                ..
            } => vec![*root, *lane, *position],
            Self::Shift { value, count, .. } => vec![*value, *count],
            Self::Select {
                condition,
                if_true,
                if_false,
            } => vec![*condition, *if_true, *if_false],
            Self::GuardedRead { address, guard, .. } => vec![*address, *guard],
            Self::ExclusiveStoreSucceeded { address, value } => vec![*address, *value],
            Self::Phi { inputs } => inputs.to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineExpr {
    ty: MachineType,
    origin: Option<CanonicalInstructionId>,
    kind: MachineExprKind,
}

impl MachineExpr {
    pub const fn ty(&self) -> &MachineType {
        &self.ty
    }

    pub const fn origin(&self) -> Option<CanonicalInstructionId> {
        self.origin
    }

    pub const fn kind(&self) -> &MachineExprKind {
        &self.kind
    }
}

/// Immutable owner of all expression nodes for one machine function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineExprArena {
    nodes: Box<[MachineExpr]>,
}

impl MachineExprArena {
    pub fn get(&self, id: MachineExprId) -> Option<&MachineExpr> {
        self.nodes.get(id.index())
    }

    pub fn iter(&self) -> impl Iterator<Item = (MachineExprId, &MachineExpr)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, expr)| (MachineExprId(index as u32), expr))
    }

    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Proof-bearing semantic root for one source instruction output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineEntity {
    output: MachineValueBinding,
    root: MachineExprId,
    producer: CanonicalInstructionId,
    source_obligations: crate::obligation::InstructionObligations,
}

impl MachineEntity {
    pub const fn output(&self) -> MachineValueBinding {
        self.output
    }

    pub const fn root(&self) -> MachineExprId {
        self.root
    }

    pub const fn producer(&self) -> CanonicalInstructionId {
        self.producer
    }

    pub const fn source_obligations(&self) -> &crate::obligation::InstructionObligations {
        &self.source_obligations
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum MachineBuildError {
    UntrustedArtifactProvenance,
    IncompleteObligationInventory,
    MissingGraphValue(ValueId),
    MissingGraphBlock(BlockId),
    DuplicateBlockAddress(u64),
    TopologyMismatch,
    MachineContextMismatch,
    MissingInstruction(InstId),
    MissingInstructionDisposition(InstId),
    MissingUseDisposition(UseSite),
    MissingWriteDisposition(InstId),
    MissingOutput(InstId),
    InvalidValueWidth {
        value: ValueId,
        size_bytes: u32,
    },
    ConstantTooWide {
        value: ValueId,
        width_bits: u32,
    },
    WrongOperandCount {
        inst: InstId,
        expected: usize,
        actual: usize,
    },
    WidthMismatch {
        inst: InstId,
        expected_bits: u32,
        actual_bits: u32,
    },
    InvalidCastWidth {
        inst: InstId,
        kind: MachineCastKind,
        from_bits: u32,
        to_bits: u32,
    },
    InvalidSubpiece {
        inst: InstId,
        source_bits: u32,
        result_bits: u32,
        lsb_bits: u32,
    },
    InvalidChild {
        expr: MachineExprId,
        child: MachineExprId,
    },
    InvalidExpressionType {
        expr: MachineExprId,
    },
    DuplicateEntity(ValueId),
    EntityMismatch(InstId),
    ObligationMismatch(InstId),
    UseDispositionMismatch(UseSite),
    WriteDispositionMismatch(InstId),
    /// A source obligation has no coherent graph-instruction owner. This keeps
    /// first-class native spans keyed by exact source identity instead of
    /// coercing them into a fabricated `InstId`.
    ObligationSourceMismatch(CanonicalInstructionId),
    UnsupportedOperation {
        inst: InstId,
        op: Box<SSAOp>,
    },
}

impl std::fmt::Display for MachineBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "machine expression construction failed: {self:?}")
    }
}

impl std::error::Error for MachineBuildError {}

/// One value producer that could not enter the machine-expression vocabulary.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MachineProjectionFailure {
    output: ValueId,
    producer: CanonicalInstructionId,
    error: MachineBuildError,
}

impl MachineProjectionFailure {
    pub const fn output(&self) -> ValueId {
        self.output
    }

    pub const fn producer(&self) -> CanonicalInstructionId {
        self.producer
    }

    pub const fn error(&self) -> &MachineBuildError {
        &self.error
    }
}

/// Partial machine projection with explicit, source-bound failures.
///
/// Unsupported value semantics remain in `failures`; they are never converted
/// to input leaves or guessed expressions. `r2cert` can therefore residualize
/// both the failed producer and all dependent value producers exactly once.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MachineProjection {
    machine: MachineFunction,
    failures: Box<[MachineProjectionFailure]>,
    /// Dense by `ValueId`; every graph value has one explicit geometry disposition.
    value_geometries: Box<[MachineValueGeometryDisposition]>,
    /// Where each instruction's uses begin in `use_slots`, with a final entry
    /// for the total, so a row is a slice rather than its own allocation.
    use_offsets: Box<[u32]>,
    use_slots: Box<[PackedUseDisposition]>,
    /// Dense beside `use_slots`: the bit past the last one the operation reads
    /// of its operand, or zero where the projection cannot say. A `Subpiece`
    /// reads only the piece it extracts, whatever the canonical slice says of
    /// the operand as a whole.
    use_read_ends: Box<[u32]>,
    /// The address certificates the `MemoryAddress` cells stand for.
    address_uses: Box<[MachineValueUse]>,
    /// Dense by `InstId`; `None` is reserved for graph instructions with no output.
    write_dispositions: Box<[Option<MachineWriteDisposition>]>,
}

impl MachineProjection {
    pub fn from_artifact(artifact: &SsaArtifact) -> Result<Self, MachineBuildError> {
        if !artifact.obligations().is_complete() {
            return Err(MachineBuildError::IncompleteObligationInventory);
        }
        let graph = artifact.graph();
        let value_geometries = canonical_machine_value_geometries(artifact)?;
        let mut builder = MachineBuilder::for_graph(graph);
        let mut entities = Vec::new();
        let mut failures = Vec::new();
        let mut write_dispositions = Vec::with_capacity(graph.insts.len());
        let mut pending_roots = vec![None; graph.insts.len()];

        for (inst_index, inst) in graph.insts.iter().enumerate() {
            if inst.id.0 as usize != inst_index {
                return Err(MachineBuildError::TopologyMismatch);
            }
            let Some(output_id) = inst.output else {
                builder.lower_outputless_inst(artifact, inst)?;
                write_dispositions.push(None);
                continue;
            };
            let disposition = artifact
                .obligations()
                .instruction_for_inst(inst.id)
                .ok_or(MachineBuildError::MissingInstructionDisposition(inst.id))?;
            let graph_value = graph
                .value(output_id)
                .ok_or(MachineBuildError::MissingGraphValue(output_id))?;
            let output = binding_for_value(graph_value)?;
            match builder.lower_inst(artifact, inst, disposition.id, output) {
                Ok(root) => {
                    // The write decision is deferred. Whether a partial write
                    // preserves anything depends on what reads the carrier
                    // elsewhere in the function, and that is not known until
                    // every instruction has been lowered.
                    pending_roots[inst_index] = Some(root);
                    write_dispositions.push(None);
                    entities.push(MachineEntity {
                        output,
                        root,
                        producer: disposition.id,
                        source_obligations: disposition.obligations.clone(),
                    });
                }
                Err(error) if is_local_projection_failure(&error, inst.id) => {
                    r2il::refusal_evidence!(
                        "machine-lowering",
                        "{:?} at {:?} not projected: {error:?}",
                        inst.id,
                        inst.payload
                    );
                    builder.refuse_inst_uses(graph, inst, use_refusal_for_error(&error))?;
                    write_dispositions.push(Some(MachineWriteDisposition::Refused(
                        write_refusal_for_error(&error),
                    )));
                    failures.push(MachineProjectionFailure {
                        output: output_id,
                        producer: disposition.id,
                        error,
                    });
                }
                Err(error) => return Err(error),
            }
        }

        // Now that every operand read is known, settle the deferred writes.
        for (inst_index, inst) in graph.insts.iter().enumerate() {
            let Some(root) = pending_roots[inst_index] else {
                continue;
            };
            let root_expr = builder
                .nodes
                .get(root.index())
                .ok_or(MachineBuildError::MissingWriteDisposition(inst.id))?;
            write_dispositions[inst_index] =
                Some(machine_write_disposition(artifact, inst, root_expr));
        }
        let mut use_slots = builder.use_slots;
        canonical_machine_use_dispositions(artifact, &builder.use_offsets, &mut use_slots)?;
        let packed = pack_use_dispositions(builder.use_offsets, use_slots);
        let mut projection = Self {
            machine: MachineFunction {
                arena: MachineExprArena {
                    nodes: builder.nodes.into_boxed_slice(),
                },
                entity_index_by_output: entity_index_by_output(&entities, graph.values.len()),
                entities: entities.into_boxed_slice(),
                store_addresses: builder.store_addresses.into_iter().collect(),
            },
            failures: failures.into_boxed_slice(),
            value_geometries: value_geometries.into_boxed_slice(),
            use_offsets: packed.offsets,
            use_slots: packed.slots,
            use_read_ends: Box::new([]),
            address_uses: packed.addresses,
            write_dispositions: write_dispositions.into_boxed_slice(),
        };
        projection.use_read_ends = projection.operation_read_ends(artifact);
        projection.validate_against(artifact)?;
        Ok(projection)
    }

    pub const fn arena(&self) -> &MachineExprArena {
        self.machine.arena()
    }

    pub const fn entities(&self) -> &[MachineEntity] {
        self.machine.entities()
    }

    /// The typed address leaf of the store performing `access`, if the store
    /// was projected. See [`MachineFunction::store_address`].
    pub fn store_address(&self, access: StructuredAccessId) -> Option<MachineExprId> {
        self.machine.store_address(access)
    }

    pub const fn failures(&self) -> &[MachineProjectionFailure] {
        &self.failures
    }

    /// Dense O(1) lookup for one exact graph value's source-owned geometry.
    pub fn value_geometry(&self, value: ValueId) -> Option<&MachineValueGeometryDisposition> {
        self.value_geometries.get(value.0 as usize)
    }

    /// Dense cells indexed by `ValueId`.
    pub const fn value_geometries(&self) -> &[MachineValueGeometryDisposition] {
        &self.value_geometries
    }

    /// The bit past the last one the operation at `site` reads of its
    /// operand, when the projection can state it.
    pub fn use_read_end_bits(&self, site: UseSite) -> Option<u32> {
        let start = *self.use_offsets.get(site.inst.0 as usize)? as usize;
        let end = *self.use_offsets.get(site.inst.0 as usize + 1)? as usize;
        let read_end = *self.use_read_ends.get(start..end)?.get(site.input_idx)?;
        (read_end != 0).then_some(read_end)
    }

    /// What each operation reads of each operand, in the machine's own terms:
    /// the operand whole, or the piece an extraction takes of it. An operation
    /// with no output reads its operands whole; one that failed to project
    /// states nothing.
    fn operation_read_ends(&self, artifact: &SsaArtifact) -> Box<[u32]> {
        let graph = artifact.graph();
        let mut ends = vec![0u32; self.use_slots.len()];
        for (inst_index, inst) in graph.insts.iter().enumerate() {
            let Some(start) = self
                .use_offsets
                .get(inst_index)
                .map(|start| *start as usize)
            else {
                continue;
            };
            if inst
                .output
                .is_some_and(|output| self.failures.iter().any(|failure| failure.output == output))
            {
                continue;
            }
            let root = inst
                .output
                .and_then(|output| self.machine.entity_for_output(output))
                .and_then(|entity| self.machine.expr(entity.root()));
            let children = root.map(|root| root.kind.children());
            for (input_idx, input) in inst.inputs.iter().enumerate() {
                let Some(source) = graph
                    .value(*input)
                    .and_then(|value| binding_for_value(value).ok())
                else {
                    continue;
                };
                let end = match (root, &children) {
                    (Some(root), Some(children)) => children.get(input_idx).and_then(|child| {
                        machine_use_slice_for_input(
                            &self.machine.arena,
                            root,
                            *child,
                            source,
                            false,
                        )
                        .map(|slice| slice.bit_offset() + slice.width_bits())
                    }),
                    (None, _) if inst.output.is_none() => Some(source.width_bits),
                    _ => None,
                };
                if let Some(cell) = ends.get_mut(start + input_idx) {
                    *cell = end.unwrap_or(0);
                }
            }
        }
        ends.into_boxed_slice()
    }

    /// Dense O(1) lookup for the disposition of one exact graph input use.
    pub fn use_disposition(&self, site: UseSite) -> Option<MachineUseDisposition> {
        let packed = *self.packed_use(site)?;
        self.unpack_use(packed)
    }

    fn packed_use(&self, site: UseSite) -> Option<&PackedUseDisposition> {
        let start = *self.use_offsets.get(site.inst.0 as usize)? as usize;
        let end = *self.use_offsets.get(site.inst.0 as usize + 1)? as usize;
        self.use_slots.get(start..end)?.get(site.input_idx)
    }

    fn unpack_use(&self, packed: PackedUseDisposition) -> Option<MachineUseDisposition> {
        Some(match packed {
            PackedUseDisposition::Exact(slice) => MachineUseDisposition::Exact(slice),
            PackedUseDisposition::MemoryAddress(index) => {
                MachineUseDisposition::MemoryAddress(*self.address_uses.get(index as usize)?)
            }
            PackedUseDisposition::Refused(refusal) => MachineUseDisposition::Refused(refusal),
        })
    }

    /// How many inputs the dense table holds for one instruction.
    pub fn use_row_len(&self, inst: InstId) -> Option<usize> {
        let start = *self.use_offsets.get(inst.0 as usize)? as usize;
        let end = *self.use_offsets.get(inst.0 as usize + 1)? as usize;
        end.checked_sub(start)
    }

    /// Every graph input use and what the projection says about it, in
    /// instruction and then input order.
    pub fn uses(&self) -> impl Iterator<Item = (UseSite, MachineUseDisposition)> + '_ {
        self.use_offsets
            .windows(2)
            .enumerate()
            .flat_map(move |(inst, bounds)| {
                let range = bounds[0] as usize..bounds[1] as usize;
                self.use_slots[range]
                    .iter()
                    .enumerate()
                    .filter_map(move |(input_idx, packed)| {
                        Some((
                            UseSite {
                                inst: InstId(inst as u32),
                                input_idx,
                            },
                            self.unpack_use(*packed)?,
                        ))
                    })
            })
    }

    /// Dense O(1) lookup for one output-producing graph instruction.
    pub fn write_disposition(&self, inst: InstId) -> Option<&MachineWriteDisposition> {
        self.write_dispositions.get(inst.0 as usize)?.as_ref()
    }

    /// Dense rows indexed by `InstId`; `None` means the instruction has no output.
    pub const fn write_dispositions(&self) -> &[Option<MachineWriteDisposition>] {
        &self.write_dispositions
    }

    /// The carrier extensions this write's projection stands for, in the order
    /// the clearing chain consumed them.
    ///
    pub fn expr(&self, id: MachineExprId) -> Option<&MachineExpr> {
        self.machine.expr(id)
    }

    pub fn entity_for_output(&self, value: ValueId) -> Option<&MachineEntity> {
        self.machine.entity_for_output(value)
    }

    pub fn entity_for_producer(&self, producer: CanonicalInstructionId) -> Option<&MachineEntity> {
        self.machine.entity_for_producer(producer)
    }

    pub fn failure_for_output(&self, value: ValueId) -> Option<&MachineProjectionFailure> {
        self.failures.iter().find(|failure| failure.output == value)
    }

    pub fn validate_against(&self, artifact: &SsaArtifact) -> Result<(), MachineBuildError> {
        let entities = self.machine.validate_entities_against(artifact)?;
        let graph = artifact.graph();
        let mut failed_outputs = ByValue::over(graph.values.len());
        for failure in &self.failures {
            if !failed_outputs.put(failure.output, failure)
                || entities.get(failure.output).is_some()
            {
                return Err(MachineBuildError::DuplicateEntity(failure.output));
            }
            let inst_id = graph
                .def_inst(failure.output)
                .ok_or(MachineBuildError::EntityMismatch(InstId(u32::MAX)))?;
            let disposition = artifact
                .obligations()
                .instruction_for_inst(inst_id)
                .ok_or(MachineBuildError::MissingInstructionDisposition(inst_id))?;
            if disposition.id != failure.producer {
                return Err(MachineBuildError::EntityMismatch(inst_id));
            }
        }
        for inst in &graph.insts {
            let Some(output) = inst.output else {
                continue;
            };
            let projected = entities.get(output).is_some();
            if projected == failed_outputs.get(output).is_some() {
                r2il::refusal_evidence!(
                    "machine-entity",
                    "{:?} at {:?} is {}",
                    inst.id,
                    inst.payload,
                    match projected {
                        true => "both projected and refused",
                        false => "neither projected nor refused",
                    }
                );
                return Err(MachineBuildError::EntityMismatch(inst.id));
            }
        }
        self.validate_value_geometries(artifact)?;
        self.validate_use_dispositions(artifact, &entities, &failed_outputs)?;
        self.validate_write_dispositions(artifact, &entities, &failed_outputs)?;
        Ok(())
    }

    fn validate_value_geometries(&self, artifact: &SsaArtifact) -> Result<(), MachineBuildError> {
        let expected = canonical_machine_value_geometries(artifact)?;
        if self.value_geometries.as_ref() != expected.as_slice() {
            return Err(MachineBuildError::TopologyMismatch);
        }
        Ok(())
    }

    fn validate_use_dispositions(
        &self,
        artifact: &SsaArtifact,
        entities: &ByValue<&MachineEntity>,
        failures: &ByValue<&MachineProjectionFailure>,
    ) -> Result<(), MachineBuildError> {
        let graph = artifact.graph();
        if self.use_offsets.len() != graph.insts.len() + 1
            || self.use_read_ends.len() != self.use_slots.len()
        {
            return Err(MachineBuildError::TopologyMismatch);
        }
        let constant_bindings = self
            .machine
            .arena
            .iter()
            .filter_map(|(_, expr)| match expr.kind() {
                MachineExprKind::Constant { binding, .. } => Some(*binding),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for (inst_index, inst) in graph.insts.iter().enumerate() {
            if inst.id.0 as usize != inst_index {
                return Err(MachineBuildError::TopologyMismatch);
            }
            let row = (self.use_offsets[inst_index] as usize
                ..self.use_offsets[inst_index + 1] as usize)
                .map(|slot| self.use_slots[slot])
                .map(|packed| {
                    self.unpack_use(packed)
                        .ok_or(MachineBuildError::TopologyMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if row.len() != inst.inputs.len() {
                return Err(MachineBuildError::TopologyMismatch);
            }
            let expected_refusal = inst
                .output
                .and_then(|output| failures.get(output))
                .map(|failure| use_refusal_for_error(failure.error()));
            let root = inst
                .output
                .and_then(|output| entities.get(output))
                .and_then(|entity| self.machine.expr(entity.root()));
            let root_children = root.map(|root| root.kind.children());

            for (input_idx, disposition) in row.iter().enumerate() {
                let site = UseSite {
                    inst: inst.id,
                    input_idx,
                };
                let input = *inst
                    .inputs
                    .get(input_idx)
                    .ok_or(MachineBuildError::MissingUseDisposition(site))?;
                let graph_value = graph
                    .value(input)
                    .ok_or(MachineBuildError::MissingGraphValue(input))?;
                let source = binding_for_value(graph_value)?;
                let operation_relative = match (expected_refusal, root) {
                    (Some(expected), _) => MachineUseDisposition::Refused(expected),
                    (None, Some(root)) => MachineUseDisposition::Exact(
                        machine_use_slice_for_input(
                            &self.machine.arena,
                            root,
                            *root_children
                                .as_ref()
                                .and_then(|children| children.get(input_idx))
                                .ok_or(MachineBuildError::UseDispositionMismatch(site))?,
                            source,
                            matches!(inst.payload, InstPayload::Op(SSAOp::Subpiece { .. })),
                        )
                        .ok_or(MachineBuildError::UseDispositionMismatch(site))?,
                    ),
                    (None, None) if inst.output.is_none() => {
                        if graph_value.var.constant_bits().is_some()
                            && !constant_bindings.contains(&source)
                        {
                            return Err(MachineBuildError::UseDispositionMismatch(site));
                        }
                        MachineUseDisposition::Exact(whole_machine_use(source))
                    }
                    (None, None) => {
                        return Err(MachineBuildError::UseDispositionMismatch(site));
                    }
                };
                validate_canonical_machine_use_disposition(
                    artifact,
                    site,
                    input,
                    operation_relative,
                    *disposition,
                )?;
            }
        }
        Ok(())
    }

    fn validate_write_dispositions(
        &self,
        artifact: &SsaArtifact,
        entities: &ByValue<&MachineEntity>,
        failures: &ByValue<&MachineProjectionFailure>,
    ) -> Result<(), MachineBuildError> {
        let graph = artifact.graph();
        if self.write_dispositions.len() != graph.insts.len() {
            return Err(MachineBuildError::TopologyMismatch);
        }
        for (inst_index, inst) in graph.insts.iter().enumerate() {
            if inst.id.0 as usize != inst_index {
                return Err(MachineBuildError::TopologyMismatch);
            }
            let actual = self
                .write_dispositions
                .get(inst_index)
                .ok_or(MachineBuildError::MissingWriteDisposition(inst.id))?;
            let Some(output) = inst.output else {
                if actual.is_some() {
                    return Err(MachineBuildError::WriteDispositionMismatch(inst.id));
                }
                continue;
            };
            let expected = if let Some(entity) = entities.get(output) {
                let root = self
                    .machine
                    .expr(entity.root())
                    .ok_or(MachineBuildError::WriteDispositionMismatch(inst.id))?;
                machine_write_disposition(artifact, inst, root)
            } else if let Some(failure) = failures.get(output) {
                MachineWriteDisposition::Refused(write_refusal_for_error(failure.error()))
            } else {
                return Err(MachineBuildError::WriteDispositionMismatch(inst.id));
            };
            if *actual != Some(expected) {
                return Err(MachineBuildError::WriteDispositionMismatch(inst.id));
            }
        }
        Ok(())
    }

    fn into_machine(self) -> MachineFunction {
        self.machine
    }
}

fn is_local_projection_failure(error: &MachineBuildError, inst: InstId) -> bool {
    matches!(
        error,
        MachineBuildError::UnsupportedOperation { inst: actual, .. }
            | MachineBuildError::WrongOperandCount { inst: actual, .. }
            | MachineBuildError::WidthMismatch { inst: actual, .. }
            | MachineBuildError::InvalidCastWidth { inst: actual, .. }
            | MachineBuildError::InvalidSubpiece { inst: actual, .. }
            if *actual == inst
    )
}

fn use_refusal_for_error(error: &MachineBuildError) -> MachineUseRefusal {
    match error {
        MachineBuildError::UnsupportedOperation { inst, op } => {
            // The flattened refusal keeps only the class, and the operation is
            // the whole question a reader of it has.
            r2il::refusal_evidence!(
                "machine-unsupported-operation",
                "{inst:?} is outside the machine vocabulary: {op}"
            );
            MachineUseRefusal::UnsupportedOperation
        }
        _ => MachineUseRefusal::IncoherentOperation,
    }
}

fn write_refusal_for_error(error: &MachineBuildError) -> MachineWriteRefusal {
    match error {
        MachineBuildError::UnsupportedOperation { .. } => MachineWriteRefusal::UnsupportedOperation,
        _ => MachineWriteRefusal::IncoherentOperation,
    }
}

fn canonical_machine_value_geometries(
    artifact: &SsaArtifact,
) -> Result<Vec<MachineValueGeometryDisposition>, MachineBuildError> {
    let graph = artifact.graph();
    let mut geometries = Vec::with_capacity(graph.values.len());
    for (index, value) in graph.values.iter().enumerate() {
        if value.id.0 as usize != index {
            return Err(MachineBuildError::TopologyMismatch);
        }
        geometries.push(canonical_machine_value_geometry(artifact, value)?);
    }
    Ok(geometries)
}

fn canonical_machine_value_geometry(
    artifact: &SsaArtifact,
    value: &GraphValue,
) -> Result<MachineValueGeometryDisposition, MachineBuildError> {
    let binding = binding_for_value(value)?;
    let Some(storage) = value.canonical_storage else {
        return Ok(MachineValueGeometryDisposition::Direct(
            MachineDirectValueGeometry {
                storage: None,
                value_width_bits: binding.width_bits,
            },
        ));
    };
    if storage.space != CanonicalStorageSpace::Register {
        let storage_width_bits = storage.size.checked_mul(8);
        if storage_width_bits != Some(binding.width_bits) {
            return Ok(MachineValueGeometryDisposition::Refused(
                MachineValueGeometryRefusal::InvalidBitRange,
            ));
        }
        return Ok(MachineValueGeometryDisposition::Direct(
            MachineDirectValueGeometry {
                storage: Some(storage),
                value_width_bits: binding.width_bits,
            },
        ));
    }

    let geometry = match exact_register_geometry(artifact, storage) {
        Ok(geometry) => geometry,
        Err(reason) => {
            return Ok(MachineValueGeometryDisposition::Refused(
                value_refusal_for_register_geometry(reason),
            ));
        }
    };
    if geometry.width_bits != binding.width_bits {
        return Ok(MachineValueGeometryDisposition::Refused(
            MachineValueGeometryRefusal::InvalidBitRange,
        ));
    }
    Ok(MachineValueGeometryDisposition::ExactRegister(
        MachineRegisterValueGeometry {
            carrier: geometry.carrier,
            bit_offset: geometry.bit_offset,
            value_width_bits: geometry.width_bits,
            carrier_width_bits: geometry.carrier_bits,
        },
    ))
}

/// The dense use table, flat.
struct PackedUseTable {
    offsets: Box<[u32]>,
    slots: Box<[PackedUseDisposition]>,
    addresses: Box<[MachineValueUse]>,
}

/// Flatten the per-instruction rows and lift every address certificate out of
/// the cells into its own vector.
fn pack_use_dispositions(
    offsets: Vec<u32>,
    dispositions: Vec<MachineUseDisposition>,
) -> PackedUseTable {
    let mut slots = Vec::with_capacity(dispositions.len());
    let mut addresses = Vec::new();
    for disposition in dispositions {
        slots.push(match disposition {
            MachineUseDisposition::Exact(slice) => PackedUseDisposition::Exact(slice),
            MachineUseDisposition::MemoryAddress(address) => {
                addresses.push(address);
                PackedUseDisposition::MemoryAddress(addresses.len() as u32 - 1)
            }
            MachineUseDisposition::Refused(refusal) => PackedUseDisposition::Refused(refusal),
        });
    }
    PackedUseTable {
        offsets: offsets.into_boxed_slice(),
        slots: slots.into_boxed_slice(),
        addresses: addresses.into_boxed_slice(),
    }
}

/// Rewrite every use disposition in place, from the operation's own view of
/// the slice to the canonical one. In place because the table is already the
/// shape the projection keeps, and rebuilding it row by row allocated a vector
/// for every instruction to hand back what it was given.
fn canonical_machine_use_dispositions(
    artifact: &SsaArtifact,
    offsets: &[u32],
    slots: &mut [MachineUseDisposition],
) -> Result<(), MachineBuildError> {
    let graph = artifact.graph();
    if offsets.len() != graph.insts.len() + 1 {
        return Err(MachineBuildError::TopologyMismatch);
    }
    for (inst_index, inst) in graph.insts.iter().enumerate() {
        let start = offsets[inst_index] as usize;
        let end = offsets[inst_index + 1] as usize;
        if inst.id.0 as usize != inst_index
            || end < start
            || end > slots.len()
            || end - start != inst.inputs.len()
        {
            return Err(MachineBuildError::TopologyMismatch);
        }
        for (input_idx, input) in inst.inputs.iter().enumerate() {
            let site = UseSite {
                inst: inst.id,
                input_idx,
            };
            let at = start + input_idx;
            slots[at] = canonical_machine_use_disposition(artifact, site, *input, slots[at])?;
        }
    }
    Ok(())
}

fn canonical_machine_use_disposition(
    artifact: &SsaArtifact,
    site: UseSite,
    input: ValueId,
    operation_relative: MachineUseDisposition,
) -> Result<MachineUseDisposition, MachineBuildError> {
    let MachineUseDisposition::Exact(slice) = operation_relative else {
        return Ok(operation_relative);
    };
    let graph_value = artifact
        .graph()
        .value(input)
        .ok_or(MachineBuildError::MissingGraphValue(input))?;
    let source = binding_for_value(graph_value)?;
    validate_machine_use_slice(slice, source.width_bits).map_err(|_| {
        r2il::refusal_evidence!(
            "machine-use-slice",
            "{site:?} states {slice:?} of a {}-bit carrier",
            source.width_bits
        );
        MachineBuildError::UseDispositionMismatch(site)
    })?;

    let address_use = match MachineValueUse::memory_address_for_use(artifact, site) {
        Ok(address_use) => address_use,
        Err(MachineBuildError::MachineContextMismatch) => {
            return Ok(MachineUseDisposition::Refused(
                MachineUseRefusal::MissingMemoryContext,
            ));
        }
        Err(error) => return Err(error),
    };
    if let Some(address_use) = address_use {
        if address_use.binding().value() != input {
            return Err(MachineBuildError::UseDispositionMismatch(site));
        }
        return Ok(MachineUseDisposition::MemoryAddress(address_use));
    }

    let Some(storage) = graph_value.canonical_storage else {
        return Ok(MachineUseDisposition::Exact(slice));
    };
    if storage.space != CanonicalStorageSpace::Register {
        return Ok(MachineUseDisposition::Exact(slice));
    }
    let geometry = match exact_register_geometry(artifact, storage) {
        Ok(geometry) => geometry,
        Err(reason) => {
            return Ok(MachineUseDisposition::Refused(
                use_refusal_for_register_geometry(reason),
            ));
        }
    };
    if geometry.width_bits != source.width_bits {
        return Ok(MachineUseDisposition::Refused(
            MachineUseRefusal::InvalidBitRange,
        ));
    }
    // A value this function computed is read at the width it holds; a value it
    // was entered with is read at the width the machine handed it over in.
    //
    // The second is an ABI fact rather than a use fact, and the distinction
    // matters at a call: narrowing an incoming argument to whatever the body
    // happens to read makes this function's idea of its own parameters disagree
    // with the declaration a caller writes for it, and the two renderings then
    // do not compile together. For a computed value there is no such contract --
    // the object is the value -- and re-basing it onto the register it sits in
    // only forces objects as wide as whatever the specification nests that
    // register in, which for the vector registers is a carrier no program here
    // ever addresses.
    if artifact.graph().def_inst(input).is_some() {
        return Ok(MachineUseDisposition::Exact(whole_machine_use(source)));
    }
    let slice = match compose_machine_use_slice(slice, geometry.bit_offset, geometry.carrier_bits) {
        Ok(slice) => slice,
        Err(reason) => return Ok(MachineUseDisposition::Refused(reason)),
    };
    Ok(MachineUseDisposition::Exact(slice))
}

fn validate_canonical_machine_use_disposition(
    artifact: &SsaArtifact,
    site: UseSite,
    input: ValueId,
    operation_relative: MachineUseDisposition,
    actual: MachineUseDisposition,
) -> Result<(), MachineBuildError> {
    let mismatch = || {
        r2il::refusal_evidence!(
            "machine-use-slice",
            "{site:?} operation states {operation_relative:?}, projection states {actual:?}"
        );
        MachineBuildError::UseDispositionMismatch(site)
    };
    let MachineUseDisposition::Exact(operation_slice) = operation_relative else {
        return (actual == operation_relative)
            .then_some(())
            .ok_or_else(mismatch);
    };
    let graph_value = artifact
        .graph()
        .value(input)
        .ok_or(MachineBuildError::MissingGraphValue(input))?;
    let source = binding_for_value(graph_value)?;
    validate_machine_use_slice(operation_slice, source.width_bits).map_err(|_| mismatch())?;

    let address_use = match MachineValueUse::memory_address_for_use(artifact, site) {
        Ok(address_use) => address_use,
        Err(MachineBuildError::MachineContextMismatch) => {
            return (actual
                == MachineUseDisposition::Refused(MachineUseRefusal::MissingMemoryContext))
            .then_some(())
            .ok_or_else(mismatch);
        }
        Err(error) => return Err(error),
    };
    if let Some(address_use) = address_use {
        return (address_use.binding().value() == input
            && actual == MachineUseDisposition::MemoryAddress(address_use))
        .then_some(())
        .ok_or_else(mismatch);
    }

    let Some(storage) = graph_value.canonical_storage else {
        return (actual == MachineUseDisposition::Exact(operation_slice))
            .then_some(())
            .ok_or_else(mismatch);
    };
    if storage.space != CanonicalStorageSpace::Register {
        return (actual == MachineUseDisposition::Exact(operation_slice))
            .then_some(())
            .ok_or_else(mismatch);
    }

    let geometry = match exact_register_geometry(artifact, storage) {
        Ok(geometry) if geometry.width_bits == source.width_bits => geometry,
        Ok(_) => {
            return (actual == MachineUseDisposition::Refused(MachineUseRefusal::InvalidBitRange))
                .then_some(())
                .ok_or_else(mismatch);
        }
        Err(reason) => {
            let refusal = use_refusal_for_register_geometry(reason);
            return (actual == MachineUseDisposition::Refused(refusal))
                .then_some(())
                .ok_or_else(mismatch);
        }
    };
    // Mirrors the derivation: a computed value is read as itself.
    if artifact.graph().def_inst(input).is_some() {
        return (actual == MachineUseDisposition::Exact(whole_machine_use(source)))
            .then_some(())
            .ok_or_else(mismatch);
    }
    let MachineUseDisposition::Exact(actual_slice) = actual else {
        return Err(mismatch());
    };
    let exact = actual_slice.width_bits == operation_slice.width_bits
        && actual_slice.carrier_width_bits == geometry.carrier_bits
        && actual_slice.conversion == operation_slice.conversion
        && actual_slice.bit_offset.checked_sub(geometry.bit_offset)
            == Some(operation_slice.bit_offset)
        && validate_machine_use_slice(actual_slice, geometry.carrier_bits).is_ok();
    exact.then_some(()).ok_or_else(mismatch)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachineRegisterGeometryRefusal {
    Missing,
    Malformed,
    Upstream(r2il::RegisterProjectionRefusal),
    InvalidBitRange,
}

fn value_refusal_for_register_geometry(
    reason: MachineRegisterGeometryRefusal,
) -> MachineValueGeometryRefusal {
    match reason {
        MachineRegisterGeometryRefusal::Missing => {
            MachineValueGeometryRefusal::MissingRegisterGeometry
        }
        MachineRegisterGeometryRefusal::Malformed => {
            MachineValueGeometryRefusal::MalformedRegisterGeometry
        }
        MachineRegisterGeometryRefusal::Upstream(reason) => {
            MachineValueGeometryRefusal::RegisterGeometry(reason)
        }
        MachineRegisterGeometryRefusal::InvalidBitRange => {
            MachineValueGeometryRefusal::InvalidBitRange
        }
    }
}

fn use_refusal_for_register_geometry(reason: MachineRegisterGeometryRefusal) -> MachineUseRefusal {
    match reason {
        MachineRegisterGeometryRefusal::Missing => MachineUseRefusal::MissingRegisterGeometry,
        MachineRegisterGeometryRefusal::Malformed => MachineUseRefusal::MalformedRegisterGeometry,
        MachineRegisterGeometryRefusal::Upstream(reason) => {
            MachineUseRefusal::RegisterGeometry(reason)
        }
        MachineRegisterGeometryRefusal::InvalidBitRange => MachineUseRefusal::InvalidBitRange,
    }
}

fn write_refusal_for_register_geometry(
    reason: MachineRegisterGeometryRefusal,
) -> MachineWriteRefusal {
    match reason {
        MachineRegisterGeometryRefusal::Missing => MachineWriteRefusal::MissingRegisterGeometry,
        MachineRegisterGeometryRefusal::Malformed => MachineWriteRefusal::MalformedRegisterGeometry,
        MachineRegisterGeometryRefusal::Upstream(reason) => {
            MachineWriteRefusal::RegisterGeometry(reason)
        }
        MachineRegisterGeometryRefusal::InvalidBitRange => MachineWriteRefusal::InvalidBitRange,
    }
}

fn compose_machine_use_slice(
    operation_relative: MachineUseSlice,
    carrier_bit_offset: u32,
    carrier_width_bits: u32,
) -> Result<MachineUseSlice, MachineUseRefusal> {
    let bit_offset = carrier_bit_offset
        .checked_add(operation_relative.bit_offset)
        .ok_or(MachineUseRefusal::InvalidBitRange)?;
    let canonical = MachineUseSlice {
        bit_offset,
        carrier_width_bits,
        ..operation_relative
    };
    validate_machine_use_slice(canonical, carrier_width_bits)
        .map_err(|_| MachineUseRefusal::InvalidBitRange)?;
    Ok(canonical)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactRegisterGeometry {
    carrier: CanonicalStorageId,
    bit_offset: u32,
    width_bits: u32,
    carrier_bits: u32,
}

fn exact_register_geometry(
    artifact: &SsaArtifact,
    written: CanonicalStorageId,
) -> Result<ExactRegisterGeometry, MachineRegisterGeometryRefusal> {
    if written.space != CanonicalStorageSpace::Register {
        return Err(MachineRegisterGeometryRefusal::InvalidBitRange);
    }
    match artifact.machine_context().register_geometry_state() {
        MachineRegisterGeometryState::Unavailable => {
            return Err(MachineRegisterGeometryRefusal::Missing);
        }
        MachineRegisterGeometryState::Malformed => {
            return Err(MachineRegisterGeometryRefusal::Malformed);
        }
        MachineRegisterGeometryState::Available => {}
    }
    let projection = artifact
        .machine_context()
        .register_projection(written)
        .ok_or(MachineRegisterGeometryRefusal::InvalidBitRange)?;
    if projection.written.offset != written.offset || projection.written.size != written.size {
        return Err(MachineRegisterGeometryRefusal::InvalidBitRange);
    }
    let r2il::RegisterProjectionDisposition::Bound { carrier, slice } = projection.disposition
    else {
        let r2il::RegisterProjectionDisposition::Refused { reason } = projection.disposition else {
            unreachable!("register projection disposition is exhaustive")
        };
        return Err(MachineRegisterGeometryRefusal::Upstream(reason));
    };
    if !carrier.contains(projection.written) {
        return Err(MachineRegisterGeometryRefusal::InvalidBitRange);
    }
    let written_bits = written
        .size
        .checked_mul(8)
        .ok_or(MachineRegisterGeometryRefusal::InvalidBitRange)?;
    let carrier_bits = carrier
        .size
        .checked_mul(8)
        .ok_or(MachineRegisterGeometryRefusal::InvalidBitRange)?;
    let bit_offset = u32::try_from(slice.lsb_bit_offset)
        .map_err(|_| MachineRegisterGeometryRefusal::InvalidBitRange)?;
    let width_bits = u32::try_from(slice.size_bits)
        .map_err(|_| MachineRegisterGeometryRefusal::InvalidBitRange)?;
    if width_bits == 0
        || width_bits != written_bits
        || bit_offset
            .checked_add(width_bits)
            .is_none_or(|end| end > carrier_bits)
        || (carrier == projection.written && (bit_offset != 0 || width_bits != carrier_bits))
    {
        return Err(MachineRegisterGeometryRefusal::InvalidBitRange);
    }
    // The architecture's own carrier is checked above and then set aside: a
    // register value in this SSA is its family's root already, chosen from
    // what the function touches rather than from the widest name the
    // specification has (doc/adr-register-identity.md). Its geometry is
    // therefore the whole of itself, and re-basing it onto `ZMM0` would say
    // a 128-bit load defines a slice of a register no program here mentions.
    Ok(ExactRegisterGeometry {
        carrier: written,
        bit_offset: 0,
        width_bits: written_bits,
        carrier_bits: written_bits,
    })
}

fn exact_zero_extend_write(
    artifact: &SsaArtifact,
    inst: &GraphInst,
    root: &MachineExpr,
    output: ExactRegisterGeometry,
) -> Option<MachineWriteProjection> {
    if output.bit_offset != 0 || output.width_bits != output.carrier_bits {
        return None;
    }
    if !matches!(
        &root.kind,
        MachineExprKind::Cast {
            kind: MachineCastKind::ZeroExtend,
            ..
        }
    ) {
        return None;
    }
    let [input] = inst.inputs.as_slice() else {
        return None;
    };
    let graph_value = artifact.graph().value(*input)?;
    let input_width = graph_value.var.size.checked_mul(8)?;
    if input_width >= output.carrier_bits || root.ty.width_bits() != output.carrier_bits {
        return None;
    }
    Some(MachineWriteProjection::ZeroExtend {
        from_width_bits: input_width,
        to_width_bits: output.carrier_bits,
    })
}

fn machine_write_disposition(
    artifact: &SsaArtifact,
    inst: &GraphInst,
    root: &MachineExpr,
) -> MachineWriteDisposition {
    let Some(output) = inst.output else {
        return MachineWriteDisposition::Refused(MachineWriteRefusal::IncoherentOperation);
    };
    // A phi is not a machine event. It merges the values reaching a point; no
    // instruction there writes a slice of a register and preserves the rest.
    // Reading a carrier-relative projection off its geometry says otherwise,
    // and for a merge of a sub-register that reads as `Insert`: an assertion
    // that the merge preserves the carrier's other bits, which it neither does
    // nor could. Where the carrier is live across the merge it has a phi of
    // its own, and that phi is what answers for it.
    if matches!(inst.payload, InstPayload::Phi { .. }) {
        return MachineWriteDisposition::Exact(MachineWriteProjection::Full);
    }
    // A call's definition of a register preserves nothing. The callee wrote
    // that register, so whatever sits outside the lane the prototype names is
    // what the callee left there, not what the caller had before. Reading a
    // carrier-relative projection off the geometry says otherwise, and for a
    // definition of a sub-register that comes out as `Insert` -- an assertion
    // that the call preserved the caller's other bits, which is exactly the
    // claim a call cannot make.
    if matches!(
        inst.payload,
        InstPayload::Op(crate::op::SSAOp::CallDefine { .. })
    ) {
        return MachineWriteDisposition::Exact(MachineWriteProjection::Full);
    }
    // A lane written into its root reads the root it keeps as an operand, so
    // the write is a full definition of the root from explicit inputs; the
    // expression kind, not the projection, says where the lane sits.
    if matches!(root.kind, MachineExprKind::InsertLane { .. }) {
        return MachineWriteDisposition::Exact(MachineWriteProjection::Full);
    }
    let Some(storage) = artifact
        .graph()
        .value(output)
        .and_then(|value| value.canonical_storage)
    else {
        return MachineWriteDisposition::Exact(MachineWriteProjection::Full);
    };
    if storage.space != CanonicalStorageSpace::Register {
        return MachineWriteDisposition::Exact(MachineWriteProjection::Full);
    }
    let geometry = match exact_register_geometry(artifact, storage) {
        Ok(geometry) => geometry,
        Err(reason) => {
            return MachineWriteDisposition::Refused(write_refusal_for_register_geometry(reason));
        }
    };
    if let Some(zero_extend) = exact_zero_extend_write(artifact, inst, root, geometry) {
        return MachineWriteDisposition::Exact(zero_extend);
    }
    if geometry.bit_offset == 0 && geometry.width_bits == geometry.carrier_bits {
        return MachineWriteDisposition::Exact(MachineWriteProjection::Full);
    }
    // Every register value is its family's root (doc/adr-register-identity.md),
    // so a definition at any other geometry is not a machine event this
    // projection can describe.
    MachineWriteDisposition::Refused(MachineWriteRefusal::InvalidBitRange)
}

fn validate_machine_use_slice(slice: MachineUseSlice, carrier_width_bits: u32) -> Result<(), ()> {
    if carrier_width_bits == 0
        || slice.carrier_width_bits != carrier_width_bits
        || slice.width_bits == 0
        || slice
            .bit_offset
            .checked_add(slice.width_bits)
            .is_none_or(|end| end > carrier_width_bits)
    {
        return Err(());
    }
    let Some(conversion) = slice.conversion else {
        return Ok(());
    };
    let valid = match conversion.kind {
        MachineCastKind::ZeroExtend | MachineCastKind::SignExtend => {
            conversion.to_width_bits > slice.width_bits
        }
        MachineCastKind::BitReinterpret
        | MachineCastKind::IntegerToAddress
        | MachineCastKind::AddressToInteger => conversion.to_width_bits == slice.width_bits,
        // A floating conversion reads its operand whole; it is never a slice.
        MachineCastKind::IntegerToFloat
        | MachineCastKind::FloatToInteger
        | MachineCastKind::FloatToFloat => false,
    };
    valid.then_some(()).ok_or(())
}

const fn whole_machine_use(source: MachineValueBinding) -> MachineUseSlice {
    MachineUseSlice {
        bit_offset: 0,
        width_bits: source.width_bits,
        carrier_width_bits: source.width_bits,
        conversion: None,
    }
}

fn machine_use_slice_for_input(
    arena: &MachineExprArena,
    root: &MachineExpr,
    child_id: MachineExprId,
    source: MachineValueBinding,
    root_is_extracting_operation: bool,
) -> Option<MachineUseSlice> {
    let child = arena.get(child_id)?;
    if operand_leaf_binding(arena, child_id)? != source {
        return None;
    }

    if let MachineExprKind::Cast { kind, input } = &root.kind {
        if *input != child_id {
            return None;
        }
        // A floating conversion is an operation over its whole operand, not a
        // projection of the use; the slice carries no conversion.
        let conversion = (!matches!(
            kind,
            MachineCastKind::IntegerToFloat
                | MachineCastKind::FloatToInteger
                | MachineCastKind::FloatToFloat
        ))
        .then_some(MachineUseConversion {
            kind: *kind,
            to_width_bits: root.ty.width_bits(),
        });
        return Some(MachineUseSlice {
            bit_offset: 0,
            width_bits: source.width_bits,
            carrier_width_bits: source.width_bits,
            conversion,
        });
    }
    if let MachineExprKind::Extract { input, lsb_bits } = &root.kind {
        if *input != child_id {
            return None;
        }
        // An extraction the *operation* performs reads its operand whole: the
        // operation renders the offset, and describing it again as a property
        // of the read applies it twice. An extraction that is merely how a
        // narrower read of a wider register is expressed has no such operation
        // behind it, so the read keeps the offset -- otherwise a sub-register
        // read would lose its position entirely.
        //
        // This is the mirror of the record in the `Subpiece` arm, and the two
        // have to move together: this is what the recorded slice is validated
        // against, so changing one alone makes every extraction fail validation
        // and takes the whole projection down.
        if root_is_extracting_operation {
            return Some(whole_machine_use(source));
        }
        return Some(MachineUseSlice {
            bit_offset: *lsb_bits,
            width_bits: root.ty.width_bits(),
            carrier_width_bits: source.width_bits,
            conversion: None,
        });
    }
    if let MachineExprKind::Extract { lsb_bits, .. } = &child.kind {
        return Some(MachineUseSlice {
            bit_offset: *lsb_bits,
            width_bits: child.ty.width_bits(),
            carrier_width_bits: source.width_bits,
            conversion: None,
        });
    }
    Some(whole_machine_use(source))
}

/// Immutable machine-semantic projection of the value-producing SSA graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineFunction {
    arena: MachineExprArena,
    entities: Box<[MachineEntity]>,
    /// The typed address leaf of every store, keyed by the access it writes,
    /// in access order.
    ///
    /// A load's address is the child of its `MemoryRead` root, typed with the
    /// object it reaches. A store has no root, so its address had no node,
    /// and a consumer reasoning about the cell a store writes -- the
    /// rewriter, which spells `p[i] = v` by the rule that spells `v = p[i]`
    /// -- had nothing to start from. Interned under the same key as a load's
    /// address, so a value both read and written through is one leaf.
    store_addresses: Box<[(StructuredAccessId, MachineExprId)]>,
    /// Dense by `ValueId`: the position in `entities` of the entity whose
    /// output is that value, or `NO_ENTITY`. Derived from `entities`, so it is
    /// not serialised and not part of what two functions are compared on.
    #[serde(skip)]
    entity_index_by_output: Box<[u32]>,
}

/// Cell value in `MachineFunction::entity_index_by_output` for a value no
/// entity produces.
const NO_ENTITY: u32 = u32::MAX;

fn entity_index_by_output(entities: &[MachineEntity], value_count: usize) -> Box<[u32]> {
    let mut index = vec![NO_ENTITY; value_count];
    for (position, entity) in entities.iter().enumerate() {
        if let Some(cell) = index.get_mut(entity.output.value.0 as usize) {
            *cell = position as u32;
        }
    }
    index.into_boxed_slice()
}

impl MachineFunction {
    /// Construct machine expressions only from prepared, name-independent facts.
    ///
    /// Effect-only and control-only instructions have no expression output and are
    /// intentionally outside this layer. Any unsupported value-producing operation
    /// fails explicitly instead of falling back to textual lowering.
    pub fn from_artifact(artifact: &SsaArtifact) -> Result<Self, MachineBuildError> {
        let projection = MachineProjection::from_artifact(artifact)?;
        if let Some(failure) = projection.failures.first() {
            return Err(failure.error.clone());
        }
        let function = projection.into_machine();
        function.validate_against(artifact)?;
        Ok(function)
    }

    pub const fn arena(&self) -> &MachineExprArena {
        &self.arena
    }

    pub const fn entities(&self) -> &[MachineEntity] {
        &self.entities
    }

    /// The typed address leaf of the store performing `access`, if the store
    /// was projected.
    pub fn store_address(&self, access: StructuredAccessId) -> Option<MachineExprId> {
        self.store_addresses
            .binary_search_by_key(&access, |(id, _)| *id)
            .ok()
            .map(|index| self.store_addresses[index].1)
    }

    /// Every projected store's address leaf, in access order.
    pub const fn store_addresses(&self) -> &[(StructuredAccessId, MachineExprId)] {
        &self.store_addresses
    }

    pub fn expr(&self, id: MachineExprId) -> Option<&MachineExpr> {
        self.arena.get(id)
    }

    pub fn entity_for_output(&self, value: ValueId) -> Option<&MachineEntity> {
        let position = *self.entity_index_by_output.get(value.0 as usize)?;
        if position == NO_ENTITY {
            return None;
        }
        self.entities.get(position as usize)
    }

    pub fn entity_for_producer(&self, producer: CanonicalInstructionId) -> Option<&MachineEntity> {
        self.entities
            .iter()
            .find(|entity| entity.producer == producer)
    }

    /// Recheck all arena and source-identity invariants against the owning artifact.
    pub fn validate_against(&self, artifact: &SsaArtifact) -> Result<(), MachineBuildError> {
        let by_output = self.validate_entities_against(artifact)?;
        for inst in &artifact.graph().insts {
            let Some(output) = inst.output else {
                continue;
            };
            if by_output.get(output).is_none() {
                return Err(MachineBuildError::EntityMismatch(inst.id));
            }
        }
        Ok(())
    }

    fn validate_entities_against<'a>(
        &'a self,
        artifact: &SsaArtifact,
    ) -> Result<ByValue<&'a MachineEntity>, MachineBuildError> {
        if !artifact.obligations().is_complete() {
            return Err(MachineBuildError::IncompleteObligationInventory);
        }
        self.validate_arena(artifact)?;

        let graph = artifact.graph();
        let mut by_output = ByValue::over(graph.values.len());
        for entity in &self.entities {
            let value = graph
                .value(entity.output.value)
                .ok_or(MachineBuildError::MissingGraphValue(entity.output.value))?;
            if !by_output.put(entity.output.value, entity) {
                return Err(MachineBuildError::DuplicateEntity(entity.output.value));
            }
            if binding_for_value(value)? != entity.output {
                r2il::refusal_evidence!(
                    "machine-entity",
                    "{:?}: the value binds {:?} and the entity states {:?}",
                    entity.output.value,
                    binding_for_value(value)?,
                    entity.output
                );
                return Err(MachineBuildError::EntityMismatch(
                    graph
                        .def_inst(entity.output.value)
                        .ok_or(MachineBuildError::EntityMismatch(InstId(u32::MAX)))?,
                ));
            }
            let inst_id = graph
                .def_inst(entity.output.value)
                .ok_or(MachineBuildError::EntityMismatch(InstId(u32::MAX)))?;
            let disposition = artifact
                .obligations()
                .instruction_for_inst(inst_id)
                .ok_or(MachineBuildError::MissingInstructionDisposition(inst_id))?;
            if disposition.id != entity.producer
                || self
                    .arena
                    .get(entity.root)
                    .is_none_or(|root| root.origin != Some(entity.producer))
            {
                r2il::refusal_evidence!(
                    "machine-entity",
                    "{inst_id:?}: the disposition names {:?}, the entity names {:?}, the root names {:?}",
                    disposition.id,
                    entity.producer,
                    self.arena.get(entity.root).and_then(|root| root.origin)
                );
                return Err(MachineBuildError::EntityMismatch(inst_id));
            }
            if disposition.obligations != entity.source_obligations
                || entity
                    .source_obligations
                    .iter()
                    .any(|id| id.instruction != entity.producer)
            {
                return Err(MachineBuildError::ObligationMismatch(inst_id));
            }
            let inst = graph
                .inst(inst_id)
                .ok_or(MachineBuildError::MissingInstruction(inst_id))?;
            self.validate_entity_shape(artifact, inst, entity)?;
        }
        Ok(by_output)
    }

    /// Every store address leaf names the address of exactly the store it is
    /// keyed by, at the type a load's address to the same object would have.
    fn validate_store_addresses(&self, artifact: &SsaArtifact) -> Result<(), MachineBuildError> {
        let graph = artifact.graph();
        let mut previous = None;
        for (access, node) in self.store_addresses.iter() {
            if previous.is_some_and(|last| last >= *access) {
                return Err(MachineBuildError::TopologyMismatch);
            }
            previous = Some(*access);
            let inst = graph
                .inst(access.inst)
                .ok_or(MachineBuildError::MissingInstruction(access.inst))?;
            let fact = artifact
                .facts()
                .structured
                .memory_accesses
                .get(access)
                .filter(|fact| {
                    fact.id == *access
                        && fact.provenance_complete
                        && fact.is_write
                        && fact.id.ordinal == 0
                        && inst.inputs.first() == Some(&fact.address)
                })
                .ok_or(MachineBuildError::EntityMismatch(access.inst))?;
            let source_space = artifact
                .machine_context()
                .memory_space_at(fact.block_addr, fact.op_index)
                .ok_or(MachineBuildError::MachineContextMismatch)?;
            let source_model = artifact.machine_context().memory_model();
            let space_model = source_model
                .space(source_space)
                .filter(|_| source_model.is_available() && source_model.is_coherent())
                .ok_or(MachineBuildError::MachineContextMismatch)?;
            let expected_type = MachineType::Address {
                width_bits: space_model.address_bits(),
                space: MachineAddressSpace::from(source_space),
                provenance: machine_address_provenance(artifact, fact.object),
            };
            let expr = self
                .arena
                .get(*node)
                .ok_or(MachineBuildError::EntityMismatch(access.inst))?;
            let named = match expr.kind() {
                MachineExprKind::Source { binding, .. }
                | MachineExprKind::Constant { binding, .. } => binding.value(),
                _ => return Err(MachineBuildError::EntityMismatch(access.inst)),
            };
            if named != fact.address || *expr.ty() != expected_type {
                return Err(MachineBuildError::EntityMismatch(access.inst));
            }
        }
        Ok(())
    }

    fn validate_arena(&self, artifact: &SsaArtifact) -> Result<(), MachineBuildError> {
        let address_nodes = self
            .arena
            .iter()
            .filter_map(|(_, expression)| match expression.kind() {
                MachineExprKind::MemoryRead { address, .. }
                | MachineExprKind::GuardedRead { address, .. } => Some(*address),
                _ => None,
            })
            .chain(self.store_addresses.iter().map(|(_, node)| *node))
            .collect::<BTreeSet<_>>();
        self.validate_store_addresses(artifact)?;
        for (id, expr) in self.arena.iter() {
            for child in expr.kind.children() {
                if child.index() >= id.index() || self.arena.get(child).is_none() {
                    return Err(MachineBuildError::InvalidChild { expr: id, child });
                }
            }
            self.validate_expr_type(id, expr)?;
            match &expr.kind {
                MachineExprKind::Source { binding, .. } => {
                    let value = artifact
                        .graph()
                        .value(binding.value)
                        .ok_or(MachineBuildError::MissingGraphValue(binding.value))?;
                    let rebound = binding_for_value(value)? != *binding;
                    let folded = value.var.constant_bits().is_some();
                    let unproven_bool = matches!(expr.ty, MachineType::Bool { .. })
                        && !value_has_boolean_producer(artifact.graph(), binding.value);
                    let unaddressed = matches!(expr.ty, MachineType::Address { .. })
                        && !address_nodes.contains(&id);
                    if rebound || folded || unproven_bool || unaddressed {
                        r2il::refusal_evidence!(
                            "machine-source-invalid",
                            "{id:?} {:?} rebound={rebound} folded={folded} unproven_bool={unproven_bool} unaddressed={unaddressed}",
                            binding.value
                        );
                        return Err(MachineBuildError::InvalidExpressionType { expr: id });
                    }
                }
                MachineExprKind::Constant { binding, value } => {
                    let graph_value = artifact
                        .graph()
                        .value(binding.value)
                        .ok_or(MachineBuildError::MissingGraphValue(binding.value))?;
                    let source_bits = graph_value
                        .var
                        .constant_bits()
                        .ok_or(MachineBuildError::InvalidExpressionType { expr: id })?;
                    let rebound = binding_for_value(graph_value)? != *binding;
                    let restated =
                        *value != bit_vector(binding.value, binding.width_bits, source_bits)?;
                    // Folding a comparison leaves a boolean constant, and 0 and 1 are the only ones.
                    let boolean = matches!(expr.ty, MachineType::Bool { .. }) && value.bits() > 1;
                    let unaddressed = matches!(expr.ty, MachineType::Address { .. })
                        && !address_nodes.contains(&id);
                    if rebound || restated || boolean || unaddressed {
                        r2il::refusal_evidence!(
                            "machine-constant-invalid",
                            "{id:?} {:?} rebound={rebound} restated={restated} boolean={boolean} unaddressed={unaddressed}",
                            binding.value
                        );
                        return Err(MachineBuildError::InvalidExpressionType { expr: id });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_expr_type(
        &self,
        id: MachineExprId,
        expr: &MachineExpr,
    ) -> Result<(), MachineBuildError> {
        if expr.ty.width_bits() == 0 {
            return Err(MachineBuildError::InvalidExpressionType { expr: id });
        }
        let child = |child| {
            self.arena
                .get(child)
                .ok_or(MachineBuildError::InvalidChild { expr: id, child })
        };
        let same_width = |child: &MachineExpr| child.ty.width_bits() == expr.ty.width_bits();
        let valid = match &expr.kind {
            MachineExprKind::Source { binding, .. } | MachineExprKind::Constant { binding, .. } => {
                expr.ty == integer_type(binding.width_bits, MachineSignedness::Unsigned)
                    || expr.ty
                        == MachineType::Bool {
                            storage_bits: binding.width_bits,
                        }
                    || matches!(
                        expr.ty,
                        MachineType::Address { width_bits, .. }
                            if width_bits == binding.width_bits
                    )
                    || matches!(
                        expr.ty,
                        MachineType::Float { width_bits }
                            if width_bits == binding.width_bits && float_width_is_supported(width_bits)
                    )
            }
            MachineExprKind::MemoryRead {
                space,
                endianness,
                word_size_bytes,
                address,
                width_bits,
                ..
            } => {
                expr.ty == integer_type(*width_bits, MachineSignedness::Unsigned)
                    && *word_size_bytes > 0
                    && *endianness != MachineMemoryEndianness::Unknown
                    && matches!(
                        child(*address)?.ty,
                        MachineType::Address {
                            space: address_space,
                            ..
                        } if address_space == *space
                    )
            }
            MachineExprKind::Copy { input } | MachineExprKind::BitwiseNot { input } => {
                same_width(child(*input)?)
            }
            MachineExprKind::BooleanNot { input } => {
                matches!(expr.ty, MachineType::Bool { .. }) && child(*input)?.ty == expr.ty
            }
            MachineExprKind::Boolean { left, right, .. } => {
                matches!(expr.ty, MachineType::Bool { .. })
                    && child(*left)?.ty == expr.ty
                    && child(*right)?.ty == expr.ty
            }
            MachineExprKind::Arithmetic { left, right, .. }
            | MachineExprKind::Bitwise { left, right, .. } => {
                same_width(child(*left)?) && same_width(child(*right)?)
            }
            MachineExprKind::Divide {
                interpretation,
                zero_divisor,
                dividend,
                divisor,
            }
            | MachineExprKind::Remainder {
                interpretation,
                zero_divisor,
                dividend,
                divisor,
            } => {
                // The operands are bit patterns at the carrier width; how they
                // are read is the operation's own statement, and the result
                // carries that reading in its type.
                *zero_divisor == MachineZeroDivisorBehavior::Undefined
                    && expr.ty == integer_type(expr.ty.width_bits(), *interpretation)
                    && same_width(child(*dividend)?)
                    && same_width(child(*divisor)?)
            }
            MachineExprKind::Negate { mode, input } => {
                *mode == MachineArithmeticMode::Wrapping
                    && matches!(
                        expr.ty,
                        MachineType::Integer {
                            signedness: MachineSignedness::Unsigned,
                            ..
                        }
                    )
                    && child(*input)?.ty == expr.ty
            }
            MachineExprKind::PopulationCount { input } => {
                let input_bits = child(*input)?.ty.width_bits();
                let required_output_bits = u32::BITS - input_bits.leading_zeros();
                matches!(
                    expr.ty,
                    MachineType::Integer {
                        signedness: MachineSignedness::Unsigned,
                        ..
                    }
                ) && input_bits > 0
                    && expr.ty.width_bits() >= required_output_bits
            }
            MachineExprKind::ArithmeticFlag { left, right, .. } => {
                matches!(expr.ty, MachineType::Bool { .. })
                    && child(*left)?.ty.width_bits() == child(*right)?.ty.width_bits()
            }
            MachineExprKind::Shift {
                kind,
                overshift,
                value,
                count,
            } => {
                let overshift_matches = matches!(
                    (kind, overshift),
                    (
                        MachineShiftKind::Left | MachineShiftKind::LogicalRight,
                        MachineOvershiftBehavior::Zero
                    ) | (
                        MachineShiftKind::ArithmeticRight,
                        MachineOvershiftBehavior::SignFill
                    )
                );
                same_width(child(*value)?)
                    && child(*count)?.ty.width_bits() > 0
                    && overshift_matches
            }
            MachineExprKind::Compare { left, right, .. } => {
                matches!(expr.ty, MachineType::Bool { .. })
                    && child(*left)?.ty.width_bits() == child(*right)?.ty.width_bits()
            }
            MachineExprKind::Cast { kind, input } => {
                let input = child(*input)?;
                let from = input.ty.width_bits();
                let to = expr.ty.width_bits();
                match kind {
                    MachineCastKind::ZeroExtend | MachineCastKind::SignExtend => to > from,
                    MachineCastKind::BitReinterpret => to == from,
                    MachineCastKind::IntegerToAddress | MachineCastKind::AddressToInteger => {
                        to == from
                    }
                    MachineCastKind::IntegerToFloat => {
                        matches!(input.ty, MachineType::Integer { .. })
                            && expr.ty.is_float()
                            && float_width_is_supported(to)
                    }
                    MachineCastKind::FloatToInteger => {
                        input.ty.is_float()
                            && float_width_is_supported(from)
                            && expr.ty == integer_type(to, MachineSignedness::Signed)
                    }
                    MachineCastKind::FloatToFloat => {
                        input.ty.is_float()
                            && expr.ty.is_float()
                            && float_width_is_supported(from)
                            && float_width_is_supported(to)
                            && from != to
                    }
                }
            }
            MachineExprKind::FloatArithmetic { left, right, .. } => {
                expr.ty.is_float()
                    && float_width_is_supported(expr.ty.width_bits())
                    && child(*left)?.ty == expr.ty
                    && child(*right)?.ty == expr.ty
            }
            MachineExprKind::FloatUnary { op, input } => {
                let input = child(*input)?;
                input.ty.is_float()
                    && float_width_is_supported(input.ty.width_bits())
                    && match op {
                        MachineFloatUnaryOp::IsNan => matches!(expr.ty, MachineType::Bool { .. }),
                        _ => expr.ty == input.ty,
                    }
            }
            MachineExprKind::FloatCompare { left, right, .. } => {
                let left = child(*left)?;
                matches!(expr.ty, MachineType::Bool { .. })
                    && left.ty.is_float()
                    && float_width_is_supported(left.ty.width_bits())
                    && child(*right)?.ty == left.ty
            }
            MachineExprKind::Extract { input, lsb_bits } => {
                let input_bits = child(*input)?.ty.width_bits();
                lsb_bits
                    .checked_add(expr.ty.width_bits())
                    .is_some_and(|end| end <= input_bits)
            }
            MachineExprKind::InsertLane {
                root,
                lane,
                lsb_bits,
                width_bits,
                ..
            } => {
                let root = child(*root)?;
                let lane = child(*lane)?;
                root.ty.width_bits() == expr.ty.width_bits()
                    && lane.ty.width_bits() == *width_bits
                    && lsb_bits
                        .checked_add(*width_bits)
                        .is_some_and(|end| end <= expr.ty.width_bits())
            }
            MachineExprKind::Concat { high, low } => {
                let high = child(*high)?;
                let low = child(*low)?;
                matches!(
                    expr.ty,
                    MachineType::Integer {
                        signedness: MachineSignedness::Unsigned,
                        ..
                    }
                ) && matches!(
                    high.ty,
                    MachineType::Integer {
                        signedness: MachineSignedness::Unsigned,
                        ..
                    }
                ) && matches!(
                    low.ty,
                    MachineType::Integer {
                        signedness: MachineSignedness::Unsigned,
                        ..
                    }
                ) && high.ty.width_bits().checked_add(low.ty.width_bits())
                    == Some(expr.ty.width_bits())
            }
            MachineExprKind::Select {
                condition,
                if_true,
                if_false,
            } => {
                matches!(child(*condition)?.ty, MachineType::Bool { .. })
                    && child(*if_true)?.ty == expr.ty
                    && child(*if_false)?.ty == expr.ty
            }
            MachineExprKind::Phi { inputs } => {
                !inputs.is_empty()
                    && inputs
                        .iter()
                        .all(|input| child(*input).is_ok_and(same_width))
            }
            MachineExprKind::GuardedRead {
                address,
                guard,
                width_bits,
                ..
            } => {
                child(*address).is_ok()
                    && child(*guard).is_ok_and(|guard| matches!(guard.ty, MachineType::Bool { .. }))
                    && *width_bits == expr.ty.width_bits()
            }
            MachineExprKind::ExclusiveStoreSucceeded { address, value } => {
                child(*address).is_ok()
                    && child(*value).is_ok()
                    && matches!(expr.ty, MachineType::Bool { .. })
            }
        };
        if valid {
            Ok(())
        } else {
            r2il::refusal_evidence!(
                "machine-expression-type",
                "{id:?} {:?} {:?} over {:?}",
                expr.ty,
                expr.kind,
                expr.kind
                    .children()
                    .iter()
                    .map(|child| self.arena.get(*child).map(|child| child.ty))
                    .collect::<Vec<_>>()
            );
            Err(MachineBuildError::InvalidExpressionType { expr: id })
        }
    }

    fn validate_entity_shape(
        &self,
        artifact: &SsaArtifact,
        inst: &GraphInst,
        entity: &MachineEntity,
    ) -> Result<(), MachineBuildError> {
        // Each check says what it rejected. "The entity does not match" alone
        // leaves a reader to rediscover which of four rules it broke.
        let mismatch = |why: &str| {
            r2il::refusal_evidence!("machine-entity", "{:?}: {why}", inst.id);
            MachineBuildError::EntityMismatch(inst.id)
        };
        let root = self
            .arena
            .get(entity.root)
            .ok_or_else(|| mismatch("the root is not an expression"))?;
        if root.ty.width_bits() != entity.output.width_bits {
            return Err(mismatch(&format!(
                "the root is {} bits and the output is {}",
                root.ty.width_bits(),
                entity.output.width_bits
            )));
        }
        let inputs = root.kind.children();
        if inputs.len() != inst.inputs.len() {
            return Err(mismatch(&format!(
                "the root takes {} operands and the instruction has {}",
                inputs.len(),
                inst.inputs.len()
            )));
        }
        for (child, expected) in inputs.iter().zip(&inst.inputs) {
            let binding = operand_leaf_binding(&self.arena, *child)
                .ok_or_else(|| mismatch(&format!("operand {child:?} is not a leaf")))?;
            if binding.value != *expected {
                return Err(mismatch(&format!(
                    "operand {child:?} reads {:?} and the instruction reads {expected:?}",
                    binding.value
                )));
            }
        }
        let shape_matches = match (&inst.payload, &root.kind) {
            (InstPayload::Phi { .. }, MachineExprKind::Phi { .. }) => {
                root.ty == integer_type(entity.output.width_bits, MachineSignedness::Unsigned)
            }
            (InstPayload::Op(op), kind) => {
                machine_kind_matches_op(op, kind)
                    && machine_type_matches_op(op, &root.ty, entity.output.width_bits)
            }
            _ => false,
        };
        if !shape_matches {
            return Err(mismatch(&format!(
                "{:?} does not have the shape of {:?} at {:?}",
                root.kind, inst.payload, root.ty
            )));
        }
        if let MachineExprKind::MemoryRead { .. } = &root.kind {
            self.validate_memory_read(artifact, inst, entity, root)?;
        }
        let disposition = artifact
            .obligations()
            .instruction_for_inst(inst.id)
            .ok_or(MachineBuildError::MissingInstructionDisposition(inst.id))?;
        if disposition.id != entity.producer || disposition.obligations != entity.source_obligations
        {
            return Err(MachineBuildError::ObligationMismatch(inst.id));
        }
        Ok(())
    }

    fn validate_memory_read(
        &self,
        artifact: &SsaArtifact,
        inst: &GraphInst,
        entity: &MachineEntity,
        root: &MachineExpr,
    ) -> Result<(), MachineBuildError> {
        let (MachineExprKind::MemoryRead {
            access,
            object,
            space,
            endianness,
            word_size_bytes,
            address,
            width_bits,
        }
        | MachineExprKind::GuardedRead {
            access,
            object,
            space,
            endianness,
            word_size_bytes,
            address,
            width_bits,
            ..
        }) = &root.kind
        else {
            return Err(MachineBuildError::EntityMismatch(inst.id));
        };
        let fact = artifact
            .facts()
            .structured
            .memory_accesses
            .get(access)
            .filter(|fact| {
                fact.id.inst == inst.id
                    && fact.provenance_complete
                    && !fact.is_write
                    && fact.id.ordinal == 0
                    && fact.value == Some(entity.output.value)
                    && read_operands_are_exact(source_op_of(inst), &inst.inputs, fact.address)
            })
            .ok_or(MachineBuildError::EntityMismatch(inst.id))?;
        let source_space = artifact
            .machine_context()
            .memory_space_at(fact.block_addr, fact.op_index)
            .ok_or(MachineBuildError::MachineContextMismatch)?;
        let source_op = match &inst.payload {
            InstPayload::Op(
                op @ (SSAOp::Load { .. } | SSAOp::LoadLinked { .. } | SSAOp::LoadGuarded { .. }),
            ) => op,
            _ => {
                r2il::refusal_evidence!(
                    "machine-entity",
                    "{:?}: a memory read projected from {:?}",
                    inst.id,
                    inst.payload
                );
                return Err(MachineBuildError::EntityMismatch(inst.id));
            }
        };
        let prepared_op = artifact
            .function()
            .get_block(fact.block_addr)
            .and_then(|block| block.ops.get(fact.op_index))
            .ok_or(MachineBuildError::EntityMismatch(inst.id))?;
        let source_model = artifact.machine_context().memory_model();
        let source_space_model = source_model
            .space(source_space)
            .filter(|_| source_model.is_available() && source_model.is_coherent())
            .ok_or(MachineBuildError::MachineContextMismatch)?;
        let fact_width_bits = fact.width.checked_mul(8).unwrap_or(0);
        let expected_address = self
            .arena
            .get(*address)
            .ok_or(MachineBuildError::EntityMismatch(inst.id))?;
        let expected_address_type = MachineType::Address {
            width_bits: source_space_model.address_bits(),
            space: MachineAddressSpace::from(source_space),
            provenance: machine_address_provenance(artifact, fact.object),
        };
        if !memory_access_authorities_match(
            artifact.graph(),
            artifact.objects(),
            source_op,
            prepared_op,
            source_space,
            fact,
            artifact
                .facts()
                .structured
                .member_run_stores
                .get(&fact.id.inst),
        ) || *object != fact.object
            || *space != MachineAddressSpace::from(source_space)
            || *endianness != source_space_model.endianness()
            || *word_size_bytes != source_space_model.word_size_bytes()
            || *width_bits != fact_width_bits
            || fact_width_bits != entity.output.width_bits
            || expected_address.ty != expected_address_type
        {
            return Err(MachineBuildError::EntityMismatch(inst.id));
        }
        Ok(())
    }
}

#[derive(Default)]
struct MachineBuilder {
    nodes: Vec<MachineExpr>,
    value_nodes: BTreeMap<(ValueId, MachineType), MachineExprId>,
    address_nodes: BTreeMap<(ValueId, ObjectId, MachineAddressSpace), MachineExprId>,
    store_addresses: BTreeMap<StructuredAccessId, MachineExprId>,
    /// Every instruction's use dispositions, flat, with `use_offsets` naming
    /// where each instruction's row starts. This was a vector per instruction,
    /// rebuilt as a second vector per instruction by the canonical pass and
    /// flattened by a third -- three shapes and two allocations per
    /// instruction to arrive at the one the projection keeps.
    use_slots: Vec<MachineUseDisposition>,
    use_offsets: Vec<u32>,
}

impl MachineBuilder {
    /// Where one instruction's uses sit in the flat table.
    fn use_row_range(&self, inst: InstId) -> Option<std::ops::Range<usize>> {
        let start = *self.use_offsets.get(inst.0 as usize)? as usize;
        let end = *self.use_offsets.get(inst.0 as usize + 1)? as usize;
        (start <= end && end <= self.use_slots.len()).then_some(start..end)
    }

    /// Where one use of one instruction sits in the flat table.
    fn use_slot_index(&self, inst: InstId, input_idx: usize) -> Option<usize> {
        let row = self.use_row_range(inst)?;
        let at = row.start.checked_add(input_idx)?;
        (at < row.end).then_some(at)
    }

    fn for_graph(graph: &SsaGraph) -> Self {
        Self {
            use_offsets: {
                let mut offsets = Vec::with_capacity(graph.insts.len() + 1);
                let mut total = 0u32;
                offsets.push(total);
                for inst in &graph.insts {
                    total += inst.inputs.len() as u32;
                    offsets.push(total);
                }
                offsets
            },
            use_slots: vec![
                MachineUseDisposition::Refused(MachineUseRefusal::UnsupportedOperation);
                graph
                    .insts
                    .iter()
                    .map(|inst| inst.inputs.len())
                    .sum::<usize>()
            ],
            ..Self::default()
        }
    }

    fn record_use(
        &mut self,
        graph: &SsaGraph,
        inst: &GraphInst,
        input_idx: usize,
        slice: MachineUseSlice,
    ) -> Result<(), MachineBuildError> {
        let site = UseSite {
            inst: inst.id,
            input_idx,
        };
        let input = *inst
            .inputs
            .get(input_idx)
            .ok_or(MachineBuildError::MissingUseDisposition(site))?;
        let source = binding_for_value(
            graph
                .value(input)
                .ok_or(MachineBuildError::MissingGraphValue(input))?,
        )?;
        validate_machine_use_slice(slice, source.width_bits).map_err(|_| {
            r2il::refusal_evidence!(
                "machine-use-slice",
                "{site:?} reads {slice:?} of a {}-bit carrier in {:?}",
                source.width_bits,
                inst.payload
            );
            MachineBuildError::UseDispositionMismatch(site)
        })?;
        let cell = self
            .use_slot_index(inst.id, input_idx)
            .and_then(|at| self.use_slots.get_mut(at))
            .ok_or(MachineBuildError::MissingUseDisposition(site))?;
        *cell = MachineUseDisposition::Exact(slice);
        Ok(())
    }

    fn record_whole_use(
        &mut self,
        graph: &SsaGraph,
        inst: &GraphInst,
        input_idx: usize,
    ) -> Result<(), MachineBuildError> {
        let input = *inst
            .inputs
            .get(input_idx)
            .ok_or(MachineBuildError::MissingUseDisposition(UseSite {
                inst: inst.id,
                input_idx,
            }))?;
        let source = binding_for_value(
            graph
                .value(input)
                .ok_or(MachineBuildError::MissingGraphValue(input))?,
        )?;
        self.record_use(graph, inst, input_idx, whole_machine_use(source))
    }

    /// Refuse every read of an instruction whose projection failed.
    ///
    /// A constant operand is still interned. Whether a value is a constant is a
    /// fact about the value, not about whether the operation reading it could be
    /// lowered, and leaving it out made the binding plan refuse the constant
    /// too -- reporting a missing literal projection where the truth was an
    /// operation with no model. On `/bin/ls` that is `brk 0xc471` refusing on
    /// its own immediate.
    fn refuse_inst_uses(
        &mut self,
        graph: &SsaGraph,
        inst: &GraphInst,
        refusal: MachineUseRefusal,
    ) -> Result<(), MachineBuildError> {
        for input in inst.inputs.iter().copied() {
            let graph_value = graph
                .value(input)
                .ok_or(MachineBuildError::MissingGraphValue(input))?;
            if graph_value.var.constant_bits().is_some() {
                self.intern_value(graph_value)?;
            }
        }
        let row = self
            .use_row_range(inst.id)
            .ok_or(MachineBuildError::MissingInstruction(inst.id))?;
        if row.len() != inst.inputs.len() {
            return Err(MachineBuildError::TopologyMismatch);
        }
        self.use_slots[row].fill(MachineUseDisposition::Refused(refusal));
        Ok(())
    }

    /// Intern the address a store writes through, typed as a load's address
    /// is. See [`MachineFunction::store_addresses`].
    ///
    /// A store whose access the facts cannot state exactly gets no node. That
    /// is a decline rather than a failure: the store's operand reads are
    /// already recorded, and the only consumer of the node is one that may
    /// rewrite the cell, which it then does not.
    fn intern_store_address(
        &mut self,
        artifact: &SsaArtifact,
        inst: &GraphInst,
        op: &SSAOp,
    ) -> Result<(), MachineBuildError> {
        let graph = artifact.graph();
        let accesses = artifact
            .facts()
            .structured
            .memory_accesses
            .values()
            .filter(|access| access.id.inst == inst.id)
            .collect::<Vec<_>>();
        let [access] = accesses.as_slice() else {
            return Ok(());
        };
        let source_space = artifact
            .machine_context()
            .memory_space_at(access.block_addr, access.op_index);
        let model = artifact.machine_context().memory_model();
        let space_model = source_space.and_then(|space| model.space(space));
        let prepared_op = artifact
            .function()
            .get_block(access.block_addr)
            .and_then(|block| block.ops.get(access.op_index));
        if !access.provenance_complete
            || !access.is_write
            || access.id.ordinal != 0
            || prepared_op.is_none_or(|prepared_op| {
                source_space.is_none_or(|source_space| {
                    !memory_access_authorities_match(
                        graph,
                        artifact.objects(),
                        op,
                        prepared_op,
                        source_space,
                        access,
                        artifact
                            .facts()
                            .structured
                            .member_run_stores
                            .get(&access.id.inst),
                    )
                })
            })
            || inst.inputs.first() != Some(&access.address)
            || !model.is_available()
            || !model.is_coherent()
        {
            return Ok(());
        }
        let Some(space_model) = space_model else {
            return Ok(());
        };
        let address = graph
            .value(access.address)
            .ok_or(MachineBuildError::MissingGraphValue(access.address))?;
        let space = MachineAddressSpace::from(space_model.space());
        let node = self.intern_address(
            artifact,
            address,
            access.object,
            space,
            space_model.address_bits(),
        )?;
        self.store_addresses.insert(access.id, node);
        Ok(())
    }

    fn push(
        &mut self,
        ty: MachineType,
        origin: Option<CanonicalInstructionId>,
        kind: MachineExprKind,
    ) -> MachineExprId {
        let id = MachineExprId(self.nodes.len() as u32);
        self.nodes.push(MachineExpr { ty, origin, kind });
        id
    }

    fn intern_value(&mut self, value: &GraphValue) -> Result<MachineExprId, MachineBuildError> {
        let binding = binding_for_value(value)?;
        let ty = integer_type(binding.width_bits, MachineSignedness::Unsigned);
        self.intern_value_with_type(value, ty)
    }

    fn intern_boolean_value(
        &mut self,
        graph: &crate::graph::SsaGraph,
        value: &GraphValue,
        inst: InstId,
    ) -> Result<MachineExprId, MachineBuildError> {
        let binding = binding_for_value(value)?;
        if !value_has_boolean_producer(graph, value.id) {
            // Which operand is not a boolean, and what produced it: the
            // operation refuses as a whole, and "unsupported" alone does not
            // say which of its inputs is the one to look at.
            r2il::refusal_evidence!(
                "boolean-operand",
                "{:?} reads {:?}, produced by {:?}, which is not a boolean",
                inst,
                value.id,
                graph
                    .def_inst(value.id)
                    .and_then(|def| graph.inst(def))
                    .map(|def| format!("{:?}", def.payload)
                        .chars()
                        .take(90)
                        .collect::<String>())
            );
            return Err(MachineBuildError::UnsupportedOperation {
                inst,
                op: Box::new(
                    graph
                        .inst(inst)
                        .and_then(|inst| match &inst.payload {
                            InstPayload::Op(op) => Some(op.clone()),
                            InstPayload::Phi { .. } => None,
                        })
                        .unwrap_or(SSAOp::Unimplemented),
                ),
            });
        }
        self.intern_value_with_type(
            value,
            MachineType::Bool {
                storage_bits: binding.width_bits,
            },
        )
    }

    fn intern_value_with_type(
        &mut self,
        value: &GraphValue,
        ty: MachineType,
    ) -> Result<MachineExprId, MachineBuildError> {
        let binding = binding_for_value(value)?;
        let key = (value.id, ty);
        if let Some(id) = self.value_nodes.get(&key).copied() {
            return Ok(id);
        }
        let kind = if let Some(bits) = value.var.constant_bits() {
            MachineExprKind::Constant {
                binding,
                value: bit_vector(value.id, binding.width_bits, bits)?,
            }
        } else {
            MachineExprKind::Source {
                binding,
                storage: value.canonical_storage,
            }
        };
        let id = self.push(ty, None, kind);
        self.value_nodes.insert(key, id);
        Ok(id)
    }

    fn intern_address(
        &mut self,
        artifact: &SsaArtifact,
        value: &GraphValue,
        object: ObjectId,
        space: MachineAddressSpace,
        address_bits: u32,
    ) -> Result<MachineExprId, MachineBuildError> {
        let key = (value.id, object, space);
        if let Some(id) = self.address_nodes.get(&key).copied() {
            return Ok(id);
        }
        let binding = binding_for_value(value)?;
        if binding.width_bits != address_bits {
            return Err(MachineBuildError::WidthMismatch {
                inst: artifact
                    .graph()
                    .def_inst(value.id)
                    .unwrap_or(InstId(u32::MAX)),
                expected_bits: address_bits,
                actual_bits: binding.width_bits,
            });
        }
        let provenance = machine_address_provenance(artifact, object);
        let ty = MachineType::Address {
            width_bits: address_bits,
            space,
            provenance,
        };
        let kind = if let Some(bits) = value.var.constant_bits() {
            MachineExprKind::Constant {
                binding,
                value: bit_vector(value.id, binding.width_bits, bits)?,
            }
        } else {
            MachineExprKind::Source {
                binding,
                storage: value.canonical_storage,
            }
        };
        let id = self.push(ty, None, kind);
        self.address_nodes.insert(key, id);
        Ok(id)
    }

    fn operand_nodes(
        &mut self,
        graph: &crate::graph::SsaGraph,
        inst: &GraphInst,
        expected: usize,
    ) -> Result<Vec<MachineExprId>, MachineBuildError> {
        if inst.inputs.len() != expected {
            return Err(MachineBuildError::WrongOperandCount {
                inst: inst.id,
                expected,
                actual: inst.inputs.len(),
            });
        }
        let mut nodes = Vec::with_capacity(expected);
        for (input_idx, value) in inst.inputs.iter().copied().enumerate() {
            let graph_value = graph
                .value(value)
                .ok_or(MachineBuildError::MissingGraphValue(value))?;
            nodes.push(self.intern_value(graph_value)?);
            self.record_whole_use(graph, inst, input_idx)?;
        }
        Ok(nodes)
    }

    fn narrowed_operand_nodes(
        &mut self,
        graph: &crate::graph::SsaGraph,
        inst: &GraphInst,
        expected: usize,
        result_bits: u32,
    ) -> Result<Vec<MachineExprId>, MachineBuildError> {
        if inst.inputs.len() != expected {
            return Err(MachineBuildError::WrongOperandCount {
                inst: inst.id,
                expected,
                actual: inst.inputs.len(),
            });
        }
        let mut inputs = Vec::with_capacity(expected);
        for input_idx in 0..expected {
            inputs.push(self.narrowed_operand_node(graph, inst, input_idx, result_bits)?);
        }
        Ok(inputs)
    }

    fn narrowed_operand_node(
        &mut self,
        graph: &crate::graph::SsaGraph,
        inst: &GraphInst,
        input_idx: usize,
        result_bits: u32,
    ) -> Result<MachineExprId, MachineBuildError> {
        let value = *inst
            .inputs
            .get(input_idx)
            .ok_or(MachineBuildError::MissingUseDisposition(UseSite {
                inst: inst.id,
                input_idx,
            }))?;
        let graph_value = graph
            .value(value)
            .ok_or(MachineBuildError::MissingGraphValue(value))?;
        let input = self.intern_value(graph_value)?;
        let input_bits = self.nodes[input.index()].ty.width_bits();
        if input_bits < result_bits {
            return Err(MachineBuildError::WidthMismatch {
                inst: inst.id,
                expected_bits: result_bits,
                actual_bits: input_bits,
            });
        }
        self.record_use(
            graph,
            inst,
            input_idx,
            MachineUseSlice {
                bit_offset: 0,
                width_bits: result_bits,
                carrier_width_bits: input_bits,
                conversion: None,
            },
        )?;
        if input_bits == result_bits {
            return Ok(input);
        }
        Ok(self.push(
            integer_type(result_bits, MachineSignedness::Unsigned),
            None,
            MachineExprKind::Extract { input, lsb_bits: 0 },
        ))
    }

    fn exact_width_operand_node(
        &mut self,
        graph: &crate::graph::SsaGraph,
        inst: &GraphInst,
        input_idx: usize,
        expected_bits: u32,
    ) -> Result<MachineExprId, MachineBuildError> {
        let value = *inst
            .inputs
            .get(input_idx)
            .ok_or(MachineBuildError::MissingUseDisposition(UseSite {
                inst: inst.id,
                input_idx,
            }))?;
        let graph_value = graph
            .value(value)
            .ok_or(MachineBuildError::MissingGraphValue(value))?;
        let actual_bits = binding_for_value(graph_value)?.width_bits;
        if actual_bits != expected_bits {
            return Err(MachineBuildError::WidthMismatch {
                inst: inst.id,
                expected_bits,
                actual_bits,
            });
        }
        let input = self.intern_value(graph_value)?;
        self.record_whole_use(graph, inst, input_idx)?;
        Ok(input)
    }

    fn exact_width_operand_nodes(
        &mut self,
        graph: &crate::graph::SsaGraph,
        inst: &GraphInst,
        expected: usize,
        expected_bits: u32,
    ) -> Result<Vec<MachineExprId>, MachineBuildError> {
        if inst.inputs.len() != expected {
            return Err(MachineBuildError::WrongOperandCount {
                inst: inst.id,
                expected,
                actual: inst.inputs.len(),
            });
        }
        let mut inputs = Vec::with_capacity(expected);
        for input_idx in 0..expected {
            inputs.push(self.exact_width_operand_node(graph, inst, input_idx, expected_bits)?);
        }
        Ok(inputs)
    }

    /// The floating type of `width_bits`, refusing the widths C cannot spell.
    fn float_type(
        &self,
        inst: &GraphInst,
        width_bits: u32,
    ) -> Result<MachineType, MachineBuildError> {
        if !float_width_is_supported(width_bits) {
            return Err(MachineBuildError::UnsupportedOperation {
                inst: inst.id,
                op: Box::new(match &inst.payload {
                    InstPayload::Op(op) => op.clone(),
                    InstPayload::Phi { .. } => SSAOp::Unimplemented,
                }),
            });
        }
        Ok(MachineType::Float { width_bits })
    }

    fn operand_width(
        &self,
        graph: &crate::graph::SsaGraph,
        inst: &GraphInst,
        input_idx: usize,
    ) -> Result<u32, MachineBuildError> {
        let value = *inst
            .inputs
            .get(input_idx)
            .ok_or(MachineBuildError::MissingUseDisposition(UseSite {
                inst: inst.id,
                input_idx,
            }))?;
        let graph_value = graph
            .value(value)
            .ok_or(MachineBuildError::MissingGraphValue(value))?;
        Ok(binding_for_value(graph_value)?.width_bits)
    }

    /// Operands read as floating values of exactly `expected_bits`.
    fn float_operand_nodes(
        &mut self,
        graph: &crate::graph::SsaGraph,
        inst: &GraphInst,
        expected: usize,
        expected_bits: u32,
    ) -> Result<Vec<MachineExprId>, MachineBuildError> {
        if inst.inputs.len() != expected {
            return Err(MachineBuildError::WrongOperandCount {
                inst: inst.id,
                expected,
                actual: inst.inputs.len(),
            });
        }
        let float = self.float_type(inst, expected_bits)?;
        let mut inputs = Vec::with_capacity(expected);
        for (input_idx, value) in inst.inputs.iter().copied().enumerate() {
            let graph_value = graph
                .value(value)
                .ok_or(MachineBuildError::MissingGraphValue(value))?;
            let actual_bits = binding_for_value(graph_value)?.width_bits;
            if actual_bits != expected_bits {
                return Err(MachineBuildError::WidthMismatch {
                    inst: inst.id,
                    expected_bits,
                    actual_bits,
                });
            }
            inputs.push(self.intern_value_with_type(graph_value, float)?);
            self.record_whole_use(graph, inst, input_idx)?;
        }
        Ok(inputs)
    }
}

fn integer_type(width_bits: u32, signedness: MachineSignedness) -> MachineType {
    MachineType::Integer {
        width_bits,
        signedness,
    }
}

pub fn machine_address_provenance(
    artifact: &SsaArtifact,
    object: ObjectId,
) -> MachineAddressProvenance {
    artifact
        .objects()
        .object(object)
        .map(|object| match &object.kind {
            ObjectKind::StackSlot { base, offset, .. }
            | ObjectKind::FrameObject { base, offset, .. } => MachineAddressProvenance::Stack {
                base: match base {
                    StackAddressBase::FramePointer => MachineStackBase::FramePointer,
                    StackAddressBase::StackPointer => MachineStackBase::StackPointer,
                    StackAddressBase::Realigned => MachineStackBase::Realigned,
                },
                offset: *offset,
            },
            ObjectKind::Parameter { index, .. } => u32::try_from(*index)
                .map(|index| MachineAddressProvenance::Parameter { index })
                .unwrap_or(MachineAddressProvenance::Unknown),
            ObjectKind::Global { address, .. } => {
                MachineAddressProvenance::Global { address: *address }
            }
            ObjectKind::HeapAlloc { .. }
            | ObjectKind::EscapedUnknown { .. }
            | ObjectKind::Pointee { .. } => MachineAddressProvenance::Unknown,
        })
        .unwrap_or(MachineAddressProvenance::Unknown)
}

/// One entry per graph value, addressed by the value's identifier.
///
/// The validation walks every instruction asking what a value projects to, and
/// an ordered map answered each question with a walk down a tree. Value
/// identifiers are already dense, so the answer is at the index.
struct ByValue<T>(Vec<Option<T>>);

impl<T> ByValue<T> {
    fn over(values: usize) -> Self {
        Self((0..values).map(|_| None).collect())
    }

    /// Record a value's entry. False when the value is out of range or
    /// already has one, which is the caller's duplicate.
    fn put(&mut self, value: ValueId, entry: T) -> bool {
        let Some(slot) = self.0.get_mut(value.0 as usize) else {
            return false;
        };
        if slot.is_some() {
            return false;
        }
        *slot = Some(entry);
        true
    }
}

impl<T: Copy> ByValue<T> {
    fn get(&self, value: ValueId) -> Option<T> {
        *self.0.get(value.0 as usize)?
    }
}

fn binding_for_value(value: &GraphValue) -> Result<MachineValueBinding, MachineBuildError> {
    let width_bits = value
        .var
        .size
        .checked_mul(8)
        .filter(|width| *width > 0)
        .ok_or(MachineBuildError::InvalidValueWidth {
            value: value.id,
            size_bytes: value.var.size,
        })?;
    Ok(MachineValueBinding {
        value: value.id,
        width_bits,
    })
}

fn bit_vector(
    value: ValueId,
    width_bits: u32,
    bits: u64,
) -> Result<MachineBitVector, MachineBuildError> {
    // The width is the varnode's, and the value is the `u64` the varnode
    // carried, so a constant wider than eight bytes is one whose value provably
    // fits and whose *size* is what makes it wide. Ghidra's three-operand
    // `imul r64, r/m64, imm32` is that: both operands are sign-extended to
    // sixteen bytes, multiplied, and the result sliced, and the immediate
    // arrives as a sixteen-byte constant carrying `0x2001f`. Refusing on the
    // size alone refused `adler32` and `fletcher32` at x64 -O2 while the
    // register form of the same instruction rendered.
    //
    // The ceiling is what the rest of the model spells: declaration widths go
    // to 512, but a C integer is spellable only to 128.
    if !constant_width_is_spellable(width_bits) {
        return Err(MachineBuildError::ConstantTooWide { value, width_bits });
    }
    let mask = if width_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << width_bits) - 1
    };
    Ok(MachineBitVector {
        width_bits,
        bits: bits & mask,
    })
}

fn operand_leaf_binding(
    arena: &MachineExprArena,
    expr: MachineExprId,
) -> Option<MachineValueBinding> {
    match arena.get(expr)?.kind {
        MachineExprKind::Source { binding, .. } | MachineExprKind::Constant { binding, .. } => {
            Some(binding)
        }
        MachineExprKind::Extract { input, lsb_bits: 0 } => operand_leaf_binding(arena, input),
        _ => None,
    }
}

fn machine_kind_matches_op(op: &SSAOp, kind: &MachineExprKind) -> bool {
    if let (SSAOp::Subpiece { offset, .. }, MachineExprKind::Extract { lsb_bits, .. }) = (op, kind)
    {
        return offset.checked_mul(8) == Some(*lsb_bits);
    }
    matches!(
        (op, kind),
        (
            SSAOp::Load { .. } | SSAOp::LoadLinked { .. },
            MachineExprKind::MemoryRead { .. }
        ) | (
            SSAOp::StoreConditional { .. },
            MachineExprKind::ExclusiveStoreSucceeded { .. }
        ) | (
            SSAOp::LoadGuarded { .. },
            MachineExprKind::GuardedRead { .. }
        ) | (SSAOp::CallDefine { .. }, MachineExprKind::Source { .. })
            | (SSAOp::Copy { .. }, MachineExprKind::Copy { .. })
            | (SSAOp::CallRestore { .. }, MachineExprKind::Copy { .. })
            | (
                SSAOp::IntAdd { .. },
                MachineExprKind::Arithmetic {
                    op: MachineArithmeticOp::Add,
                    mode: MachineArithmeticMode::Wrapping,
                    ..
                }
            )
            | (
                SSAOp::IntSub { .. },
                MachineExprKind::Arithmetic {
                    op: MachineArithmeticOp::Subtract,
                    mode: MachineArithmeticMode::Wrapping,
                    ..
                }
            )
            | (
                SSAOp::IntMult { .. },
                MachineExprKind::Arithmetic {
                    op: MachineArithmeticOp::Multiply,
                    mode: MachineArithmeticMode::Wrapping,
                    ..
                }
            )
            | (
                SSAOp::IntDiv { .. },
                MachineExprKind::Divide {
                    interpretation: MachineSignedness::Unsigned,
                    zero_divisor: MachineZeroDivisorBehavior::Undefined,
                    ..
                }
            )
            | (
                SSAOp::IntSDiv { .. },
                MachineExprKind::Divide {
                    interpretation: MachineSignedness::Signed,
                    zero_divisor: MachineZeroDivisorBehavior::Undefined,
                    ..
                }
            )
            | (
                SSAOp::IntRem { .. },
                MachineExprKind::Remainder {
                    interpretation: MachineSignedness::Unsigned,
                    zero_divisor: MachineZeroDivisorBehavior::Undefined,
                    ..
                }
            )
            | (
                SSAOp::IntSRem { .. },
                MachineExprKind::Remainder {
                    interpretation: MachineSignedness::Signed,
                    zero_divisor: MachineZeroDivisorBehavior::Undefined,
                    ..
                }
            )
            | (
                SSAOp::IntNegate { .. },
                MachineExprKind::Negate {
                    mode: MachineArithmeticMode::Wrapping,
                    ..
                }
            )
            | (
                SSAOp::PopCount { .. },
                MachineExprKind::PopulationCount { .. }
            )
            | (
                SSAOp::IntCarry { .. },
                MachineExprKind::ArithmeticFlag {
                    op: MachineArithmeticFlagOp::UnsignedCarry,
                    ..
                }
            )
            | (
                SSAOp::IntSCarry { .. },
                MachineExprKind::ArithmeticFlag {
                    op: MachineArithmeticFlagOp::SignedCarry,
                    ..
                }
            )
            | (
                SSAOp::IntSBorrow { .. },
                MachineExprKind::ArithmeticFlag {
                    op: MachineArithmeticFlagOp::SignedBorrow,
                    ..
                }
            )
            | (
                SSAOp::IntAnd { .. },
                MachineExprKind::Bitwise {
                    op: MachineBitwiseOp::And,
                    ..
                }
            )
            | (
                SSAOp::IntOr { .. },
                MachineExprKind::Bitwise {
                    op: MachineBitwiseOp::Or,
                    ..
                }
            )
            | (
                SSAOp::IntXor { .. },
                MachineExprKind::Bitwise {
                    op: MachineBitwiseOp::Xor,
                    ..
                }
            )
            | (SSAOp::IntNot { .. }, MachineExprKind::BitwiseNot { .. })
            | (SSAOp::BoolNot { .. }, MachineExprKind::BooleanNot { .. })
            | (
                SSAOp::BoolAnd { .. },
                MachineExprKind::Boolean {
                    op: MachineBooleanOp::And,
                    ..
                }
            )
            | (
                SSAOp::BoolOr { .. },
                MachineExprKind::Boolean {
                    op: MachineBooleanOp::Or,
                    ..
                }
            )
            | (
                SSAOp::BoolXor { .. },
                MachineExprKind::Boolean {
                    op: MachineBooleanOp::Xor,
                    ..
                }
            )
            | (
                SSAOp::IntLeft { .. },
                MachineExprKind::Shift {
                    kind: MachineShiftKind::Left,
                    overshift: MachineOvershiftBehavior::Zero,
                    ..
                }
            )
            | (
                SSAOp::IntRight { .. },
                MachineExprKind::Shift {
                    kind: MachineShiftKind::LogicalRight,
                    overshift: MachineOvershiftBehavior::Zero,
                    ..
                }
            )
            | (
                SSAOp::IntSRight { .. },
                MachineExprKind::Shift {
                    kind: MachineShiftKind::ArithmeticRight,
                    overshift: MachineOvershiftBehavior::SignFill,
                    ..
                }
            )
            | (
                SSAOp::IntEqual { .. },
                MachineExprKind::Compare {
                    op: MachineComparisonOp::Equal,
                    interpretation: MachineSignedness::Unsigned,
                    ..
                }
            )
            | (
                SSAOp::IntNotEqual { .. },
                MachineExprKind::Compare {
                    op: MachineComparisonOp::NotEqual,
                    interpretation: MachineSignedness::Unsigned,
                    ..
                }
            )
            | (
                SSAOp::IntLess { .. },
                MachineExprKind::Compare {
                    op: MachineComparisonOp::LessThan,
                    interpretation: MachineSignedness::Unsigned,
                    ..
                }
            )
            | (
                SSAOp::IntSLess { .. },
                MachineExprKind::Compare {
                    op: MachineComparisonOp::LessThan,
                    interpretation: MachineSignedness::Signed,
                    ..
                }
            )
            | (
                SSAOp::IntLessEqual { .. },
                MachineExprKind::Compare {
                    op: MachineComparisonOp::LessThanOrEqual,
                    interpretation: MachineSignedness::Unsigned,
                    ..
                }
            )
            | (
                SSAOp::IntSLessEqual { .. },
                MachineExprKind::Compare {
                    op: MachineComparisonOp::LessThanOrEqual,
                    interpretation: MachineSignedness::Signed,
                    ..
                }
            )
            | (
                SSAOp::IntZExt { .. },
                MachineExprKind::Cast {
                    kind: MachineCastKind::ZeroExtend,
                    ..
                }
            )
            | (
                SSAOp::IntSExt { .. },
                MachineExprKind::Cast {
                    kind: MachineCastKind::SignExtend,
                    ..
                }
            )
            | (
                SSAOp::Trunc { .. } | SSAOp::Float2Int { .. },
                MachineExprKind::Cast {
                    kind: MachineCastKind::FloatToInteger,
                    ..
                }
            )
            | (
                SSAOp::Int2Float { .. },
                MachineExprKind::Cast {
                    kind: MachineCastKind::IntegerToFloat,
                    ..
                }
            )
            | (
                SSAOp::FloatFloat { .. },
                MachineExprKind::Cast {
                    kind: MachineCastKind::FloatToFloat,
                    ..
                }
            )
            | (
                SSAOp::FloatAdd { .. },
                MachineExprKind::FloatArithmetic {
                    op: MachineFloatOp::Add,
                    ..
                }
            )
            | (
                SSAOp::FloatSub { .. },
                MachineExprKind::FloatArithmetic {
                    op: MachineFloatOp::Subtract,
                    ..
                }
            )
            | (
                SSAOp::FloatMult { .. },
                MachineExprKind::FloatArithmetic {
                    op: MachineFloatOp::Multiply,
                    ..
                }
            )
            | (
                SSAOp::FloatDiv { .. },
                MachineExprKind::FloatArithmetic {
                    op: MachineFloatOp::Divide,
                    ..
                }
            )
            | (
                SSAOp::FloatNeg { .. },
                MachineExprKind::FloatUnary {
                    op: MachineFloatUnaryOp::Negate,
                    ..
                }
            )
            | (
                SSAOp::FloatAbs { .. },
                MachineExprKind::FloatUnary {
                    op: MachineFloatUnaryOp::Absolute,
                    ..
                }
            )
            | (
                SSAOp::FloatSqrt { .. },
                MachineExprKind::FloatUnary {
                    op: MachineFloatUnaryOp::SquareRoot,
                    ..
                }
            )
            | (
                SSAOp::FloatCeil { .. },
                MachineExprKind::FloatUnary {
                    op: MachineFloatUnaryOp::Ceiling,
                    ..
                }
            )
            | (
                SSAOp::FloatFloor { .. },
                MachineExprKind::FloatUnary {
                    op: MachineFloatUnaryOp::Floor,
                    ..
                }
            )
            | (
                SSAOp::FloatRound { .. },
                MachineExprKind::FloatUnary {
                    op: MachineFloatUnaryOp::Round,
                    ..
                }
            )
            | (
                SSAOp::FloatNaN { .. },
                MachineExprKind::FloatUnary {
                    op: MachineFloatUnaryOp::IsNan,
                    ..
                }
            )
            | (
                SSAOp::FloatEqual { .. },
                MachineExprKind::FloatCompare {
                    op: MachineComparisonOp::Equal,
                    ..
                }
            )
            | (
                SSAOp::FloatNotEqual { .. },
                MachineExprKind::FloatCompare {
                    op: MachineComparisonOp::NotEqual,
                    ..
                }
            )
            | (
                SSAOp::FloatLess { .. },
                MachineExprKind::FloatCompare {
                    op: MachineComparisonOp::LessThan,
                    ..
                }
            )
            | (
                SSAOp::FloatLessEqual { .. },
                MachineExprKind::FloatCompare {
                    op: MachineComparisonOp::LessThanOrEqual,
                    ..
                }
            )
            | (
                SSAOp::Cast { .. },
                MachineExprKind::Cast {
                    kind: MachineCastKind::BitReinterpret,
                    ..
                }
            )
            | (SSAOp::Piece { .. }, MachineExprKind::Concat { .. })
            | (SSAOp::Insert { .. }, MachineExprKind::InsertLane { .. })
            | (SSAOp::Select { .. }, MachineExprKind::Select { .. })
    )
}

fn machine_type_matches_op(op: &SSAOp, ty: &MachineType, output_bits: u32) -> bool {
    let unsigned = integer_type(output_bits, MachineSignedness::Unsigned);
    let signed = integer_type(output_bits, MachineSignedness::Signed);
    match op {
        SSAOp::CallDefine { .. } => *ty == unsigned,
        SSAOp::IntSRight { .. }
        | SSAOp::IntSExt { .. }
        | SSAOp::IntSDiv { .. }
        | SSAOp::IntSRem { .. }
        | SSAOp::Trunc { .. }
        | SSAOp::Float2Int { .. } => *ty == signed,
        SSAOp::FloatAdd { .. }
        | SSAOp::FloatSub { .. }
        | SSAOp::FloatMult { .. }
        | SSAOp::FloatDiv { .. }
        | SSAOp::FloatNeg { .. }
        | SSAOp::FloatAbs { .. }
        | SSAOp::FloatSqrt { .. }
        | SSAOp::FloatCeil { .. }
        | SSAOp::FloatFloor { .. }
        | SSAOp::FloatRound { .. }
        | SSAOp::Int2Float { .. }
        | SSAOp::FloatFloat { .. } => {
            *ty == MachineType::Float {
                width_bits: output_bits,
            }
        }
        SSAOp::FloatNaN { .. }
        | SSAOp::FloatEqual { .. }
        | SSAOp::FloatNotEqual { .. }
        | SSAOp::FloatLess { .. }
        | SSAOp::FloatLessEqual { .. }
        | SSAOp::IntEqual { .. }
        | SSAOp::IntNotEqual { .. }
        | SSAOp::IntLess { .. }
        | SSAOp::IntSLess { .. }
        | SSAOp::IntLessEqual { .. }
        | SSAOp::IntSLessEqual { .. }
        | SSAOp::IntCarry { .. }
        | SSAOp::IntSCarry { .. }
        | SSAOp::IntSBorrow { .. }
        | SSAOp::BoolNot { .. }
        | SSAOp::BoolAnd { .. }
        | SSAOp::BoolOr { .. }
        | SSAOp::BoolXor { .. }
        | SSAOp::StoreConditional { .. } => {
            *ty == MachineType::Bool {
                storage_bits: output_bits,
            }
        }
        SSAOp::Load { .. }
        | SSAOp::LoadLinked { .. }
        | SSAOp::LoadGuarded { .. }
        | SSAOp::Copy { .. }
        | SSAOp::CallRestore { .. }
        | SSAOp::IntAdd { .. }
        | SSAOp::IntSub { .. }
        | SSAOp::IntMult { .. }
        | SSAOp::IntDiv { .. }
        | SSAOp::IntRem { .. }
        | SSAOp::IntNegate { .. }
        | SSAOp::PopCount { .. }
        | SSAOp::IntAnd { .. }
        | SSAOp::IntOr { .. }
        | SSAOp::IntXor { .. }
        | SSAOp::IntNot { .. }
        | SSAOp::IntLeft { .. }
        | SSAOp::IntRight { .. }
        | SSAOp::IntZExt { .. }
        | SSAOp::Cast { .. }
        | SSAOp::Piece { .. }
        | SSAOp::Subpiece { .. }
        | SSAOp::Insert { .. }
        | SSAOp::Select { .. } => *ty == unsigned,
        _ => false,
    }
}

fn value_has_boolean_producer(graph: &crate::graph::SsaGraph, value: ValueId) -> bool {
    fn visit(
        graph: &crate::graph::SsaGraph,
        value: ValueId,
        visiting: &mut BTreeSet<ValueId>,
    ) -> bool {
        if !visiting.insert(value) {
            return false;
        }
        // A constant zero or one is a boolean. Constant folding a comparison is
        // exactly how a boolean becomes one -- `0xfff1 == 0` collapses to a
        // `Copy` of a constant, and a constant has no defining instruction, so
        // walking producers alone concludes the value was never boolean and
        // refuses every use of the select that reads it.
        if let Some(constant) = graph
            .value(value)
            .and_then(|value| value.var.constant_bits())
            && (constant == 0 || constant == 1)
        {
            visiting.remove(&value);
            return true;
        }
        // A value the function was entered with has no producer to ask, and
        // nothing here can tell a condition flag from any other one-byte
        // register: `AL` is a byte and so is `CF`, and the architecture this
        // project carries records no flag among a register's facts. Calling
        // every one-byte entry value a boolean therefore admitted integer
        // truthiness the machine never performed, which is the claim
        // `select_rejects_unproven_integer_truthiness` exists to refuse.
        //
        // The fact is the specification's to state. Sleigh knows which
        // registers are flags and `r2il::RegisterDef` does not carry it, so
        // until it does, a function entered with a flag live keeps refusing --
        // a hundred and forty-five of them in one ARM library. Refusing is the
        // honest answer; guessing from a width is not.
        if graph.def_inst(value).is_none() {
            visiting.remove(&value);
            return false;
        }
        let result = graph
            .def_inst(value)
            .and_then(|inst| graph.inst(inst))
            .is_some_and(|inst| match &inst.payload {
                InstPayload::Op(
                    SSAOp::IntEqual { .. }
                    | SSAOp::IntNotEqual { .. }
                    | SSAOp::IntLess { .. }
                    | SSAOp::IntSLess { .. }
                    | SSAOp::IntLessEqual { .. }
                    | SSAOp::IntSLessEqual { .. }
                    | SSAOp::IntCarry { .. }
                    | SSAOp::IntSCarry { .. }
                    | SSAOp::IntSBorrow { .. }
                    | SSAOp::BoolNot { .. }
                    | SSAOp::BoolAnd { .. }
                    | SSAOp::BoolOr { .. }
                    | SSAOp::BoolXor { .. }
                    // Whether a conditional store took is one or nought, and
                    // the instruction after it reads exactly that.
                    | SSAOp::StoreConditional { .. }
                    | SSAOp::FloatNaN { .. }
                    | SSAOp::FloatEqual { .. }
                    | SSAOp::FloatNotEqual { .. }
                    | SSAOp::FloatLess { .. }
                    | SSAOp::FloatLessEqual { .. },
                ) => true,
                InstPayload::Op(SSAOp::Copy { .. }) => inst
                    .inputs
                    .as_slice()
                    .first()
                    .is_some_and(|input| visit(graph, *input, visiting)),
                // A selection is boolean only when both values it can produce
                // are boolean. The condition alone proves nothing about the
                // result: `cond ? 2 : 3` is still an integer. Instruction-local
                // conditional control is normalized into this exact shape, so
                // following both arms is what lets a later BoolNot consume a
                // selected condition-code value without treating arbitrary
                // integer truthiness as a boolean.
                // Bitwise and, or and exclusive-or of booleans are boolean:
                // {0, 1} is closed under all three. SLEIGH writes a flag the
                // machine updates under a condition exactly this way, as
                // `(guard & new) | (!guard & old)`.
                InstPayload::Op(
                    SSAOp::IntAnd { .. } | SSAOp::IntOr { .. } | SSAOp::IntXor { .. },
                ) => {
                    inst.inputs.len() == 2
                        && inst
                            .inputs
                            .iter()
                            .all(|input| visit(graph, *input, visiting))
                }
                InstPayload::Op(SSAOp::Select { .. }) => {
                    inst.inputs.len() == 3
                        && visit(graph, inst.inputs[1], visiting)
                        && visit(graph, inst.inputs[2], visiting)
                }
                InstPayload::Phi { .. } => {
                    !inst.inputs.is_empty()
                        && inst
                            .inputs
                            .iter()
                            .all(|input| visit(graph, *input, visiting))
                }
                _ => false,
            });
        visiting.remove(&value);
        result
    }

    visit(graph, value, &mut BTreeSet::new())
}
