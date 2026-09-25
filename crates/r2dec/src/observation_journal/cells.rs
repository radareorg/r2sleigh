//! What the renderer claimed for each source value, use and write.
//!
//! The journal records one of these per cell while the final tree is walked,
//! and the seal counts them into [`super::LegacyObservationCoverage`]. A cell
//! with no observation is the absence of an answer, kept as `None` by the
//! journal rather than as a variant here, so it can never be mistaken for a
//! typed refusal.

use r2ssa::{MachineUseRefusal, MachineUseSlice, MachineWriteProjection, MachineWriteRefusal};

use crate::binding_plan::ValueRefusal;

/// Renderer-local identity for one purported C object: the index of the
/// declaration the rendered function gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct LegacyBindingId(pub(crate) u32);

/// Which marked gap accounts for a cell.
///
/// A gap covers a closure of graph instructions rather than one cell, so every
/// cell it accounts for names the same anchor. Two gaps in one body are
/// therefore distinguishable, and a cell can never be claimed by both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GapAnchor {
    pub(crate) block_addr: u64,
    pub(crate) op_idx: u32,
}

/// What the renderer claimed for one dense `ValueId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyValueObservation {
    Bound {
        binding: LegacyBindingId,
    },
    InlineConstant,
    /// A surviving expression that is not a source-backed literal proof.
    InlineNonLiteral,
    Elided(crate::ledger::ElisionReason),
    Refused(ValueRefusal),
    /// Covered by the marked gap anchored here; unproven and said so.
    Gap(GapAnchor),
}

/// What the renderer claimed for one graph input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyUseObservation {
    Exact(MachineUseSlice),
    /// The address operand of a structured access. What that address is, is
    /// the binding plan's answer for this exact use site and is read back from
    /// it; a copy here would be the same answer stored a second time in every
    /// one of a function's use slots, and `MachineValueUse` is large enough
    /// that the copy set the width of the whole dense array.
    MemoryAddress,
    Elided(crate::ledger::ElisionReason),
    Refused(MachineUseRefusal),
    /// Covered by the marked gap anchored here; unproven and said so.
    Gap(GapAnchor),
}

/// What the renderer claimed for one output-producing instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyWriteObservation {
    Exact(MachineWriteProjection),
    Elided(crate::ledger::ElisionReason),
    Refused(MachineWriteRefusal),
    /// Covered by the marked gap anchored here; unproven and said so.
    Gap(GapAnchor),
}
