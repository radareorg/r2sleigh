//! What the analysis of the whole function says about each line, each claim on the smallest rung that establishes it.

use r2ssa::{CanonicalStorageId, CanonicalStorageSpace, InstructionBound, StridedInterval};

use super::Support;
use super::records::{AnnotationKind, Answered};

/// The range proved for each machine word a line leaves, where it says anything; `folded` is what the run leaves there.
pub(super) fn proved_about(
    answered: &Answered<'_>,
    address: u64,
    folded: &dyn Fn(CanonicalStorageId) -> Option<u64>,
) -> Vec<(AnnotationKind, Support)> {
    let (Some(prepared), Some(body), Some(machine)) = (
        answered.prepared,
        answered.body,
        answered.decoders.at(address),
    ) else {
        return Vec::new();
    };
    let facts = prepared.artifact().artifact();
    // A flag is proved to hold nought or one on every line that sets it, which says only that it is a flag.
    let word = |storage: &CanonicalStorageId| {
        storage.space == CanonicalStorageSpace::Register && storage.size == machine.arch.addr_size
    };
    // What the line defines is what it leaves: an earlier write it overwrites is not live after it.
    facts
        .graph()
        .left_by(address)
        .into_iter()
        .filter(|(storage, _)| word(storage))
        .filter_map(|(storage, output)| {
            let own = body.own_bound(address, storage)?;
            let range = facts.values().get(output)?;
            let certified = || facts.folded_value(output);
            let (range, support) = claimed(range, own, folded(storage), certified)?;
            let (low, high) = range.bounds()?;
            let kind = AnnotationKind::Bounds {
                storage,
                low,
                high,
                stride: range.stride().unwrap_or(0),
            };
            Some((kind, support))
        })
        .collect()
}

/// The range a line can claim and its rung: nothing where it is one value the instruction fixes or only the width it wrote.
///
/// `folded` is the one value the run leaves, and `certified` the one value the function's def-use folds it to.
fn claimed(
    range: StridedInterval,
    own: InstructionBound,
    folded: Option<u64>,
    certified: impl FnOnce() -> Option<u64>,
) -> Option<(StridedInterval, Support)> {
    let bound = own.range;
    if range.is_bottom() || range.width_bits() != bound.width_bits() {
        return None;
    }
    // Where the function proves no more, the claim is the instruction's own bound, unless that is one value or only the width written.
    if bound.join(&range) == range {
        let says_nothing = bound.as_constant().is_some() || own.spans_width_written;
        return (!says_nothing).then_some((bound, Support::Decoded));
    }
    // One value inside that bound needs the run where the run folds it, else the def-use where that does; any other range needs the solver.
    let Some(value) = range.as_constant() else {
        return Some((range, Support::Solved));
    };
    let support = if folded == Some(value) {
        Support::Folded
    } else if certified() == Some(value) {
        Support::Certified
    } else {
        Support::Solved
    };
    Some((range, support))
}
