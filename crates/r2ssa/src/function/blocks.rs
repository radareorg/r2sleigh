//! A function's blocks, and the revision of them every derived fact names.
//!
//! Facts are computed from the blocks and then read while the blocks go on
//! being rewritten: entry lanes are minted, copies forwarded, boundary
//! constants placed. A fact computed before a rewrite and read after it
//! answers for an IR that no longer exists -- the value view did, and one bit
//! identity had two answers. The invariant this module makes mechanical:
//!
//! > every mutable path to the blocks advances the revision, so a fact stamped
//! > with the revision it was computed at can say whether it still describes
//! > them.
//!
//! The vector is private to this module, so the compiler holds every other
//! module to [`Blocks::edit`]. Reading is a slice, and costs nothing.

use std::ops::Deref;

use crate::block::SSABlock;

#[derive(Debug, Clone, Default)]
pub(crate) struct Blocks {
    items: Vec<SSABlock>,
    revision: IrRevision,
}

/// How many times a function's blocks have been opened for change.
///
/// Opaque outside this crate: a fact can carry one, and only the blocks can
/// make one, so no fact claims a revision it was not computed at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrRevision(u64);

impl Blocks {
    pub(crate) fn new(items: Vec<SSABlock>) -> Self {
        Self {
            items,
            revision: IrRevision::default(),
        }
    }

    /// The blocks, to be changed: the revision moves whether or not the caller
    /// ends up changing anything, which errs towards a fact being refreshed.
    pub(crate) fn edit(&mut self) -> &mut Vec<SSABlock> {
        self.revision.0 += 1;
        &mut self.items
    }

    /// How many times the blocks have been opened for change.
    pub(crate) const fn revision(&self) -> IrRevision {
        self.revision
    }
}

impl Deref for Blocks {
    type Target = [SSABlock];

    fn deref(&self) -> &[SSABlock] {
        &self.items
    }
}

impl<'a> IntoIterator for &'a Blocks {
    type Item = &'a SSABlock;
    type IntoIter = std::slice::Iter<'a, SSABlock>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_keeps_the_revision_and_opening_for_change_moves_it() {
        let mut blocks = Blocks::new(Vec::new());
        assert_eq!(blocks.len(), 0);
        assert_eq!(blocks.revision(), IrRevision(0));
        blocks.edit();
        assert_eq!(blocks.revision(), IrRevision(1));
    }
}
