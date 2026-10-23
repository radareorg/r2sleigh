//! Control structure: the dominator-tree placement of
//! `doc/adr-structure-dominator-tree.md`, the certificate that checks the
//! text against the CFG, and the rewrites that shape it afterwards.

pub(crate) mod certify;
pub(crate) mod condition;
pub(crate) mod guard;
pub(crate) mod latch;
pub(crate) mod order;
pub(crate) mod place;
pub(crate) mod rotate;
pub(crate) mod shape;
#[cfg(test)]
pub(crate) mod support;
pub(crate) mod tails;
