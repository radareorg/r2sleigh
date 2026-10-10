//! Control structure: the dominator-tree placement of
//! `doc/adr-structure-dominator-tree.md`, the certificate that checks the
//! text against the CFG, and the rewrites that shape it afterwards.

pub(crate) mod certify;
pub(crate) mod place;
pub(crate) mod shape;
