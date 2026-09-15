//! Certified canonicalising rewriter over `r2ssa` machine expressions.
//!
//! The base machine arena is one node deep per instruction and is validated
//! structurally against the SSA graph, so it is never rewritten in place.
//! This crate imports it into a hash-consed term arena, canonicalises every
//! value's term with a table of rules that are each a proven equivalence, and
//! reports per value the canonical term, the rules that produced it, and the
//! instructions rendering it would discharge. The binding plan decides what
//! to render; this crate decides what is equal to what.

pub mod canon;
pub mod driver;
pub mod eval;
pub mod import;
pub mod rules;
pub mod term;
pub mod typed;

pub use driver::{
    BudgetFailure, CanonicalAccess, CanonicalRoots, CanonicalValue, Multiplicity, Rewrite,
    RewriteError, canonicalize, canonicalize_with, discharged_origins, renders_inline,
};
pub use eval::{LeafRef, eval, mask, signed};
pub use import::{
    COPY_ELIDE, ExpansionPolicy, ExpansionQuery, Import, ImportedAccess, ImportedValue,
    OBJECT_ADDRESS, default_expansion_policy, exact_stack_object_address, import, import_with,
    machine_expr_is_literal, term_is_duplicable,
};
pub use rules::{
    DEFAULT_PROOF_WIDTHS, Measure, MeasureVector, RULES, Rule, RuleGroup, RuleId, measure,
};
pub use term::{
    LeafOrigin, LeafRead, MAX_TERM_WIDTH_BITS, ObjectPlacement, OccurrenceId, PointerWalk, Term,
    TermArena, TermId, TermKind,
};
pub use typed::{CValue, RenderTypes, TypedBoundaries, c_type_of, promoted, typed_boundaries};

/// One line spelling of a term for a dump.
pub fn spell_term(arena: &TermArena, root: TermId) -> String {
    arena.spell(root)
}
