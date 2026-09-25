use std::hash::Hash;

use r2ssa::SSAVar;

use crate::model::TypeId;

/// A node of the type graph the solver assigns types to.
///
/// The solver is the same whether the nodes are SSA variables of one function
/// or the values, objects and slots of a prepared artifact, so the node type is
/// a parameter and only the label used in diagnostics differs.
pub trait SolverNode: Clone + Eq + Hash {
    fn solver_label(&self) -> String;
}

impl SolverNode for SSAVar {
    fn solver_label(&self) -> String {
        self.display_name()
    }
}

/// Where a constraint's evidence came from.
///
/// Provenance only: every bound holds at once, so no source outranks another.
/// Two sources that disagree meet at `Bottom`, which is a refusal of that
/// node's type, not a contest one of them wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintSource {
    Inferred,
    SignatureRegistry,
    External,
}

/// One fact about the type of a node.
///
/// Every constraint only tightens: `Equal` makes two nodes one class, and
/// `Subtype` bounds a class from above. A constraint that loosens -- a join, an
/// override, a rewrite of a field already typed -- cannot be written here,
/// because meets and joins over one class do not settle and no round count
/// makes them.
#[derive(Debug, Clone)]
pub enum Constraint<K = SSAVar> {
    Equal {
        a: K,
        b: K,
        source: ConstraintSource,
    },
    Subtype {
        var: K,
        ty: TypeId,
        source: ConstraintSource,
    },
}

impl<K> Constraint<K> {
    pub fn source(&self) -> ConstraintSource {
        match self {
            Self::Equal { source, .. } | Self::Subtype { source, .. } => *source,
        }
    }
}
