use r2ssa::SSAVar;

use crate::model::TypeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintSource {
    Inferred,
    SignatureRegistry,
    External,
}

impl ConstraintSource {
    pub fn priority(self) -> u8 {
        match self {
            Self::Inferred => 1,
            Self::SignatureRegistry => 2,
            Self::External => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryCapability {
    Load,
    Store,
}

#[derive(Debug, Clone)]
pub enum Constraint {
    SetType {
        var: SSAVar,
        ty: TypeId,
        source: ConstraintSource,
    },
    Equal {
        a: SSAVar,
        b: SSAVar,
        source: ConstraintSource,
    },
    Subtype {
        var: SSAVar,
        ty: TypeId,
        source: ConstraintSource,
    },
    HasCapability {
        ptr: SSAVar,
        capability: MemoryCapability,
        elem_ty: TypeId,
        source: ConstraintSource,
    },
    CallSig {
        target: SSAVar,
        args: Vec<SSAVar>,
        params: Vec<TypeId>,
        ret: Option<(SSAVar, TypeId)>,
        source: ConstraintSource,
    },
    FieldAccess {
        base_ptr: SSAVar,
        offset: u64,
        field_ty: TypeId,
        field_name: Option<String>,
        source: ConstraintSource,
    },
}

impl Constraint {
    pub fn source(&self) -> ConstraintSource {
        match self {
            Self::SetType { source, .. }
            | Self::Equal { source, .. }
            | Self::Subtype { source, .. }
            | Self::HasCapability { source, .. }
            | Self::CallSig { source, .. }
            | Self::FieldAccess { source, .. } => *source,
        }
    }
}
