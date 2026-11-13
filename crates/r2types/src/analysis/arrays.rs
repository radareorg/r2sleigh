//! Which accesses certify an array, and what its elements are.

use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ScalarArrayAccessCertificates {
    pub(crate) array_index: Vec<ArrayIndexCertificate>,
    pub(crate) render_candidates: Vec<ScalarArrayRenderCandidate>,
}

pub(crate) fn scalar_element_stride(ty: &CTypeLike, ptr_bits: u32) -> Option<u64> {
    match ty {
        CTypeLike::Const(inner) => scalar_element_stride(inner, ptr_bits),
        CTypeLike::Bool | CTypeLike::Int { .. } | CTypeLike::Float(_) => {
            estimate_type_like_size_bytes(ty, ptr_bits).filter(|size| *size > 0)
        }
        CTypeLike::Typedef { name, ty } => {
            match crate::convert::typedef_target(name, ty, ptr_bits) {
                Some(target @ (CTypeLike::Bool | CTypeLike::Int { .. } | CTypeLike::Float(_))) => {
                    estimate_type_like_size_bytes(&target, ptr_bits).filter(|size| *size > 0)
                }
                _ => None,
            }
        }
        CTypeLike::Void
        | CTypeLike::Unknown
        | CTypeLike::Array(_, _)
        | CTypeLike::Struct(_)
        | CTypeLike::Union(_)
        | CTypeLike::Enum(_)
        | CTypeLike::BitVector(_)
        | CTypeLike::Function { .. } => None,
        CTypeLike::Pointer(_) | CTypeLike::UnprototypedFunction(_) => {
            Some((ptr_bits / 8).max(1) as u64)
        }
    }
}
