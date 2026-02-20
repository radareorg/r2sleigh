//! Optional metadata hints for r2il values and operations.
//!
//! These hints are advisory and do not change core r2il semantics.

use serde::{Deserialize, Serialize};

use crate::{AtomicKind, Endianness, MemoryOrdering, MemoryPermissions, MemoryRange};

/// Storage classification hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    Stack,
    Heap,
    Global,
    ThreadLocal,
    ConstData,
    Volatile,
    Register,
    #[default]
    Unknown,
}

/// Scalar interpretation hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScalarKind {
    Bool,
    SignedInt,
    UnsignedInt,
    Float,
    Bitvector,
    #[default]
    Unknown,
}

/// Pointer interpretation hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PointerHint {
    PointerLike,
    CodePointer,
    #[default]
    Unknown,
}

/// Floating-point encoding hint for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FloatEncodingHint {
    Ieee754Binary16,
    Ieee754Binary32,
    Ieee754Binary64,
    Ieee754Binary80,
    Ieee754Binary128,
    #[default]
    Unknown,
}

/// Memory classification hint for operations that touch memory-like domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    Ram,
    Stack,
    Heap,
    Global,
    ThreadLocal,
    Mmio,
    IoPort,
    Code,
    #[default]
    Unknown,
}

/// Optional metadata hints attached to a varnode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VarnodeMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<StorageClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scalar_kind: Option<ScalarKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_hint: Option<PointerHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub float_encoding: Option<FloatEncodingHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<MemoryPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_range: Option<MemoryRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bank_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<String>,
}

/// Optional metadata hints attached to an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OpMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_class: Option<MemoryClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_ordering: Option<MemoryOrdering>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<MemoryPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_range: Option<MemoryRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bank_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atomic_kind: Option<AtomicKind>,
}

#[cfg(test)]
mod tests {
    use super::{OpMetadata, VarnodeMetadata};
    use crate::Endianness;

    #[test]
    fn varnode_metadata_endianness_serde_omits_when_none() {
        let meta = VarnodeMetadata::default();
        let json = serde_json::to_string(&meta).expect("serialize");
        assert!(!json.contains("endianness"));
    }

    #[test]
    fn op_metadata_endianness_serde_omits_when_none() {
        let meta = OpMetadata::default();
        let json = serde_json::to_string(&meta).expect("serialize");
        assert!(!json.contains("endianness"));
    }

    #[test]
    fn metadata_endianness_roundtrip_when_present() {
        let meta = VarnodeMetadata {
            endianness: Some(Endianness::Big),
            ..Default::default()
        };
        let json = serde_json::to_string(&meta).expect("serialize");
        let decoded: VarnodeMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.endianness, Some(Endianness::Big));
    }
}
