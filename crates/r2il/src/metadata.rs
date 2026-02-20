//! Optional metadata hints for r2il values and operations.
//!
//! These hints are advisory and do not change core r2il semantics.

use serde::{Deserialize, Serialize};

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
}

/// Optional metadata hints attached to an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OpMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_class: Option<MemoryClass>,
}
