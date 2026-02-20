//! Memory semantics and topology model for r2il.
//!
//! This module defines ordering, permissions, ranges, and atomic-kind hints.

use serde::{Deserialize, Serialize};

/// Memory ordering semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOrdering {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
    #[default]
    Unknown,
}

/// Memory access permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Valid memory range expressed as a half-open interval `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub start: u64,
    pub end: u64,
}

impl MemoryRange {
    /// Returns true when the given access interval is fully contained.
    pub fn contains_interval(&self, start: u64, size: u32) -> bool {
        let Some(end) = start.checked_add(size as u64) else {
            return false;
        };
        start >= self.start && end <= self.end
    }
}

/// Atomic operation kind hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AtomicKind {
    LoadLinked,
    StoreConditional,
    CompareExchange,
    ReadModifyWrite,
    Fence,
    #[default]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::{AtomicKind, MemoryOrdering, MemoryPermissions, MemoryRange};

    #[test]
    fn memory_ordering_serde_roundtrip() {
        let json = serde_json::to_string(&MemoryOrdering::AcqRel).expect("serialize");
        let decoded: MemoryOrdering = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, MemoryOrdering::AcqRel);
    }

    #[test]
    fn atomic_kind_serde_roundtrip() {
        let json = serde_json::to_string(&AtomicKind::ReadModifyWrite).expect("serialize");
        let decoded: AtomicKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, AtomicKind::ReadModifyWrite);
    }

    #[test]
    fn memory_permissions_serde_roundtrip() {
        let perms = MemoryPermissions {
            read: true,
            write: false,
            execute: true,
        };
        let json = serde_json::to_string(&perms).expect("serialize");
        let decoded: MemoryPermissions = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, perms);
    }

    #[test]
    fn memory_range_contains_interval() {
        let range = MemoryRange {
            start: 0x1000,
            end: 0x1100,
        };
        assert!(range.contains_interval(0x1000, 4));
        assert!(range.contains_interval(0x10fc, 4));
        assert!(!range.contains_interval(0x10fd, 4));
        assert!(!range.contains_interval(0x0ff0, 4));
    }
}
