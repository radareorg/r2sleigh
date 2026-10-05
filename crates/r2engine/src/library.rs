//! Library routines a program imports, as summaries the analysis can reason
//! with (AGENTS.md: summary classification is the engine's).
//!
//! An import is bound by its name, so the name says what the callee is; a
//! local function's name is only a hint, and none is modelled.

use std::collections::{BTreeMap, BTreeSet};

use r2ssa::interproc::{
    FunctionSemanticLinkage, FunctionSemanticSummary, InterprocFunctionId, SummaryAllocationEffect,
    SummaryArgEffect, SummaryLifetimeEffect, SummaryLifetimeOp, SummaryMemoryEffect,
    SummaryMemoryEffectKind, SummaryMemoryLocation, SummaryMemoryRegion, SummaryReturnRelation,
    SummarySyncEffect, SummarySyncOp, SummaryTransferEffect, SummaryTransferLength,
};

/// The model of the import `name` called at `target`, where the routine is one
/// this table describes.
pub(crate) fn import_summary(target: u64, name: &str) -> Option<FunctionSemanticSummary> {
    model(InterprocFunctionId(target), &format!("sym.imp.{name}"))
}

/// The memory the pointer handed in position `index` points at.
fn arg(index: usize) -> SummaryMemoryLocation {
    SummaryMemoryLocation {
        region: SummaryMemoryRegion::Arg { index },
        range: None,
    }
}

fn model(id: InterprocFunctionId, name: &str) -> Option<FunctionSemanticSummary> {
    let normalized = normalize_seed_name(name)?;
    // The normalized spelling selects the model; it does not rename the
    // callee. `_Exit` is not `exit`, and a rendering that says so names a
    // function the program does not call.
    let called = import_basename(name).to_owned();
    let mut arg_effects = BTreeMap::new();
    let mut effect = |idx: usize, read: bool, write: bool, escape: bool, free: bool| {
        arg_effects.insert(
            idx,
            SummaryArgEffect {
                read,
                write,
                escape,
                free,
            },
        );
    };
    let mut memory_effects = Vec::new();
    let mut transfer_effects = Vec::new();
    let mut allocation_effects = Vec::new();
    let mut lifetime_effects = Vec::new();
    let mut sync_effects = Vec::new();
    let atomic_effects = Vec::new();

    let return_relation = match normalized {
        "malloc" => {
            effect(0, true, false, false, false);
            allocation_effects.push(SummaryAllocationEffect {
                size_arg: Some(0),
                zeroed: false,
            });
            SummaryReturnRelation::HeapAlloc
        }
        "calloc" => {
            effect(0, true, false, false, false);
            effect(1, true, false, false, false);
            allocation_effects.push(SummaryAllocationEffect {
                size_arg: Some(1),
                zeroed: true,
            });
            SummaryReturnRelation::HeapAlloc
        }
        "free" => {
            effect(0, false, false, true, true);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Free,
                location: arg(0),
            });
            lifetime_effects.push(SummaryLifetimeEffect {
                arg: 0,
                op: SummaryLifetimeOp::Free,
            });
            SummaryReturnRelation::Void
        }
        "memcpy" | "memmove" => {
            effect(0, false, true, true, false);
            effect(1, true, false, false, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: arg(0),
            });
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: arg(1),
            });
            transfer_effects.push(SummaryTransferEffect {
                dst: arg(0),
                src: arg(1),
                len: SummaryTransferLength::Arg(2),
            });
            SummaryReturnRelation::Arg(0)
        }
        "copyin" | "copyout" => {
            effect(0, true, false, false, false);
            effect(1, false, true, true, false);
            effect(2, true, false, false, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: arg(0),
            });
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: arg(1),
            });
            transfer_effects.push(SummaryTransferEffect {
                dst: arg(1),
                src: arg(0),
                len: SummaryTransferLength::Arg(2),
            });
            SummaryReturnRelation::Unknown
        }
        "memset" => {
            effect(0, false, true, true, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: arg(0),
            });
            transfer_effects.push(SummaryTransferEffect {
                dst: arg(0),
                src: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Unknown,
                    range: None,
                },
                len: SummaryTransferLength::Arg(2),
            });
            SummaryReturnRelation::Arg(0)
        }
        // The `n`-bounded writers: at most `n` bytes land in the destination.
        "snprintf" | "vsnprintf" => {
            effect(0, false, true, true, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: arg(0),
            });
            transfer_effects.push(SummaryTransferEffect {
                dst: arg(0),
                src: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Unknown,
                    range: None,
                },
                len: SummaryTransferLength::Arg(1),
            });
            SummaryReturnRelation::Unknown
        }
        // `__snprintf_chk(s, maxlen, flag, slen, format, ...)` on glibc and
        // Apple alike: the write is bounded by `maxlen`; `slen` is the
        // object size the check compares it against.
        "snprintf_chk" => {
            effect(0, false, true, true, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: arg(0),
            });
            transfer_effects.push(SummaryTransferEffect {
                dst: arg(0),
                src: SummaryMemoryLocation {
                    region: SummaryMemoryRegion::Unknown,
                    range: None,
                },
                len: SummaryTransferLength::Arg(1),
            });
            SummaryReturnRelation::Unknown
        }
        "strncpy" => {
            effect(0, false, true, true, false);
            effect(1, true, false, false, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Write,
                location: arg(0),
            });
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: arg(1),
            });
            transfer_effects.push(SummaryTransferEffect {
                dst: arg(0),
                src: arg(1),
                len: SummaryTransferLength::Arg(2),
            });
            SummaryReturnRelation::Arg(0)
        }
        "strlen" => {
            effect(0, true, false, false, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: arg(0),
            });
            SummaryReturnRelation::Unknown
        }
        "strcmp" | "memcmp" => {
            effect(0, true, false, false, false);
            effect(1, true, false, false, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: arg(0),
            });
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: arg(1),
            });
            SummaryReturnRelation::Unknown
        }
        "puts" | "printf" => {
            effect(0, true, false, false, false);
            memory_effects.push(SummaryMemoryEffect {
                kind: SummaryMemoryEffectKind::Read,
                location: arg(0),
            });
            SummaryReturnRelation::Unknown
        }
        "retain" => {
            effect(0, true, false, true, false);
            lifetime_effects.push(SummaryLifetimeEffect {
                arg: 0,
                op: SummaryLifetimeOp::Retain,
            });
            SummaryReturnRelation::Arg(0)
        }
        "release" => {
            effect(0, false, false, true, false);
            lifetime_effects.push(SummaryLifetimeEffect {
                arg: 0,
                op: SummaryLifetimeOp::Release,
            });
            SummaryReturnRelation::Void
        }
        "lock" => {
            effect(0, false, false, true, false);
            sync_effects.push(SummarySyncEffect {
                arg: 0,
                op: SummarySyncOp::Lock,
            });
            SummaryReturnRelation::Void
        }
        "unlock" => {
            effect(0, false, false, true, false);
            sync_effects.push(SummarySyncEffect {
                arg: 0,
                op: SummarySyncOp::Unlock,
            });
            SummaryReturnRelation::Void
        }
        "exit" => SummaryReturnRelation::Void,
        _ => return None,
    };

    Some(FunctionSemanticSummary {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        id,
        name: Some(called),
        linkage: FunctionSemanticLinkage::Unknown,
        arg_count_hint: Some(match normalized {
            "malloc" | "free" | "strlen" | "puts" | "printf" | "exit" | "retain" | "release"
            | "lock" | "unlock" => 1,
            "calloc" => 2,
            "strcmp" | "memcmp" => 2,
            "memcpy" | "memmove" | "copyin" | "copyout" | "memset" | "strncpy" | "snprintf"
            | "vsnprintf" => 3,
            "snprintf_chk" => 5,
            _ => 0,
        }),
        direct_callees: BTreeSet::new(),
        callsite_count: 0,
        has_unknown_calls: false,
        arg_effects,
        memory_effects,
        transfer_effects,
        allocation_effects,
        lifetime_effects,
        sync_effects,
        atomic_effects,
        return_relation,
        reads_global_memory: false,
        writes_global_memory: false,
        touches_unknown_memory: false,
    })
}

/// The name the program links against, with radare2's namespace removed.
fn import_basename(name: &str) -> &str {
    let mut bare = name.trim();
    for prefix in ["sym.imp.", "sym.", "imp.", "reloc.", "dbg."] {
        while let Some(rest) = bare.strip_prefix(prefix) {
            bare = rest;
        }
    }
    bare.split_once('@').map_or(bare, |(base, _)| base)
}

fn normalize_seed_name(name: &str) -> Option<&'static str> {
    let normalized_owned = name.trim().to_ascii_lowercase();
    let mut normalized = normalized_owned.as_str();
    let has_external_marker = ["sym.imp.", "imp.", "reloc."]
        .iter()
        .any(|prefix| normalized.strip_prefix(prefix).is_some())
        || normalized.ends_with("@plt")
        || normalized.ends_with(".plt");
    if !has_external_marker {
        return None;
    }
    for prefix in ["sym.imp.", "sym.", "imp.", "reloc.", "dbg."] {
        while let Some(rest) = normalized.strip_prefix(prefix) {
            normalized = rest;
        }
    }
    while let Some(rest) = normalized.strip_suffix("@plt") {
        normalized = rest;
    }
    while let Some(rest) = normalized.strip_suffix(".plt") {
        normalized = rest;
    }
    if let Some((base, _)) = normalized.split_once('@') {
        normalized = base;
    }
    if let Some(rest) = normalized.strip_prefix("__isoc99_") {
        normalized = rest;
    }
    if let Some(rest) = normalized.strip_prefix("__gi_") {
        normalized = rest;
    }
    while let Some(rest) = normalized.strip_prefix('_') {
        normalized = rest;
    }
    match normalized {
        // Names arrive with their leading underscores already stripped, so
        // the fortified variants match by their bare spelling. Those that keep
        // the plain layout share a model; the ones that insert the object size
        // before the length get their own.
        "strlen" | "strlen_chk" => Some("strlen"),
        "strcmp" => Some("strcmp"),
        "memcmp" => Some("memcmp"),
        "memcpy" => Some("memcpy"),
        "memmove" => Some("memmove"),
        "copyin" => Some("copyin"),
        "copyout" => Some("copyout"),
        "memset" => Some("memset"),
        "snprintf" => Some("snprintf"),
        "vsnprintf" => Some("vsnprintf"),
        "snprintf_chk" | "vsnprintf_chk" => Some("snprintf_chk"),
        "strncpy" => Some("strncpy"),
        "malloc" | "__libc_malloc" | "__gi___libc_malloc" => Some("malloc"),
        "calloc" | "__libc_calloc" => Some("calloc"),
        "free" => Some("free"),
        "os_ref_retain" | "osobject_retain" => Some("retain"),
        "os_ref_release" | "osobject_release" => Some("release"),
        "lck_mtx_lock" | "lck_rw_lock_shared" | "lck_rw_lock_exclusive" => Some("lock"),
        "lck_mtx_unlock" | "lck_rw_unlock_shared" | "lck_rw_unlock_exclusive" => Some("unlock"),
        "puts" => Some("puts"),
        "printf" | "__printf_chk" => Some("printf"),
        "exit" | "_exit" => Some("exit"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_summary_models_the_fortified_snprintf_by_its_length_argument() {
        let seed = import_summary(9, "__snprintf_chk").expect("snprintf_chk seed");
        assert_eq!(seed.transfer_effects.len(), 1);
        assert_eq!(
            seed.transfer_effects[0].len,
            SummaryTransferLength::Arg(1),
            "the fortified layout bounds the write by maxlen"
        );
        assert_eq!(
            seed.transfer_effects[0].dst.region,
            SummaryMemoryRegion::Arg { index: 0 }
        );
        let plain = import_summary(10, "snprintf").expect("snprintf seed");
        assert_eq!(plain.transfer_effects[0].len, SummaryTransferLength::Arg(1));
    }

    #[test]
    fn seed_summary_models_malloc_and_memcpy() {
        let malloc = import_summary(1, "malloc").expect("malloc seed");
        assert_eq!(malloc.return_relation, SummaryReturnRelation::HeapAlloc);
        assert_eq!(
            malloc.allocation_effects,
            vec![SummaryAllocationEffect {
                size_arg: Some(0),
                zeroed: false,
            }]
        );
        let memcpy = import_summary(2, "memcpy").expect("memcpy seed");
        assert_eq!(memcpy.return_relation, SummaryReturnRelation::Arg(0));
        assert!(memcpy.arg_effects.get(&0).expect("dst").write);
        assert!(memcpy.arg_effects.get(&1).expect("src").read);
        assert_eq!(
            memcpy.transfer_effects,
            vec![SummaryTransferEffect {
                dst: arg(0),
                src: arg(1),
                len: SummaryTransferLength::Arg(2),
            }]
        );
    }

    #[test]
    fn only_a_modelled_routine_has_a_summary() {
        for name in ["not_a_libc_routine", "main", "memcpy_impl"] {
            assert!(import_summary(0xdead, name).is_none(), "{name}");
        }
    }

    #[test]
    fn seed_summary_models_kernel_helpers_as_canonical_effects() {
        let copyin = import_summary(3, "copyin").expect("copyin seed");
        assert_eq!(
            copyin.transfer_effects,
            vec![SummaryTransferEffect {
                dst: arg(1),
                src: arg(0),
                len: SummaryTransferLength::Arg(2),
            }]
        );
        assert!(copyin.arg_effects.get(&0).expect("src").read);
        assert!(copyin.arg_effects.get(&1).expect("dst").write);

        let retain = import_summary(4, "os_ref_retain").expect("retain seed");
        assert_eq!(retain.return_relation, SummaryReturnRelation::Arg(0));
        assert_eq!(
            retain.lifetime_effects,
            vec![SummaryLifetimeEffect {
                arg: 0,
                op: SummaryLifetimeOp::Retain,
            }]
        );

        let lock = import_summary(5, "lck_mtx_lock").expect("lock seed");
        assert_eq!(
            lock.sync_effects,
            vec![SummarySyncEffect {
                arg: 0,
                op: SummarySyncOp::Lock,
            }]
        );
    }
}
