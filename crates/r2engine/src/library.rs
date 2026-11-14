//! The summary a bound import's cited row states (ROADMAP D383): its `effects` clauses as an upper
//! bound, never a name. A row with no effects, a tail or an unbound import has no summary.

use std::collections::{BTreeMap, BTreeSet};

use r2abi::{Effect, Extent, LibraryRow, LibraryRows, Tail, TypeId};
use r2ssa::interproc::{
    FunctionSemanticLinkage, FunctionSemanticSummary, InterprocFunctionId, SummaryAllocationEffect,
    SummaryArgEffect, SummaryLifetimeEffect, SummaryLifetimeOp, SummaryMemoryEffect,
    SummaryMemoryEffectKind, SummaryMemoryLocation, SummaryMemoryRegion, SummaryReturnRelation,
    SummaryTransferEffect, SummaryTransferLength,
};

/// The summary of the import `name` called at `target`, from the row `imports` binds it to. A tail
/// may write through any argument (`%n`), so a row with one states no bound and gets none. O(clauses).
pub(crate) fn import_summary(
    target: u64,
    name: &str,
    imports: &crate::imports::Imports,
) -> Option<FunctionSemanticSummary> {
    let row = imports.bind(name).ok()?;
    summary(target, name, row, imports.rows())
}

fn summary(
    target: u64,
    name: &str,
    row: &LibraryRow,
    rows: &LibraryRows,
) -> Option<FunctionSemanticSummary> {
    let effects = row.effects.as_ref().filter(|_| row.tail == Tail::None)?;
    let prototype = rows.prototype(row);
    let mut arg_effects = BTreeMap::<usize, SummaryArgEffect>::new();
    let mut memory_effects = Vec::new();
    let mut transfer_effects = Vec::new();
    let mut allocation_effects = Vec::new();
    let mut lifetime_effects = Vec::new();
    let mut return_relation = match prototype.return_type == TypeId::VOID {
        true => SummaryReturnRelation::Void,
        false => SummaryReturnRelation::Unknown,
    };
    let reads = |at: u8| {
        (effects.0.iter()).find_map(|effect| match effect {
            Effect::Reads { at: from, extent } if *from != at => Some((*from, *extent)),
            _ => None,
        })
    };
    for effect in &effects.0 {
        match *effect {
            Effect::Reads { at, .. } => {
                arg_effects.entry(at.into()).or_default().read = true;
                memory_effects.push(at_arg(SummaryMemoryEffectKind::Read, at));
            }
            Effect::Writes { at, extent } => {
                arg_effects.entry(at.into()).or_default().write = true;
                memory_effects.push(at_arg(SummaryMemoryEffectKind::Write, at));
                // The source is the parameter read as far as this write reaches, where one is.
                let src = (reads(at).filter(|(_, read)| *read == extent))
                    .map_or_else(unknown, |(from, _)| arg(from));
                transfer_effects.push(SummaryTransferEffect {
                    dst: arg(at),
                    src,
                    len: match extent {
                        Extent::Arg(count) => SummaryTransferLength::Arg(count.into()),
                        Extent::String => SummaryTransferLength::Unknown,
                    },
                });
            }
            Effect::Frees { at } => {
                arg_effects.entry(at.into()).or_default().free = true;
                memory_effects.push(at_arg(SummaryMemoryEffectKind::Free, at));
                lifetime_effects.push(SummaryLifetimeEffect {
                    arg: at.into(),
                    op: SummaryLifetimeOp::Free,
                });
            }
            Effect::Allocates { zeroed } => {
                // The size is a value: the row names no parameter the allocation reads through.
                allocation_effects.push(SummaryAllocationEffect {
                    size_arg: None,
                    zeroed,
                });
                return_relation = SummaryReturnRelation::HeapAlloc;
            }
            Effect::Returns { at } => return_relation = SummaryReturnRelation::Arg(at.into()),
        }
    }
    Some(FunctionSemanticSummary {
        schema_version: r2ssa::interproc::INTERPROC_SUMMARY_SCHEMA_VERSION,
        id: InterprocFunctionId(target),
        name: Some(name.to_owned()),
        linkage: FunctionSemanticLinkage::Unknown,
        arg_count_hint: Some(prototype.parameters.len()),
        direct_callees: BTreeSet::new(),
        callsite_count: 0,
        has_unknown_calls: false,
        arg_effects,
        memory_effects,
        transfer_effects,
        allocation_effects,
        lifetime_effects,
        sync_effects: Vec::new(),
        atomic_effects: Vec::new(),
        return_relation,
        reads_global_memory: false,
        writes_global_memory: false,
        touches_unknown_memory: false,
    })
}

/// The memory the pointer handed in position `index` points at.
fn arg(index: u8) -> SummaryMemoryLocation {
    SummaryMemoryLocation {
        region: SummaryMemoryRegion::Arg {
            index: index.into(),
        },
        range: None,
    }
}

fn unknown() -> SummaryMemoryLocation {
    SummaryMemoryLocation {
        region: SummaryMemoryRegion::Unknown,
        range: None,
    }
}

fn at_arg(kind: SummaryMemoryEffectKind, index: u8) -> SummaryMemoryEffect {
    SummaryMemoryEffect {
        kind,
        location: arg(index),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2abi::CLibrary;

    fn seed(name: &str) -> Option<FunctionSemanticSummary> {
        let rows = LibraryRows::embedded(CLibrary::Glibc);
        let row = rows.find(CLibrary::Glibc.scope(), name)?;
        summary(1, name, row, &rows)
    }

    /// memcpy's cited row: the copy is bounded by `n`, from `s2`, and returns `s1`.
    #[test]
    fn a_cited_row_states_memcpys_copy() {
        let memcpy = seed("memcpy").expect("memcpy's row states effects");
        assert_eq!(memcpy.return_relation, SummaryReturnRelation::Arg(0));
        assert!(memcpy.arg_effects[&0].write && memcpy.arg_effects[&1].read);
        assert_eq!(
            memcpy.transfer_effects,
            vec![SummaryTransferEffect {
                dst: arg(0),
                src: arg(1),
                len: SummaryTransferLength::Arg(2),
            }]
        );
    }

    /// D383: malloc's size is a value, so no effect names parameter 0; the result is a heap block.
    #[test]
    fn mallocs_size_is_read_as_a_value_only() {
        let malloc = seed("malloc").expect("malloc's row states effects");
        assert!(malloc.arg_effects.is_empty(), "{:?}", malloc.arg_effects);
        assert_eq!(malloc.return_relation, SummaryReturnRelation::HeapAlloc);
        assert!(malloc.memory_effects.is_empty());
    }

    /// A row with a tail (`snprintf`, `__snprintf_chk`, `printf`) may write through a tail argument,
    /// and a row that states no effects (`exit`) or no row at all has no summary.
    #[test]
    fn a_tail_or_an_unstated_row_has_no_summary() {
        for name in [
            "snprintf",
            "__snprintf_chk",
            "printf",
            "exit",
            "not_a_libc_routine",
        ] {
            assert!(seed(name).is_none(), "{name}");
        }
    }

    /// D383: a summary binds only through the import's row. `memcpy` imported from a DLL no cited
    /// table states has no row, so no summary whatever its name; from UCRT it binds the cited row.
    #[test]
    fn an_import_no_row_binds_has_no_summary_by_its_name() {
        use crate::imports::{Imports, Linkage};
        use r2abi::statement::{Container, Format, Symbol};
        let pe = |dll: &str| Container {
            format: Format::Pe,
            symbols: vec![Symbol {
                name: "memcpy".into(),
                import: true,
                library: Some(dll.into()),
                ..Symbol::default()
            }],
            ..Container::default()
        };
        let imports = |dll: &str| {
            let rows = LibraryRows::embedded(CLibrary::Ucrt);
            Imports::new(rows, CLibrary::Ucrt, Linkage::of(&pe(dll)))
        };
        assert!(import_summary(1, "memcpy", &imports("foo.dll")).is_none());
        let bound = import_summary(1, "memcpy", &imports("ucrtbase.dll"));
        assert_eq!(
            bound.map(|summary| summary.return_relation),
            Some(SummaryReturnRelation::Arg(0))
        );
    }
}
