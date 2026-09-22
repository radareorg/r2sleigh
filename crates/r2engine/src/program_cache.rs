//! Program-scope data object types, accumulated across requests.
//!
//! What was here before this was a byte-keyed cache of prepared functions,
//! whose whole lookup surface had no callers: the plugin deletion took them
//! and the native path was never wired to it. Its doctrine now lives in
//! `crate::query::memo`, which holds one analysis keyed by the revision of the
//! program it is about rather than by a copy of the bytes it was built from.
//!
//! What remains is the one thing that was live and is a different question.
//! A snapshot and a renderer are function-local; a data object's type is a
//! fact about the program. A missing or unplaceable observation cannot
//! displace an accepted source fact, and two accepted types for one address
//! poison that address into an explicit conflict, so accumulating loses
//! precision rather than stating the wrong type.
//!
//! **This map is process-scoped, monotone, and keyed by no program at all.**
//! An accepted type therefore survives a patch and survives opening a second
//! binary, which is wrong and is not yet fixed: moving it onto the open
//! program means changing three public signatures on the render path. It is
//! recorded here rather than left to be rediscovered.

use std::sync::{Mutex, MutexGuard, OnceLock};

#[derive(Default)]
struct ProgramCache {
    data_objects: r2types::ProgramDataObjectTypeFacts,
}

fn program_cache() -> &'static Mutex<ProgramCache> {
    static CACHE: OnceLock<Mutex<ProgramCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(ProgramCache::default()))
}

/// A poisoned map is still a correct map: every fact in it is accepted or
/// conflicting and nothing rewrites one in place, so a panic mid-absorb cannot
/// leave an address claiming another's type. Recovering the guard is right
/// here, where refusing would turn one panic into a permanently slow process.
fn lock_program_cache() -> MutexGuard<'static, ProgramCache> {
    program_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Add source-owned observations and return the complete program-scope view.
pub fn cache_program_data_object_types(
    observed: &r2types::ProgramDataObjectTypeFacts,
) -> r2types::ProgramDataObjectTypeFacts {
    let mut cache = lock_program_cache();
    cache.data_objects.absorb(observed);
    cache.data_objects.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_object_type_survives_the_function_snapshot_that_carried_it() {
        let observed = r2types::ProgramDataObjectTypeFacts::from_radare2(
            [(0x7000, Some("int32_t"))],
            64,
            &r2types::ExternalTypeDb::default(),
        );
        let later_snapshot = r2types::ProgramDataObjectTypeFacts::from_radare2(
            [(0x7000, None)],
            64,
            &r2types::ExternalTypeDb::default(),
        );
        let mut cache = ProgramCache::default();
        cache.data_objects.absorb(&observed);
        cache.data_objects.absorb(&later_snapshot);

        assert_eq!(
            cache.data_objects.get(0x7000).map(|fact| &fact.ty),
            Some(&r2types::CTypeLike::i32())
        );
    }
}
