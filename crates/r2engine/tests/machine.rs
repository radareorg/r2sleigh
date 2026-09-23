//! What the open program says about the machine a storage lives in.

mod common;

use common::{ONE, opened};
use r2ssa::{CanonicalStorageId, CanonicalStorageSpace};

fn register(offset: u64, size: u32) -> CanonicalStorageId {
    CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size,
    }
}

#[test]
fn a_register_is_spelled_by_the_machine_it_lives_in() {
    let mut program = opened();
    program.ensure_current().expect("the machine loads");
    let rax = register(0, 8);
    let eax = register(0, 4);
    let slot = CanonicalStorageId {
        space: CanonicalStorageSpace::Ram,
        ..rax
    };
    assert_eq!(program.spell_storage(ONE, rax).as_deref(), Some("rax"));
    assert_eq!(program.spell_storage(ONE, eax).as_deref(), Some("eax"));
    assert_eq!(program.spell_storage(ONE, slot), None);
}
