//! The linker states where every function begins, and a stripped binary keeps it.
//!
//! Discovery closes over calls from what it can seed. A body that nothing
//! calls directly -- reached through a pointer, or laid out between two
//! others -- is invisible to that closure, and once a walk correctly stops at
//! a call that never returns it is not stumbled into either. `LC_FUNCTION_STARTS`
//! is what finds it, and the linker wrote it from what it actually laid out.

#[test]
fn a_stripped_mach_o_still_states_its_function_starts() {
    let bytes = include_bytes!("data/function_starts.macho").to_vec();
    let image = r2image::Image::parse(bytes).expect("a mach-o fixture");

    let declared: Vec<u64> = image
        .entry_points()
        .iter()
        .filter(|entry| entry.kind == r2image::EntryKind::Declared)
        .map(|entry| entry.vaddr)
        .collect();
    assert!(
        declared.len() >= 4,
        "the fixture defines four functions: {declared:?}"
    );

    // The static one lost its symbol to the strip and kept its start, which
    // is the whole point: nothing else in the file says it is a function.
    let named: Vec<u64> = image
        .symbols()
        .iter()
        .filter(|symbol| symbol.kind == r2image::SymbolKind::Function && symbol.defined)
        .map(|symbol| symbol.vaddr)
        .collect();
    assert!(
        declared.iter().any(|start| !named.contains(start)),
        "{declared:?} are all named by {named:?}"
    );
}
