//! A symbol's type and binding as its table states them. The fixtures are written by `data/symbol_kinds.py` and `data/static_weak.py`.

use r2image::{Binding, SymbolKind};

fn symbol(name: &str) -> r2image::Symbol {
    let image = r2image::Image::parse(include_bytes!("data/symbol_kinds.elf").to_vec())
        .expect("the symbol-kinds fixture");
    image
        .symbols()
        .iter()
        .find(|symbol| &*symbol.name == name)
        .cloned()
        .expect("the fixture states it")
}

#[test]
fn a_thread_local_symbol_is_tls_and_names_no_address() {
    let counter = symbol("counter");
    assert_eq!(counter.kind, SymbolKind::Tls);
    assert!(
        !counter.defined,
        "a TLS value is an offset into the thread's block"
    );
}

#[test]
fn gnu_unique_is_its_own_binding_under_the_gnu_abi() {
    assert_eq!(symbol("unique").binding, Binding::Unique);
}

fn weak_ref(fixture: &[u8]) -> r2image::Symbol {
    let image = r2image::Image::parse(fixture.to_vec()).expect("the static-weak fixture");
    (image.symbols().iter())
        .find(|symbol| &*symbol.name == "weak_ref")
        .cloned()
        .expect("the fixture states it")
}

/// A static image has no loader to bind a reference the link left undefined: it is no import.
#[test]
fn an_undefined_weak_symbol_of_a_static_image_is_no_import() {
    let weak = weak_ref(include_bytes!("data/static_weak.elf"));
    assert_eq!(weak.binding, Binding::Weak);
    assert!(!weak.import && !weak.defined);
}

#[test]
fn an_undefined_weak_symbol_of_a_dynamic_image_is_an_import() {
    let weak = weak_ref(include_bytes!("data/static_weak_dynamic.elf"));
    assert!(weak.import);
}
