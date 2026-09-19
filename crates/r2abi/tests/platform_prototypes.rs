//! `_Exit` and `__errno_location` are declared by the platform rather than by
//! the table every target shares, so a call to one has no prototype until the
//! platform's own declarations are read.

#[test]
fn the_portable_table_does_not_declare_a_platform_function() {
    let portable = r2abi::Prototypes::embedded_for(r2abi::Platform::Unknown);
    assert!(portable.get("_Exit").is_none());
}

#[test]
fn linux_declares_its_own() {
    let linux = r2abi::Prototypes::embedded_for(r2abi::Platform::Linux);
    let exit = linux.get("_Exit").expect("_Exit is declared on linux");
    assert_eq!(exit.parameters.len(), 1);
    assert!(
        linux.get("printf").is_some(),
        "the portable table still applies"
    );
}

#[test]
fn darwin_declares_its_own() {
    let darwin = r2abi::Prototypes::embedded_for(r2abi::Platform::Darwin);
    assert!(
        darwin.get("printf").is_some(),
        "the portable table still applies"
    );
}
