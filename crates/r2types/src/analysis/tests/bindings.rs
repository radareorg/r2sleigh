//! What each variable ends up called and typed.

use super::super::*;

#[test]
fn visible_binding_merge_prefers_typed_pointer_over_void_pointer() {
    let slot = StackSlotKey {
        base: ExternalStackBase::FramePointer,
        offset: -0x8,
    };
    let typed = Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
        bits: 8,
        signedness: Signedness::Signed,
    })));
    let mut binding = VisibleBinding {
        name: "buf".to_string(),
        ty: Some(CTypeLike::Pointer(Box::new(CTypeLike::Void))),
        kind: VisibleBindingKind::Local,
        stack_slot: Some(slot),
        param_index: None,
        source_reg: None,
    };
    merge_visible_binding(
        &mut binding,
        VisibleBinding {
            name: "var_8h".to_string(),
            ty: typed.clone(),
            kind: VisibleBindingKind::Local,
            stack_slot: Some(slot),
            param_index: None,
            source_reg: None,
        },
    );

    assert_eq!(binding.name, "buf");
    assert_eq!(binding.ty, typed);
}
