//! What a parameter's pointee is read as (doc/adr-aggregates.md).

use super::*;
use crate::semantic::{ParameterFieldRefusal, ParameterFields};

const RDI: u64 = 8;
const SP: u64 = 32;
const RETURN: u64 = 40;

/// `rdi` the one parameter, its home `sp - 8`.
fn parameter_artifact(blocks: Vec<R2ILBlock>) -> SsaArtifact {
    let interface = SourceFunctionInterface::new_exact(
        b"parameter-fields".to_vec(),
        r2source::ConventionId::SysVAmd64,
        [SourceAbiParameterSpec::new(
            0,
            register_storage(RDI, 8),
            r2source::SourceSlot::integer(0),
        )],
        SourceFunctionReturn::Void,
        [SourceStackSlotSpec::new_local(
            StackAddressBase::StackPointer,
            register_storage(SP, 8),
            -8,
            8,
        )],
    )
    .and_then(|interface| interface.with_stack_pointer_storage(register_storage(SP, 8)))
    .and_then(|interface| interface.with_return_address_storage(register_storage(RETURN, 8)))
    .expect("exact parameter interface");
    SsaArtifact::for_decompile_with_interface(&blocks, Some(&return_boundary_arch()), interface)
        .expect("parameter artifact")
}

fn at(base: Varnode, offset: u64, unique: u64, block: &mut R2ILBlock) -> Varnode {
    let address = Varnode::unique(unique, 8);
    block.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: base,
        b: test_const(offset),
    });
    address
}

fn load(block: &mut R2ILBlock, address: Varnode, width: u32, unique: u64) -> Varnode {
    let dst = Varnode::unique(unique, width);
    block.push(R2ILOp::Load {
        dst: dst.clone(),
        space: SpaceId::Ram,
        addr: address,
    });
    dst
}

fn store(block: &mut R2ILBlock, address: Varnode, width: u32, value: u64) {
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: address,
        val: Varnode::constant(value, width),
    });
}

fn returned(block: &mut R2ILBlock) {
    block.push(R2ILOp::Return {
        target: test_reg(RETURN),
    });
}

fn offsets(fields: Option<&ParameterFields>) -> Option<Vec<(i64, u32)>> {
    match fields? {
        ParameterFields::Constant(accesses) => Some(
            accesses
                .iter()
                .map(|access| (access.offset, access.width))
                .collect(),
        ),
        ParameterFields::Refused { .. } => None,
    }
}

/// `-O0` spills the parameter to its home and reloads it for each field.
#[test]
fn a_spilled_parameter_s_constant_offsets_are_its_fields() {
    let mut block = R2ILBlock::new(0x1000, 4);
    let home = at(test_reg(SP), 8u64.wrapping_neg(), 0x10, &mut block);
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: home.clone(),
        val: test_reg(RDI),
    });
    let first = load(&mut block, home.clone(), 8, 0x20);
    let byte = load(&mut block, first, 1, 0x28);
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::constant(0x5000, 8),
        val: byte,
    });
    let second = load(&mut block, home, 8, 0x30);
    let half = at(second, 2, 0x38, &mut block);
    store(&mut block, half, 2, 0xbeef);
    let word = at(test_reg(RDI), 4, 0x40, &mut block);
    store(&mut block, word, 4, 7);
    let quad = at(test_reg(RDI), 8, 0x48, &mut block);
    store(&mut block, quad, 8, 9);
    returned(&mut block);
    let artifact = parameter_artifact(vec![block]);

    assert_eq!(
        offsets(artifact.certificates().parameter_fields.get(&0)),
        Some(vec![(0, 1), (2, 2), (4, 4), (8, 8)]),
        "{:?}",
        artifact.certificates().parameter_fields
    );
}

/// A field that holds a pointer is the parameter's; what that pointer addresses is not.
#[test]
fn a_followed_pointer_field_is_a_field_and_its_pointee_is_not() {
    let mut block = R2ILBlock::new(0x1000, 4);
    let next = at(test_reg(RDI), 8, 0x10, &mut block);
    let pointer = load(&mut block, next, 8, 0x18);
    let inner = at(pointer, 4, 0x20, &mut block);
    store(&mut block, inner, 4, 1);
    let first = at(test_reg(RDI), 0, 0x28, &mut block);
    store(&mut block, first, 4, 2);
    returned(&mut block);
    let artifact = parameter_artifact(vec![block]);

    assert_eq!(
        offsets(artifact.certificates().parameter_fields.get(&0)),
        Some(vec![(0, 4), (8, 8)])
    );
}

/// A loop that walks `p += 8` reaches its accesses through a merge of two offsets.
#[test]
fn a_walked_parameter_has_no_fields() {
    let mut entry = R2ILBlock::new(0x1000, 4);
    entry.push(R2ILOp::Branch {
        target: test_const(0x1004),
    });
    let mut body = R2ILBlock::new(0x1004, 4);
    store(&mut body, test_reg(RDI), 8, 0);
    body.push(R2ILOp::IntAdd {
        dst: test_reg(RDI),
        a: test_reg(RDI),
        b: test_const(8),
    });
    let cond = Varnode::unique(0x1004, 1);
    body.push(R2ILOp::IntEqual {
        dst: cond.clone(),
        a: test_reg(0),
        b: test_const(1),
    });
    body.push(R2ILOp::CBranch {
        target: test_const(0x1004),
        cond,
    });
    let mut exit = R2ILBlock::new(0x1008, 4);
    returned(&mut exit);
    let artifact = parameter_artifact(vec![entry, body, exit]);

    assert!(
        matches!(
            artifact.certificates().parameter_fields.get(&0),
            Some(ParameterFields::Refused {
                reason: ParameterFieldRefusal::NotAffine | ParameterFieldRefusal::Indexed,
                ..
            })
        ),
        "{:?}",
        artifact.certificates().parameter_fields
    );
}

/// A linked load beside two plain fields of different widths is a parameter access the layout
/// does not model: no layout, and its loaded value is not followed as the parameter.
#[test]
fn a_linked_load_from_the_parameter_refuses_its_fields() {
    let mut block = R2ILBlock::new(0x1000, 4);
    let first = at(test_reg(RDI), 0, 0x10, &mut block);
    store(&mut block, first, 8, 1);
    let second = at(test_reg(RDI), 8, 0x18, &mut block);
    store(&mut block, second, 4, 2);
    let linked = at(test_reg(RDI), 16, 0x20, &mut block);
    block.push(R2ILOp::LoadLinked {
        dst: Varnode::unique(0x28, 8),
        space: SpaceId::Ram,
        addr: linked,
        ordering: r2il::MemoryOrdering::SeqCst,
    });
    returned(&mut block);
    let artifact = parameter_artifact(vec![block]);

    assert!(matches!(
        artifact.certificates().parameter_fields.get(&0),
        Some(ParameterFields::Refused {
            reason: ParameterFieldRefusal::Unmodelled,
            ..
        })
    ));
}
