//! The caller's stack slots a body only reads (doc/adr-frame-model.md, "Caller slots").

use super::super::*;
use super::*;
use crate::semantic::{CallerSlotSupply, CallerStackSlotCertificate};
use std::collections::BTreeMap;

const SP: u64 = 32;
const RA: u64 = 16;

fn storage(offset: u64) -> CanonicalStorageId {
    CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset,
        size: 8,
    }
}

/// `dst = [sp + offset]`, the address in its own temporary.
fn load(ops: &mut Vec<R2ILOp>, offset: u64, dst: Varnode) {
    let address = make_unique(0x100 + offset, 8);
    ops.push(R2ILOp::IntAdd {
        dst: address.clone(),
        a: make_reg(SP, 8),
        b: make_const(offset, 8),
    });
    ops.push(R2ILOp::Load {
        dst,
        space: SpaceId::Ram,
        addr: address,
    });
}

/// A stacked-return body that reads [sp+8], [sp+16] and [sp+24] after writing [sp+24], then
/// returns through [sp]; the interface admits a stack parameter at +16.
fn caller_slots() -> BTreeMap<i64, CallerSlotSupply> {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("rax", 0, 8));
    arch.add_register(RegisterDef::new("rdi", 8, 8));
    arch.add_register(RegisterDef::new("rip", RA, 8));
    arch.add_register(RegisterDef::new("rsp", SP, 8));
    let mut ops = Vec::new();
    let written = make_unique(0x300, 8);
    ops.push(R2ILOp::IntAdd {
        dst: written.clone(),
        a: make_reg(SP, 8),
        b: make_const(24, 8),
    });
    ops.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: written,
        val: make_reg(8, 8),
    });
    load(&mut ops, 8, make_unique(0x400, 8));
    load(&mut ops, 16, make_unique(0x408, 8));
    load(&mut ops, 24, make_unique(0x410, 8));
    let sum = make_unique(0x418, 8);
    ops.push(R2ILOp::IntAdd {
        dst: sum.clone(),
        a: make_unique(0x400, 8),
        b: make_unique(0x408, 8),
    });
    ops.push(R2ILOp::IntAdd {
        dst: make_reg(0, 8),
        a: sum,
        b: make_unique(0x410, 8),
    });
    let body = ops.len();
    load(&mut ops, 0, make_reg(RA, 8));
    ops.push(R2ILOp::IntAdd {
        dst: make_reg(SP, 8),
        a: make_reg(SP, 8),
        b: make_const(8, 8),
    });
    ops.push(R2ILOp::Return {
        target: make_reg(RA, 8),
    });
    let mut block = R2ILBlock::new(0x1000, 16);
    let count = ops.len();
    block.ops = ops;
    // The body is one instruction and each load another, as the temporaries they pass require.
    for index in 0..count {
        let instruction = match index {
            _ if index < body => 0x1000,
            _ if index < body + 2 => 0x1004,
            _ => 0x1008 + 4 * (index - body - 2) as u64,
        };
        block.stamp_instruction(index, instruction);
    }
    let interface = SourceFunctionInterface::new_exact(
        b"caller-slots".to_vec(),
        r2source::ConventionId::SysVAmd64,
        [SourceAbiParameterSpec::on_stack(0, 16, 8)],
        SourceFunctionReturn::Register {
            storage: storage(0),
        },
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(storage(RA)))
    .and_then(|interface| interface.with_stack_pointer_storage(storage(SP)))
    .and_then(|interface| interface.with_exact_stacked_return(0, 8, 8, 8))
    .expect("stacked-return interface");
    let convention =
        SourceConventionSlots::new(r2source::ConventionId::SysVAmd64, [], Some(storage(0)))
            .expect("stack-only convention")
            .with_stack_arguments(r2source::SourceStackArgumentPlacement::new(8, 8));
    let artifact = SsaArtifact::for_decompile_with(
        &[block],
        DecompileInputs {
            arch: Some(&crate::Arch::from(arch.clone())),
            function_interface: Some(interface),
            machine_roles: SourceMachineRoles::new(Some(storage(RA)), Some(storage(SP)))
                .expect("machine roles"),
            convention_slots: Some(convention),
            call_effect: preserving([storage(SP)]),
            ..Default::default()
        },
    )
    .expect("artifact");
    let formal = artifact
        .facts()
        .boundaries
        .parameters
        .get(&0)
        .expect("the stack formal");
    assert!(
        matches!(
            formal.home,
            crate::semantic::FormalHome::Frame {
                offset: 16,
                bytes: 8,
                ..
            }
        ),
        "{formal:?}"
    );
    (artifact.certificates().caller_stack_slots.values())
        .map(
            |CallerStackSlotCertificate {
                 entry_offset,
                 supply,
             }| (*entry_offset, *supply),
        )
        .collect()
}

#[test]
fn caller_slots_name_the_unadmitted_argument_the_formal_and_the_return_address() {
    let slots = caller_slots();
    // +8: the argument area, at no parameter the interface admits.
    assert_eq!(
        slots.get(&8),
        Some(&CallerSlotSupply::UnadmittedArgument),
        "{slots:?}"
    );
    // +0: the slot the call pushed the return address into.
    assert_eq!(
        slots.get(&0),
        Some(&CallerSlotSupply::HeldFromEntry),
        "{slots:?}"
    );
    // +16: the admitted stack parameter, its formal read whole; +24: written before it is read.
    assert_eq!(
        slots.get(&16),
        Some(&CallerSlotSupply::Formal(0)),
        "{slots:?}"
    );
    assert!(!slots.contains_key(&24), "{slots:?}");
}
