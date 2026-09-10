//! Genuine embedded lifts through optimized SSA and typed machine projection.

use r2sleigh_lift::{Disassembler, TrustedSleighProfile};
use r2ssa::{
    CanonicalStorageId, CanonicalStorageSpace, FunctionPrepareMode, MachineProjection,
    MachineUseDisposition, MachineUseSlice, MachineWriteDisposition, MachineWriteProjection,
    SsaArtifact, UseSite,
};

fn declared_register_storage(arch: &r2il::ArchSpec, name: &str) -> CanonicalStorageId {
    let register = arch
        .get_register(name)
        .unwrap_or_else(|| panic!("embedded specification is missing {name}"));
    CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: register.offset,
        size: register.size,
    }
}

fn genuine_optimized_projection(
    profile: TrustedSleighProfile,
    instruction: &[u8],
) -> (SsaArtifact, MachineProjection, r2il::ArchSpec) {
    assert!(!instruction.is_empty() && instruction.len() <= 16);
    let disassembler =
        Disassembler::from_trusted_profile(profile).expect("trusted embedded profile");
    let mut bytes = [0_u8; 16];
    bytes[..instruction.len()].copy_from_slice(instruction);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, instruction.len())
        .expect("complete genuine instruction lift");
    let arch = lifted.authority().arch_spec().clone();
    let blocks = [lifted.block().clone()];
    let artifact = SsaArtifact::for_decompile(&blocks, Some(&arch))
        .expect("decompiler-optimized SSA artifact");
    assert_eq!(artifact.mode(), FunctionPrepareMode::Decompile);
    let projection = MachineProjection::from_artifact(&artifact).expect("typed machine projection");
    assert!(
        projection.failures().is_empty(),
        "simple register write must project without residual failures: {:?}",
        projection.failures()
    );
    (artifact, projection, arch)
}

fn genuine_projection_allowing_residuals(
    profile: TrustedSleighProfile,
    instructions: &[u8],
) -> (SsaArtifact, MachineProjection, r2il::ArchSpec) {
    assert!(!instructions.is_empty() && instructions.len() <= 16);
    let disassembler =
        Disassembler::from_trusted_profile(profile).expect("trusted embedded profile");
    let mut bytes = [0_u8; 16];
    bytes[..instructions.len()].copy_from_slice(instructions);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, instructions.len())
        .expect("complete genuine instruction lift");
    let arch = lifted.authority().arch_spec().clone();
    let blocks = [lifted.block().clone()];
    let artifact = SsaArtifact::for_decompile(&blocks, Some(&arch))
        .expect("decompiler-optimized SSA artifact");
    let projection = MachineProjection::from_artifact(&artifact).expect("typed machine projection");
    (artifact, projection, arch)
}

/// The one surviving definition of `destination`, and its write projection.
fn exact_single_write_to(
    artifact: &SsaArtifact,
    projection: &MachineProjection,
    destination: CanonicalStorageId,
) -> (r2ssa::InstId, MachineWriteProjection) {
    let writes = artifact
        .graph()
        .insts
        .iter()
        .filter(|inst| {
            inst.output
                .and_then(|output| artifact.graph().value(output))
                .and_then(|value| value.canonical_storage)
                == Some(destination)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        writes.len(),
        1,
        "the destination must have exactly one surviving definition, got {:?}",
        writes
            .iter()
            .map(|write| (write, projection.write_disposition(write.id)))
            .collect::<Vec<_>>()
    );
    match projection
        .write_disposition(writes[0].id)
        .copied()
        .expect("dense storage write disposition")
    {
        MachineWriteDisposition::Exact(write) => (writes[0].id, write),
        MachineWriteDisposition::Refused(reason) => {
            panic!("storage write must be exact, got {reason:?}")
        }
    }
}

fn no_insert_survives(artifact: &SsaArtifact) {
    assert!(
        !artifact.graph().insts.iter().any(|inst| matches!(
            inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::Insert { .. })
        )),
        "the lift's own extension of the lane into its root supersedes the insert"
    );
}

fn exact_uses_from_storage(
    artifact: &SsaArtifact,
    projection: &MachineProjection,
    storage: CanonicalStorageId,
) -> Vec<MachineUseSlice> {
    let uses = artifact
        .graph()
        .insts
        .iter()
        .flat_map(|inst| {
            inst.inputs
                .iter()
                .enumerate()
                .filter_map(move |(input_idx, input)| {
                    (artifact
                        .graph()
                        .value(*input)
                        .and_then(|value| value.canonical_storage)
                        == Some(storage))
                    .then_some(UseSite {
                        inst: inst.id,
                        input_idx,
                    })
                })
        })
        .collect::<Vec<_>>();
    assert!(!uses.is_empty(), "storage must have a surviving use");
    uses.into_iter()
        .map(|site| {
            match projection
                .use_disposition(site)
                .copied()
                .expect("dense storage use disposition")
            {
                MachineUseDisposition::Exact(slice) => slice,
                MachineUseDisposition::MemoryAddress(address) => {
                    panic!("expected bit slice, got contextual address {address:?}")
                }
                MachineUseDisposition::Refused(reason) => {
                    panic!("storage use must be exact, got {reason:?}")
                }
            }
        })
        .collect()
}

/// `mov eax, ebx`: the lane read is a `Subpiece` of `RBX`, read whole, and
/// the lift's own clear of `RAX` is the root's one definition, a zero
/// extension of the lane (doc/adr-register-identity.md).
#[test]
fn genuine_x86_eax_write_survives_as_one_carrier_zero_extension() {
    let (artifact, projection, arch) = genuine_optimized_projection(
        TrustedSleighProfile::X86_64,
        &[0x89, 0xd8], // mov eax, ebx
    );
    let rax = declared_register_storage(&arch, "RAX");
    // Nothing here touches more of `RBX` than the instruction names, so the
    // four-byte register is this function's root for that family and the read
    // is of the whole of it.
    let ebx = declared_register_storage(&arch, "EBX");

    assert_eq!(
        exact_single_write_to(&artifact, &projection, rax).1,
        MachineWriteProjection::ZeroExtend {
            from_width_bits: 32,
            to_width_bits: 64,
        }
    );
    no_insert_survives(&artifact);
    assert!(
        exact_uses_from_storage(&artifact, &projection, ebx)
            .iter()
            .all(|slice| slice.bit_offset() == 0 && slice.width_bits() == 32)
    );
}

#[test]
fn genuine_aarch64_w0_write_survives_as_one_carrier_zero_extension() {
    let (artifact, projection, arch) = genuine_optimized_projection(
        TrustedSleighProfile::Aarch64Le,
        &[0xe0, 0x03, 0x01, 0x2a], // mov w0, w1
    );
    let x0 = declared_register_storage(&arch, "x0");
    let w1 = declared_register_storage(&arch, "w1");

    assert_eq!(
        exact_single_write_to(&artifact, &projection, x0).1,
        MachineWriteProjection::ZeroExtend {
            from_width_bits: 32,
            to_width_bits: 64,
        }
    );
    no_insert_survives(&artifact);
    assert!(
        exact_uses_from_storage(&artifact, &projection, w1)
            .iter()
            .all(|slice| slice.bit_offset() == 0 && slice.width_bits() == 32)
    );
}

/// `mov ah, bl`: the byte is inserted into `RAX` at bit 8, and that insert is
/// the root's full definition from explicit inputs.
///
/// The `mov rcx, rax` after it is what makes `RAX` the root: a function that
/// touches only `AH` has `AH` itself for a root and composes nothing.
#[test]
fn genuine_x86_ah_write_survives_as_one_high_slice_insert() {
    let (artifact, projection, arch) = genuine_optimized_projection(
        TrustedSleighProfile::X86_64,
        &[0x88, 0xdc, 0x48, 0x89, 0xc1], // mov ah, bl; mov rcx, rax
    );
    let rax = declared_register_storage(&arch, "RAX");

    let (definition, write) = exact_single_write_to(&artifact, &projection, rax);
    assert_eq!(write, MachineWriteProjection::Full);
    let Some(r2ssa::InstPayload::Op(r2ssa::SSAOp::Insert {
        position, value, ..
    })) = artifact.graph().inst(definition).map(|inst| &inst.payload)
    else {
        panic!("the high byte write inserts into the root");
    };
    assert_eq!(position.constant_bits(), Some(8));
    assert_eq!(value.size, 1);
}

/// `mov bl, ah`: the byte is read as a `Subpiece` of `RAX` one byte up, and
/// the read of `RAX` underneath is whole.
#[test]
fn genuine_x86_ah_read_is_relative_to_rax() {
    let (artifact, projection, arch) = genuine_optimized_projection(
        TrustedSleighProfile::X86_64,
        &[0x88, 0xe3, 0x48, 0x89, 0xc1], // mov bl, ah; mov rcx, rax
    );
    let rax = declared_register_storage(&arch, "RAX");

    let slices = exact_uses_from_storage(&artifact, &projection, rax);
    assert_eq!(slices.len(), 2);
    assert!(slices.iter().all(|slice| {
        slice.bit_offset() == 0
            && slice.width_bits() == 64
            && slice.carrier_width_bits() == 64
            && slice.conversion().is_none()
    }));
    assert!(artifact.graph().insts.iter().any(|inst| matches!(
        &inst.payload,
        r2ssa::InstPayload::Op(r2ssa::SSAOp::Subpiece { dst, offset: 1, .. }) if dst.size == 1
    )));
}

/// `movzx eax, ah`: the byte lane is read a byte up the root, and the root is
/// redefined by the lift's own extension of the widened lane.
#[test]
fn genuine_x86_ah_zero_extend_redefines_rax_from_the_lane() {
    let (artifact, projection, arch) = genuine_optimized_projection(
        TrustedSleighProfile::X86_64,
        &[0x0f, 0xb6, 0xc4], // movzx eax, ah
    );
    let rax = declared_register_storage(&arch, "RAX");

    let slices = exact_uses_from_storage(&artifact, &projection, rax);
    assert!(
        slices
            .iter()
            .all(|slice| slice.bit_offset() == 0 && slice.width_bits() == 64),
        "{slices:?}"
    );
    assert_eq!(
        exact_single_write_to(&artifact, &projection, rax).1,
        MachineWriteProjection::ZeroExtend {
            from_width_bits: 32,
            to_width_bits: 64,
        }
    );
    no_insert_survives(&artifact);
}

#[test]
fn genuine_x86_eax_read_is_relative_to_rax() {
    let (artifact, projection, arch) = genuine_optimized_projection(
        TrustedSleighProfile::X86_64,
        &[0x89, 0xc3, 0x48, 0x89, 0xc1], // mov ebx, eax; mov rcx, rax
    );
    let rax = declared_register_storage(&arch, "RAX");
    let rbx = declared_register_storage(&arch, "RBX");

    let slices = exact_uses_from_storage(&artifact, &projection, rax);
    assert!(slices.iter().all(|slice| {
        slice.bit_offset() == 0 && slice.width_bits() == 64 && slice.carrier_width_bits() == 64
    }));
    assert_eq!(
        exact_single_write_to(&artifact, &projection, rbx).1,
        MachineWriteProjection::ZeroExtend {
            from_width_bits: 32,
            to_width_bits: 64,
        }
    );
}

/// A subpiece reads its operand whole, and the carrier is still the source's.
///
/// The extraction is the operation's own semantics and the operation renders it,
/// so the read underneath carries no offset -- stating it in both places applied
/// it twice and made every vector lane above the first read as zero. What the
/// source still owns is the carrier width, which is what this checks.
#[test]
fn genuine_x86_xmm_subpieces_read_their_operand_whole_of_the_owned_carrier() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted embedded profile");
    let lifted = disassembler
        .lift_genuine_block(&[0x90], 0x1000, 1)
        .expect("genuine x86 authority");
    let arch = lifted.authority().arch_spec().clone();
    // The block touches only `XMM2`, so that is the family's root here.
    let xmm2 = declared_register_storage(&arch, "XMM2");
    let blocks = [r2il::R2ILBlock {
        addr: 0x1000,
        size: 1,
        ops: vec![r2il::R2ILOp::Subpiece {
            dst: r2il::Varnode::unique(0x10, 4),
            src: r2il::Varnode::register(xmm2.offset, xmm2.size),
            offset: 4,
        }],
        switch_info: None,
        op_metadata: Default::default(),
    }];
    let artifact = SsaArtifact::raw(&blocks, Some(&arch)).expect("x86 vector subpiece SSA");
    let projection = MachineProjection::from_artifact(&artifact).expect("machine projection");

    let slices = exact_uses_from_storage(&artifact, &projection, xmm2);
    assert!(!slices.is_empty(), "the subpiece must record a use of XMM2");
    assert!(
        slices
            .iter()
            .all(|slice| slice.bit_offset() == 0 && slice.width_bits() == 128),
        "an extracting operation reads its operand whole: {slices:?}"
    );
}

/// `NEON_ext` is no longer opaque: the lift gives it its semantics.
///
/// `EXT` takes the vector's width of bytes from the concatenation of its second
/// operand above its first, starting at a byte index, which is exactly a shift
/// down, a shift up and an or. Expanding it there is what lets the projection
/// and everything after it stay free of vector-specific machinery -- and what
/// lets `crc32_bitwise` at arm64 -O2 render at all, since a `CallOther` carries
/// no semantics and refuses the whole function.
#[test]
fn genuine_aarch64_neon_ext_is_expanded_into_exact_operations() {
    let (artifact, projection, _) = genuine_projection_allowing_residuals(
        TrustedSleighProfile::Aarch64Le,
        &[
            0x43, 0x40, 0x02, 0x6e, // ext v3.16b, v2.16b, v2.16b, 8
            0x42, 0x1c, 0x23, 0x2e, // eor v2.8b, v2.8b, v3.8b
        ],
    );
    let graph = artifact.graph();
    assert!(
        !graph.insts.iter().any(|inst| matches!(
            &inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::CallOther { userop, .. }) if *userop == 150
        )),
        "the lift must give NEON_ext its semantics rather than leave it opaque"
    );
    // The expansion is a 64-bit rotate for this index, so both shifts are there
    // and neither is refused by the projection.
    for (shifted, amount) in [(false, 64_u64), (true, 64)] {
        let inst = graph
            .insts
            .iter()
            .find(|inst| match &inst.payload {
                r2ssa::InstPayload::Op(r2ssa::SSAOp::IntLeft { .. }) if shifted => true,
                r2ssa::InstPayload::Op(r2ssa::SSAOp::IntRight { .. }) if !shifted => true,
                _ => false,
            })
            .unwrap_or_else(|| panic!("the expansion must shift by {amount}"));
        assert!(
            projection
                .failure_for_output(inst.output.expect("shift result"))
                .is_none(),
            "an expanded operation must project exactly"
        );
    }
}

/// `NEON_ushl` is no longer opaque: the lift gives it its semantics.
///
/// `USHL` shifts each element of its first operand by the signed low byte of
/// the corresponding element of its second -- left when positive, logical right
/// when negative, and to zero once the distance reaches the element's width.
/// That is expressible element by element, so it is expanded here rather than
/// left as a `CallOther` carrying no semantics at all, which refuses the whole
/// function.
#[test]
fn genuine_aarch64_neon_ushl_is_expanded_into_exact_operations() {
    let (artifact, projection, _) = genuine_projection_allowing_residuals(
        TrustedSleighProfile::Aarch64Le,
        &[
            0x01, 0x44, 0xa1, 0x6e, // ushl v1.4s, v0.4s, v1.4s
            0x00, 0x1c, 0xa1, 0x4e, // orr v0.16b, v0.16b, v1.16b
        ],
    );
    let graph = artifact.graph();
    assert!(
        !graph.insts.iter().any(|inst| matches!(
            &inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::CallOther { userop, .. }) if *userop == 294
        )),
        "the lift must give NEON_ushl its semantics rather than leave it opaque"
    );
    // The distance is read as a signed byte and both directions are present.
    let signed = graph.insts.iter().any(|inst| {
        matches!(
            &inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::IntSExt { .. })
        )
    });
    let selects = graph
        .insts
        .iter()
        .filter(|inst| {
            matches!(
                &inst.payload,
                r2ssa::InstPayload::Op(r2ssa::SSAOp::Select { .. })
            )
        })
        .count();
    assert!(
        signed,
        "the shift distance is the element's signed low byte"
    );
    assert!(
        selects >= 8,
        "each element chooses a direction and saturates to zero"
    );
    for inst in &graph.insts {
        if let Some(output) = inst.output {
            assert!(
                projection.failure_for_output(output).is_none(),
                "an expanded operation must project exactly"
            );
        }
    }
}
