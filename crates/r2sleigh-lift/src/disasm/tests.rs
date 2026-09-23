use super::*;
use r2il::OpMetadata;

const PINNED_ARM64_O2_LOAD_BLOCK_ADDR: u64 = 0x1_0000_05b4;
const PINNED_ARM64_O2_LOAD_BLOCK: &[u8] = &[
    0x0a, 0x15, 0x40, 0x38, 0x4b, 0x05, 0x01, 0x51, 0x4c, 0x01, 0x1b, 0x32, 0x7f, 0x69, 0x00, 0x71,
    0x8a, 0x31, 0x8a, 0x1a, 0x0a, 0x00, 0x0a, 0xca, 0x40, 0x7d, 0x09, 0x9b, 0x21, 0x04, 0x00, 0xf1,
    0x01, 0xff, 0xff, 0x54,
];
const PINNED_X86_CONDITIONAL_RETURN_ADDR: u64 = 0x1_0000_0650;
const PINNED_X86_CONDITIONAL_RETURN_BYTES: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x81, 0xff, 0xad, 0xde, 0x00, 0x00, 0x0f, 0x94, 0xc0, 0x5d,
    0xc3,
];

fn declared_register_storage(arch: &r2il::ArchSpec, name: &str) -> r2il::RegisterStorage {
    arch.get_register(name)
        .unwrap_or_else(|| panic!("embedded specification is missing {name}"))
        .storage()
}

fn register_varnode(storage: r2il::RegisterStorage) -> Varnode {
    Varnode::register(storage.offset, storage.size)
}

fn padded_instruction<const N: usize>(instruction: [u8; N]) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..N].copy_from_slice(&instruction);
    bytes
}

#[cfg(feature = "x86")]
#[test]
fn x86_32_bit_register_write_explicitly_zero_extends_its_declared_carrier() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 specification");
    let bytes = padded_instruction([0x89, 0xd8]);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, 2)
        .expect("mov eax, ebx lift");
    let arch = lifted.authority().arch_spec();
    let eax = declared_register_storage(arch, "EAX");
    let ebx = declared_register_storage(arch, "EBX");
    let rax = declared_register_storage(arch, "RAX");

    assert_eq!(
        lifted.block().ops,
        vec![
            R2ILOp::Copy {
                dst: register_varnode(eax),
                src: register_varnode(ebx),
            },
            R2ILOp::IntZExt {
                dst: register_varnode(rax),
                src: register_varnode(eax),
            },
        ]
    );
}

#[cfg(feature = "arm")]
#[test]
fn aarch64_w_register_write_explicitly_zero_extends_its_declared_carrier() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted AArch64 specification");
    // mov w0, w1 (alias of orr w0, wzr, w1), little-endian encoding.
    let bytes = padded_instruction([0xe0, 0x03, 0x01, 0x2a]);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, 4)
        .expect("mov w0, w1 lift");
    let arch = lifted.authority().arch_spec();
    let w0 = declared_register_storage(arch, "w0");
    let w1 = declared_register_storage(arch, "w1");
    let x0 = declared_register_storage(arch, "x0");

    assert_eq!(
        lifted.block().ops,
        vec![R2ILOp::IntZExt {
            dst: register_varnode(x0),
            src: register_varnode(w1),
        }]
    );
    assert!(matches!(
        arch.register_projection(w0).map(|projection| projection.disposition),
        Some(r2il::RegisterProjectionDisposition::Bound { carrier, .. })
            if carrier == x0
    ));
}

#[cfg(feature = "arm")]
#[test]
fn aarch64_conditional_compare_normalizes_instruction_local_control() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted AArch64 specification");
    // ccmp w1, #14, #0, eq, little-endian encoding.
    let bytes = padded_instruction([0x20, 0x08, 0x4e, 0x7a]);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, 4)
        .expect("ccmp w1, #14, #0, eq lift");

    assert!(
        !lifted
            .block()
            .ops
            .iter()
            .any(|op| matches!(op, R2ILOp::CBranch { .. })),
        "instruction-local CBranch must not escape the canonical lift: {:?}",
        lifted.block().ops
    );
    assert!(
        lifted
            .block()
            .ops
            .iter()
            .any(|op| matches!(op, R2ILOp::Select { .. })),
        "the conditional flag updates must retain their exact Select semantics"
    );
    assert!(
        lifted.block().ops.iter().all(|op| {
            !matches!(op, R2ILOp::Select { dst, .. } if dst.space == SpaceId::Unique)
        }),
        "instruction-local temporaries must feed the selected register candidates instead of preserving an undefined temporary: {:?}",
        lifted.block().ops
    );
}

#[cfg(feature = "arm")]
#[test]
fn a_branch_to_the_next_instruction_of_its_own_block_is_not_a_terminator() {
    // `b .+4; bl target`, which is what arm64 -O0 emits before a
    // `__stack_chk_fail` call and radare2 keeps in one block. The branch
    // goes where the block was going, so the block still ends at the call.
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted AArch64 specification");
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&[0x01, 0x00, 0x00, 0x14]);
    bytes[4..8].copy_from_slice(&[0x02, 0x00, 0x00, 0x94]);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, 8)
        .expect("the block lifts");
    // The call returns, so the block's one successor is its fallthrough;
    // taking the branch as the terminator would name `0x1004` instead.
    let successors = genuine_block_successors(&lifted).expect("the block names successors");
    assert_eq!(successors, vec![0x1008], "{successors:?}");
}

#[cfg(feature = "x86")]
#[test]
fn x86_imul_overflow_chain_retains_its_exact_128_bit_product_geometry() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 specification");
    let bytes = padded_instruction([0x4c, 0x0f, 0xaf, 0xca]);
    let lifted = disassembler
        .lift_genuine_block(&bytes, 0x1000, 4)
        .expect("imul r9, rdx genuine lift");
    let arch = lifted.authority().arch_spec();

    r2il::validate_block_semantic(lifted.block(), arch)
        .expect("genuine IMUL P-code is width coherent");
    let product = lifted.block().ops.iter().find_map(|op| match op {
        R2ILOp::IntMult { dst, a, b } if dst.size == 16 && a.size == 16 && b.size == 16 => {
            Some(dst)
        }
        _ => None,
    });
    let product = product.expect("exact signed 128-bit product");
    assert!(lifted.block().ops.iter().any(|op| matches!(
        op,
        R2ILOp::IntSExt { dst, src } if dst.size == 16 && src.size == 8
    )));
    assert!(lifted.block().ops.iter().any(|op| matches!(
        op,
        R2ILOp::IntNotEqual { a, b, .. }
            if a.size == 16 && b == product
    )));
}

#[cfg(feature = "arm")]
#[test]
fn aarch64_dup_and_sbfx_retain_proven_width_changes() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted AArch64 specification");

    let dup = disassembler
        .lift_genuine_block(&padded_instruction([0x40, 0x0c, 0x04, 0x4e]), 0x1000, 4)
        .expect("dup v0.4s, w2 genuine lift");
    r2il::validate_block_semantic(dup.block(), dup.authority().arch_spec())
        .expect("genuine DUP P-code is width coherent");
    assert!(dup.block().ops.iter().all(|op| match op {
        R2ILOp::Copy { dst, src } => dst.size == src.size,
        _ => true,
    }));

    let sbfx = disassembler
        .lift_genuine_block(&padded_instruction([0x4b, 0x01, 0x00, 0x13]), 0x2000, 4)
        .expect("sbfx w11, w10, 0, 1 genuine lift");
    r2il::validate_block_semantic(sbfx.block(), sbfx.authority().arch_spec())
        .expect("genuine SBFX P-code is width coherent");
    assert!(sbfx.block().ops.iter().any(|op| matches!(
        op,
        R2ILOp::IntZExt { dst, src } if dst.size == 8 && src.size == 4
    )));
}

#[cfg(feature = "x86")]
#[test]
fn x86_byte_register_writes_do_not_invent_full_carrier_zero_extensions() {
    for (instruction, destination_name) in [([0x88, 0xd8], "AL"), ([0x88, 0xdc], "AH")] {
        let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
            .expect("trusted x86-64 specification");
        let bytes = padded_instruction(instruction);
        let lifted = disassembler
            .lift_genuine_block(&bytes, 0x1000, 2)
            .unwrap_or_else(|error| panic!("mov {destination_name}, bl lift: {error}"));
        let arch = lifted.authority().arch_spec();
        let destination = declared_register_storage(arch, destination_name);
        let bl = declared_register_storage(arch, "BL");
        let rax = declared_register_storage(arch, "RAX");

        assert_eq!(
            lifted.block().ops,
            vec![R2ILOp::Copy {
                dst: register_varnode(destination),
                src: register_varnode(bl),
            }]
        );
        assert!(!lifted.block().ops.iter().any(|op| matches!(
            op,
            R2ILOp::IntZExt { dst, src }
                if dst == &register_varnode(rax)
                    && src == &register_varnode(destination)
        )));
    }
}

#[test]
fn pinned_arm64_memory_space_is_ram_and_instance_stable() {
    let first = Disassembler::from_sla(
        sleigh_config::processor_aarch64::SLA_AARCH64_APPLESILICON,
        sleigh_config::processor_aarch64::PSPEC_AARCH64,
        "aarch64",
    )
    .expect("first AARCH64 AppleSilicon disassembler");
    let second = Disassembler::from_sla(
        sleigh_config::processor_aarch64::SLA_AARCH64_APPLESILICON,
        sleigh_config::processor_aarch64::PSPEC_AARCH64,
        "aarch64",
    )
    .expect("second AARCH64 AppleSilicon disassembler");

    let first_block = first
        .lift_block(
            PINNED_ARM64_O2_LOAD_BLOCK,
            PINNED_ARM64_O2_LOAD_BLOCK_ADDR,
            PINNED_ARM64_O2_LOAD_BLOCK.len(),
        )
        .expect("first real ARM64 O2 FNV lift");
    let second_block = second
        .lift_block(
            PINNED_ARM64_O2_LOAD_BLOCK,
            PINNED_ARM64_O2_LOAD_BLOCK_ADDR,
            PINNED_ARM64_O2_LOAD_BLOCK.len(),
        )
        .expect("second real ARM64 O2 FNV lift");

    for block in [&first_block, &second_block] {
        let memory_spaces = block
            .ops
            .iter()
            .filter_map(|op| match op {
                R2ILOp::Load { space, .. } | R2ILOp::Store { space, .. } => Some(*space),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !memory_spaces.is_empty(),
            "real block must contain memory IO"
        );
        assert!(
            memory_spaces.iter().all(|space| *space == SpaceId::Ram),
            "real ARM64 LOAD/STORE spaces must translate to Ram: {memory_spaces:?}"
        );
    }

    assert_eq!(first_block.addr, second_block.addr);
    assert_eq!(first_block.size as usize, PINNED_ARM64_O2_LOAD_BLOCK.len());
    assert_eq!(second_block.size as usize, PINNED_ARM64_O2_LOAD_BLOCK.len());
    assert_eq!(first_block.size, second_block.size);
    assert_eq!(first_block.ops, second_block.ops);
    assert_eq!(first_block.op_metadata, second_block.op_metadata);
    assert!(first_block.switch_info.is_none());
    assert!(second_block.switch_info.is_none());
}

#[test]
#[cfg(feature = "arm")]
fn trusted_arm64_radare_tuple_selects_generic_aarch64() {
    assert_eq!(
        TrustedSleighProfile::from_tuple("arm", "arm", 64, SourceEndianness::Little)
            .expect("verified radare ARM64 tuple"),
        TrustedSleighProfile::Aarch64Le
    );
}

#[test]
#[cfg(feature = "arm")]
fn trusted_arm32_tuples_select_the_instruction_set_the_symbol_named() {
    assert_eq!(
        TrustedSleighProfile::from_tuple("arm", "arm", 32, SourceEndianness::Little).unwrap(),
        TrustedSleighProfile::ArmCortexLe
    );
    assert_eq!(
        TrustedSleighProfile::from_tuple("arm", "thumb", 32, SourceEndianness::Little).unwrap(),
        TrustedSleighProfile::ArmThumbLe
    );
}

#[test]
#[cfg(feature = "arm")]
fn trusted_arm64_radare_tuple_refuses_unverified_neighbors() {
    for (arch_id, cpu_id, bits, endianness) in [
        ("arm", "arm", 32, SourceEndianness::Big),
        ("arm", "arm", 64, SourceEndianness::Big),
        ("aarch64", "arm", 64, SourceEndianness::Little),
        ("arm", "arm64", 64, SourceEndianness::Little),
        ("arm", "all", 64, SourceEndianness::Little),
    ] {
        assert!(matches!(
            TrustedSleighProfile::from_tuple(arch_id, cpu_id, bits, endianness),
            Err(LiftError::Unsupported(_))
        ));
    }
}

#[test]
#[cfg(not(feature = "arm"))]
fn trusted_arm64_radare_tuple_requires_arm_feature() {
    assert!(matches!(
        TrustedSleighProfile::from_tuple("arm", "arm", 64, SourceEndianness::Little),
        Err(LiftError::Unsupported(_))
    ));
}

#[test]
#[cfg(feature = "arm")]
fn trusted_generic_aarch64_profile_lifts_pinned_real_bytes() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64Le)
        .expect("trusted generic AArch64 disassembler");
    let block = disassembler
        .lift_genuine_block(
            PINNED_ARM64_O2_LOAD_BLOCK,
            PINNED_ARM64_O2_LOAD_BLOCK_ADDR,
            PINNED_ARM64_O2_LOAD_BLOCK.len(),
        )
        .expect("genuine lift of pinned real ARM64 bytes");

    assert_eq!(block.source_bytes(), PINNED_ARM64_O2_LOAD_BLOCK);
    assert_eq!(block.block().addr, PINNED_ARM64_O2_LOAD_BLOCK_ADDR);
    assert_eq!(
        block.block().size as usize,
        PINNED_ARM64_O2_LOAD_BLOCK.len()
    );
    assert_eq!(block.authority().arch_name(), "aarch64");
    assert!(!block.block().ops.is_empty());
}

#[test]
fn genuine_lift_binds_full_bytes_to_one_opaque_session() {
    let first = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("first trusted x86-64 disassembler");
    let second = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("independent trusted x86-64 disassembler");

    let mut first_bytes = PINNED_X86_CONDITIONAL_RETURN_BYTES.to_vec();
    let first_entry = first
        .lift_genuine_block(
            &first_bytes,
            PINNED_X86_CONDITIONAL_RETURN_ADDR,
            first_bytes.len(),
        )
        .expect("complete genuine entry lift");
    first_bytes.fill(0);
    assert_eq!(
        first_entry.source_bytes(),
        PINNED_X86_CONDITIONAL_RETURN_BYTES
    );
    let first_blocks = vec![first_entry];
    let layout = GenuineFunctionLayout::new(
        b"pinned-check-secret-o2-complete-function".to_vec(),
        PINNED_X86_CONDITIONAL_RETURN_ADDR,
        [GenuineFunctionBlockRange::new(
            PINNED_X86_CONDITIONAL_RETURN_ADDR,
            u32::try_from(PINNED_X86_CONDITIONAL_RETURN_BYTES.len()).expect("block size"),
        )],
        [],
    )
    .expect("exact complete function layout");
    let function = GenuineLiftedFunction::try_from_layout(layout.clone(), first_blocks.clone())
        .expect("closed single-session genuine function");
    let function_alias = function.clone();
    assert!(
        function.authority().same_lift(function_alias.authority()),
        "clones must preserve the same opaque function-lift identity"
    );
    assert!(
        function
            .authority()
            .lift_authority()
            .same_session(first_blocks[0].authority())
    );
    assert_eq!(function.blocks().len(), 1);
    let pinned_block = &function.blocks()[0];
    assert_eq!(
        pinned_block
            .instruction_spans()
            .iter()
            .map(|span| (span.addr(), span.size()))
            .collect::<Vec<_>>(),
        vec![
            (PINNED_X86_CONDITIONAL_RETURN_ADDR, 1),
            (PINNED_X86_CONDITIONAL_RETURN_ADDR + 1, 3),
            (PINNED_X86_CONDITIONAL_RETURN_ADDR + 4, 2),
            (PINNED_X86_CONDITIONAL_RETURN_ADDR + 6, 6),
            (PINNED_X86_CONDITIONAL_RETURN_ADDR + 12, 3),
            (PINNED_X86_CONDITIONAL_RETURN_ADDR + 15, 1),
            (PINNED_X86_CONDITIONAL_RETURN_ADDR + 16, 1),
        ],
        "native instruction coverage must match the manually reversed function"
    );
    let memory_spaces = pinned_block
        .block()
        .ops
        .iter()
        .filter_map(|op| match op {
            R2ILOp::Load { space, .. } | R2ILOp::Store { space, .. } => Some(*space),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(memory_spaces, vec![SpaceId::Ram; 3]);
    assert!(pinned_block.block().ops.iter().any(|op| matches!(
        op,
        R2ILOp::Copy { dst, src }
            if dst.space == SpaceId::Unique
                && dst.size == 4
                && src == &Varnode::register(56, 4)
    )));
    assert!(pinned_block.block().ops.iter().any(|op| matches!(
        op,
        R2ILOp::IntSub { b, .. }
            if b.space == SpaceId::Const && b.offset == 0xdead && b.size == 4
    )));
    assert!(pinned_block.block().ops.iter().any(|op| matches!(
        op,
        R2ILOp::Copy { dst, src }
            if dst == &Varnode::register(0, 1)
                && src == &Varnode::register(518, 1)
    )));
    assert!(matches!(
        pinned_block.block().ops.last(),
        Some(R2ILOp::Return { target }) if target == &Varnode::register(648, 8)
    ));
    for metadata in function.blocks()[0].block().op_metadata.values() {
        let mut canonical = metadata.clone();
        assert!(canonical.instruction_addr.is_some());
        canonical.instruction_addr = None;
        assert_eq!(
            canonical,
            OpMetadata::default(),
            "certifying lift must not retain inferred semantic metadata"
        );
    }

    let second_blocks = vec![
        second
            .lift_genuine_block(
                PINNED_X86_CONDITIONAL_RETURN_BYTES,
                PINNED_X86_CONDITIONAL_RETURN_ADDR,
                PINNED_X86_CONDITIONAL_RETURN_BYTES.len(),
            )
            .expect("independent genuine function block"),
    ];
    assert!(
        !first_blocks[0]
            .authority()
            .same_session(second_blocks[0].authority())
    );
    assert!(
        GenuineLiftedFunction::try_from_layout(layout.clone(), Vec::new()).is_err(),
        "omitting a declared genuine block must fail closed"
    );
    let independent = GenuineLiftedFunction::try_from_layout(layout, second_blocks)
        .expect("an independently complete session is genuine in its own right");
    assert_eq!(
        function.authority().source_manifest_hash(),
        independent.authority().source_manifest_hash(),
        "identical immutable inputs should retain the same diagnostic manifest"
    );
    assert!(
        !function.authority().same_lift(independent.authority()),
        "a matching diagnostic manifest must not replay function-lift authority"
    );
    let authorities = HashSet::from([
        function.authority().clone(),
        independent.authority().clone(),
    ]);
    assert_eq!(
        authorities.len(),
        2,
        "authority hashing must use opaque event identity"
    );
}

#[test]
fn genuine_zero_op_instructions_preserve_exact_native_spans_without_changing_pcode() {
    const ADDR: u64 = 0x401000;
    const BYTES: &[u8] = &[0x90, 0x31, 0xc0, 0x90];

    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let lifted = disassembler
        .lift_genuine_block(BYTES, ADDR, BYTES.len())
        .expect("genuine NOP/XOR/NOP block");
    let canonical_ops = lifted.block().ops.clone();
    let canonical_metadata = lifted.block().op_metadata.clone();
    let spans = lifted
        .instruction_spans()
        .iter()
        .map(|span| {
            (
                span.addr(),
                span.size(),
                span.first_canonical_op(),
                span.canonical_op_count(),
            )
        })
        .collect::<Vec<_>>();

    let xor_op_count = u64::try_from(canonical_ops.len()).expect("canonical op count fits u64");
    assert_eq!(
        spans,
        vec![
            (ADDR, 1, 0, 0),
            (ADDR + 1, 2, 0, xor_op_count),
            (ADDR + 3, 1, xor_op_count, 0),
        ]
    );
    assert!(
        !canonical_ops.is_empty(),
        "XOR must retain canonical P-code"
    );
    assert!(
        !canonical_ops
            .iter()
            .any(|op| matches!(op, R2ILOp::Unimplemented))
    );
    assert!(
        canonical_metadata
            .values()
            .all(|metadata| metadata.instruction_addr == Some(ADDR + 1))
    );

    assert_eq!(lifted.source_bytes(), BYTES);
    assert_eq!(lifted.block().ops, canonical_ops);
    assert_eq!(lifted.block().op_metadata, canonical_metadata);
}

#[test]
fn genuine_consecutive_all_zero_op_spans_remain_first_class_native_evidence() {
    const ADDR: u64 = 0x402000;
    const BYTES: &[u8] = &[0x90, 0x90, 0x90];

    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let lifted = disassembler
        .lift_genuine_block(BYTES, ADDR, BYTES.len())
        .expect("genuine consecutive NOP block");

    assert!(lifted.block().ops.is_empty());
    assert!(lifted.block().op_metadata.is_empty());
    assert_eq!(lifted.source_bytes(), BYTES);
    assert_eq!(
        lifted
            .instruction_spans()
            .iter()
            .map(|span| {
                (
                    span.addr(),
                    span.size(),
                    span.first_canonical_op(),
                    span.canonical_op_count(),
                )
            })
            .collect::<Vec<_>>(),
        vec![(ADDR, 1, 0, 0), (ADDR + 1, 1, 0, 0), (ADDR + 2, 1, 0, 0),]
    );
}

#[cfg(any(feature = "arm", feature = "riscv"))]
fn assert_public_lifts_preserve_canonical_ops(
    disassembler: &Disassembler,
    bytes: &[u8],
    addr: u64,
) -> R2ILBlock {
    let mut padded = bytes.to_vec();
    padded.resize(Disassembler::MIN_BYTES, 0);
    let canonical = disassembler
        .lift_canonical(&padded, addr)
        .expect("canonical Sleigh lift");
    let default = disassembler
        .lift(&padded, addr)
        .expect("default public lift");

    assert_eq!(default.ops, canonical.ops);
    canonical
}

#[cfg(any(feature = "arm", feature = "riscv"))]
fn assert_native_instruction(
    disassembler: &Disassembler,
    bytes: &[u8],
    addr: u64,
    expected_token: &str,
) {
    let mut padded = bytes.to_vec();
    padded.resize(Disassembler::MIN_BYTES, 0);
    let (instruction, size) = disassembler
        .disasm_native(&padded, addr)
        .expect("native instruction decode");
    assert_eq!(size, bytes.len());
    assert_eq!(
        instruction
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        expected_token
    );
}

#[cfg(feature = "arm")]
#[test]
fn aarch64_pauth_and_barrier_retain_only_canonical_sleigh_semantics() {
    const PACIBSP: &[u8] = &[0x7f, 0x23, 0x03, 0xd5];
    const DMB_ISH: &[u8] = &[0xbf, 0x3b, 0x03, 0xd5];
    const ADDR: u64 = 0x410000;

    let disassembler =
        Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64AppleSilicon)
            .expect("trusted Apple AArch64 disassembler");
    assert_native_instruction(&disassembler, PACIBSP, ADDR, "pacibsp");
    assert_native_instruction(&disassembler, DMB_ISH, ADDR + PACIBSP.len() as u64, "dmb");
    let pacibsp = assert_public_lifts_preserve_canonical_ops(&disassembler, PACIBSP, ADDR);
    assert!(
        pacibsp.ops.is_empty(),
        "zero-P-code PACIBSP must not acquire fabricated CallOther semantics"
    );

    let genuine = disassembler
        .lift_genuine_block(PACIBSP, ADDR, PACIBSP.len())
        .expect("genuine PACIBSP lift");
    assert!(genuine.block().ops.is_empty());
    assert_eq!(genuine.source_bytes(), PACIBSP);
    assert_eq!(
        genuine
            .instruction_spans()
            .iter()
            .map(|span| {
                (
                    span.addr(),
                    span.size(),
                    span.first_canonical_op(),
                    span.canonical_op_count(),
                )
            })
            .collect::<Vec<_>>(),
        vec![(ADDR, 4, 0, 0)]
    );

    let barrier = assert_public_lifts_preserve_canonical_ops(
        &disassembler,
        DMB_ISH,
        ADDR + PACIBSP.len() as u64,
    );
    let numeric_userops = barrier
        .ops
        .iter()
        .filter_map(|op| match op {
            R2ILOp::CallOther { userop, .. } => Some(*userop),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !numeric_userops.is_empty(),
        "DMB must retain the translator's numeric CallOther evidence"
    );
    assert!(
        !barrier
            .ops
            .iter()
            .any(|op| matches!(op, R2ILOp::Fence { .. }))
    );

    let independent = Disassembler::from_trusted_profile(TrustedSleighProfile::Aarch64AppleSilicon)
        .expect("independent trusted Apple AArch64 disassembler");
    let repeated = assert_public_lifts_preserve_canonical_ops(
        &independent,
        DMB_ISH,
        ADDR + PACIBSP.len() as u64,
    );
    assert_eq!(repeated.ops, barrier.ops);
}

#[cfg(feature = "riscv")]
#[test]
fn riscv_atomic_bytes_retain_only_canonical_sleigh_semantics() {
    const FENCE_IORW_IORW: &[u8] = &[0x0f, 0x00, 0xf0, 0x0f];
    const LR_W_A0_A1: &[u8] = &[0x2f, 0xa5, 0x05, 0x10];
    const SC_W_A0_A1_A2: &[u8] = &[0x2f, 0x25, 0xb6, 0x18];
    const AMOADD_W_AQRL_A0_A1_A2: &[u8] = &[0x2f, 0x25, 0xb6, 0x06];
    const ADDR: u64 = 0x420000;

    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::RiscV64Gc)
        .expect("trusted RV64GC disassembler");
    for (index, (bytes, expected_token)) in [
        (FENCE_IORW_IORW, "fence"),
        (LR_W_A0_A1, "lr.w"),
        (SC_W_A0_A1_A2, "sc.w"),
        (AMOADD_W_AQRL_A0_A1_A2, "amoadd.w.aqrl"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_native_instruction(
            &disassembler,
            bytes,
            ADDR + (index as u64 * 4),
            expected_token,
        );
        let canonical = assert_public_lifts_preserve_canonical_ops(
            &disassembler,
            bytes,
            ADDR + (index as u64 * 4),
        );
        assert!(
            !canonical.ops.iter().any(|op| matches!(
                op,
                R2ILOp::Fence { .. } | R2ILOp::LoadLinked { .. } | R2ILOp::StoreConditional { .. }
            )),
            "mnemonic-derived atomic operations must not be synthesized"
        );
    }
}

#[test]
fn genuine_instruction_span_address_overflow_fails_closed() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");

    assert!(
        disassembler
            .lift_genuine_block(&[0x90, 0x90], u64::MAX, 2)
            .is_err()
    );
}

#[test]
fn genuine_lift_rejects_partial_or_empty_source_ranges() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");

    assert!(
        disassembler
            .lift_genuine_block(
                PINNED_X86_CONDITIONAL_RETURN_BYTES,
                PINNED_X86_CONDITIONAL_RETURN_ADDR,
                0,
            )
            .is_err()
    );
    assert!(
        disassembler
            .lift_genuine_block(
                PINNED_X86_CONDITIONAL_RETURN_BYTES,
                PINNED_X86_CONDITIONAL_RETURN_ADDR,
                PINNED_X86_CONDITIONAL_RETURN_BYTES.len() + 1,
            )
            .is_err()
    );
}

#[test]
fn arbitrary_specs_cannot_mint_genuine_lifts() {
    let arbitrary = Disassembler::from_sla(
        sleigh_config::processor_x86::SLA_X86_64,
        sleigh_config::processor_x86::PSPEC_X86_64,
        "x86-64",
    )
    .expect("analysis-only disassembler");
    assert!(
        arbitrary
            .lift_genuine_block(
                PINNED_X86_CONDITIONAL_RETURN_BYTES,
                PINNED_X86_CONDITIONAL_RETURN_ADDR,
                PINNED_X86_CONDITIONAL_RETURN_BYTES.len(),
            )
            .is_err(),
        "even byte-identical caller-supplied specs remain analysis-only"
    );
}

#[test]
fn callother_translation_preserves_numeric_id_and_operands() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let address_spaces = disassembler.address_spaces();
    let constant_space = address_spaces
        .iter()
        .find(|space| space.space_type == libsla::AddressSpaceType::Constant)
        .expect("constant space")
        .clone();
    let register_space = address_spaces
        .iter()
        .find(|space| space.name == "register")
        .expect("register space")
        .clone();
    let instruction = PcodeInstruction {
        address: Address::new(
            disassembler.default_code_space(),
            PINNED_X86_CONDITIONAL_RETURN_ADDR,
        ),
        op_code: OpCode::Pseudo(PseudoOp::CallOther),
        inputs: vec![
            VarnodeData::new(Address::new(constant_space.clone(), u32::MAX.into()), 4),
            VarnodeData::new(Address::new(constant_space, 0xfeed_face), 8),
        ],
        output: Some(VarnodeData::new(Address::new(register_space, 0), 8)),
    };

    assert_eq!(
        disassembler
            .translate_pcode_op(&instruction)
            .expect("CallOther translation"),
        Some(R2ILOp::CallOther {
            userop: u32::MAX,
            output: Some(Varnode::register(0, 8)),
            inputs: vec![Varnode::constant(0xfeed_face, 8)],
        })
    );
}

#[test]
fn unsupported_pcode_is_explicitly_refused() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let address = Address::new(
        disassembler.default_code_space(),
        PINNED_X86_CONDITIONAL_RETURN_ADDR,
    );

    for op_code in [
        OpCode::Pseudo(PseudoOp::ConstantPoolRef),
        OpCode::Pseudo(PseudoOp::New),
        OpCode::Unknown(i32::MAX),
    ] {
        let instruction = PcodeInstruction {
            address: address.clone(),
            op_code,
            inputs: Vec::new(),
            output: None,
        };
        assert!(
            matches!(
                disassembler.translate_pcode_op(&instruction),
                Err(LiftError::Unsupported(_))
            ),
            "unsupported {op_code:?} must never disappear from a canonical lift"
        );
    }
}

fn controlled_space(
    id: usize,
    name: &'static str,
    space_type: libsla::AddressSpaceType,
) -> AddressSpace {
    AddressSpace {
        id: AddressSpaceId::new(id),
        name: name.into(),
        word_size: 1,
        address_size: 8,
        space_type,
        big_endian: false,
    }
}

#[test]
fn trusted_return_mechanism_validation_uses_only_exact_machine_facts() {
    let stack_pointer = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 64,
        size: 8,
    };
    let return_address = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 80,
        size: 8,
    };
    let without_mechanism = SourceFunctionInterface::new_exact(
        b"trusted-return-mechanism".to_vec(),
        "test-abi",
        [],
        r2source::SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(return_address))
    .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
    .expect("exact machine roles");
    let exact = without_mechanism
        .clone()
        .with_exact_stacked_return(0, 8, 8, 8)
        .expect("canonical stacked return");
    let mut arch = r2il::ArchSpec::new("controlled-return-mechanism");
    arch.addr_size = 8;
    arch.add_register(r2il::RegisterDef::new("opaque-a", return_address.offset, 8));
    arch.add_register(r2il::RegisterDef::new("opaque-b", stack_pointer.offset, 8));
    arch.add_space(r2il::AddressSpace::ram(8));

    assert!(captured_return_mechanism_matches_arch(&exact, &arch));
    assert!(captured_return_mechanism_matches_arch(
        &without_mechanism,
        &arch
    ));

    arch.spaces[0].word_size = 2;
    assert!(!captured_return_mechanism_matches_arch(&exact, &arch));
    assert!(captured_return_mechanism_matches_arch(
        &without_mechanism,
        &arch
    ));
}

#[test]
fn trusted_frame_pointer_validation_uses_only_exact_machine_facts() {
    let stack_pointer = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 64,
        size: 8,
    };
    let frame_pointer = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 72,
        size: 8,
    };
    let return_address = CanonicalStorageId {
        space: CanonicalStorageSpace::Register,
        offset: 80,
        size: 8,
    };
    let absent = SourceFunctionInterface::new_exact(
        b"trusted-frame-pointer".to_vec(),
        "test-abi",
        [],
        r2source::SourceFunctionReturn::Void,
        [],
    )
    .and_then(|interface| interface.with_return_address_storage(return_address))
    .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
    .expect("exact machine roles");
    let exact = absent
        .clone()
        .with_frame_pointer_storage(frame_pointer)
        .expect("explicit frame-pointer role");
    let mut arch = r2il::ArchSpec::new("controlled-frame-pointer");
    arch.addr_size = 8;
    arch.add_register(r2il::RegisterDef::new("opaque-a", return_address.offset, 8));
    arch.add_register(r2il::RegisterDef::new("opaque-b", stack_pointer.offset, 8));
    arch.add_register(r2il::RegisterDef::new("opaque-c", frame_pointer.offset, 8));

    assert!(captured_frame_pointer_storage_matches_arch(&exact, &arch));
    assert!(captured_frame_pointer_storage_matches_arch(&absent, &arch));
    assert!(!is_exact_top_level_address_register(
        &arch,
        CanonicalStorageId {
            space: CanonicalStorageSpace::Ram,
            ..frame_pointer
        },
        8,
    ));

    arch.registers[2].parent = Some("missing-parent".to_string());
    assert!(!captured_frame_pointer_storage_matches_arch(&exact, &arch));
    assert!(captured_frame_pointer_storage_matches_arch(&absent, &arch));
    arch.registers[2].parent = None;
    arch.addr_size = 4;
    assert!(!captured_frame_pointer_storage_matches_arch(&exact, &arch));
    assert!(captured_frame_pointer_storage_matches_arch(&absent, &arch));
}

#[test]
fn address_space_mapping_is_exact_and_collision_free() {
    use libsla::AddressSpaceType;

    let spaces = vec![
        controlled_space(1, "const", AddressSpaceType::Constant),
        controlled_space(2, "ram", AddressSpaceType::Processor),
        controlled_space(3, "register", AddressSpaceType::Processor),
        controlled_space(4, "unique", AddressSpaceType::Internal),
        controlled_space(5, "ab", AddressSpaceType::Processor),
        controlled_space(6, "ba", AddressSpaceType::Processor),
    ];
    let mut ctx = crate::context::LiftContext::new("controlled");
    let mapping =
        crate::sleigh::extract_address_space_map(&mut ctx, &spaces, AddressSpaceId::new(2))
            .expect("representable controlled address-space inventory");

    assert_eq!(mapping[&AddressSpaceId::new(1)], SpaceId::Const);
    assert_eq!(mapping[&AddressSpaceId::new(2)], SpaceId::Ram);
    assert_eq!(mapping[&AddressSpaceId::new(3)], SpaceId::Register);
    assert_eq!(mapping[&AddressSpaceId::new(4)], SpaceId::Unique);
    assert_eq!(mapping[&AddressSpaceId::new(5)], SpaceId::Custom(0));
    assert_eq!(mapping[&AddressSpaceId::new(6)], SpaceId::Custom(1));
    assert_ne!(
        mapping[&AddressSpaceId::new(5)],
        mapping[&AddressSpaceId::new(6)],
        "equal byte-sum names must not collide"
    );

    let ambiguous = vec![
        controlled_space(10, "ram", AddressSpaceType::Processor),
        controlled_space(11, "ram", AddressSpaceType::Processor),
    ];
    let mut ambiguous_ctx = crate::context::LiftContext::new("ambiguous");
    assert!(
        crate::sleigh::extract_address_space_map(
            &mut ambiguous_ctx,
            &ambiguous,
            AddressSpaceId::new(10),
        )
        .is_err(),
        "distinct Sleigh spaces that collapse to one r2il id are unrepresentable"
    );
}

#[test]
fn trusted_space_map_matches_exported_architecture() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let authority = disassembler
        .genuine_authority
        .as_ref()
        .expect("trusted profile authority");
    let spaces = disassembler.address_spaces();

    assert_eq!(spaces.len(), disassembler.spec.space_map.len());
    for space in spaces {
        let mapped = disassembler
            .translate_space(&space)
            .expect("every trusted source space is mapped");
        let exported = authority
            .arch_spec()
            .spaces
            .iter()
            .find(|candidate| candidate.name.as_str() == space.name.as_ref())
            .expect("mapped space must be exported in the ArchSpec");
        assert_eq!(mapped, exported.id);
    }
}

#[test]
fn function_layout_rejects_external_exits_inside_declared_ranges() {
    let range = GenuineFunctionBlockRange::new(0x1000, 0x20);
    assert!(GenuineFunctionLayout::new(b"revision".to_vec(), 0x1000, [range], [0x1010]).is_err());
}

#[test]
fn analysis_pcode_is_invalid_at_the_machine_lift_boundary() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let address = Address::new(
        disassembler.default_code_space(),
        PINNED_X86_CONDITIONAL_RETURN_ADDR,
    );

    for operation in [
        libsla::AnalysisOp::MultiEqual,
        libsla::AnalysisOp::CopyIndirect,
        libsla::AnalysisOp::PointerAdd,
        libsla::AnalysisOp::PointerSubcomponent,
        libsla::AnalysisOp::Cast,
        libsla::AnalysisOp::Insert,
        libsla::AnalysisOp::Extract,
        libsla::AnalysisOp::SegmentOp,
    ] {
        let instruction = PcodeInstruction {
            address: address.clone(),
            op_code: OpCode::Analysis(operation),
            inputs: Vec::new(),
            output: None,
        };
        assert!(
            matches!(
                disassembler.translate_pcode_op(&instruction),
                Err(LiftError::Unsupported(_))
            ),
            "analysis operation {operation:?} must be refused at the machine lift boundary"
        );
    }
}

#[test]
fn callother_translation_rejects_ids_that_do_not_fit_r2il() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let constant_space = disassembler
        .address_spaces()
        .into_iter()
        .find(|space| space.space_type == libsla::AddressSpaceType::Constant)
        .expect("constant space");
    let invalid_userop = u64::from(u32::MAX) + 1;
    let instruction = PcodeInstruction {
        address: Address::new(
            disassembler.default_code_space(),
            PINNED_X86_CONDITIONAL_RETURN_ADDR,
        ),
        op_code: OpCode::Pseudo(PseudoOp::CallOther),
        inputs: vec![VarnodeData::new(
            Address::new(constant_space, invalid_userop),
            8,
        )],
        output: None,
    };

    let error = disassembler
        .translate_pcode_op(&instruction)
        .expect_err("oversized CallOther id must be refused");
    assert_eq!(
        error.to_string(),
        format!("Unsupported feature: Sleigh CALLOTHER id does not fit r2il: {invalid_userop}")
    );
}

#[test]
fn fixed_ram_copy_is_canonical_memory_io() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let ram_space = disassembler.default_code_space();
    let register_space = disassembler
        .address_spaces()
        .into_iter()
        .find(|space| space.name == "register")
        .expect("register space");
    let address_size = u32::try_from(ram_space.address_size).expect("r2il address size");
    let address = Address::new(ram_space.clone(), PINNED_X86_CONDITIONAL_RETURN_ADDR);
    let write = PcodeInstruction {
        address: address.clone(),
        op_code: OpCode::Copy,
        inputs: vec![VarnodeData::new(Address::new(register_space.clone(), 0), 4)],
        output: Some(VarnodeData::new(Address::new(ram_space.clone(), 0x4000), 4)),
    };
    let read = PcodeInstruction {
        address,
        op_code: OpCode::Copy,
        inputs: vec![VarnodeData::new(Address::new(ram_space, 0x4000), 4)],
        output: Some(VarnodeData::new(Address::new(register_space, 0), 4)),
    };

    let ops = [write, read]
        .iter()
        .map(|op| {
            disassembler
                .translate_pcode_op(op)
                .expect("fixed RAM copy translation")
                .expect("a copy translates to one operation")
        })
        .collect::<Vec<_>>();
    let mut next_temp = 0;
    assert_eq!(
        translate::canonicalize_memory_operands(ops, address_size, &mut next_temp),
        vec![
            R2ILOp::Store {
                space: SpaceId::Ram,
                addr: Varnode::constant(0x4000, address_size),
                val: Varnode::register(0, 4),
            },
            R2ILOp::Load {
                dst: Varnode::register(0, 4),
                space: SpaceId::Ram,
                addr: Varnode::constant(0x4000, address_size),
            },
        ]
    );
    assert_eq!(next_temp, 0);
}

#[test]
fn fixed_value_pcode_uses_the_typed_sleigh_translation() {
    let disassembler = Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64)
        .expect("trusted x86-64 disassembler");
    let address_spaces = disassembler.address_spaces();
    let constant_space = address_spaces
        .iter()
        .find(|space| space.space_type == libsla::AddressSpaceType::Constant)
        .expect("constant space")
        .clone();
    let register_space = address_spaces
        .iter()
        .find(|space| space.name == "register")
        .expect("register space")
        .clone();
    let address = Address::new(
        disassembler.default_code_space(),
        PINNED_X86_CONDITIONAL_RETURN_ADDR,
    );
    let copy = PcodeInstruction {
        address: address.clone(),
        op_code: OpCode::Copy,
        inputs: vec![VarnodeData::new(
            Address::new(constant_space.clone(), 42),
            8,
        )],
        output: Some(VarnodeData::new(Address::new(register_space.clone(), 0), 8)),
    };
    let add = PcodeInstruction {
        address,
        op_code: OpCode::Int(IntOp::Add),
        inputs: vec![
            VarnodeData::new(Address::new(register_space.clone(), 0), 4),
            VarnodeData::new(Address::new(constant_space, 1), 4),
        ],
        output: Some(VarnodeData::new(Address::new(register_space, 0), 4)),
    };

    assert_eq!(
        disassembler
            .translate_pcode_op(&copy)
            .expect("COPY translation"),
        Some(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(42, 8),
        })
    );
    assert_eq!(
        disassembler
            .translate_pcode_op(&add)
            .expect("INT_ADD translation"),
        Some(R2ILOp::IntAdd {
            dst: Varnode::register(0, 4),
            a: Varnode::register(0, 4),
            b: Varnode::constant(1, 4),
        })
    );
}
