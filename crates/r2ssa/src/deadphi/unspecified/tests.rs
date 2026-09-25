use super::*;
use crate::SSAFunction;
use r2il::{ArchSpec, R2ILBlock, R2ILOp, RegisterDef, SpaceId, Varnode};

fn reg(offset: u64, size: u32) -> Varnode {
    Varnode::new(SpaceId::Register, offset, size)
}

fn tmp(offset: u64, size: u32) -> Varnode {
    Varnode::unique(offset, size)
}

fn arch() -> ArchSpec {
    let mut arch = ArchSpec::new("x86-64");
    arch.addr_size = 8;
    arch.add_register(RegisterDef::new("RAX", 0, 8));
    arch.add_register(RegisterDef::new("RDI", 0x38, 8));
    arch.add_register(RegisterDef::new("RIP", 0x288, 8));
    arch
}

/// The unspecified bytes of the value `RAX` holds when `ops` return, with the
/// caller's `RAX` the only seed.
fn returned_rax(ops: Vec<R2ILOp>) -> (ByteMask, ByteMask) {
    let mut block = R2ILBlock::new(0x1000, 4);
    // The caller's register is also stored whole, so the entry value is a
    // value of the function's own and not only the root of a lane write.
    block.push(R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::constant(0x2000, 8),
        val: reg(0, 8),
    });
    for op in ops {
        block.push(op);
    }
    block.push(R2ILOp::Return {
        target: Varnode::constant(0, 8),
    });
    let func = SSAFunction::from_blocks_raw(&[block], Some(&arch())).expect("ssa");
    let graph = SsaGraph::from_function(&func);
    let named = |version: u32| {
        graph
            .values
            .iter()
            .filter(|value| value.var.name().eq_ignore_ascii_case("rax"))
            .filter(|value| value.var.version == version)
            .map(|value| value.id)
            .next()
    };
    let seed = named(0).expect("the caller's rax");
    let last = graph
        .values
        .iter()
        .filter(|value| value.var.name().eq_ignore_ascii_case("rax"))
        .max_by_key(|value| value.var.version)
        .map(|value| value.id)
        .expect("a returned rax");
    let found = UnspecifiedBytes::find(&graph, &BTreeSet::from([seed]));
    (found.may(last), found.must(last))
}

/// `movsx ax, dil; lea edx, [rax*4]; sub eax, edx`: the sixteen-bit lane is
/// defined, and bytes two and three of `-3 * rax` must carry the caller's
/// `rax`. The coefficient of the leading garbage byte is `1 - 4`, not zero.
fn sext_body(scale: u64) -> Vec<R2ILOp> {
    vec![
        R2ILOp::Subpiece {
            dst: tmp(0x10, 1),
            src: reg(0x38, 8),
            offset: 0,
        },
        R2ILOp::IntSExt {
            dst: tmp(0x20, 2),
            src: tmp(0x10, 1),
        },
        R2ILOp::Insert {
            dst: reg(0, 8),
            src: reg(0, 8),
            value: tmp(0x20, 2),
            position: Varnode::constant(0, 4),
        },
        R2ILOp::IntMult {
            dst: tmp(0x30, 8),
            a: reg(0, 8),
            b: Varnode::constant(scale, 8),
        },
        R2ILOp::Subpiece {
            dst: tmp(0x40, 4),
            src: tmp(0x30, 8),
            offset: 0,
        },
        R2ILOp::Subpiece {
            dst: tmp(0x50, 4),
            src: reg(0, 8),
            offset: 0,
        },
        R2ILOp::IntSub {
            dst: tmp(0x60, 4),
            a: tmp(0x50, 4),
            b: tmp(0x40, 4),
        },
        R2ILOp::IntZExt {
            dst: reg(0, 8),
            src: tmp(0x60, 4),
        },
    ]
}

#[test]
fn a_byte_computed_from_the_callers_garbage_must_carry_it() {
    let (may, must) = returned_rax(sext_body(4));
    assert_eq!(may, ByteMask::Bytes(0b1100), "bytes two and three may");
    assert!(
        must.contains_byte(2),
        "x - 4x is -3x: byte two must carry the caller's byte two ({must:?})"
    );
    assert_eq!(must.lowest(), Some(2), "the sixteen-bit lane is defined");
}

/// The negative: `x - x` over the same garbage cancels, so may-taint alone
/// is no proof, and nothing must.
#[test]
fn garbage_that_cancels_is_may_but_never_must() {
    let (may, must) = returned_rax(sext_body(1));
    assert_eq!(
        may,
        ByteMask::Bytes(0b1100),
        "a byte-wise closure cannot see the cancellation"
    );
    assert_eq!(
        must,
        ByteMask::NONE,
        "x - x is zero: no byte must carry garbage"
    );
}

/// `mov al, 1`: the lane is a constant and every byte above it is the
/// caller's, unchanged.
#[test]
fn a_low_lane_write_leaves_every_byte_above_it_unspecified() {
    let (may, must) = returned_rax(vec![R2ILOp::Insert {
        dst: reg(0, 8),
        src: reg(0, 8),
        value: Varnode::constant(1, 1),
        position: Varnode::constant(0, 4),
    }]);
    assert_eq!(may, ByteMask::Bytes(0xfe));
    assert_eq!(must, ByteMask::Bytes(0xfe));
}

/// `xor eax, eax` then a lane write defines every byte: nothing is seeded.
#[test]
fn a_full_write_before_the_lane_leaves_nothing_unspecified() {
    let (may, must) = returned_rax(vec![
        R2ILOp::Copy {
            dst: reg(0, 8),
            src: Varnode::constant(0, 8),
        },
        R2ILOp::Insert {
            dst: reg(0, 8),
            src: reg(0, 8),
            value: Varnode::constant(1, 1),
            position: Varnode::constant(0, 4),
        },
    ]);
    assert_eq!((may, must), (ByteMask::NONE, ByteMask::NONE));
}

/// An exclusive or with a defined byte keeps the byte unspecified; an `and`
/// with one does not prove it, because a zero byte would clear it.
#[test]
fn a_bijection_keeps_garbage_and_an_absorbing_mask_does_not_prove_it() {
    let xor = |b: Varnode| {
        vec![R2ILOp::IntXor {
            dst: reg(0, 8),
            a: reg(0, 8),
            b,
        }]
    };
    let (_, must) = returned_rax(xor(reg(0x38, 8)));
    assert_eq!(must, ByteMask::whole(8), "rax ^ rdi, rdi specified");
    let (may, must) = returned_rax(vec![R2ILOp::IntAnd {
        dst: reg(0, 8),
        a: reg(0, 8),
        b: reg(0x38, 8),
    }]);
    assert_eq!(may, ByteMask::whole(8));
    assert_eq!(must, ByteMask::NONE);
}
