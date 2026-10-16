//! Every embedded language lifts deterministic random bytes without a fault (libflutter's `vldm`,
//! #278), and each lift pass leaves an instruction computing what it computed (ROADMAP D34).

use std::collections::BTreeMap;

use r2il::eval::{AccessKind, Flow, State, run};
use r2il::{Endianness, R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::PassRun;

const WORDS: usize = 50_000;
/// The random words whose passes are run through `r2il::eval`, after the instructions named below.
const PASS_WORDS: usize = 15_000;
/// Entry states each pass's input and output run from.
const SEEDS: u64 = 4;
/// The pass that gives a user operation its meaning; `r2il::eval` runs none, so an input that
/// executes one is inconclusive and only an expansion the run skipped is compared.
const EXPANSION: &str = "expand_user_operations";

fn sweep(name: &str) {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ name.len() as u64;
    let mut window = [0u8; 16];
    for at in (0..WORDS as u64).map(|i| 0x10_0000 + 4 * i) {
        for chunk in window.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        let _ = machine.disasm.lift(&window, at);
    }
}

#[cfg(feature = "x86")]
#[test]
fn x86_lifts_random_bytes_without_faulting() {
    sweep("x86-64");
    sweep("x86");
}

#[cfg(feature = "arm")]
#[test]
fn arm_lifts_random_bytes_without_faulting() {
    sweep("aarch64");
    sweep("arm");
    sweep("arm-thumb");
    sweep("arm-be");
    sweep("arm-thumb-be");
}

#[cfg(feature = "riscv")]
#[test]
fn riscv_lifts_random_bytes_without_faulting() {
    sweep("riscv64");
}

/// How one run ended, what the registers the passes write hold, and each store with its value.
#[derive(Debug, PartialEq)]
struct Left {
    exit: Flow,
    registers: Vec<Option<u128>>,
    stores: Vec<(u64, u32, Option<u128>)>,
}

/// The register pieces, at most sixteen bytes each, that either side of a pass writes.
fn written(run: &PassRun) -> Vec<(u64, u32)> {
    let mut pieces = Vec::new();
    for output in run
        .before
        .iter()
        .chain(&run.after)
        .filter_map(R2ILOp::output)
    {
        if output.space != SpaceId::Register {
            continue;
        }
        for start in (0..output.size).step_by(16) {
            pieces.push((
                output.offset + u64::from(start),
                (output.size - start).min(16),
            ));
        }
    }
    pieces.sort_unstable();
    pieces.dedup();
    pieces
}

/// The registers the pass's input reads, each given one value; the output must read no others.
fn entry(run: &PassRun, seed: u64) -> Vec<(u64, u32, u128)> {
    let mut stream = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut draw = || {
        stream ^= stream << 13;
        stream ^= stream >> 7;
        stream ^= stream << 17;
        stream
    };
    run.before
        .iter()
        .flat_map(R2ILOp::inputs)
        .filter(|read| read.space == SpaceId::Register)
        .map(|read| {
            let value = match draw() % 4 {
                0 => 0,
                1 => 1,
                _ => (u128::from(draw()) << 64) | u128::from(draw()),
            };
            // A flag is a boolean; a wider register is any value.
            let value = if read.size == 1 { value & 1 } else { value };
            (read.offset, read.size, value)
        })
        .collect()
}

/// Run `ops` from `entry` over memory every byte of which is mapped to a hash of its address.
fn left(
    ops: &[R2ILOp],
    endian: Endianness,
    entry: &[(u64, u32, u128)],
    seed: u64,
    watched: &[(u64, u32)],
) -> Left {
    let mapped = move |address: u64| {
        Some(((address ^ seed).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8)
    };
    let mut state = State::new(endian, mapped, 4096).expect("a machine with an order");
    for &(offset, size, value) in entry {
        state
            .set_register(offset, size, value)
            .expect("an entry register");
    }
    let exit = run(ops, &mut state);
    let registers = watched
        .iter()
        .map(|&(offset, size)| state.register(offset, size))
        .collect();
    let writes: Vec<_> = state
        .take_accesses()
        .into_iter()
        .filter(|access| access.kind == AccessKind::Write)
        .collect();
    let stores = writes
        .into_iter()
        .map(|access| {
            let value = state.load(access.address, access.width).ok();
            (access.address, access.width, value)
        })
        .collect();
    Left {
        exit,
        registers,
        stores,
    }
}

/// What the entry states say of one pass.
#[derive(Debug, Default, PartialEq)]
struct Verdict {
    /// States whose input ran to its end and whose output agreed.
    agreed: u64,
    /// States whose input could not run (an operation `r2il::eval` does not model, a loop).
    inconclusive: u64,
    /// The first state on which the output disagreed.
    differs: Option<String>,
}

fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// An operation the evaluator cannot run, as what it returns: a user operation's result is a value
/// of the seed's, and one with no result does nothing. Input and output are given the same values.
fn opaque(ops: &[R2ILOp], seed: u64) -> Vec<R2ILOp> {
    ops.iter()
        .map(|op| match op {
            R2ILOp::CallOther {
                userop,
                output: Some(output),
                ..
            } if output.size <= 8 => {
                let bits = mix(u64::from(*userop) << 32 ^ seed);
                let bits = bits & u64::MAX.checked_shr(64 - 8 * output.size).unwrap_or(0);
                // A one-byte result is a flag.
                let bits = if output.size == 1 { bits & 1 } else { bits };
                R2ILOp::Copy {
                    dst: output.clone(),
                    src: Varnode::constant(bits, output.size),
                }
            }
            R2ILOp::CallOther { output: None, .. } => R2ILOp::Nop,
            other => other.clone(),
        })
        .collect()
}

/// Run a pass's input and output from the same seeded states and compare how they ended, the
/// registers either writes and every store.
fn judge(run: &PassRun, endian: Endianness) -> Verdict {
    let watched = written(run);
    let mut verdict = Verdict::default();
    // The pass that gives user operations their meaning is the one that cannot see them as values.
    let opaque_user_operations = run.pass != EXPANSION;
    for seed in 0..SEEDS {
        let entry = entry(run, seed);
        let ops = |ops: &[R2ILOp]| match opaque_user_operations {
            true => opaque(ops, seed),
            false => ops.to_vec(),
        };
        let before = left(&ops(&run.before), endian, &entry, seed, &watched);
        if matches!(before.exit, Flow::Stop(_)) {
            verdict.inconclusive += 1;
            continue;
        }
        let after = left(&ops(&run.after), endian, &entry, seed, &watched);
        if after == before {
            verdict.agreed += 1;
        } else if verdict.differs.is_none() {
            verdict.differs = Some(format!(
                "seed {seed}, entry {entry:x?}\n  input  {before:x?}\n  output {after:x?}"
            ));
        }
    }
    verdict
}

/// What a sweep compared for one pass.
#[derive(Debug, Default)]
struct Tally {
    agreed: u64,
    inconclusive: u64,
    /// Lifts where the pass changed the operations, whatever the verdict.
    fired: u64,
    /// Agreed runs where the pass changed the operations.
    edited: u64,
    /// Agreed runs where the pass changed an instruction that has a local label.
    relabelled: u64,
}

/// Whether the operations write a temporary strictly inside an earlier write to one, which
/// `whole_unique_reads` rebuilds the holder for (GP-5581, the resync's `insert_piece`).
fn writes_inside_a_live_temporary(ops: &[R2ILOp]) -> bool {
    let mut live: Vec<(u64, u64)> = Vec::new();
    ops.iter()
        .filter_map(R2ILOp::output)
        .filter(|output| output.space == SpaceId::Unique)
        .any(|output| {
            let (start, end) = (output.offset, output.offset + u64::from(output.size));
            let inside = live
                .iter()
                .any(|&(from, to)| from <= start && end <= to && (from, to) != (start, end));
            live.push((start, end));
            inside
        })
}

fn sweep_passes(name: &str, words: &[[u8; 16]]) -> BTreeMap<&'static str, Tally> {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let endian = machine.arch.memory_endianness;
    let mut tallies: BTreeMap<&'static str, Tally> = BTreeMap::new();
    for (index, window) in words.iter().enumerate() {
        let at = 0x10_0000 + 4 * index as u64;
        let Ok(runs) = machine.disasm.lift_passes(window, at) else {
            continue;
        };
        for run in runs {
            let tally = tallies.entry(run.pass).or_default();
            // A pass that changed nothing leaves every run as it was.
            if run.before == run.after {
                continue;
            }
            tally.fired += 1;
            let verdict = judge(&run, endian);
            assert!(
                verdict.differs.is_none(),
                "{name} {window:02x?} at {at:#x}: {} changed what the instruction computes: {}\n{:#?}\n=>\n{:#?}",
                run.pass,
                verdict.differs.unwrap_or_default(),
                run.before,
                run.after
            );
            tally.agreed += verdict.agreed;
            tally.inconclusive += verdict.inconclusive;
            if verdict.agreed > 0 {
                tally.edited += 1;
                tally.relabelled += u64::from(run.before.iter().any(R2ILOp::is_local_branch));
            }
        }
    }
    tallies
}

/// The sweep's deterministic random words.
fn random_words(name: &str, words: usize) -> Vec<[u8; 16]> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ name.len() as u64;
    (0..words)
        .map(|_| {
            let mut window = [0u8; 16];
            for chunk in window.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            window
        })
        .collect()
}

/// Instructions whose operations carry a local label a pass has to keep, padded to a window.
fn labelled(bytes: &[&[u8]]) -> Vec<[u8; 16]> {
    bytes
        .iter()
        .map(|word| {
            let mut window = [0u8; 16];
            window[..word.len()].copy_from_slice(word);
            window
        })
        .collect()
}

/// Sweep the known instructions and the random words; where `relabelled`, some pass must have
/// edited an instruction that carries a local label, and each pass in `edits` one the input ran.
fn passes_preserve(name: &str, known: &[&[u8]], relabelled: bool, edits: &[&str]) {
    let mut words = labelled(known);
    words.extend(random_words(name, PASS_WORDS));
    let tallies = sweep_passes(name, &words);
    println!("{name}: {tallies:#?}");
    let compared: u64 = tallies.values().map(|tally| tally.agreed).sum();
    assert!(compared > 0, "{name}: no pass was compared: {tallies:?}");
    let moved: u64 = tallies.values().map(|tally| tally.relabelled).sum();
    assert!(
        moved > 0 || !relabelled,
        "{name}: no label moved under a pass: {tallies:?}"
    );
    for pass in edits {
        let edited = tallies.get(pass).map_or(0, |tally| tally.edited);
        assert!(
            edited > 0,
            "{name}: {pass} edited no instruction the evaluator ran to its end: {tallies:?}"
        );
    }
}

// `cmpxchg [rip+d], r32` and `bsf ecx, [rip+d]` read memory inside their own local branches.
#[cfg(feature = "x86")]
#[test]
fn x86_passes_leave_each_instruction_computing_what_it_computed() {
    let cmpxchg: &[&[u8]] = &[
        &[0x0f, 0xb0, 0x3d, 0x5a, 0x05, 0xa2, 0x14],
        &[0x0f, 0xb0, 0x05, 0x39, 0x38, 0x83, 0x1b],
        &[0x0f, 0xbc, 0x0d, 0x00, 0x20, 0x00, 0x00],
    ];
    let edits = [
        "whole_unique_reads",
        "canonicalize_memory_operands",
        "forward_repeated_loads",
    ];
    passes_preserve("x86-64", cmpxchg, true, &edits);
    passes_preserve("x86", cmpxchg, false, &edits);
}

// Advanced SIMD scalar conversions, whose temporaries are read in pieces under a local skip.
#[cfg(feature = "arm")]
#[test]
fn arm_passes_leave_each_instruction_computing_what_it_computed() {
    let simd: &[&[u8]] = &[
        &[0xce, 0xfe, 0x37, 0x7f],
        &[0x58, 0xfd, 0x1b, 0x7f],
        &[0x90, 0xfe, 0x1d, 0x7f],
    ];
    // `stxrb` and `stxrh`: a skip over a store of a piece of a temporary.
    let exclusive: &[&[u8]] = &[&[0x01, 0x7c, 0x02, 0x08], &[0xba, 0xd9, 0x10, 0x48]];
    // The expansion edits a run `eval` finishes only on ARM32, where a condition skips the operation;
    // on AArch64 it is outside the floor (doc/adr-verified-layers.md).
    let aarch64 = ["whole_unique_reads", "split_odd_register_zeroes"];
    let thumb = ["whole_unique_reads", "canonicalize_memory_operands"];
    passes_preserve("aarch64", &[simd, exclusive].concat(), true, &aarch64);
    let arm = [
        "whole_unique_reads",
        "canonicalize_memory_operands",
        "forward_repeated_loads",
        EXPANSION,
    ];
    passes_preserve("arm", &[], false, &arm);
    passes_preserve("arm-thumb", &[], false, &thumb);
    passes_preserve("arm-be", &[], false, &["whole_unique_reads", EXPANSION]);
    passes_preserve("arm-thumb-be", &[], false, &thumb);
}

#[cfg(feature = "riscv")]
#[test]
fn riscv_passes_leave_each_instruction_computing_what_it_computed() {
    passes_preserve("riscv64", &[], false, &["whole_unique_reads"]);
}

/// The gate is only worth its name if a broken pass fails it: a label left behind an insertion
/// and a dropped effect each make the output disagree with the input.
#[test]
fn the_gate_fails_a_pass_that_moves_a_label_or_drops_an_effect() {
    let register = |n: u64| Varnode::register(8 * n, 8);
    let set = |n: u64| R2ILOp::Copy {
        dst: register(n),
        src: Varnode::constant(n + 1, 8),
    };
    let mut skip = R2ILOp::CBranch {
        target: Varnode::constant(0, 4),
        cond: Varnode::register(0x100, 1),
    };
    skip.set_local_offset(2);
    let store = R2ILOp::Store {
        space: SpaceId::Ram,
        addr: Varnode::constant(0x2000, 8),
        val: register(2),
    };
    let before = vec![skip.clone(), set(0), set(1), store.clone()];
    let judged = |after: Vec<R2ILOp>| {
        let run = PassRun {
            pass: "mutant",
            before: before.clone(),
            after,
        };
        judge(&run, Endianness::Little)
    };
    let neutral = R2ILOp::Copy {
        dst: Varnode::unique(0x1000, 1),
        src: Varnode::constant(0, 1),
    };
    // Inserting a temporary before the skipped operation, with the label left to name it.
    let with_label = |label: i64| {
        let mut skip = skip.clone();
        skip.set_local_offset(label);
        vec![skip, neutral.clone(), set(0), set(1), store.clone()]
    };
    assert_eq!(
        judged(with_label(3)).differs,
        None,
        "the label kept on its op"
    );
    assert!(judged(with_label(3)).agreed > 0);
    assert!(
        judged(with_label(2)).differs.is_some(),
        "a label left behind"
    );
    let dropped_store = vec![skip.clone(), set(0), set(1)];
    assert!(judged(dropped_store).differs.is_some(), "a dropped store");
    let dropped_write = vec![skip, set(0), store];
    assert!(
        judged(dropped_write).differs.is_some(),
        "a dropped register write"
    );
}

/// Each word writes a piece into a live temporary, so `whole_unique_reads` must rebuild the holder
/// and the rebuilt instruction must compute what the input did, with every label on its op.
fn rebuilds_holders(name: &str, words: &[&[u8]]) {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let endian = machine.arch.memory_endianness;
    for (window, bytes) in labelled(words).iter().zip(words) {
        let runs = machine
            .disasm
            .lift_passes(window, 0x10_0000)
            .expect("lifts");
        let run = runs
            .iter()
            .find(|run| run.pass == "whole_unique_reads")
            .expect("the pass ran");
        assert!(
            writes_inside_a_live_temporary(&run.before) && run.before != run.after,
            "{name} {bytes:02x?}: no holder was rebuilt\n{:#?}",
            run.before
        );
        let verdict = judge(run, endian);
        assert!(
            verdict.differs.is_none() && verdict.agreed > 0,
            "{name} {bytes:02x?}: {verdict:?}\n{:#?}\n=>\n{:#?}",
            run.before,
            run.after
        );
    }
}

// MOVBE byte by byte (GP-7027), VPADDW and VPADDD lane by lane (GP-6061); no ARM word is judged
// (doc/adr-verified-layers.md, D34).
#[cfg(feature = "x86")]
#[test]
fn x86_pieces_written_into_a_live_temporary_rebuild_their_holder() {
    let movbe: &[&[u8]] = &[
        &[0x0f, 0x38, 0xf0, 0x06],
        &[0x48, 0x0f, 0x38, 0xf0, 0x06],
        &[0xc5, 0xc1, 0xfd, 0xc4],
        &[0xc5, 0xf1, 0xfe, 0x0e],
    ];
    rebuilds_holders("x86-64", movbe);
    rebuilds_holders(
        "x86",
        &[
            &[0x0f, 0x38, 0xf0, 0x06],
            &[0xc5, 0xc1, 0xfd, 0xc4],
            &[0xc5, 0xc9, 0xfe, 0x08],
        ],
    );
}
