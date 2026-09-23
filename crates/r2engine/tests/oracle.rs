//! Every claim `pd` and `pdf` make holds on every run of the function's own lift, and a claim no run rules on fails.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use common::{BASE, CALLER, FORKED, JOINED, Literal, ONE, PASSES, STEPPED, TWO};
use r2engine::program::{OpenProgram, Source};
use r2engine::query::{AnnotationKind, Decoders, Line, Listing, Stop};
use r2il::eval::{Access, AccessKind, Flow, Mapped, State, TransferKind, step};
use r2il::{Endianness, R2ILOp, SpaceId, Varnode};
use r2ssa::{CanonicalStorageId, CanonicalStorageSpace};

/// `cmp rdi, 10; jae L; mov esi, 0; L: mov rax, rdi; ret`: L is entered with rdi below ten and above.
const GUARDED_JOIN: &[u8] = &[
    0x48, 0x83, 0xff, 0x0a, // cmp rdi, 10
    0x73, 0x05, // jae L
    0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, 0
    0x48, 0x89, 0xf8, // L: mov rax, rdi
    0xc3, // ret
];

/// `eax` is one, eleven or twenty-one where `shr eax, 2` reads it, so the shift leaves nought, two or five.
const SHIFT_MERGE: &[u8] = &[
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0x83, 0xff, 0x01, // cmp edi, 1
    0x74, 0x07, // je 0x1011
    0x83, 0xff, 0x02, // cmp edi, 2
    0x74, 0x09, // je 0x1018
    0xeb, 0x0c, // jmp 0x101d
    0xb8, 0x0b, 0x00, 0x00, 0x00, // 0x1011 mov eax, 11
    0xeb, 0x05, // jmp 0x101d
    0xb8, 0x15, 0x00, 0x00, 0x00, // 0x1018 mov eax, 21
    0xc1, 0xe8, 0x02, // 0x101d shr eax, 2
    0xc3, // ret
];

/// `mov eax, [0x1010]; add eax, 1; mov [0x1010], eax; ret`, then the word it counts in.
const COUNTED: &[u8] = &[
    0x8b, 0x05, 0x0a, 0x00, 0x00, 0x00, // mov eax, dword [rip + 0xa]
    0x83, 0xc0, 0x01, // add eax, 1
    0x89, 0x05, 0x01, 0x00, 0x00, 0x00, // mov dword [rip + 1], eax
    0xc3, // ret
    0x29, 0x00, 0x00, 0x00, // 0x1010, the count
];

/// `setc al; movzx eax, al; jc L; L: ret`: the branch reads the carry as a p-code boolean.
const FLAGGED: &[u8] = &[
    0x0f, 0x92, 0xc0, // setc al
    0x0f, 0xb6, 0xc0, // movzx eax, al
    0x72, 0x00, // jc 0x1008
    0xc3, // ret
];

/// `lea rdi, [0x1020]; mov ecx, 4; xor eax, eax; rep stosb; mov rax, rdi; ret`, then the four bytes it clears.
const FILLED: &[u8] = &[
    0x48, 0x8d, 0x3d, 0x19, 0x00, 0x00, 0x00, // lea rdi, [rip + 0x19]
    0xb9, 0x04, 0x00, 0x00, 0x00, // mov ecx, 4
    0x31, 0xc0, // xor eax, eax
    0xf3, 0xaa, // rep stosb
    0x48, 0x89, 0xf8, // mov rax, rdi
    0xc3, // ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // to 0x1020
    0x11, 0x11, 0x11, 0x11, // 0x1020, what it clears
];

/// `lea rbx, [0x1000]; test edi, edi; cmovne rax, rbx; mov ebx, 0; add rax, 8; ret`: the move selects the address.
const SELECTED: &[u8] = &[
    0x48, 0x8d, 0x1d, 0xf9, 0xff, 0xff, 0xff, // lea rbx, [rip - 7]
    0x85, 0xff, // test edi, edi
    0x48, 0x0f, 0x45, 0xc3, // cmovne rax, rbx
    0xbb, 0x00, 0x00, 0x00, 0x00, // mov ebx, 0
    0x48, 0x83, 0xc0, 0x08, // add rax, 8
    0xc3, // ret
];

/// Operations and block elements one run executes before it stops, ruling on nothing after.
const BUDGET: u64 = 1 << 14;
/// Runs from seeded random entry states, after the edge values.
const RANDOM_RUNS: u64 = 64;
/// Where the draws start, fixed so every run of this test draws the same states.
const SEED: u64 = 0x5eed;

/// Each function the oracle runs: the shared program's seven, then its own.
fn oracle_set() -> Vec<(&'static str, Literal, u64)> {
    let common = [
        ("one", ONE),
        ("caller", CALLER),
        ("two", TWO),
        ("forked", FORKED),
        ("joined", JOINED),
        ("passes", PASSES),
        ("stepped", STEPPED),
    ];
    let own = [
        ("guarded_join", GUARDED_JOIN, GUARDED_JOIN.len()),
        ("shift_merge", SHIFT_MERGE, SHIFT_MERGE.len()),
        ("counted", COUNTED, 0x10),
        ("flagged", FLAGGED, FLAGGED.len()),
        ("filled", FILLED, 0x14),
        ("selected", SELECTED, SELECTED.len()),
    ];
    let common = common.map(|(name, entry)| (name, Literal::new(), entry));
    let own = own.map(|(name, code, size)| {
        let literal = Literal::of_code(code, &[(name, BASE, size as u64)]);
        (name, literal, BASE)
    });
    common.into_iter().chain(own).collect()
}

#[test]
fn every_claim_a_listing_makes_holds_on_every_run_of_the_lift() {
    let mut failures = Vec::new();
    for (name, literal, entry) in oracle_set() {
        let judged = judged(literal, entry, &[]);
        failures.extend(judged.iter().map(|failure| format!("{name}: {failure}")));
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// What a claim beside the engine's comes to, where the oracle is right to judge it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Contradicted,
    Unexamined,
    Held,
}

#[test]
fn a_claim_no_run_supports_fails_and_one_every_run_supports_holds() {
    let rax = Injected::Bounds("rax", 0x2a, 0x2a);
    let cases = [
        // `add rax, 8` builds on the address, so it is a step and not what the line computes.
        (
            Literal::new(),
            STEPPED,
            STEPPED,
            Injected::Kind(AnnotationKind::Computes { value: ONE }),
            Expected::Contradicted,
        ),
        // The count is memory the program writes, so the revision's 0x29 is one state of many.
        (counted(), BASE, BASE + 6, rax, Expected::Contradicted),
        // The revision holds 0x29 little-endian, not that word's bytes the other way round.
        (
            counted(),
            BASE,
            BASE,
            Injected::Kind(AnnotationKind::Holds {
                address: 0x1010,
                width: 4,
                value: 0x2900_0000,
            }),
            Expected::Contradicted,
        ),
        // Only the callee decides what rdi holds after the call, and no run executes it.
        (
            Literal::new(),
            PASSES,
            PASSES + 7,
            Injected::Bounds("rdi", ONE, ONE),
            Expected::Unexamined,
        ),
        // The carry is a bit, so `movzx eax, al` after `setc al` leaves nought or one.
        (
            Literal::of_code(FLAGGED, &[("flagged", BASE, FLAGGED.len() as u64)]),
            BASE,
            BASE + 3,
            Injected::Bounds("rax", 0, 1),
            Expected::Held,
        ),
        // The processor specification says the direction flag is clear on entry, so the fill walks up.
        (
            Literal::of_code(FILLED, &[("filled", BASE, 0x14)]),
            BASE,
            BASE + 0xe,
            Injected::Bounds("rdi", 0x1024, 0x1024),
            Expected::Held,
        ),
    ];
    for (literal, entry, at, injected, expected) in cases {
        let failures = judged(literal, entry, &[(at, injected.clone())]);
        let (ours, theirs): (Vec<_>, Vec<_>) = failures
            .iter()
            .partition(|failure| failure.listing == "injected");
        assert!(theirs.is_empty(), "the engine's own claims: {theirs:?}");
        let found = match ours.as_slice() {
            [] => Expected::Held,
            [one] if one.why.is_some() => Expected::Contradicted,
            [_] => Expected::Unexamined,
            more => panic!("one claim failed {} times: {more:?}", more.len()),
        };
        assert_eq!(found, expected, "{injected:?} at {at:#x}: {ours:?}");
    }
}

fn counted() -> Literal {
    Literal::of_code(COUNTED, &[("counted", BASE, 0x10)])
}

/// A claim the test adds beside the engine's, naming a register as the architecture does.
#[derive(Debug, Clone)]
enum Injected {
    Kind(AnnotationKind),
    Bounds(&'static str, u64, u64),
}

/// Run one function's lift from every entry state, and say which claims failed or went unexamined.
fn judged(literal: Literal, entry: u64, injected: &[(u64, Injected)]) -> Vec<Failure> {
    let mut program = OpenProgram::of(literal);
    let pdf = program.function_listing(entry).expect("it lists").value;
    let stop = Stop::After(pdf.len());
    let pd = program
        .listing(Listing { start: entry, stop })
        .expect("it lists");
    let machine = Decoders::at(&program, entry).expect("a decoder");
    let body = r2ssa::body::lift_body(entry, &machine.disasm, &program, &BTreeMap::new())
        .expect("it walks");
    let lift = Lift::of(&body, machine, program.endian(), program.source());
    let mut ledger = Ledger::default();
    ledger.claim("pdf", &pdf);
    ledger.claim("pd", &pd.value);
    for (at, injected) in injected {
        let kind = match injected {
            Injected::Kind(kind) => kind.clone(),
            &Injected::Bounds(name, low, high) => {
                let register = lift.register(name).expect("the architecture names it");
                AnnotationKind::Bounds {
                    storage: CanonicalStorageId::from_varnode(&register),
                    low,
                    high,
                    stride: 0,
                }
            }
        };
        ledger.add(*at, "injected", kind);
    }
    ledger.rule_revision(&lift);
    let entries = lift.entry_states();
    let traces = entries
        .iter()
        .map(|state| run(&lift, entry, state, &Memory::default(), &mut ledger))
        .collect::<Vec<_>>();
    // A byte any run stores to is one the program writes, so what it holds on entry is an input too.
    let stored = traces
        .iter()
        .flatten()
        .filter(|access| access.kind == AccessKind::Write)
        .flat_map(bytes)
        .collect::<BTreeSet<_>>();
    for (state, trace) in entries.iter().zip(&traces) {
        let memory = lift.memory(trace, &stored, state);
        if !memory.words.is_empty() {
            run(&lift, entry, state, &memory, &mut ledger);
        }
    }
    ledger.failures()
}

/// Why a claim did not pass.
#[derive(Debug)]
struct Failure {
    listing: &'static str,
    kind: AnnotationKind,
    at: u64,
    /// What the first run that contradicted it saw, or `None` where no run ruled on it.
    why: Option<String>,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (listing, kind, at) = (self.listing, &self.kind, self.at);
        match &self.why {
            Some(why) => write!(f, "{listing} claims {kind:?} at {at:#x}, but {why}"),
            None => write!(f, "no run rules on {listing}'s {kind:?} at {at:#x}"),
        }
    }
}

/// One claim a listing makes about a line, how many runs ruled on it, and the first that contradicted it.
struct Claim {
    listing: &'static str,
    kind: AnnotationKind,
    ruled: usize,
    contradicted: Option<String>,
}

impl Claim {
    fn decided(&mut self, held: Result<(), String>, described: &str) {
        self.ruled += 1;
        if let Err(observed) = held
            && self.contradicted.is_none()
        {
            self.contradicted = Some(format!("{observed} where {described} runs"));
        }
    }
}

/// Where a claim is in the ledger.
#[derive(Debug, Clone, Copy)]
struct ClaimAt {
    at: u64,
    index: usize,
}

/// Every claim about the function, by the line it is on.
#[derive(Default)]
struct Ledger {
    claims: BTreeMap<u64, Vec<Claim>>,
}

impl Ledger {
    fn claim(&mut self, listing: &'static str, lines: &[Line]) {
        for line in lines {
            for annotation in &line.annotations {
                self.add(line.address, listing, annotation.kind.clone());
            }
        }
    }

    fn add(&mut self, at: u64, listing: &'static str, kind: AnnotationKind) {
        self.claims.entry(at).or_default().push(Claim {
            listing,
            kind,
            ruled: 0,
            contradicted: None,
        });
    }

    fn decide(&mut self, claim: ClaimAt, held: Result<(), String>, described: &str) {
        let claims = self.claims.get_mut(&claim.at).expect("a claimed line");
        claims[claim.index].decided(held, described);
    }

    /// Rule on what each claim says the revision holds, read by the evaluator's own load.
    fn rule_revision(&mut self, lift: &Lift<'_>) {
        let image = |address: u64| lift.source.read(address, 1)?.first().copied();
        for claim in self.claims.values_mut().flatten() {
            // A load spends none of a run's budget.
            let mut revision = State::new(lift.endian, image, 0).expect("a byte order");
            let verdict = match &claim.kind {
                &AnnotationKind::Holds {
                    address,
                    width,
                    value,
                } => {
                    let held = revision.load(address, width);
                    match held == Ok(u128::from(value)) {
                        true => Ok(()),
                        false => Err(format!("the revision holds {held:x?}")),
                    }
                }
                // Text is its bytes and the terminator that ends it.
                AnnotationKind::Text { address, text } => {
                    let spelled = text.bytes().chain([0]).map(u128::from);
                    let held = (0..)
                        .zip(spelled)
                        .map(|(at, byte)| (revision.load(address + at, 1), byte))
                        .find(|(held, byte)| held.as_ref() != Ok(byte));
                    match held {
                        None => Ok(()),
                        Some((held, _)) => Err(format!("the revision holds {held:x?}")),
                    }
                }
                _ => continue,
            };
            claim.decided(verdict, "the revision");
        }
    }

    /// Rule on every claim about the instruction that just ran, and follow each number a line claims to compute.
    fn rule<M: Mapped>(
        &mut self,
        lift: &Lift<'_>,
        after: &After<'_, M>,
        described: &str,
    ) -> Vec<Following> {
        let Some(claims) = self.claims.get_mut(&after.at) else {
            return Vec::new();
        };
        let targets = claims
            .iter()
            .filter_map(|claim| match claim.kind {
                AnnotationKind::Target { address, call } => Some((claim.listing, address, call)),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut following = Vec::new();
        for (index, claim) in claims.iter_mut().enumerate() {
            match verdict(claim, &targets, after, lift) {
                None => {}
                Some(Verdict::Held(held)) => claim.decided(held, described),
                Some(Verdict::Follow(holders)) => following.push(Following {
                    claim: ClaimAt {
                        at: after.at,
                        index,
                    },
                    holders,
                    derived: Vec::new(),
                }),
            }
        }
        following
    }

    fn failures(self) -> Vec<Failure> {
        let failed = self.claims.into_iter().flat_map(|(at, claims)| {
            claims.into_iter().filter_map(move |claim| {
                (claim.ruled == 0 || claim.contradicted.is_some()).then_some(Failure {
                    listing: claim.listing,
                    kind: claim.kind,
                    at,
                    why: claim.contradicted,
                })
            })
        });
        failed.collect()
    }
}

/// One instruction of the walked body.
struct Instruction {
    ops: Vec<R2ILOp>,
    /// Where control falls through to.
    next: u64,
    /// The widest registers it writes, which is where it leaves a number it computes.
    widest: Vec<Varnode>,
}

/// How an entry state gives each input a value: all one edge, or seeded draws.
#[derive(Clone)]
enum Draw {
    Edge(u128),
    Random(SplitMix),
}

impl Draw {
    fn next(&mut self, bytes: u32, edges: &[u128]) -> u128 {
        let value = match self {
            Self::Edge(edge) => *edge,
            Self::Random(draws) => match draws.draw() % 2 {
                0 => edges[(draws.draw() % edges.len() as u64) as usize],
                _ => u128::from(draws.draw()) << 64 | u128::from(draws.draw()),
            },
        };
        value & mask(bytes)
    }
}

/// The registers one run starts from, and the draw its memory inputs continue.
struct Entry {
    registers: Vec<(Varnode, u128)>,
    draw: Draw,
}

/// What memory one run starts from beyond the program's bytes: each writable word it reads before writing.
#[derive(Default)]
struct Memory {
    bytes: BTreeMap<u64, u8>,
    words: Vec<(u64, u32, u128)>,
}

/// The walked body instruction by instruction, and what an entry state has to give a value.
struct Lift<'a> {
    instructions: BTreeMap<u64, Instruction>,
    /// The register ranges the body reads, apart from the ones a run pins.
    inputs: Vec<Varnode>,
    /// The registers the lift reads as a p-code boolean.
    booleans: Vec<Varnode>,
    /// Nought, one, all ones, and each constant the body names with one either side.
    edges: Vec<u128>,
    /// What a run sets before it starts: the stack pointer, and what the processor specification tracks.
    pinned: Vec<(Varnode, u128)>,
    program_counter: Option<Varnode>,
    /// The first byte of the stack, above everything the program maps; every byte from it on is mapped.
    stack: u64,
    /// The registers the default convention says a callee may destroy.
    clobbered: Vec<Varnode>,
    endian: Endianness,
    names: BTreeMap<(u64, u32), String>,
    registers: BTreeMap<String, Varnode>,
    source: &'a Literal,
}

impl<'a> Lift<'a> {
    fn of(
        body: &r2ssa::body::Body,
        machine: &r2sleigh_lift::EmbeddedMachine,
        endian: Endianness,
        source: &'a Literal,
    ) -> Self {
        let registers = machine
            .arch
            .registers
            .iter()
            .map(|register| {
                let at = Varnode::register(register.offset, register.size);
                (register.name.to_lowercase(), at)
            })
            .collect::<BTreeMap<_, _>>();
        let named = |name: &str| registers.get(&name.to_lowercase()).cloned();
        let compiler = r2abi::CompilerSpec::parse(machine.compiler_spec);
        let stack_pointer = compiler.stack_pointer.as_deref().and_then(named);
        let stack_pointer = stack_pointer.expect("the compiler specification names it");
        let program_counter = named(machine.disasm.program_counter());
        let container = source.container();
        let sections = &container.sections;
        let end = sections.iter().map(|section| section.vaddr + section.vsize);
        let aligned = u64::from(stack_pointer.size);
        let stack = end.max().unwrap_or(0).next_multiple_of(aligned);
        // Half-way up the pointer's range, so the stack grows either way without reaching the program.
        let top = 1u64 << (8 * stack_pointer.size.min(8) - 1);
        assert!(
            stack < top,
            "the stack must lie above everything the program maps"
        );
        let tracked = machine.arch.tracked_entry_values.iter();
        let tracked = tracked.map(|tracked| {
            let register = named(&tracked.register).expect("the architecture names it");
            (register, u128::from(tracked.value))
        });
        let pinned = [(stack_pointer, u128::from(top))]
            .into_iter()
            .chain(tracked)
            .collect::<Vec<_>>();
        let conventions = r2abi::Conventions::for_arch(&machine.arch.name, container.arch.bits);
        let clobbered = conventions
            .as_ref()
            .and_then(r2abi::Conventions::default_convention)
            .map_or_else(Vec::new, |convention| {
                convention
                    .clobbered
                    .iter()
                    .filter_map(|name| named(name))
                    .collect()
            });
        let ops = || body.blocks.iter().flat_map(|block| &block.lifted.ops);
        let around = |constant: u64| {
            let constant = u128::from(constant);
            [constant.wrapping_sub(1), constant, constant.wrapping_add(1)]
        };
        let constants = ops()
            .flat_map(R2ILOp::inputs)
            .filter(|input| input.space == SpaceId::Const)
            .flat_map(|input| around(input.offset));
        let edges = [0, 1, u128::MAX].into_iter().chain(constants);
        let edges = edges.collect::<BTreeSet<_>>().into_iter().collect();
        let held = pinned.iter().map(|(register, _)| register);
        let held = held.chain(&program_counter).collect::<Vec<_>>();
        let inputs = read_ranges(ops().flat_map(R2ILOp::inputs))
            .into_iter()
            .filter(|input| !held.iter().any(|pinned| overlaps(input, pinned)))
            .collect();
        let booleans = ops().flat_map(read_as_boolean).cloned().collect();
        let names = registers
            .iter()
            .map(|(name, at)| ((at.offset, at.size), name.clone()));
        Self {
            instructions: instructions(body),
            inputs,
            booleans,
            edges,
            pinned,
            program_counter,
            stack,
            clobbered,
            endian,
            names: names.collect(),
            registers,
            source,
        }
    }

    fn register(&self, name: &str) -> Option<Varnode> {
        self.registers.get(name).cloned()
    }

    /// Every register the body reads at one edge value in turn, then at seeded draws.
    fn entry_states(&self) -> Vec<Entry> {
        let edges = self.edges.iter().map(|edge| Draw::Edge(*edge));
        let randoms =
            (0..RANDOM_RUNS).map(|index| Draw::Random(SplitMix(SEED.wrapping_add(index))));
        edges.chain(randoms).map(|draw| self.entry(draw)).collect()
    }

    /// The value one draw gives each register the body reads.
    fn entry(&self, mut draw: Draw) -> Entry {
        let mut registers = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let value = draw.next(input.size, &self.edges);
            // p-code defines a boolean as nought or one, so no machine holds another there.
            let boolean = self.booleans.contains(input);
            registers.push((input.clone(), if boolean { value & 1 } else { value }));
        }
        Entry { registers, draw }
    }

    /// The memory a second run from `entry` starts from: each writable word the first read before writing it.
    fn memory(&self, trace: &[Access], stored: &BTreeSet<u64>, entry: &Entry) -> Memory {
        let writable = |byte: u64| byte >= self.stack || stored.contains(&byte);
        let (mut written, mut memory, mut draw) =
            (BTreeSet::new(), Memory::default(), entry.draw.clone());
        for access in trace {
            let unwritten = bytes(access)
                .filter(|byte| writable(*byte) && !written.contains(byte))
                .filter(|byte| !memory.bytes.contains_key(byte))
                .collect::<BTreeSet<_>>();
            match access.kind {
                AccessKind::Write => written.extend(bytes(access)),
                AccessKind::Read if !unwritten.is_empty() => {
                    let value = draw.next(access.width, &self.edges);
                    memory.words.push((access.address, access.width, value));
                    let laid = bytes(access).zip(self.laid_out(value, access.width));
                    let laid = laid.filter(|(byte, _)| unwritten.contains(byte));
                    memory.bytes.extend(laid);
                }
                AccessKind::Read => {}
            }
        }
        memory
    }

    /// The bytes a value of `size` bytes is in the program's order, lowest address first.
    fn laid_out(&self, value: u128, size: u32) -> Vec<u8> {
        let little = (0..size).map(|at| (value >> (8 * at)) as u8);
        match self.endian {
            Endianness::Big => little.rev().collect(),
            _ => little.collect(),
        }
    }

    /// How a register is spelled.
    fn spelled(&self, register: &Varnode) -> String {
        let key = (register.offset, register.size);
        let fallback = || format!("reg:{:#x}[{}]", register.offset, register.size);
        self.names.get(&key).cloned().unwrap_or_else(fallback)
    }

    /// An entry state as a failure reports it.
    fn described(&self, entry: &Entry, memory: &Memory) -> String {
        let registers = entry
            .registers
            .iter()
            .map(|(register, value)| format!("{}={value:#x}", self.spelled(register)));
        let words = memory
            .words
            .iter()
            .map(|(address, width, value)| format!("[{address:#x}:{width}]={value:#x}"));
        registers.chain(words).collect::<Vec<_>>().join(" ")
    }
}

/// The bytes one access covers.
fn bytes(access: &Access) -> impl Iterator<Item = u64> + '_ {
    (0..u64::from(access.width)).map(|at| access.address.wrapping_add(at))
}

/// The registers an operation reads as a p-code boolean.
fn read_as_boolean(op: &R2ILOp) -> Vec<&Varnode> {
    let read = match op {
        R2ILOp::CBranch { cond, .. } => vec![cond],
        R2ILOp::BoolNot { src, .. } => vec![src],
        R2ILOp::BoolAnd { a, b, .. }
        | R2ILOp::BoolOr { a, b, .. }
        | R2ILOp::BoolXor { a, b, .. } => {
            vec![a, b]
        }
        _ => Vec::new(),
    };
    read.into_iter()
        .filter(|read| read.space == SpaceId::Register)
        .collect()
}

/// The instructions of a body, from the address each operation's metadata records.
fn instructions(body: &r2ssa::body::Body) -> BTreeMap<u64, Instruction> {
    let mut found = BTreeMap::new();
    for block in &body.blocks {
        let lifted = &block.lifted;
        let at = |index: usize| lifted.op_metadata(index)?.instruction_addr;
        let mut parts: Vec<(u64, Vec<R2ILOp>)> = vec![(lifted.addr, Vec::new())];
        for (index, op) in lifted.ops.iter().enumerate() {
            let at = at(index).unwrap_or(lifted.addr);
            match parts.last_mut() {
                Some((last, ops)) if *last == at => ops.push(op.clone()),
                _ => parts.push((at, vec![op.clone()])),
            }
        }
        let end = lifted.addr + u64::from(lifted.size);
        let nexts = parts.iter().skip(1).map(|(at, _)| *at).chain([end]);
        let nexts = nexts.collect::<Vec<_>>();
        for ((at, ops), next) in parts.into_iter().zip(nexts) {
            let widest = widest_written(&ops);
            found.insert(at, Instruction { ops, next, widest });
        }
    }
    found
}

/// The widest registers these operations write.
fn widest_written(ops: &[R2ILOp]) -> Vec<Varnode> {
    let written = ops.iter().filter_map(R2ILOp::output);
    let registers = written.filter(|output| output.space == SpaceId::Register);
    let registers = registers.cloned().collect::<Vec<_>>();
    let widest = registers.iter().map(|register| register.size).max();
    registers
        .into_iter()
        .filter(|register| Some(register.size) == widest)
        .collect()
}

/// The register ranges these storages cover, overlapping ones merged.
fn read_ranges<'v>(read: impl Iterator<Item = &'v Varnode>) -> Vec<Varnode> {
    let registers = read.filter(|input| input.space == SpaceId::Register);
    let mut ranges = registers
        .map(|input| (input.offset, input.offset + u64::from(input.size)))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let size = |start: u64, end: u64| u32::try_from(end - start).ok();
    merged
        .into_iter()
        .filter_map(|(start, end)| Some(Varnode::register(start, size(start, end)?)))
        .collect()
}

fn overlaps(left: &Varnode, right: &Varnode) -> bool {
    left.space == right.space
        && left.offset < right.offset + u64::from(right.size)
        && right.offset < left.offset + u64::from(left.size)
}

/// Whether a write to `outer` replaces every byte of `inner`.
fn covers(outer: &Varnode, inner: &Varnode) -> bool {
    outer.space == inner.space
        && outer.offset <= inner.offset
        && inner.offset + u64::from(inner.size) <= outer.offset + u64::from(outer.size)
}

/// Every value a width holds, as far as the 128 bits a draw has reach.
fn mask(bytes: u32) -> u128 {
    let spare = 128u32.saturating_sub(bytes.saturating_mul(8));
    u128::MAX.checked_shr(spare).unwrap_or(0)
}

/// SplitMix64: a stream of well-mixed numbers from one seed.
#[derive(Clone)]
struct SplitMix(u64);

impl SplitMix {
    fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mixed = (self.0 ^ (self.0 >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        let mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }
}

/// Run the lift from one entry state, ruling on each claim about each instruction it executes whole.
///
/// Returns every memory access the run made, oldest first.
fn run(
    lift: &Lift<'_>,
    entry: u64,
    start: &Entry,
    memory: &Memory,
    ledger: &mut Ledger,
) -> Vec<Access> {
    let described = lift.described(start, memory);
    let mapped = |address: u64| {
        let seeded = memory.bytes.get(&address).copied();
        let stack = || (address >= lift.stack).then_some(0);
        let image = || lift.source.read(address, 1)?.first().copied();
        seeded.or_else(stack).or_else(image)
    };
    let mut state = State::new(lift.endian, mapped, BUDGET).expect("a byte order");
    let registers = start.registers.iter().chain(&lift.pinned);
    for (register, value) in registers {
        state
            .set_register(register.offset, register.size, *value)
            .expect("a register");
    }
    let (mut trace, mut following) = (Vec::new(), Vec::<Following>::new());
    let mut at = entry;
    while let Some(instruction) = lift.instructions.get(&at) {
        if let Some(counter) = &lift.program_counter {
            let here = u128::from(at);
            state
                .set_register(counter.offset, counter.size, here)
                .expect("a program counter");
        }
        let ran = executed(&instruction.ops, &mut state);
        trace.extend(ran.accesses.iter().copied());
        let ops = &instruction.ops[..ran.executed];
        following.retain_mut(|number| match number.through(ops, &ran.chosen, lift) {
            Some(held) => {
                ledger.decide(number.claim, held, &described);
                false
            }
            None => true,
        });
        if let Flow::Stop(_) = ran.flow {
            break;
        }
        let after = After {
            at,
            instruction,
            ran: &ran,
            state: &state,
        };
        following.extend(ledger.rule(lift, &after, &described));
        match ran.flow {
            Flow::Transfer(transfer) if transfer.kind == TransferKind::Jump => at = transfer.to,
            Flow::Next => at = instruction.next,
            // A call or a return: nothing after it is this run's to rule on.
            _ => break,
        }
    }
    trace
}

/// What one instruction did on one run.
struct Ran {
    flow: Flow,
    /// How many of its operations ran; all of them is what "executed unguarded" means.
    executed: usize,
    /// The direct transfer it left by, and whether that was a call.
    direct: Option<(u64, bool)>,
    accesses: Vec<Access>,
    /// Which arm each selection it executed took, by the operation's index.
    chosen: BTreeMap<usize, bool>,
}

/// Execute one instruction's operations, as far as the run goes.
fn executed<M: Mapped>(ops: &[R2ILOp], state: &mut State<M>) -> Ran {
    let mut chosen = BTreeMap::new();
    for (index, op) in ops.iter().enumerate() {
        if let R2ILOp::Select { cond, .. } = op
            && let Ok(cond) = state.value(cond)
        {
            chosen.insert(index, cond != 0);
        }
        let (flow, executed, direct) = match step(op, state) {
            Flow::Next => continue,
            Flow::Stop(stop) => (Flow::Stop(stop), index, None),
            Flow::Transfer(transfer) => {
                let direct = matches!(
                    op,
                    R2ILOp::Branch { .. } | R2ILOp::CBranch { .. } | R2ILOp::Call { .. }
                );
                let called = transfer.kind == TransferKind::Call;
                let direct = direct.then_some((transfer.to, called));
                (Flow::Transfer(transfer), index + 1, direct)
            }
        };
        let accesses = state.take_accesses();
        return Ran {
            flow,
            executed,
            direct,
            accesses,
            chosen,
        };
    }
    Ran {
        flow: Flow::Next,
        executed: ops.len(),
        direct: None,
        accesses: state.take_accesses(),
        chosen,
    }
}

/// The machine just after one instruction ran.
struct After<'r, M> {
    at: u64,
    instruction: &'r Instruction,
    ran: &'r Ran,
    state: &'r State<M>,
}

impl<M> After<'_, M> {
    /// Whether every operation of the instruction ran.
    fn whole(&self) -> bool {
        self.ran.executed == self.instruction.ops.len()
    }

    /// Whether the instruction's own operations wrote every byte of `storage`.
    fn wrote(&self, storage: &Varnode) -> bool {
        let ops = &self.instruction.ops[..self.ran.executed];
        let outputs = ops.iter().filter_map(R2ILOp::output).collect::<Vec<_>>();
        (0..u64::from(storage.size)).all(|at| {
            let byte = Varnode::register(storage.offset + at, 1);
            outputs.iter().any(|output| covers(output, &byte))
        })
    }
}

/// What one run of an instruction says about one claim.
enum Verdict {
    Held(Result<(), String>),
    /// The number is where the line says; whether anything builds on it is for the rest of the run.
    Follow(Vec<Varnode>),
}

/// What one run of its instruction says about a claim, or `None` where it says nothing.
fn verdict<M: Mapped>(
    claim: &Claim,
    targets: &BTreeSet<(&'static str, u64, bool)>,
    after: &After<'_, M>,
    lift: &Lift<'_>,
) -> Option<Verdict> {
    let ran = after.ran;
    let held = match claim.kind {
        AnnotationKind::Target { address, call } => {
            let (to, _) = ran.direct.filter(|(_, called)| *called == call)?;
            match (to == address, targets.contains(&(claim.listing, to, call))) {
                (true, _) => Ok(()),
                // Another target the line claims: this one was not the one taken.
                (false, true) => return None,
                (false, false) => Err(format!("it transferred to {to:#x}")),
            }
        }
        AnnotationKind::Reads { address, width } => after
            .whole()
            .then(|| accessed(ran, AccessKind::Read, address, width))?,
        AnnotationKind::Writes { address, width } => after
            .whole()
            .then(|| accessed(ran, AccessKind::Write, address, width))?,
        AnnotationKind::Computes { value } => {
            let widest = after.instruction.widest.iter();
            let holding = widest.filter(|register| {
                after.state.register(register.offset, register.size) == Some(u128::from(value))
            });
            let holding = holding.cloned().collect::<Vec<_>>();
            return after.whole().then_some(match holding.is_empty() {
                false => Verdict::Follow(holding),
                true => Verdict::Held(Err(format!("it left {:x?}", left(after)))),
            });
        }
        AnnotationKind::Bounds {
            storage,
            low,
            high,
            stride,
        } => {
            let register = (storage.space == CanonicalStorageSpace::Register)
                .then(|| Varnode::register(storage.offset, storage.size))?;
            // A value only a callee's effect defines is not one this run can see.
            if !after.whole() || !after.wrote(&register) {
                return None;
            }
            let held = after.state.register(register.offset, register.size)?;
            let within = u64::try_from(held).is_ok_and(|held| {
                (low..=high).contains(&held) && (stride == 0 || (held - low) % stride == 0)
            });
            let spelled = lift.spelled(&register);
            within
                .then_some(())
                .ok_or(format!("{spelled} holds {held:#x}"))
        }
        // What the revision holds is ruled once, against the revision: see `rule_revision`.
        AnnotationKind::Holds { .. } | AnnotationKind::Text { .. } => return None,
    };
    Some(Verdict::Held(held))
}

/// What the instruction's widest registers hold.
fn left<M: Mapped>(after: &After<'_, M>) -> Vec<Option<u128>> {
    let widest = after.instruction.widest.iter();
    let held = widest.map(|register| after.state.register(register.offset, register.size));
    held.collect()
}

fn accessed(ran: &Ran, kind: AccessKind, address: u64, width: u32) -> Result<(), String> {
    let claimed = r2il::eval::Access {
        kind,
        address,
        width,
    };
    match ran.accesses.contains(&claimed) {
        true => Ok(()),
        false => Err(format!("it accessed {:?}", ran.accesses)),
    }
}

/// A number a line claims to compute, followed through the run until nothing holds it or something builds on it.
///
/// Copying, storing, comparing, loading through or passing the number is using it as it stands; an arithmetic
/// operation over it derives another, which a temporary may carry into a test but no other storage may hold.
struct Following {
    claim: ClaimAt,
    /// Where the number stands.
    holders: Vec<Varnode>,
    /// Temporaries holding a number derived from it.
    derived: Vec<Varnode>,
}

impl Following {
    /// What the operations of one instruction, as far as the run executed them, settle about the claim.
    fn through(
        &mut self,
        ops: &[R2ILOp],
        chosen: &BTreeMap<usize, bool>,
        lift: &Lift<'_>,
    ) -> Option<Result<(), String>> {
        let mut ops = ops.iter().enumerate();
        if let Some(settled) = ops.find_map(|(at, op)| self.meets(op, chosen.get(&at), lift)) {
            return Some(settled);
        }
        // A temporary lives only as long as its instruction.
        self.holders.retain(|held| held.space != SpaceId::Unique);
        self.derived.clear();
        self.holders.is_empty().then_some(Ok(()))
    }

    fn meets(
        &mut self,
        op: &R2ILOp,
        chosen: Option<&bool>,
        lift: &Lift<'_>,
    ) -> Option<Result<(), String>> {
        // A selection carries only the arm the run took; its condition is a test.
        let inputs = match (op, chosen) {
            (R2ILOp::Select { if_true, .. }, Some(true)) => vec![if_true],
            (R2ILOp::Select { if_false, .. }, Some(false)) => vec![if_false],
            _ => op.inputs(),
        };
        let reads = |set: &[Varnode]| {
            let mut read = inputs.iter();
            read.any(|input| set.iter().any(|held| overlaps(held, input)))
        };
        let (held, built) = (reads(&self.holders), reads(&self.derived));
        let derived = || Some(Err(format!("`{op}` builds on it")));
        let carried = match op {
            R2ILOp::Copy { .. }
            | R2ILOp::IntZExt { .. }
            | R2ILOp::IntSExt { .. }
            | R2ILOp::Subpiece { .. }
            | R2ILOp::Select { .. } => (held || built).then_some(built),
            R2ILOp::IntAdd { .. }
            | R2ILOp::IntSub { .. }
            | R2ILOp::IntMult { .. }
            | R2ILOp::IntDiv { .. }
            | R2ILOp::IntSDiv { .. }
            | R2ILOp::IntRem { .. }
            | R2ILOp::IntSRem { .. }
            | R2ILOp::IntNegate { .. }
            | R2ILOp::IntAnd { .. }
            | R2ILOp::IntOr { .. }
            | R2ILOp::IntXor { .. }
            | R2ILOp::IntNot { .. }
            | R2ILOp::IntLeft { .. }
            | R2ILOp::IntRight { .. }
            | R2ILOp::IntSRight { .. }
            | R2ILOp::Piece { .. }
            | R2ILOp::PtrAdd { .. }
            | R2ILOp::PtrSub { .. } => (held || built).then_some(true),
            // A test's result is a flag, which is not a number.
            R2ILOp::IntEqual { .. }
            | R2ILOp::IntNotEqual { .. }
            | R2ILOp::IntLess { .. }
            | R2ILOp::IntSLess { .. }
            | R2ILOp::IntLessEqual { .. }
            | R2ILOp::IntSLessEqual { .. }
            | R2ILOp::IntCarry { .. }
            | R2ILOp::IntSCarry { .. }
            | R2ILOp::IntSBorrow { .. }
            | R2ILOp::BoolNot { .. }
            | R2ILOp::BoolAnd { .. }
            | R2ILOp::BoolOr { .. }
            | R2ILOp::BoolXor { .. }
            | R2ILOp::PopCount { .. }
            | R2ILOp::Lzcount { .. }
            | R2ILOp::Branch { .. }
            | R2ILOp::CBranch { .. }
            | R2ILOp::Nop => None,
            // An address, a stored value, a target: the number as it stands, and no derived one.
            R2ILOp::Load { .. }
            | R2ILOp::Store { .. }
            | R2ILOp::BlockTransfer(_)
            | R2ILOp::Call { .. }
            | R2ILOp::CallInd { .. }
            | R2ILOp::BranchInd { .. }
            | R2ILOp::Return { .. } => match built {
                true => return derived(),
                false => None,
            },
            _ if held || built => {
                return Some(Err(format!("`{op}` reads it, and no rule here says how")));
            }
            _ => None,
        };
        match op {
            // A register the convention clobbers holds nothing of the caller's once the callee runs.
            R2ILOp::Call { .. } | R2ILOp::CallInd { .. } => {
                let clobbered =
                    |held: &Varnode| lift.clobbered.iter().any(|register| covers(register, held));
                self.holders.retain(|held| !clobbered(held));
                return self.holders.is_empty().then_some(Ok(()));
            }
            // The claim is the function's: what leaves it is not built on inside it.
            R2ILOp::Return { .. } => return Some(Ok(())),
            _ => {}
        }
        let written = op.output()?;
        self.holders.retain(|held| !covers(written, held));
        self.derived.retain(|held| !covers(written, held));
        match carried {
            Some(true) if written.space != SpaceId::Unique => return derived(),
            Some(true) => self.derived.push(written.clone()),
            Some(false) => self.holders.push(written.clone()),
            None => {}
        }
        None
    }
}
