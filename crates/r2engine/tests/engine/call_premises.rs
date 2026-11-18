//! A call's argument mapping states the premises it rests on, and a function's own closed result
//! rests on the result fact alone (D592).

use crate::common;

use common::{BASE, CALLER, Literal, ONE};
use r2engine::program::OpenProgram;
use r2engine::query::{Annotation, AnnotationKind, Line};
use r2source::Premise;

/// The notes of the line at `address` in the listing of the function at `entry`.
fn notes(program: &mut OpenProgram<Literal>, entry: u64, address: u64) -> Vec<Annotation> {
    let listing = program.function_listing(entry).expect("it lists");
    let lines: Vec<Line> = listing.lines.value;
    let line = lines.iter().find(|line| line.address == address);
    line.expect("the line").annotations.clone()
}

fn call_note(notes: &[Annotation]) -> &Annotation {
    let call = notes
        .iter()
        .find(|note| matches!(note.kind, AnnotationKind::Call { .. }));
    call.unwrap_or_else(|| panic!("a call note in {notes:?}"))
}

/// `caller: call one; ret` over `one: mov eax, 1; ret`, a leaf whose alone read states no
/// parameter exactly: the mapping rests on nothing.
#[test]
fn a_call_to_a_leaf_exact_alone_rests_on_no_premise() {
    let mut program = OpenProgram::of(Literal::new());
    let notes = notes(&mut program, CALLER, CALLER);
    let note = call_note(&notes);
    assert!(note.confidence.premises.is_empty(), "{note:?}");
    let AnnotationKind::Call { callee, .. } = note.kind else {
        unreachable!();
    };
    assert_eq!(callee, Some(ONE));
}

/// `f: call g; ret` over `g: mov eax, [rsp + 8]; ret`: `g` reads past its registers, so its arity
/// is a floor only the closed world settles, and the call keeps that premise.
#[test]
fn a_call_to_a_floor_rests_on_the_closed_world() {
    const CODE: &[u8] = &[
        0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3, // 1000 call 0x1010; ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1006 padding
        0x8b, 0x44, 0x24, 0x08, 0xc3, // 1010 mov eax, [rsp + 8]; ret
    ];
    let functions = [("f", BASE, 6), ("g", BASE + 0x10, 5)];
    let mut program = OpenProgram::of(Literal::of_code(CODE, &functions));
    let notes = notes(&mut program, BASE, BASE);
    let note = call_note(&notes);
    assert!(
        note.confidence.premises.contains(&Premise::ClosedWorld),
        "{note:?}"
    );
}

/// `f: mov rdi, 0x1100; mov esi, 4; call g; add eax, 1; ret` over gcc -O2's `fnv1a32` as `g`: the
/// caller reads `g`'s result, so the closed world decides it, and `g`'s loop rests on none of that.
#[test]
fn a_loop_rests_on_no_premise_of_its_function_s_closed_result() {
    const CODE: &[u8] = &[
        0x48, 0xc7, 0xc7, 0x00, 0x11, 0x00, 0x00, // 1000 mov rdi, 0x1100
        0xbe, 0x04, 0x00, 0x00, 0x00, // 1007 mov esi, 4
        0xe8, 0x0f, 0x00, 0x00, 0x00, // 100c call 0x1020
        0x83, 0xc0, 0x01, // 1011 add eax, 1
        0xc3, // 1014 ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1015 padding
        0x48, 0x85, 0xf6, // 1020 test rsi, rsi
        0x74, 0x24, // 1023 je 0x1049
        0x48, 0x01, 0xfe, // 1025 add rsi, rdi
        0xb8, 0xc5, 0x9d, 0x1c, 0x81, // 1028 mov eax, 0x811c9dc5
        0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, // 102d nop
        0x0f, 0xb6, 0x17, // 1034 movzx edx, byte [rdi]
        0x48, 0x83, 0xc7, 0x01, // 1037 add rdi, 1
        0x31, 0xd0, // 103b xor eax, edx
        0x69, 0xc0, 0x93, 0x01, 0x00, 0x01, // 103d imul eax, eax, 0x1000193
        0x48, 0x39, 0xfe, // 1043 cmp rsi, rdi
        0x75, 0xec, // 1046 jne 0x1034
        0xc3, // 1048 ret
        0xb8, 0xc5, 0x9d, 0x1c, 0x81, // 1049 mov eax, 0x811c9dc5
        0xc3, // 104e ret
    ];
    let functions = [("f", BASE, 0x15), ("g", BASE + 0x20, 0x2f)];
    let mut program = OpenProgram::of(Literal::of_code(CODE, &functions));
    let notes = notes(&mut program, BASE + 0x20, BASE + 0x34);
    let looped = notes
        .iter()
        .find(|note| matches!(note.kind, AnnotationKind::Loop { .. }));
    let looped = looped.unwrap_or_else(|| panic!("a loop note in {notes:?}"));
    assert!(
        !looped.confidence.premises.contains(&Premise::ClosedWorld),
        "{looped:?}"
    );
}

/// gcc -O2's `fnv1a32` from `tests/coverage/pinned/hashes_gcc_x64_O2`, at `BASE`.
const FNV1A32_O2: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x48, 0x85, 0xf6, // test rsi, rsi
    0x74, 0x27, // je 0x30
    0x48, 0x01, 0xfe, // add rsi, rdi
    0xb8, 0xc5, 0x9d, 0x1c, 0x81, // mov eax, 0x811c9dc5
    0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, // nop
    0x0f, 0xb6, 0x17, // 0x18 movzx edx, byte [rdi]
    0x48, 0x83, 0xc7, 0x01, // add rdi, 1
    0x31, 0xd0, // xor eax, edx
    0x69, 0xc0, 0x93, 0x01, 0x00, 0x01, // imul eax, eax, 0x1000193
    0x48, 0x39, 0xfe, // cmp rsi, rdi
    0x75, 0xec, // jne 0x18
    0xc3, // ret
    0x0f, 0x1f, 0x00, // nop
    0xb8, 0xc5, 0x9d, 0x1c, 0x81, // 0x30 mov eax, 0x811c9dc5
    0xc3, // ret
];

/// `fnv1a32` alone, its result decided by the closed world or by nothing.
struct Decided(Option<r2source::SourceClosedDecision>);

impl r2engine::body::Program for Decided {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = FNV1A32_O2.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
        let end = BASE + FNV1A32_O2.len() as u64;
        (BASE..end)
            .contains(&vaddr)
            .then_some(r2engine::body::Region {
                start: BASE,
                end,
                file_end: end,
                execute: true,
                write: false,
            })
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        vaddr == BASE
    }
}

impl r2engine::native::Program for Decided {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
        false
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
        NONE
    }

    fn name_at(&self, vaddr: u64) -> Option<r2abi::SymbolName> {
        (vaddr == BASE).then(|| r2abi::SymbolName::new("fnv1a32"))
    }

    fn import_at(&self, _vaddr: u64) -> Option<r2abi::SymbolName> {
        None
    }

    fn closed_result(&self, entry: u64) -> Option<r2source::SourceClosedDecision> {
        self.0.filter(|_| entry == BASE)
    }
}

/// Built with and without a closed result, `fnv1a32` states the same loop, induction and switch
/// certificates, and its closed premises rest on the result fact alone (D592's witness).
#[test]
fn a_closed_result_moves_no_loop_certificate() {
    use r2abi::{CLibrary, ConventionId, Kernel, LibraryRows};
    let embedded = r2engine::machine::Machine::new(
        r2sleigh_lift::embedded_machine("x86-64").expect("embedded machine"),
    );
    let compiler =
        r2sleigh_lift::profile::LanguageProfile::parse(embedded.compiler_spec).expect("parses");
    let row = ConventionId::SysVAmd64.row();
    let guards = (Kernel::Unknown, CLibrary::Unknown, Default::default());
    let convention = r2engine::native::convention_model(&embedded.arch, 64, guards, &compiler, row);
    let convention = std::sync::Arc::new(convention.expect("System V"));
    let imports = r2engine::imports::Imports::new(
        LibraryRows::embedded(CLibrary::Unknown),
        CLibrary::Unknown,
        r2engine::imports::Linkage::one_c_library(),
    );
    let declarations = r2abi::Declarations::default();
    let target = r2engine::native::NativeTarget {
        arch: embedded.tables(),
        disasm: &embedded.disasm,
        cpu: embedded.cpu,
        convention: std::sync::Arc::clone(&convention),
        call: convention,
        compiler: &compiler,
        program: None,
        dwarf: &embedded.dwarf,
        imports: &imports,
        declarations: &declarations,
        data_model: None,
        premises: r2engine::native::accepted_premises(),
    };
    let read = r2source::SourceReadLanes::Integer { widest: Some(4) };
    let decision = r2source::SourceClosedDecision {
        result: Some(r2source::SourceClosedResult::Read(read)),
        integer_unread: false,
        through_slot: false,
    };
    let built = |closed| {
        let program = Decided(closed);
        let prepared = r2engine::native::analysed(&target, &program, BASE).expect("prepares");
        prepared.artifact().shared_artifact()
    };
    let (open, closed) = (built(None), built(Some(decision)));
    let (open_facts, closed_facts) = (open.certificates(), closed.certificates());
    assert!(!closed_facts.loops.is_empty(), "the loop is certified");
    assert_eq!(open_facts.loops, closed_facts.loops);
    assert_eq!(open_facts.switches, closed_facts.switches);
    let function = closed.function();
    assert!(function.result_premises().contains(&Premise::ClosedWorld));
    assert!(!function.premises().contains(&Premise::ClosedWorld));
}
