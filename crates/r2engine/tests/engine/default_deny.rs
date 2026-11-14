//! The default-deny matrix (ROADMAP D405): each unknown input against each negative fact. A callee
//! nothing states may read, clobber, return and come back; no cell may state otherwise.

use crate::common;

use common::{BASE, Literal, PLT_CALLER};
use r2engine::program::OpenProgram;
use r2source::{Negative, NegativeFact};

/// Each type that states a negative fact, by the facts it states (D411): every column is some
/// type's, so a fact no type carries has no column.
const CARRIERS: &[&[NegativeFact]] = &[
    <r2ssa::call_reads::ReadBound as Negative>::FACTS,
    <r2ssa::call_reads::StackWrites as Negative>::FACTS,
    <r2ssa::site_boundary::CallEffect as Negative>::FACTS,
    <r2ssa::SummaryArgEffect as Negative>::FACTS,
    <r2source::Never as Negative>::FACTS,
    <r2source::SourceFunctionReturn as Negative>::FACTS,
    <r2il::eval::independence::Cancelled as Negative>::FACTS,
];

/// A cell another row owns and that fails today, held exactly: it fails until its row lands, then
/// this entry goes in the same change.
const OPEN: &[(&str, NegativeFact, &str)] = &[];

/// The unknown inputs: a call through a register nothing sets, a call to an import no row states,
/// and one to an import only an uncited row states ([`UNCITED`]; D395: a bound, never a proof).
#[derive(Clone, Copy, Debug)]
enum Unknown {
    IndirectCall,
    UnboundImport,
    UncitedRow,
}

/// An import whose library row no header cites (`r2abi/data/uncited-rows.txt`).
const UNCITED: &str = "xmalloc";

impl Unknown {
    const ALL: [Self; 3] = [Self::IndirectCall, Self::UnboundImport, Self::UncitedRow];

    const fn name(self) -> &'static str {
        match self {
            Self::IndirectCall => "indirect_call",
            Self::UnboundImport => "unbound_import",
            Self::UncitedRow => "uncited_row",
        }
    }

    /// The import the call goes to, where it goes to one.
    const fn import(self) -> &'static str {
        match self {
            Self::IndirectCall | Self::UnboundImport => "r2s_default_deny_unstated",
            Self::UncitedRow => UNCITED,
        }
    }

    /// `before`, the call, then `after`, as a program with its function at the returned entry.
    fn around(self, before: &[u8], after: &[u8]) -> (Literal, u64) {
        match self {
            Self::IndirectCall => {
                let code = [before, &[0x41, 0xff, 0xd3], after].concat(); // call r11
                let functions = [("f", BASE, code.len() as u64)];
                (Literal::of_code(Box::leak(code.into()), &functions), BASE)
            }
            Self::UnboundImport | Self::UncitedRow => {
                let plt = common::plt_then::<0x20>(&[]);
                let after_call = PLT_CALLER + (before.len() + 5) as u64;
                let rel = (common::PLT_STUB as i64 - after_call as i64) as i32;
                let call = [&[0xe8][..], &rel.to_le_bytes()].concat(); // call stub
                let code = [&plt[..], before, &call, after].concat();
                let literal = Literal::plt_wrapped(self.import(), Box::leak(code.into()));
                (literal, PLT_CALLER)
            }
        }
    }
}

fn rendered((literal, entry): (Literal, u64)) -> String {
    let rendered = OpenProgram::of(literal).rendered(entry);
    rendered.expect("it renders").response.output.into_text()
}

/// The `return` lines of a rendering.
fn returns(text: &str) -> Vec<&str> {
    (text.lines())
        .filter(|line| line.trim_start().starts_with("return"))
        .collect()
}

/// Each row's cell of `column`, `Err` with the evidence where the negative fact was stated.
fn cell(
    row: &str,
    fact: NegativeFact,
    check: impl FnOnce() -> Result<(), String>,
) -> Option<String> {
    let column = fact.column();
    let open = OPEN.iter().find(|(r, c, _)| *r == row && *c == fact);
    match (check(), open) {
        (Ok(()), None) => None,
        (Err(evidence), Some((_, _, owner))) => {
            println!("{row} x {column} open ({owner}):\n{evidence}");
            None
        }
        (Err(evidence), None) => Some(format!("{row} x {column}: {evidence}")),
        (Ok(()), Some((_, _, owner))) => Some(format!(
            "{row} x {column} holds now: delete its OPEN entry ({owner})"
        )),
    }
}

fn hold(failures: Vec<Option<String>>) {
    let failures = failures.into_iter().flatten().collect::<Vec<_>>();
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// `mov rdi, rsi; call`: no read at a call to an unknown callee is ignored (D283's flip).
#[test]
fn an_unknown_callee_performs_every_read_it_names() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), NegativeFact::IgnoredReads, || {
            let (literal, entry) = row.around(&[0x48, 0x89, 0xf7], &[0xc3]);
            let prepared = OpenProgram::of(literal)
                .prepared(entry)
                .expect("it prepares");
            let artifact = prepared.artifact().shared_artifact();
            let graph = artifact.graph();
            let call = (artifact.facts().boundaries.calls.values().next()).ok_or("no call")?;
            let reads = graph.call_boundary_reads(call.at);
            let ignored = (reads.iter())
                .filter(|read| {
                    let site = r2ssa::UseSite {
                        inst: **read,
                        input_idx: 0,
                    };
                    artifact.ignored_reads().contains(&site)
                })
                .map(|read| format!("{:?}", graph.op(*read)))
                .collect::<Vec<_>>();
            match (reads.is_empty(), ignored.is_empty()) {
                (true, _) => Err(format!("the call names no read\n{}", artifact.dump())),
                (false, true) => Ok(()),
                (false, false) => Err(format!("ignored: {ignored:?}")),
            }
        })
    });
    hold(failures.into());
}

/// `cmp rdi, rsi; sbb eax, eax; ret`: the instruction cancels EAX against itself, and still reads
/// the carry the compare left, so the result is the parameters' (D393): a cancel ignores one register.
#[test]
fn a_cancelling_instruction_ignores_only_the_register_it_cancels() {
    let failure = cell("cancelling_instruction", NegativeFact::IgnoredReads, || {
        const CODE: &[u8] = &[0x48, 0x39, 0xf7, 0x19, 0xc0, 0xc3];
        let text = rendered((Literal::of_code(CODE, &[("f", BASE, 6)]), BASE));
        match returns(&text).iter().any(|line| line.contains("arg")) {
            true => Ok(()),
            false => Err(text),
        }
    });
    hold(vec![failure]);
}

/// `mov esi, 7; call; mov eax, esi; ret`: an unknown callee keeps nothing, so 7 is not returned.
#[test]
fn an_unknown_callee_keeps_no_register() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), NegativeFact::Kept, || {
            let text = rendered(row.around(&[0xbe, 0x07, 0, 0, 0], &[0x89, 0xf0, 0xc3]));
            match returns(&text).iter().any(|line| line.contains('7')) {
                true => Err(text),
                false => Ok(()),
            }
        })
    });
    hold(failures.into());
}

/// `mov edx, 5; call; ret`: an unknown callee may read RDX, so the 5 reaches a read the call performs.
#[test]
fn an_unknown_callee_reads_each_argument_register() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), NegativeFact::CallReadBytes, || {
            let (literal, entry) = row.around(&[0xba, 0x05, 0, 0, 0], &[0xc3]);
            let prepared = OpenProgram::of(literal).prepared(entry).expect("it prepares");
            let artifact = prepared.artifact().shared_artifact();
            let graph = artifact.graph();
            let call = (artifact.facts().boundaries.calls.values().next()).ok_or("no call")?;
            let performed = (graph.call_boundary_reads(call.at).iter()).any(|read| {
                let site = r2ssa::UseSite {
                    inst: *read,
                    input_idx: 0,
                };
                let rdx = matches!(graph.op(*read), Some(r2ssa::SSAOp::CallUse { storage, .. })
                    if storage.space == r2ssa::CanonicalStorageSpace::Register && storage.offset == 0x10);
                rdx && !artifact.ignored_reads().contains(&site)
            });
            match performed {
                true => Ok(()),
                false => Err(artifact.dump()),
            }
        })
    });
    hold(failures.into());
}

/// `mov eax, 7; call; ret`: an unknown callee's result is unproven, never void and never the 7.
#[test]
fn an_unknown_callee_returns_an_unproven_result() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), NegativeFact::Void, || {
            let text = rendered(row.around(&[0xb8, 0x07, 0, 0, 0], &[0xc3]));
            let seven = returns(&text).iter().any(|line| line.contains('7'));
            match text.trim_start().starts_with("void ") || seven {
                true => Err(text),
                false => Ok(()),
            }
        })
    });
    hold(failures.into());
}

/// `call; mov eax, 1; ret`: an unknown callee comes back, so the 1 is returned and nothing is noreturn.
#[test]
fn an_unknown_callee_comes_back() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), NegativeFact::Never, || {
            let text = rendered(row.around(&[], &[0xb8, 0x01, 0, 0, 0, 0xc3]));
            let one = returns(&text).iter().any(|line| line.contains('1'));
            match one && !text.contains("noreturn") {
                true => Ok(()),
                false => Err(text),
            }
        })
    });
    let walk = cell("walk_without_return", NegativeFact::Never, || {
        // `f: call g; mov eax, 1; ret`, `g: ud2`: only the walk finds g never returning (RULING 1.4).
        const CODE: &[u8] = &[
            0xe8, 0x0b, 0x00, 0x00, 0x00, // 1000 call 0x1010
            0xb8, 0x01, 0x00, 0x00, 0x00, // 1005 mov eax, 1
            0xc3, // 100a ret
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding to 0x1010
            0x0f, 0x0b, // 1010 ud2
        ];
        let functions = [("f", BASE, 0x0b), ("g", BASE + 0x10, 2)];
        let text = rendered((Literal::of_code(CODE, &functions), BASE));
        match text.contains("noreturn") {
            true => Err(text),
            false => Ok(()),
        }
    });
    hold([failures.as_slice(), &[walk]].concat());
}

/// `push rbx; mov rbx, rdi; call; mov rax, rbx; pop rbx; ret`: the parameter handed to an unknown
/// callee is returned, and the callee's may-effects are no evidence that it is a pointer. The
/// function states `arg0`, so a cell cannot pass on a signature with no parameter.
#[test]
fn an_unknown_callee_types_no_argument_a_pointer() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), NegativeFact::Pointer, || {
            let before = [0x53, 0x48, 0x89, 0xfb]; // push rbx; mov rbx, rdi
            let text = rendered(row.around(&before, &[0x48, 0x89, 0xd8, 0x5b, 0xc3]));
            // The function's own parameters, not a callee's declaration (`void* xmalloc(...)`).
            let signature = text.lines().next().unwrap_or_default();
            let parameters = (signature.split_once('(')).map_or("", |(_, rest)| rest);
            match parameters.contains("arg0") && !parameters.contains('*') {
                true => Ok(()),
                false => Err(text),
            }
        })
    });
    hold(failures.into());
}

/// `main: sub rsp, 0x18; mov qword [rsp+8], 5; call f; mov rax, [rsp+8]; add rsp, 0x18; ret`,
/// `f: jmp clear`, `clear: mov qword [rsp+0x10], 0; ret`: the tail writes main's slot (D381).
const TAIL_WRITES: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
    0x48, 0xc7, 0x44, 0x24, 0x08, 0x05, 0x00, 0x00, 0x00, // 1004 mov qword [rsp+8], 5
    0xe8, 0x0e, 0x00, 0x00, 0x00, // 100d call 0x1020
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1012 mov rax, [rsp+8]
    0x48, 0x83, 0xc4, 0x18, // 1017 add rsp, 0x18
    0xc3, // 101b ret
    0xcc, 0xcc, 0xcc, 0xcc, // padding to 0x1020
    0xeb, 0x0e, // 1020 jmp 0x1030
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // padding to 0x1030
    0x48, 0xc7, 0x44, 0x24, 0x10, 0x00, 0x00, 0x00, 0x00, // 1030 mov qword [rsp+0x10], 0
    0xc3, // 1039 ret
];

/// A tail transfer's writes are the callee's: the slot read back is not the 5 stored before the call.
#[test]
fn a_tail_transfer_writes_what_its_target_writes() {
    let failure = cell("tail_transfer", NegativeFact::IncomingWrites, || {
        let functions = [
            ("main", BASE, 0x1c),
            ("f", BASE + 0x20, 2),
            ("clear", BASE + 0x30, 0xa),
        ];
        let text = rendered((Literal::of_code(TAIL_WRITES, &functions), BASE));
        match returns(&text).iter().any(|line| line.contains('5')) {
            true => Err(text),
            false => Ok(()),
        }
    });
    hold(vec![failure]);
}

/// `TAIL_WRITES` with `f: lea rdi, [rsp + 0x10]; jmp g`, where `g: mov qword [rdi], 0` states no
/// stack write: only the register handed to the tail reaches the caller's slot.
const TAIL_HANDED: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
    0x48, 0xc7, 0x44, 0x24, 0x08, 0x05, 0x00, 0x00, 0x00, // 1004 mov qword [rsp+8], 5
    0xe8, 0x0e, 0x00, 0x00, 0x00, // 100d call 0x1020
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1012 mov rax, [rsp+8]
    0x48, 0x83, 0xc4, 0x18, // 1017 add rsp, 0x18
    0xc3, // 101b ret
    0xcc, 0xcc, 0xcc, 0xcc, // padding to 0x1020
    0x48, 0x8d, 0x7c, 0x24, 0x10, // 1020 lea rdi, [rsp+0x10]
    0xeb, 0x09, // 1025 jmp 0x1030
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding to 0x1030
    0x48, 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, // 1030 mov qword [rdi], 0
    0xc3, // 1037 ret
];

/// A frame address a register holds at a tail transfer escapes to the tail's callee (D381).
#[test]
fn a_frame_address_handed_to_a_tail_is_written_through() {
    let failure = cell("tail_handed", NegativeFact::IncomingWrites, || {
        let functions = [
            ("main", BASE, 0x1c),
            ("f", BASE + 0x20, 7),
            ("g", BASE + 0x30, 8),
        ];
        let text = rendered((Literal::of_code(TAIL_HANDED, &functions), BASE));
        match returns(&text).iter().any(|line| line.contains('5')) {
            true => Err(text),
            false => Ok(()),
        }
    });
    hold(vec![failure]);
}

/// Each column's test, by a match with no wildcard arm: a new [`NegativeFact`] does not compile
/// until it has one (D411).
fn column(fact: NegativeFact) -> fn() {
    match fact {
        NegativeFact::IgnoredReads => an_unknown_callee_performs_every_read_it_names,
        NegativeFact::Kept => an_unknown_callee_keeps_no_register,
        NegativeFact::CallReadBytes => an_unknown_callee_reads_each_argument_register,
        NegativeFact::Void => an_unknown_callee_returns_an_unproven_result,
        NegativeFact::Never => an_unknown_callee_comes_back,
        NegativeFact::Pointer => an_unknown_callee_types_no_argument_a_pointer,
        NegativeFact::IncomingWrites => a_tail_transfer_writes_what_its_target_writes,
    }
}

/// Every negative fact has a column and a type that carries it.
#[test]
fn every_negative_fact_has_a_column_and_a_carrier() {
    for fact in NegativeFact::ALL {
        let _ = column(fact);
        assert!(
            CARRIERS.iter().any(|facts| facts.contains(&fact)),
            "no type carries {}",
            fact.column()
        );
    }
}

/// The uncited row's cells test an uncited row: [`UNCITED`] stays in `uncited-rows.txt` and its row
/// binds, so the call is declared. A citation of it fails here, and the row moves to another import.
#[test]
fn the_uncited_row_binds_an_uncited_declaration() {
    let uncited =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../r2abi/data/uncited-rows.txt");
    let uncited = std::fs::read_to_string(uncited).expect("it reads");
    assert!(
        (uncited.lines()).any(|line| line.split('|').next().map(str::trim) == Some(UNCITED)),
        "{UNCITED} is cited now; pick an import uncited-rows.txt lists"
    );
    let text = rendered(Unknown::UncitedRow.around(&[], &[0xc3]));
    assert!(
        text.contains(&format!("{UNCITED}(uint64_t);")),
        "the row does not bind:\n{text}"
    );
}
