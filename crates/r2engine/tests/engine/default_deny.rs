//! The default-deny matrix (ROADMAP D405): each unknown input against each negative fact. A callee
//! nothing states may read, clobber, return and come back; no cell may state otherwise.

use crate::common;

use common::{BASE, Literal, PLT_CALLER};
use r2engine::program::OpenProgram;

/// The negative facts, one per `#[doc(alias = "default_deny_<column>")]` tag in the sources.
const COLUMNS: &[&str] = &[
    "ignored_reads",
    "kept",
    "call_read_bytes",
    "void",
    "never",
    "pointer",
    "incoming_writes",
];

/// A cell another row owns and that fails today, held exactly: it fails until its row lands, then
/// this entry goes in the same change.
const OPEN: &[(&str, &str, &str)] = &[
    ("tail_transfer", "incoming_writes", "D381"),
    ("indirect_call", "pointer", "D382"),
    ("unbound_import", "pointer", "D382"),
    ("walk_without_return", "never", "D379"),
];

/// The unknown inputs: a call through a register nothing sets, and a call to an import no row states.
#[derive(Clone, Copy, Debug)]
enum Unknown {
    IndirectCall,
    UnboundImport,
}

impl Unknown {
    const ALL: [Self; 2] = [Self::IndirectCall, Self::UnboundImport];

    const fn name(self) -> &'static str {
        match self {
            Self::IndirectCall => "indirect_call",
            Self::UnboundImport => "unbound_import",
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
            Self::UnboundImport => {
                let plt = common::plt_then::<0x20>(&[]);
                let after_call = PLT_CALLER + (before.len() + 5) as u64;
                let rel = (common::PLT_STUB as i64 - after_call as i64) as i32;
                let call = [&[0xe8][..], &rel.to_le_bytes()].concat(); // call stub
                let code = [&plt[..], before, &call, after].concat();
                let literal =
                    Literal::plt_wrapped("r2s_default_deny_unstated", Box::leak(code.into()));
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
fn cell(row: &str, column: &str, check: impl FnOnce() -> Result<(), String>) -> Option<String> {
    let open = OPEN.iter().find(|(r, c, _)| *r == row && *c == column);
    match (check(), open) {
        (Ok(()), None) | (Err(_), Some(_)) => None,
        (Err(evidence), None) => Some(format!("{row} x {column}: {evidence}")),
        (Ok(()), Some((_, _, owner))) => Some(format!(
            "{row} x {column} holds now: delete its OPEN entry ({owner})"
        )),
    }
}

fn hold(column: &str, failures: Vec<Option<String>>) {
    assert!(COLUMNS.contains(&column), "{column} is no column");
    let failures = failures.into_iter().flatten().collect::<Vec<_>>();
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// `mov rdi, rsi; call`: no read at a call to an unknown callee is ignored (D283's flip).
#[test]
fn an_unknown_callee_performs_every_read_it_names() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), "ignored_reads", || {
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
    hold("ignored_reads", failures.into());
}

/// `mov esi, 7; call; mov eax, esi; ret`: an unknown callee keeps nothing, so 7 is not returned.
#[test]
fn an_unknown_callee_keeps_no_register() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), "kept", || {
            let text = rendered(row.around(&[0xbe, 0x07, 0, 0, 0], &[0x89, 0xf0, 0xc3]));
            match returns(&text).iter().any(|line| line.contains('7')) {
                true => Err(text),
                false => Ok(()),
            }
        })
    });
    hold("kept", failures.into());
}

/// `mov edx, 5; call; ret`: an unknown callee may read RDX whole, so the setup is no dead store.
#[test]
fn an_unknown_callee_reads_each_argument_register() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), "call_read_bytes", || {
            let text = rendered(row.around(&[0xba, 0x05, 0, 0, 0], &[0xc3]));
            match text.contains('5') {
                true => Ok(()),
                false => Err(text),
            }
        })
    });
    hold("call_read_bytes", failures.into());
}

/// `mov eax, 7; call; ret`: an unknown callee's result is unproven, never void and never the 7.
#[test]
fn an_unknown_callee_returns_an_unproven_result() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), "void", || {
            let text = rendered(row.around(&[0xb8, 0x07, 0, 0, 0], &[0xc3]));
            let seven = returns(&text).iter().any(|line| line.contains('7'));
            match text.trim_start().starts_with("void ") || seven {
                true => Err(text),
                false => Ok(()),
            }
        })
    });
    hold("void", failures.into());
}

/// `call; mov eax, 1; ret`: an unknown callee comes back, so the 1 is returned and nothing is noreturn.
#[test]
fn an_unknown_callee_comes_back() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), "never", || {
            let text = rendered(row.around(&[], &[0xb8, 0x01, 0, 0, 0, 0xc3]));
            let one = returns(&text).iter().any(|line| line.contains('1'));
            match one && !text.contains("noreturn") {
                true => Ok(()),
                false => Err(text),
            }
        })
    });
    let walk = cell("walk_without_return", "never", || {
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
    hold("never", [failures.as_slice(), &[walk]].concat());
}

/// `call; ret` with RDI the caller's: an unknown callee's may-effects are no evidence of a pointer.
#[test]
fn an_unknown_callee_types_no_argument_a_pointer() {
    let failures = Unknown::ALL.map(|row| {
        cell(row.name(), "pointer", || {
            let text = rendered(row.around(&[], &[0xc3]));
            match text.contains("void *") || text.contains("void*") {
                true => Err(text),
                false => Ok(()),
            }
        })
    });
    hold("pointer", failures.into());
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
    let failure = cell("tail_transfer", "incoming_writes", || {
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
    hold("incoming_writes", vec![failure]);
}

/// Every `default_deny_<column>` tag on an accessor in the sources names a column here, and every
/// column has a tagged accessor: a new negative fact joins the matrix (D405).
#[test]
fn every_tagged_negative_fact_has_a_column() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut tagged = std::collections::BTreeSet::new();
    let mut pending = vec![crates];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("it lists").flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if path.is_dir() && name != "target" && name != "tests" {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("it reads");
                for (at, _) in text.match_indices("alias = \"default_deny_") {
                    let rest = &text[at + "alias = \"default_deny_".len()..];
                    let column = rest.split('"').next().unwrap_or_default().to_owned();
                    tagged.insert((column, path.display().to_string()));
                }
            }
        }
    }
    for (column, path) in &tagged {
        assert!(
            COLUMNS.contains(&column.as_str()),
            "{path} tags {column}, which has no column"
        );
    }
    for column in COLUMNS {
        assert!(
            tagged.iter().any(|(tag, _)| tag == column),
            "no accessor is tagged default_deny_{column}"
        );
    }
}
