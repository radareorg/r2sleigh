//! An import data object (`optarg`) is typed only where the loader's copy, the C library's row and
//! the copy's size agree (D653, doc/adr-memory-places.md invariant 12); a name proves nothing.

use crate::common;

use common::{BASE, GLIBC, Literal};
use r2engine::program::{
    Applies, LoaderWrite, OpenProgram, Relocation, RelocationSymbol, Symbol, SymbolKind, WriteKind,
};

/// Where the executable keeps its copy of the object.
const WORD: u64 = BASE + 0x80;

/// `mov rax, [rip + 0x79]` (the word), `ret`: `f` returns the 8 byte object.
const READ_8: &[u8] = &{
    let mut code = [0u8; 0x88];
    let text = [0x48, 0x8b, 0x05, 0x79, 0x00, 0x00, 0x00, 0xc3];
    let mut at = 0;
    while at < text.len() {
        code[at] = text[at];
        at += 1;
    }
    code
};

/// `mov eax, [rip + 0x7a]` (the word), `ret`: `f` returns its low 4 bytes.
const READ_4: &[u8] = &{
    let mut code = [0u8; 0x88];
    let text = [0x8b, 0x05, 0x7a, 0x00, 0x00, 0x00, 0xc3];
    let mut at = 0;
    while at < text.len() {
        code[at] = text[at];
        at += 1;
    }
    code
};

/// `code` on glibc, with a data symbol `name` of `size` bytes at the word.
fn named(code: &'static [u8], name: &str, size: u64) -> Literal {
    on(
        Literal::of_code(code, &[("f", BASE, 8)]).running_on(GLIBC),
        name,
        size,
    )
}

fn on(program: Literal, name: &str, size: u64) -> Literal {
    program.writable_data_after(WORD).declaring(Symbol {
        name: name.into(),
        vaddr: WORD,
        size,
        kind: SymbolKind::Data,
        defined: true,
        ..Symbol::default()
    })
}

/// An `R_X86_64_COPY` of `name`, `size` bytes, into the word.
fn copied(program: Literal, name: &str, size: u64) -> Literal {
    program
        .relocated(Relocation {
            vaddr: WORD,
            ntype: 5,
            width: size,
            symbol: Some(Box::new(RelocationSymbol {
                name: name.into(),
                size,
                ..RelocationSymbol::default()
            })),
            applies: Applies::Copy,
            ..Relocation::default()
        })
        .loader_written(LoaderWrite {
            place: WORD,
            width: size,
            kind: WriteKind::Copy {
                symbol: Some(name.into()),
            },
            encoding: r2engine::program::Encoding::Word,
        })
}

fn rendered(program: Literal) -> String {
    OpenProgram::of(program)
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text()
}

fn assert_untyped(text: &str, name: &str) {
    assert!(text.contains(&format!("extern char {name}[];")), "{text}");
    assert!(text.contains("1 data object type refused"), "{text}");
}

#[test]
fn a_copied_optarg_on_glibc_is_its_declared_object() {
    let text = rendered(copied(named(READ_8, "optarg", 8), "optarg", 8));
    assert!(!text.contains("r2sleigh_load_u64"), "{text}");
    assert!(text.contains("extern char* optarg;"), "{text}");
    assert!(
        text.contains("optarg);") || text.contains("optarg;\n"),
        "{text}"
    );
    assert!(
        text.contains("1 data object type from C library rows"),
        "{text}"
    );
}

/// `FILE *` names a tag no declaration of this unit states, so `stderr` keeps its byte copy and
/// its refusal (ROADMAP D653's open part: r2dec's tags read no data object's graph).
#[test]
fn a_copied_stderr_is_refused_while_its_tag_is_undeclared() {
    let text = rendered(copied(named(READ_8, "stderr", 8), "stderr", 8));
    assert!(text.contains("r2sleigh_load_u64((void*)&stderr)"), "{text}");
    assert_untyped(&text, "stderr");
}

/// A 4 byte read of the 8 byte object is no read of the object: its bytes stay a copy.
#[test]
fn a_narrower_read_keeps_the_byte_copy() {
    let text = rendered(copied(named(READ_4, "optarg", 8), "optarg", 8));
    assert!(text.contains("r2sleigh_load_u32((void*)&optarg)"), "{text}");
}

/// A copy of 4 bytes is no `char *` under LP64: the type stays refused.
#[test]
fn a_copy_of_another_size_keeps_the_refusal() {
    let text = rendered(copied(named(READ_8, "optarg", 4), "optarg", 4));
    assert!(text.contains("r2sleigh_load_u64((void*)&optarg)"), "{text}");
    assert_untyped(&text, "optarg");
}

/// A symbol named `optarg` that no loader write copies is a name, and binds nothing.
#[test]
fn a_symbol_with_no_copy_keeps_the_refusal() {
    let text = rendered(named(READ_8, "optarg", 8));
    assert!(text.contains("r2sleigh_load_u64((void*)&optarg)"), "{text}");
    assert_untyped(&text, "optarg");
}

/// No C library named, no row: the copied object stays untyped.
#[test]
fn without_a_library_row_the_copy_keeps_the_refusal() {
    let unknown = Literal::of_code(READ_8, &[("f", BASE, 8)]).needing(&[]);
    let text = rendered(copied(on(unknown, "optarg", 8), "optarg", 8));
    assert!(text.contains("r2sleigh_load_u64((void*)&optarg)"), "{text}");
    assert_untyped(&text, "optarg");
}
