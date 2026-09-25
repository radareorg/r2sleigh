//! A program built from byte literals, for the tests that need an open one.
//!
//! Seven x86-64 functions in one run of bytes, a container that says where they
//! are, and a patch layer, which is everything `Source` asks for. No binary on
//! disk: the engine never knows what a file is, so its tests need not either.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ops::Range;

use r2engine::program::{
    Applies, Arch, Container, Endian, Entry, EntryKind, Format, LoaderWrite, Mapping, OpenProgram,
    Permissions, PlatformEvidence, Relocation, RelocationSymbol, Section, SectionRole, Segment,
    Source, Symbol, SymbolKind, WriteKind,
};

/// What a program linked against the GNU C library states of its platform:
/// glibc's dynamic linker in `PT_INTERP`.
pub const GLIBC: &[PlatformEvidence] = &[PlatformEvidence::Interpreter(
    r2engine::program::Libc::Glibc,
)];

pub const BASE: u64 = 0x1000;
/// `mov eax, 1; ret`
pub const ONE: u64 = BASE;
/// `call one; ret`
pub const CALLER: u64 = BASE + 0x10;
/// `mov eax, 2; ret`
pub const TWO: u64 = BASE + 0x20;
/// `lea rax, [one]; test edi, edi; je L; mov eax, 5; L: add rax, 8; ret`
pub const FORKED: u64 = BASE + 0x30;
/// `test edi, edi; je L; lea rax, [one]; L: add rax, 8; ret`
pub const JOINED: u64 = BASE + 0x50;
/// `lea rdi, [one]; call one; ret`
pub const PASSES: u64 = BASE + 0x70;
/// `lea rax, [one]; add rax, 8; ret`
pub const STEPPED: u64 = BASE + 0x80;
/// `jmp qword [rip + 2]`, the linkage stub for an import where the program has one.
pub const STUB: u64 = BASE + 0x90;
/// The slot that stub reads, which the loader fills with the import.
pub const SLOT: u64 = BASE + 0x98;
/// Where the program keeps a string, where it has one.
pub const TEXT: u64 = BASE + 0xa0;

/// Copy `bytes` into `code` at `at`.
const fn place<const N: usize>(mut code: [u8; 0xb0], at: usize, bytes: [u8; N]) -> [u8; 0xb0] {
    let mut offset = 0;
    while offset < N {
        code[at + offset] = bytes[offset];
        offset += 1;
    }
    code
}

const CODE: [u8; 0xb0] = {
    let code = [0xcc; 0xb0];
    // one: mov eax, 1; ret
    let code = place(code, 0x00, [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    // caller: call one (rel32 = 0x1000 - 0x1015); ret
    let code = place(code, 0x10, [0xe8, 0xeb, 0xff, 0xff, 0xff, 0xc3]);
    // two: mov eax, 2; ret
    let code = place(code, 0x20, [0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3]);
    // forked: the address is built on only on the path that skips the overwrite
    let code = place(
        code,
        0x30,
        [
            0x48, 0x8d, 0x05, 0xc9, 0xff, 0xff, 0xff, // lea rax, [rip - 0x37]
            0x85, 0xff, // test edi, edi
            0x74, 0x05, // je 0x1040
            0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
            0x48, 0x83, 0xc0, 0x08, // add rax, 8
            0xc3, // ret
        ],
    );
    // joined: the address falls through into a block another path also enters
    let code = place(
        code,
        0x50,
        [
            0x85, 0xff, // test edi, edi
            0x74, 0x07, // je 0x105b
            0x48, 0x8d, 0x05, 0xa5, 0xff, 0xff, 0xff, // lea rax, [rip - 0x5b]
            0x48, 0x83, 0xc0, 0x08, // add rax, 8
            0xc3, // ret
        ],
    );
    // passes: the address is an argument, which uses it as it stands
    let code = place(
        code,
        0x70,
        [
            0x48, 0x8d, 0x3d, 0x89, 0xff, 0xff, 0xff, // lea rdi, [rip - 0x77]
            0xe8, 0x84, 0xff, 0xff, 0xff, // call one
            0xc3, // ret
        ],
    );
    // stub: jmp qword [rip + 2], which is the slot at 0x98
    let code = place(code, 0x90, [0xff, 0x25, 0x02, 0x00, 0x00, 0x00]);
    // stepped: the address is a base the next instruction moves past
    place(
        code,
        0x80,
        [
            0x48, 0x8d, 0x05, 0x79, 0xff, 0xff, 0xff, // lea rax, [rip - 0x87]
            0x48, 0x83, 0xc0, 0x08, // add rax, 8
            0xc3, // ret
        ],
    )
};

/// An ARM function the container states: `blx thumb; bx lr`.
pub const ARM_ENTRY: u64 = BASE;
/// A Thumb function nothing states, reached only by that `blx`:
/// `push {r4, lr}; bl leaf; pop {r4, pc}`.
pub const THUMB_CALLED: u64 = BASE + 0x10;
/// A Thumb function reached only by the Thumb `bl`: `movs r0, 1; bx lr`.
pub const THUMB_LEAF: u64 = BASE + 0x20;
/// A stated Thumb veneer whose mapping symbols switch it to ARM halfway:
/// `bx pc; mov r8, r8` then `bx lr`.
pub const VENEER: u64 = BASE + 0x24;

const ARM_THUMB: [u8; 0x30] = {
    let mut code = [0; 0x30];
    let runs: [(usize, &[u8]); 7] = [
        (0x00, &[0x02, 0x00, 0x00, 0xfa]), // blx 0x1010
        (0x04, &[0x1e, 0xff, 0x2f, 0xe1]), // bx lr
        (0x10, &[0x10, 0xb5, 0x00, 0xf0]), // push {r4, lr}; bl 0x1020 (first half)
        (0x14, &[0x05, 0xf8, 0x10, 0xbd]), // bl (second half); pop {r4, pc}
        (0x20, &[0x01, 0x20, 0x70, 0x47]), // movs r0, 1; bx lr
        (0x24, &[0x78, 0x47, 0xc0, 0x46]), // bx pc; mov r8, r8
        (0x28, &[0x1e, 0xff, 0x2f, 0xe1]), // bx lr
    ];
    let mut index = 0;
    while index < runs.len() {
        let (at, run) = runs[index];
        let mut offset = 0;
        while offset < run.len() {
            code[at + offset] = run[offset];
            offset += 1;
        }
        index += 1;
    }
    code
};

/// The one import stub in `Literal::plt`, after PLT0 and four zero bytes.
pub const PLT_STUB: u64 = BASE + 0x10;
/// `call stub; ret`
pub const PLT_CALLER: u64 = BASE + 0x20;
/// The slot the stub jumps through, which the loader fills with `_Exit`.
pub const PLT_SLOT: u64 = BASE + 0x1000;

const PLT: [u8; 0x26] = [
    0xff, 0x35, 0xea, 0x0f, 0x00, 0x00, // push qword [rip + 0xfea]
    0xff, 0x25, 0xec, 0x0f, 0x00, 0x00, // jmp qword [rip + 0xfec]
    0x00, 0x00, 0x00, 0x00, // the pad, which decodes as add byte [rax], al
    0xff, 0x25, 0xea, 0x0f, 0x00, 0x00, // jmp qword [rip + 0xfea], the slot
    0x68, 0x00, 0x00, 0x00, 0x00, // push 0
    0xe9, 0xe0, 0xff, 0xff, 0xff, // jmp PLT0
    0xe8, 0xeb, 0xff, 0xff, 0xff, // call stub
    0xc3, // ret
];

/// `cmp rdi, 10; jae L; mov esi, 0; L: mov rax, rdi; ret`: L is entered with rdi below ten and above.
pub const GUARDED_JOIN: &[u8] = &[
    0x48, 0x83, 0xff, 0x0a, // cmp rdi, 10
    0x73, 0x05, // jae L
    0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, 0
    0x48, 0x89, 0xf8, // L: mov rax, rdi
    0xc3, // ret
];

/// `eax` is one, eleven or twenty-one where `shr eax, 2` reads it, so the shift leaves nought, two or five.
pub const SHIFT_MERGE: &[u8] = &[
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

/// `mov rax, 0x1010; mov rcx, [rax]; mov al, 5; mov rdx, [rax]; ret`, then the word at 0x1010: `mov al` leaves rax 0x1005.
pub const OVERWRITTEN: &[u8] = &[
    0x48, 0xc7, 0xc0, 0x10, 0x10, 0x00, 0x00, // mov rax, 0x1010
    0x48, 0x8b, 0x08, // mov rcx, qword [rax]
    0xb0, 0x05, // mov al, 5
    0x48, 0x8b, 0x10, // mov rdx, qword [rax]
    0xc3, // ret
    0x0d, 0xf0, 0xad, 0x0b, 0x00, 0x00, 0x00, 0x00, // 0x1010, the word
];

/// An ARM import stub that builds its slot's address in two halves: `movw ip, #0x2000; movt ip, #0; ldr pc, [ip]`.
pub const MOVED_STUB: &[u8] = &[
    0x00, 0xc0, 0x02, 0xe3, // movw ip, #0x2000
    0x00, 0xc0, 0x40, 0xe3, // movt ip, #0
    0x00, 0xf0, 0x9c, 0xe5, // ldr pc, [ip]
];

/// ARM `movw r0, #0x1010; movt r0, #0; ldr r1, [r0]; bx lr`, then the word at 0x1010: the pair builds one address.
pub const MOVED: &[u8] = &[
    0x10, 0x00, 0x01, 0xe3, // movw r0, #0x1010
    0x00, 0x00, 0x40, 0xe3, // movt r0, #0
    0x00, 0x10, 0x90, 0xe5, // ldr r1, [r0]
    0x1e, 0xff, 0x2f, 0xe1, // bx lr
    0x0d, 0xf0, 0xad, 0x0b, // 0x1010, the word
];

/// `ident: mov rax, rdi; ret` at `BASE`, `hands: lea rdi, [text]; call ident; ret` at `HANDS`, and `"hi"` at `HANDED`.
pub const HANDING: &[u8] = &[
    0x48, 0x89, 0xf8, 0xc3, // ident: mov rax, rdi; ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // to 0x1010
    0x48, 0x8d, 0x3d, 0x29, 0x00, 0x00, 0x00, // 0x1010 lea rdi, [rip + 0x29]
    0xe8, 0xe4, 0xff, 0xff, 0xff, // 0x1017 call ident
    0xc3, // 0x101c ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // to 0x1034
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // to 0x1040
    b'h', b'i', 0x00, 0x00, // 0x1040, the text
];
/// Where `HANDING` places `hands`, and the text it hands on.
pub const HANDS: u64 = BASE + 0x10;
pub const HANDED: u64 = BASE + 0x40;

/// `HANDING` opened: its code up to the text, and the text a data section.
pub fn handing() -> Literal {
    let functions = [("ident", BASE, 4), ("hands", HANDS, 0xd)];
    Literal::of_code(HANDING, &functions).with_data_after(HANDED)
}

/// `f: call t; ret`, `g: jmp t`, `h: lea rdi, [t]; call one; ret` and
/// `one: mov eax, 1; ret`, then `"1"` at `t`: two transfers to one address
/// and one use of it as a value.
pub const TRANSFERRING: [u8; 0x102] = {
    let mut bytes = [0xcc; 0x102];
    let runs: [(usize, &[u8]); 5] = [
        (0x00, &[0xe8, 0xfb, 0x00, 0x00, 0x00, 0xc3]), // f: call 0x1100; ret
        (0x10, &[0xe9, 0xeb, 0x00, 0x00, 0x00]),       // g: jmp 0x1100
        (
            0x20,
            &[
                0x48, 0x8d, 0x3d, 0xd9, 0x00, 0x00, 0x00, // h: lea rdi, [rip + 0xd9]
                0xe8, 0x04, 0x00, 0x00, 0x00, // call one
                0xc3, // ret
            ],
        ),
        (0x30, &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]), // one: mov eax, 1; ret
        (0x100, b"1\0"),                               // t, the text
    ];
    let mut index = 0;
    while index < runs.len() {
        let (at, run) = runs[index];
        let mut offset = 0;
        while offset < run.len() {
            bytes[at + offset] = run[offset];
            offset += 1;
        }
        index += 1;
    }
    bytes
};
/// Where `TRANSFERRING` keeps `"1"`, which is also where its calls and jumps go.
pub const TRANSFERRED: u64 = BASE + 0x100;

/// `TRANSFERRING` as one run of code, stating `t` a function where its text is; the caller says what the section after its code is.
pub fn transferring() -> Literal {
    let functions = [
        ("f", BASE, 6),
        ("g", BASE + 0x10, 5),
        ("h", BASE + 0x20, 0xd),
        ("one", BASE + 0x30, 6),
        ("t", TRANSFERRED, 2),
    ];
    Literal::of_code(&TRANSFERRING, &functions)
}

/// A jump table of absolute addresses, the form x86-64 uses:
///
/// ```text
///   1000  cmp  edi, 3              ; the bound the guard proves
///   1003  ja   0x1020              ; out of range takes the default
///   1005  mov  edi, edi            ; the index, zero-extended
///   1007  jmp  [rdi*8 + 0x1030]    ; read one entry of the table
///   100e  mov  eax, 10  ; ret      ; case 0
///   1014  mov  eax, 20  ; ret      ; case 1
///   101a  mov  eax, 30  ; ret      ; case 2
///   1020  mov  eax, -1  ; ret      ; default
///   1026  mov  eax, 40  ; ret      ; case 3
///   1030  the four entries
/// ```
pub const TABLE_SWITCH: &[u8] = &[
    0x83, 0xff, 0x03, // 1000 cmp edi, 3
    0x77, 0x1b, // 1003 ja 0x1020
    0x89, 0xff, // 1005 mov edi, edi
    0xff, 0x24, 0xfd, 0x30, 0x10, 0x00, 0x00, // 1007 jmp [rdi*8 + 0x1030]
    0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, // 100e case 0
    0xb8, 0x14, 0x00, 0x00, 0x00, 0xc3, // 1014 case 1
    0xb8, 0x1e, 0x00, 0x00, 0x00, 0xc3, // 101a case 2
    0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3, // 1020 default
    0xb8, 0x28, 0x00, 0x00, 0x00, 0xc3, // 1026 case 3
    0x00, 0x00, 0x00, 0x00, // 102c padding
    0x0e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1030 -> 0x100e
    0x14, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1038 -> 0x1014
    0x1a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1040 -> 0x101a
    0x26, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1048 -> 0x1026
];

/// `TABLE_SWITCH` opened as one function, `pick`.
pub fn table_switch() -> Literal {
    Literal::of_code(TABLE_SWITCH, &[("pick", BASE, 0x2c)])
}

/// A slot the loader binds to an import, as a `JUMP_SLOT` record states it.
pub fn import_slot(vaddr: u64, import: &str) -> Relocation {
    Relocation {
        vaddr,
        ntype: 7,
        width: 8,
        symbol: Some(RelocationSymbol {
            name: import.to_owned(),
            ..RelocationSymbol::default()
        }),
        applies: Applies::Symbol,
        ..Relocation::default()
    }
}

/// What the loader writes into an import's slot: the import's address, which another image defines.
pub fn import_write(place: u64, width: u64, import: &str) -> LoaderWrite {
    LoaderWrite {
        place,
        width,
        kind: WriteKind::Import {
            symbol: import.to_owned(),
        },
    }
}

/// One run of code the loader maps readable and executable.
pub fn code_segment(vaddr: u64, vsize: u64) -> Segment {
    Segment {
        vaddr,
        vsize,
        file_size: vsize,
        permissions: Permissions {
            read: true,
            write: false,
            execute: true,
        },
        ..Segment::default()
    }
}

/// The bytes, the container's statement about them, and what has been written.
pub struct Literal {
    code: &'static [u8],
    patches: BTreeMap<u64, u8>,
    written: Vec<(u64, Range<u64>)>,
    revision: u64,
    container: Container,
}

impl Literal {
    pub fn new() -> Self {
        let function = |name: &str, vaddr, size| Symbol {
            name: name.to_owned(),
            vaddr,
            size,
            kind: SymbolKind::Function,
            defined: true,
            thumb: false,
            ..Symbol::default()
        };
        Self {
            code: &CODE,
            patches: BTreeMap::new(),
            written: Vec::new(),
            revision: 0,
            container: Container {
                format: Format::Elf,
                arch: Arch {
                    name: "x86-64".to_owned(),
                    bits: 64,
                    endian: Endian::Little,
                },
                segments: vec![code_segment(BASE, CODE.len() as u64)],
                sections: vec![Section {
                    name: ".text".to_owned(),
                    vaddr: BASE,
                    vsize: STUB - BASE,
                    role: SectionRole::Code,
                    loaded: true,
                    ..Section::default()
                }],
                symbols: vec![
                    function("one", ONE, 6),
                    function("caller", CALLER, 6),
                    function("two", TWO, 6),
                    function("forked", FORKED, 0x15),
                    function("joined", JOINED, 0x10),
                    function("passes", PASSES, 0xd),
                    function("stepped", STEPPED, 0xc),
                ],
                ..Container::default()
            },
        }
    }

    /// An x86-64 program of one run of code at `BASE`, stating each `(name, vaddr, size)` as a function.
    pub fn of_code(code: &'static [u8], functions: &[(&str, u64, u64)]) -> Self {
        let mut program = Self::new();
        program.code = code;
        program.container.segments = vec![code_segment(BASE, code.len() as u64)];
        program.container.sections[0].vsize = code.len() as u64;
        program.container.symbols = functions
            .iter()
            .map(|(name, vaddr, size)| Symbol {
                name: (*name).to_owned(),
                vaddr: *vaddr,
                size: *size,
                kind: SymbolKind::Function,
                defined: true,
                thumb: false,
                ..Symbol::default()
            })
            .collect();
        program
    }

    /// A little-endian ARM program: a stated ARM function that calls into
    /// Thumb code nothing states, and a stated veneer that switches to ARM.
    pub fn arm_thumb() -> Self {
        let mut program = Self::new().in_arm();
        program.code = &ARM_THUMB;
        program.container.segments = vec![code_segment(BASE, ARM_THUMB.len() as u64)];
        program.container.sections[0].vsize = ARM_THUMB.len() as u64;
        let symbol = |name: &str, vaddr, kind, thumb| Symbol {
            name: name.to_owned(),
            vaddr,
            size: 0,
            kind,
            defined: true,
            thumb,
            ..Symbol::default()
        };
        program.container.symbols = vec![
            symbol("entry", ARM_ENTRY, SymbolKind::Function, false),
            symbol("veneer", VENEER, SymbolKind::Function, true),
            symbol("$t", VENEER, SymbolKind::Mapping(Mapping::Thumb), false),
            symbol("$a", VENEER + 4, SymbolKind::Mapping(Mapping::Arm), false),
        ];
        program
    }

    /// The same bytes as little-endian 32-bit ARM.
    pub fn in_arm(mut self) -> Self {
        self.container.arch = Arch {
            name: "arm".to_owned(),
            bits: 32,
            endian: Endian::Little,
        };
        self
    }

    /// A `.plt` holding PLT0, the zero pad after it, and one stub for `_Exit`, then a caller.
    pub fn plt() -> Self {
        Self::plt_importing("_Exit")
    }

    /// The same `.plt`, its one stub standing for `import`.
    pub fn plt_importing(import: &str) -> Self {
        let mut program = Self::new();
        program.code = &PLT;
        program.container.segments = vec![code_segment(BASE, PLT.len() as u64)];
        program.container.sections = vec![
            Section {
                name: ".plt".to_owned(),
                vaddr: BASE,
                vsize: 0x20,
                role: SectionRole::Code,
                loaded: true,
                ..Section::default()
            },
            Section {
                name: ".text".to_owned(),
                vaddr: PLT_CALLER,
                vsize: 6,
                role: SectionRole::Code,
                loaded: true,
                ..Section::default()
            },
        ];
        program.container.symbols.clear();
        program.container.relocations = vec![import_slot(PLT_SLOT, import)];
        // The two words before the slot are the ones the x86-64 psABI reserves
        // for the lazy resolver, which the loader writes with no relocation
        // naming them, and which the first entry reads.
        program.container.loader_writes = vec![
            LoaderWrite {
                place: PLT_SLOT - 0x10,
                width: 0x10,
                kind: WriteKind::Unknown,
            },
            import_write(PLT_SLOT, 8, import),
        ];
        program
    }

    /// The same program, its container stating this of the platform it runs on.
    pub fn running_on(mut self, evidence: &[PlatformEvidence]) -> Self {
        self.container.platform = evidence.iter().copied().collect();
        self
    }

    /// The same code as a `.plt`, stating a 32-bit slot at `slot` the loader fills with `import`.
    pub fn in_plt(mut self, slot: u64, import: &str) -> Self {
        ".plt".clone_into(&mut self.container.sections[0].name);
        self.container.symbols.clear();
        self.container.relocations.push(import_slot(slot, import));
        self.container
            .loader_writes
            .push(import_write(slot, 4, import));
        self
    }

    /// The same program with one symbol stripped from the container.
    pub fn stripped_of(mut self, name: &str) -> Self {
        self.container.symbols.retain(|symbol| symbol.name != name);
        self
    }

    /// The same program with one more function stated, wherever it points.
    pub fn stating(mut self, name: &str, vaddr: u64) -> Self {
        self.container.symbols.push(Symbol {
            name: name.to_owned(),
            vaddr,
            size: 0,
            kind: SymbolKind::Function,
            defined: true,
            thumb: false,
            ..Symbol::default()
        });
        self
    }

    /// The same program with a section listed ahead of its code.
    pub fn preceded_by(mut self, section: Section) -> Self {
        self.container.sections.insert(0, section);
        self
    }

    /// The same program with one more entry point in the container.
    pub fn entering(mut self, vaddr: u64, kind: EntryKind) -> Self {
        self.container.entries.push(Entry {
            vaddr,
            kind,
            thumb: false,
            ..Entry::default()
        });
        self
    }

    /// The same program with one more symbol in the container.
    pub fn declaring(mut self, symbol: Symbol) -> Self {
        self.container.symbols.push(symbol);
        self
    }

    /// The same program with an import: a linkage stub, and the slot it reads.
    pub fn importing(mut self, import: &str) -> Self {
        let section = |name: &str, vaddr, vsize, is_code| Section {
            name: name.to_owned(),
            vaddr,
            vsize,
            role: if is_code {
                SectionRole::Code
            } else {
                SectionRole::Data
            },
            loaded: true,
            ..Section::default()
        };
        // The code before the stub is the program's own; the stub and its slot are the loader's.
        let code = &mut self.container.sections[0];
        code.vsize = code.vsize.min(STUB - code.vaddr);
        self.container.sections.extend([
            section(".plt", STUB, 6, true),
            section(".got", SLOT, 8, false),
        ]);
        self.container.relocations.push(import_slot(SLOT, import));
        // The loader writes the import's address into the slot, as the container states for every relocation.
        self.container
            .loader_writes
            .push(import_write(SLOT, 8, import));
        self
    }

    /// The same program with a data section, where a write can put a string.
    pub fn with_data(mut self) -> Self {
        self.container.sections.push(Section {
            name: ".data".to_owned(),
            vaddr: TEXT,
            vsize: 8,
            role: SectionRole::Data,
            loaded: true,
            ..Section::default()
        });
        self
    }

    /// The same program with its code ending at `end` and the rest of its bytes a data section.
    pub fn with_data_after(self, end: u64) -> Self {
        self.split_at(end, ".rodata", false)
    }

    /// The same program with its code ending at `end` and the rest of its bytes a second section the container states holds instructions.
    pub fn with_code_after(self, end: u64) -> Self {
        self.split_at(end, ".init", true)
    }

    /// The same program with its first section ending at `end` and the rest of its bytes this one.
    fn split_at(mut self, end: u64, name: &str, is_code: bool) -> Self {
        let code = &mut self.container.sections[0];
        let stop = code.vaddr + code.vsize;
        code.vsize = end - code.vaddr;
        self.container.sections.push(Section {
            name: name.to_owned(),
            vaddr: end,
            vsize: stop - end,
            role: if is_code {
                SectionRole::Code
            } else {
                SectionRole::Data
            },
            loaded: true,
            ..Section::default()
        });
        self
    }

    /// The same program with its bytes from `end` on mapped as data: readable, and no instruction there can run.
    pub fn data_mapped_after(self, end: u64) -> Self {
        self.data_after(end, false)
    }

    /// The same program with its bytes from `end` on mapped as data the program may write once it runs.
    pub fn writable_data_after(self, end: u64) -> Self {
        self.data_after(end, true)
    }

    fn data_after(mut self, end: u64, write: bool) -> Self {
        let code = &mut self.container.segments[0];
        let stop = code.vaddr + code.vsize;
        code.vsize = end - code.vaddr;
        code.file_size = code.vsize;
        self.container.segments.push(Segment {
            vaddr: end,
            vsize: stop - end,
            file_size: stop - end,
            permissions: Permissions {
                read: true,
                write,
                execute: false,
            },
            ..Segment::default()
        });
        self
    }

    /// The same program, stating that the loader makes this range read-only once it is done.
    pub fn sealed(mut self, range: Range<u64>) -> Self {
        self.container.sealed.push(range);
        self
    }

    /// The same program, with the container naming its `index`th section `name`.
    pub fn renamed(mut self, index: usize, name: &str) -> Self {
        name.clone_into(&mut self.container.sections[index].name);
        self
    }

    /// The same program, stating that the loader writes this before it runs.
    pub fn loader_written(mut self, write: LoaderWrite) -> Self {
        self.container.loader_writes.push(write);
        self.container
            .loader_writes
            .sort_by_key(|write| write.place);
        self
    }

    /// Write bytes over the program's own, as a patch would.
    pub fn write(&mut self, vaddr: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().enumerate() {
            self.patches.insert(vaddr + offset as u64, *byte);
        }
        self.revision += 1;
        self.written
            .push((self.revision, vaddr..vaddr + bytes.len() as u64));
    }
}

impl Source for Literal {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let rest = self.code.get(offset..).filter(|rest| !rest.is_empty())?;
        Some(
            rest.iter()
                .take(max)
                .enumerate()
                .map(|(at, byte)| *self.patches.get(&(vaddr + at as u64)).unwrap_or(byte))
                .collect(),
        )
    }

    fn container(&self) -> &Container {
        &self.container
    }

    fn identity(&self) -> u64 {
        0
    }

    fn byte_revision(&self) -> u64 {
        self.revision
    }

    fn written_since(&self, revision: u64, range: &Range<u64>) -> bool {
        self.written.iter().any(|(at, written)| {
            *at > revision && written.start < range.end && range.start < written.end
        })
    }
}

/// The literal program, opened.
pub fn opened() -> OpenProgram<Literal> {
    OpenProgram::of(Literal::new())
}
