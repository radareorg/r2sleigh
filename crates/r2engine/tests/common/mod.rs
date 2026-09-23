//! A program built from byte literals, for the tests that need an open one.
//!
//! Seven x86-64 functions in one run of bytes, a container that says where they
//! are, and a patch layer, which is everything `Source` asks for. No binary on
//! disk: the engine never knows what a file is, so its tests need not either.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ops::Range;

use r2engine::program::{
    Arch, Container, Entry, EntryKind, Format, Mapping, OpenProgram, Relocation, Section, Source,
    Symbol, SymbolKind,
};

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
                    endian: r2il::Endianness::Little,
                },
                sections: vec![Section {
                    name: ".text".to_owned(),
                    vaddr: BASE,
                    vsize: STUB - BASE,
                    is_code: true,
                    loaded: true,
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
            })
            .collect();
        program
    }

    /// A little-endian ARM program: a stated ARM function that calls into
    /// Thumb code nothing states, and a stated veneer that switches to ARM.
    pub fn arm_thumb() -> Self {
        let mut program = Self::new();
        program.code = &ARM_THUMB;
        program.container.arch = Arch {
            name: "arm".to_owned(),
            bits: 32,
            endian: r2il::Endianness::Little,
        };
        program.container.sections[0].vsize = ARM_THUMB.len() as u64;
        let symbol = |name: &str, vaddr, kind, thumb| Symbol {
            name: name.to_owned(),
            vaddr,
            size: 0,
            kind,
            defined: true,
            thumb,
        };
        program.container.symbols = vec![
            symbol("entry", ARM_ENTRY, SymbolKind::Function, false),
            symbol("veneer", VENEER, SymbolKind::Function, true),
            symbol("$t", VENEER, SymbolKind::Mapping(Mapping::Thumb), false),
            symbol("$a", VENEER + 4, SymbolKind::Mapping(Mapping::Arm), false),
        ];
        program
    }

    /// A `.plt` holding PLT0, the zero pad after it, and one stub, then a caller.
    pub fn plt() -> Self {
        let mut program = Self::new();
        program.code = &PLT;
        program.container.sections = vec![
            Section {
                name: ".plt".to_owned(),
                vaddr: BASE,
                vsize: 0x20,
                is_code: true,
                loaded: true,
            },
            Section {
                name: ".text".to_owned(),
                vaddr: PLT_CALLER,
                vsize: 6,
                is_code: true,
                loaded: true,
            },
        ];
        program.container.symbols.clear();
        program.container.relocations = vec![Relocation {
            vaddr: PLT_SLOT,
            symbol: "_Exit".to_owned(),
        }];
        program
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
            is_code,
            loaded: true,
        };
        self.container.sections.extend([
            section(".plt", STUB, 6, true),
            section(".got", SLOT, 8, false),
        ]);
        self.container.relocations.push(Relocation {
            vaddr: SLOT,
            symbol: import.to_owned(),
        });
        self
    }

    /// The same program with a data section, where a write can put a string.
    pub fn with_data(mut self) -> Self {
        self.container.sections.push(Section {
            name: ".data".to_owned(),
            vaddr: TEXT,
            vsize: 8,
            is_code: false,
            loaded: true,
        });
        self
    }

    /// The same program with its code ending at `end` and the rest of its bytes a data section.
    pub fn with_data_after(mut self, end: u64) -> Self {
        let code = &mut self.container.sections[0];
        let stop = code.vaddr + code.vsize;
        code.vsize = end - code.vaddr;
        self.container.sections.push(Section {
            name: ".rodata".to_owned(),
            vaddr: end,
            vsize: stop - end,
            is_code: false,
            loaded: true,
        });
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
