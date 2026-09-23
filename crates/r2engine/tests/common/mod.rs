//! A program built from byte literals, for the tests that need an open one.
//!
//! Five x86-64 functions in one run of bytes, a container that says where they
//! are, and a patch layer, which is everything `Source` asks for. No binary on
//! disk: the engine never knows what a file is, so its tests need not either.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ops::Range;

use r2engine::program::{
    Arch, Container, Format, Mapping, OpenProgram, Section, Source, Symbol, SymbolKind,
};

pub const BASE: u64 = 0x1000;
/// `mov eax, 1; ret`
pub const ONE: u64 = BASE;
/// `call one; ret`
pub const CALLER: u64 = BASE + 0x10;
/// `mov eax, 2; ret`
pub const TWO: u64 = BASE + 0x20;
/// `lea rax, [one]; test edi, edi; je L; mov eax, 5; L: mov rdi, rax; ret`
pub const FORKED: u64 = BASE + 0x30;
/// `test edi, edi; je L; lea rax, [one]; L: mov rdi, rax; ret`
pub const JOINED: u64 = BASE + 0x50;

const CODE: [u8; 0x70] = {
    let mut code = [0xcc; 0x70];
    // one: mov eax, 1; ret
    code[0x00] = 0xb8;
    code[0x01] = 0x01;
    code[0x02] = 0x00;
    code[0x03] = 0x00;
    code[0x04] = 0x00;
    code[0x05] = 0xc3;
    // caller: call one (rel32 = 0x1000 - 0x1015); ret
    code[0x10] = 0xe8;
    code[0x11] = 0xeb;
    code[0x12] = 0xff;
    code[0x13] = 0xff;
    code[0x14] = 0xff;
    code[0x15] = 0xc3;
    // two: mov eax, 2; ret
    code[0x20] = 0xb8;
    code[0x21] = 0x02;
    code[0x22] = 0x00;
    code[0x23] = 0x00;
    code[0x24] = 0x00;
    code[0x25] = 0xc3;
    // forked: the address is read back only on the path that skips the overwrite
    let forked = [
        0x48, 0x8d, 0x05, 0xc9, 0xff, 0xff, 0xff, // lea rax, [rip - 0x37]
        0x85, 0xff, // test edi, edi
        0x74, 0x05, // je 0x1040
        0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
        0x48, 0x89, 0xc7, // mov rdi, rax
        0xc3, // ret
    ];
    let mut at = 0;
    while at < forked.len() {
        code[0x30 + at] = forked[at];
        at += 1;
    }
    // joined: the address falls through into a block another path also enters
    let joined = [
        0x85, 0xff, // test edi, edi
        0x74, 0x07, // je 0x105b
        0x48, 0x8d, 0x05, 0xa5, 0xff, 0xff, 0xff, // lea rax, [rip - 0x5b]
        0x48, 0x89, 0xc7, // mov rdi, rax
        0xc3, // ret
    ];
    let mut at = 0;
    while at < joined.len() {
        code[0x50 + at] = joined[at];
        at += 1;
    }
    code
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
                    vsize: CODE.len() as u64,
                    is_code: true,
                    loaded: true,
                }],
                symbols: vec![
                    function("one", ONE, 6),
                    function("caller", CALLER, 6),
                    function("two", TWO, 6),
                    function("forked", FORKED, 0x14),
                    function("joined", JOINED, 0xf),
                ],
                ..Container::default()
            },
        }
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

    /// The same program with one symbol stripped from the container.
    pub fn stripped_of(mut self, name: &str) -> Self {
        self.container.symbols.retain(|symbol| symbol.name != name);
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
