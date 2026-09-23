//! A program built from byte literals, for the tests that need an open one.
//!
//! Three x86-64 functions in one run of bytes, a container that says where they
//! are, and a patch layer, which is everything `Source` asks for. No binary on
//! disk: the engine never knows what a file is, so its tests need not either.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::ops::Range;

use r2engine::program::{
    Arch, Container, Format, OpenProgram, Section, Source, Symbol, SymbolKind,
};

pub const BASE: u64 = 0x1000;
/// `mov eax, 1; ret`
pub const ONE: u64 = BASE;
/// `call one; ret`
pub const CALLER: u64 = BASE + 0x10;
/// `mov eax, 2; ret`
pub const TWO: u64 = BASE + 0x20;

const CODE: [u8; 0x30] = {
    let mut code = [0xcc; 0x30];
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
    code
};

/// The bytes, the container's statement about them, and what has been written.
pub struct Literal {
    patches: BTreeMap<u64, u8>,
    written: Vec<(u64, Range<u64>)>,
    revision: u64,
    container: Container,
}

impl Literal {
    pub fn new() -> Self {
        let function = |name: &str, vaddr| Symbol {
            name: name.to_owned(),
            vaddr,
            size: 6,
            kind: SymbolKind::Function,
            defined: true,
            thumb: false,
        };
        Self {
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
                    function("one", ONE),
                    function("caller", CALLER),
                    function("two", TWO),
                ],
                ..Container::default()
            },
        }
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
        let rest = CODE.get(offset..).filter(|rest| !rest.is_empty())?;
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
