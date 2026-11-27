//! What a word of the program holds when it starts running, as the container states it.
//!
//! The one reader of program memory as data. The file's bytes are what the
//! program reads only where the loader leaves them alone; where it writes, the
//! container states what it writes -- an address of this image, a definition
//! nothing can replace, an import, a resolver's result -- and that statement,
//! not the file's word, is what the program starts with. A listing's word, a
//! dispatch table's entries and a string's bytes all read through here, so a
//! rebased pointer is read as the address it is and a chained fixup is never
//! read as the link it encodes. Whether a word keeps that value for the run is
//! `native::TableBytes`'s question.

use std::ops::Range;

use crate::native::Program;

/// The value a word holds when the program starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatedWord {
    /// This revision's bytes, which the loader leaves alone.
    Held(u64),
    /// The loader writes it, and the container states the address it writes:
    /// one of this image's own, or a definition no other image can replace.
    Loaded(u64),
}

impl StatedWord {
    pub const fn value(self) -> u64 {
        match self {
            Self::Held(value) | Self::Loaded(value) => value,
        }
    }
}

/// The import a call through the word at `slot` reaches: the loader binds it there as a pointer
/// word and seals it (RELRO, a read-only Mach-O segment), and its stated write is what stays.
/// A lazily bound slot names none. O(log W) in the loader's writes (audit W8).
pub fn sealed_import(program: &dyn crate::body::Program, slot: u64) -> Option<&str> {
    let write = r2abi::statement::write_at(program.loader_writes(), slot)?;
    let r2abi::statement::WriteKind::Import { symbol, .. } = &write.kind else {
        return None;
    };
    let word = write.place == slot && write.encoding == r2abi::statement::Encoding::Word;
    let kept = program.permanence(&(slot..write.end())) != crate::program::Permanence::Writable;
    (word && kept).then_some(symbol.as_str())
}

/// Where the container binds a library's global stack guard: its sealed import words and its one
/// `R_*_COPY` (doc/adr-call-boundary.md, "S27 as built"). O(W + R).
pub fn linked_guard(
    container: &crate::program::Container,
    guard: &r2abi::LinkedGuard,
    pointer: u32,
) -> Option<r2source::SourceLinkedGuard> {
    use r2abi::statement::{Applies, Encoding, WriteKind};
    let slots = (container.loader_writes.iter())
        .filter(|write| {
            matches!(&write.kind, WriteKind::Import { symbol, .. } if symbol == guard.symbol)
                && write.encoding == Encoding::Word
                && write.width == u64::from(pointer)
                && container.permanence(&(write.place..write.end()))
                    != crate::program::Permanence::Writable
        })
        .map(|write| write.place)
        .collect::<std::collections::BTreeSet<_>>();
    let mut copies = (container.relocations.iter()).filter(|record| {
        record.applies == Applies::Copy
            && record.width == u64::from(guard.width)
            && record
                .symbol
                .as_ref()
                .is_some_and(|symbol| &*symbol.name == guard.symbol)
    });
    let copy = copies.next().map(|record| record.vaddr);
    // Two copies of one object state no one place for it.
    let copy = copy.filter(|_| copies.next().is_none());
    (copy.is_some() || !slots.is_empty()).then(|| r2source::SourceLinkedGuard {
        copy,
        slots: slots.into_iter().collect(),
        slot_width: pointer,
        width: guard.width,
    })
}

/// Whether the loader writes any byte of `range`: one search.
pub fn written(program: &dyn Program, range: &Range<u64>) -> bool {
    r2abi::statement::writes_any(program.loader_writes(), range)
}

/// What the `width`-byte word at `place` holds when the program starts, where
/// the container states it; `None` where it does not.
///
/// A word the loader leaves alone is read from this revision's bytes, in the
/// container's byte order. A word the loader writes is its stated value where
/// one write covers exactly those bytes and states an address; a word part
/// written, or written with a value chosen when the program runs, states
/// nothing. `O(log W)` in the loader's writes.
pub fn stated_word(
    program: &dyn Program,
    place: u64,
    width: u32,
    endian: r2il::Endianness,
) -> Option<StatedWord> {
    let bytes = usize::try_from(width)
        .ok()
        .filter(|bytes| (1..=8).contains(bytes))?;
    let end = place.checked_add(u64::from(width))?;
    let writes = program.loader_writes();
    if r2abi::statement::writes_any(writes, &(place..end)) {
        let write = r2abi::statement::write_at(writes, place)?;
        let exact = write.place == place && write.width == u64::from(width);
        return exact
            .then(|| write.value())
            .flatten()
            .map(StatedWord::Loaded);
    }
    let read = program
        .read(place, bytes)
        .filter(|read| read.len() == bytes)?;
    let mut word = [0u8; 8];
    word[..bytes].copy_from_slice(&read);
    Some(StatedWord::Held(match endian {
        r2il::Endianness::Little => u64::from_le_bytes(word),
        r2il::Endianness::Big => u64::from_be_bytes(word) >> (8 * (8 - bytes)),
        // Nothing says which way a word reads here, so nothing is claimed.
        r2il::Endianness::Mixed | r2il::Endianness::Custom => return None,
    }))
}

/// The bytes of instructions as the program runs them: the file's, with each field the loader writes re-encoded where the container states its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub bytes: Vec<u8>,
    /// Each written field whose value the container does not state, sorted.
    unstated: Vec<Range<u64>>,
}

impl Code {
    /// Whether the instruction at `range` holds a field the loader writes with no value stated: what it decodes there is not what runs.
    pub fn unstated(&self, range: &Range<u64>) -> bool {
        let first = self
            .unstated
            .partition_point(|field| field.end <= range.start);
        self.unstated
            .get(first)
            .is_some_and(|field| field.start < range.end)
    }
}

/// The `bytes` at `at` once the loader is done: each write holds what its encoding states, else the
/// file's bytes or an unstated range (audit W5). `O(log W + k)` for `k` writes.
pub fn code(
    writes: &[crate::program::LoaderWrite],
    at: u64,
    mut bytes: Vec<u8>,
    endian: r2il::Endianness,
) -> Code {
    use r2abi::statement::{Encoding, WriteKind};
    let end = at.saturating_add(bytes.len() as u64);
    let first = writes.partition_point(|write| write.end() <= at);
    let mut unstated = Vec::new();
    for write in writes[first..].iter().take_while(|write| write.place < end) {
        let inside = write.place >= at && write.end() <= end;
        let from = write.place.wrapping_sub(at) as usize;
        let encoded = match (write.encoding, &write.kind) {
            (Encoding::Word, WriteKind::Unknown | WriteKind::Reserved | WriteKind::Copy { .. }) => {
                continue;
            }
            (Encoding::Word, _) => {
                (write.target()).and_then(|value| encode(value, write.width, endian))
            }
            (Encoding::FromPlace, _) => write
                .target()
                .map(|target| target.wrapping_sub(write.place))
                .filter(|field| fits(*field, write.width))
                .and_then(|value| encode(value, write.width, endian)),
            // An AArch64 instruction is little-endian whatever the data's order.
            (Encoding::Field(field), _) if inside => {
                let word = bytes[from..from + write.width as usize].try_into().ok();
                (word.map(u32::from_le_bytes).zip(write.target()))
                    .and_then(|(insn, target)| field.patch(insn, write.place, target))
                    .map(|insn| insn.to_le_bytes().to_vec())
            }
            (Encoding::Field(_) | Encoding::Typed, _) => None,
        };
        let (Some(encoded), true) = (encoded, inside) else {
            unstated.push(write.place..write.end());
            continue;
        };
        bytes[from..from + encoded.len()].copy_from_slice(&encoded);
    }
    Code { bytes, unstated }
}

/// Whether a signed difference fits a field of `width` bytes.
fn fits(value: u64, width: u64) -> bool {
    match width {
        8 => true,
        1..=7 => {
            let bits = 8 * width as u32;
            let signed = value as i64;
            signed >= -(1i64 << (bits - 1)) && signed < (1i64 << (bits - 1))
        }
        _ => false,
    }
}

/// `value`'s low `width` bytes in the program's byte order.
fn encode(value: u64, width: u64, endian: r2il::Endianness) -> Option<Vec<u8>> {
    let width = usize::try_from(width)
        .ok()
        .filter(|width| (1..=8).contains(width))?;
    Some(match endian {
        r2il::Endianness::Little => value.to_le_bytes()[..width].to_vec(),
        r2il::Endianness::Big => value.to_be_bytes()[8 - width..].to_vec(),
        r2il::Endianness::Mixed | r2il::Endianness::Custom => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2abi::statement::{Encoding, LoaderWrite, WriteKind};

    fn write(place: u64, width: u64, kind: WriteKind, encoding: Encoding) -> LoaderWrite {
        LoaderWrite {
            place,
            width,
            kind,
            encoding,
        }
    }

    /// A base relocation's word holds its link-time value; an import's word and a field out of reach hold none.
    #[test]
    fn only_a_stated_value_is_encoded_and_a_word_with_none_keeps_the_files_link_time_value() {
        let import = WriteKind::Import {
            symbol: "f".into(),
            library: None,
        };
        let writes = [
            write(0x10, 4, WriteKind::Unknown, Encoding::Word),
            write(0x14, 4, WriteKind::Absolute(0x1000), Encoding::FromPlace),
            write(0x18, 4, import, Encoding::Word),
            write(0x1c, 1, WriteKind::Absolute(0x1000), Encoding::FromPlace),
        ];
        let code = code(&writes, 0x10, vec![0xaa; 16], r2il::Endianness::Little);
        assert_eq!(
            &code.bytes[..8],
            &[0xaa, 0xaa, 0xaa, 0xaa, 0xec, 0x0f, 0, 0]
        );
        assert!(!code.unstated(&(0x10..0x18)));
        assert!(code.unstated(&(0x17..0x19)), "the import's word");
        assert!(
            code.unstated(&(0x1c..0x1d)),
            "0x1000 - 0x1c does not fit a byte"
        );
    }

    /// wc.o's `adrp x9; add x9, x9, :lo12:` against `.bss` at 0x08001bd0 reads as radare2 applies it
    /// (`090000b0 29412f91`), and `bl` takes its word distance; a branch out of reach stays unstated.
    #[test]
    fn an_aarch64_immediate_holds_its_target_as_its_relocation_type_encodes_it() {
        use r2abi::statement::InstructionField as F;
        let (bss, place) = (WriteKind::Absolute(0x0800_1bd0), 0x0800_0118);
        let writes = [
            write(
                place,
                4,
                bss.clone(),
                Encoding::Field(F::Page21 { checked: true }),
            ),
            write(place + 4, 4, bss, Encoding::Field(F::Lo12 { shift: 0 })),
            write(
                place + 8,
                4,
                WriteKind::Absolute(place - 0x400),
                Encoding::Field(F::Branch26),
            ),
            write(
                place + 12,
                4,
                WriteKind::Absolute(place + (1 << 28)),
                Encoding::Field(F::Branch26),
            ),
        ];
        let words: [u32; 4] = [0x9000_0009, 0x9100_0129, 0x9400_0000, 0x9400_0000];
        let bytes = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        // Big-endian data leaves the instruction words little-endian.
        let code = code(&writes, place, bytes, r2il::Endianness::Big);
        let held = (code.bytes.chunks(4))
            .map(|word| u32::from_le_bytes(word.try_into().expect("a word")))
            .collect::<Vec<_>>();
        assert_eq!(held, [0xb000_0009, 0x912f_4129, 0x97ff_fefe, 0x9400_0000]);
        assert!(!code.unstated(&(place..place + 12)));
        assert!(
            code.unstated(&(place + 12..place + 16)),
            "bl reaches 128 MiB"
        );
    }

    #[test]
    fn an_aarch64_field_refuses_a_value_it_cannot_hold() {
        use r2abi::statement::InstructionField as F;
        // ldr x0, [x1, :lo12:] of a target 4 bytes past a doubleword.
        assert_eq!(F::Lo12 { shift: 3 }.patch(0xf940_0020, 0, 0x1004), None);
        assert_eq!(
            F::Lo12 { shift: 3 }.patch(0xf940_0020, 0, 0x1008),
            Some(0xf940_0420)
        );
        // movz x0, #:abs_g0: of a value past 16 bits; the _NC type keeps the low half.
        let movz = 0xd280_0000;
        let wide = F::MovW {
            group: 0,
            checked: true,
        };
        assert_eq!(wide.patch(movz, 0, 0x1_2345), None);
        let narrow = F::MovW {
            group: 0,
            checked: false,
        };
        assert_eq!(narrow.patch(movz, 0, 0x1_2345), Some(movz | 0x2345 << 5));
        // b.eq one word back, and a misaligned branch.
        assert_eq!(
            F::Branch19.patch(0x5400_0000, 0x1004, 0x1000),
            Some(0x54ff_ffe0)
        );
        assert_eq!(F::Branch19.patch(0x5400_0000, 0x1004, 0x1002), None);
    }
}
