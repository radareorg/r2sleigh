//! What the binary's call-frame information says about each function's frame.
//!
//! `.eh_frame` survives `strip --strip-all`: the C++ runtime and every
//! unwinder need it, so a stripped binary still states, for each function it
//! covers, where the function starts and ends and where it saves each register
//! it preserves. That is a fact the container states, not one inferred from
//! the code, and the frame partition takes its save slots as boundaries no
//! local may cross.
//!
//! Each save is placed relative to the stack pointer on entry. The CFI places
//! it relative to the CFA, and the CFA at the function's first address is the
//! entry stack pointer plus a constant the CIE states (`rsp + 8` on x86-64,
//! `sp + 0` on AArch64). A frame whose CFA at entry is not stated that way, or
//! is not stated from the stack pointer, has its extent read and its saves
//! refused: a slot placed from a guessed CFA would be a guessed boundary.
//!
//! It fails closed per entry. An FDE that does not parse is skipped; the rest
//! of the section is still read.

use std::collections::BTreeMap;

/// One function the call-frame information describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindFrame {
    /// The first address the entry covers.
    pub start: u64,
    /// One past the last address it covers.
    pub end: u64,
    /// Where each register the function preserves is saved, as a DWARF
    /// register number and an offset from the stack pointer on entry. Empty
    /// when the CFA on entry is not stated from the stack pointer.
    pub saves: BTreeMap<u16, i64>,
}

/// Every frame the call-frame information states, by start address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnwindFrames {
    by_start: BTreeMap<u64, UnwindFrame>,
}

impl UnwindFrames {
    pub fn frames(&self) -> impl Iterator<Item = &UnwindFrame> {
        self.by_start.values()
    }

    /// The frame that starts at this address.
    pub fn at(&self, start: u64) -> Option<&UnwindFrame> {
        self.by_start.get(&start)
    }

    /// The frame that covers this address. Frames do not overlap, so the
    /// nearest start at or below the address is the only candidate.
    pub fn covering(&self, address: u64) -> Option<&UnwindFrame> {
        self.by_start
            .range(..=address)
            .next_back()
            .map(|(_, frame)| frame)
            .filter(|frame| address < frame.end)
    }

    pub fn is_empty(&self) -> bool {
        self.by_start.is_empty()
    }

    fn insert(&mut self, frame: UnwindFrame) {
        // `.eh_frame` and `.debug_frame` may both describe a function. They
        // describe one frame; the first read is kept.
        self.by_start.entry(frame.start).or_insert(frame);
    }
}

/// The DWARF number of the stack pointer, for the architectures whose CFI this
/// reads. `None` for an architecture whose numbering is not stated here, which
/// reads every frame's extent and no saves.
pub(crate) fn stack_pointer_register(architecture: object::Architecture) -> Option<u16> {
    match architecture {
        object::Architecture::X86_64 | object::Architecture::X86_64_X32 => Some(7),
        object::Architecture::I386 => Some(4),
        object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32 => Some(31),
        object::Architecture::Arm => Some(13),
        object::Architecture::Riscv32 | object::Architecture::Riscv64 => Some(2),
        _ => None,
    }
}

/// Read every frame `.eh_frame` and `.debug_frame` describe.
pub(crate) fn read(file: &object::File<'_>) -> UnwindFrames {
    use object::{Object as _, ObjectSection as _};
    let endian = match file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };
    let stack_pointer = stack_pointer_register(file.architecture());
    let address_size = if file.is_64() { 8 } else { 4 };
    let section = |name: &str| {
        file.section_by_name(name)
            .and_then(|section| Some((section.address(), section.data().ok()?)))
    };
    let mut bases = gimli::BaseAddresses::default();
    if let Some((address, _)) = section(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(address);
    }
    if let Some((address, _)) = section(".text") {
        bases = bases.set_text(address);
    }
    if let Some((address, _)) = section(".got") {
        bases = bases.set_got(address);
    }
    let mut frames = UnwindFrames::default();
    if let Some((address, data)) = section(".eh_frame") {
        let mut eh_frame = gimli::EhFrame::new(data, endian);
        eh_frame.set_address_size(address_size);
        let bases = bases.clone().set_eh_frame(address);
        read_section(&eh_frame, &bases, stack_pointer, &mut frames);
    }
    if let Some((_, data)) = section(".debug_frame") {
        let mut debug_frame = gimli::DebugFrame::new(data, endian);
        debug_frame.set_address_size(address_size);
        read_section(&debug_frame, &bases, stack_pointer, &mut frames);
    }
    frames
}

fn read_section<'a, S>(
    section: &S,
    bases: &gimli::BaseAddresses,
    stack_pointer: Option<u16>,
    frames: &mut UnwindFrames,
) where
    S: gimli::UnwindSection<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    S::Offset: gimli::UnwindOffset<usize>,
{
    let mut context = gimli::UnwindContext::new();
    let mut entries = section.entries(bases);
    loop {
        let entry = match entries.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            // A malformed length stops the walk: nothing after it can be found.
            Err(_) => break,
        };
        let gimli::CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) =
            partial.parse(|section, bases, offset| section.cie_from_offset(bases, offset))
        else {
            continue;
        };
        if fde.len() == 0 {
            continue;
        }
        let start = fde.initial_address();
        let Some(end) = start.checked_add(fde.len()) else {
            continue;
        };
        let saves = stack_pointer
            .and_then(|stack_pointer| saves(section, bases, &mut context, &fde, stack_pointer))
            .unwrap_or_default();
        frames.insert(UnwindFrame { start, end, saves });
    }
}

/// Where the function saves each register, from the stack pointer on entry.
///
/// A save keeps its place for the rest of the function, so the union over
/// every row is the set of save slots. `None` when the CFA at the first row is
/// not the stack pointer plus a constant: the entry stack pointer is then not
/// what the offsets are measured from.
fn saves<'a, S>(
    section: &S,
    bases: &gimli::BaseAddresses,
    context: &mut gimli::UnwindContext<usize>,
    fde: &gimli::FrameDescriptionEntry<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    stack_pointer: u16,
) -> Option<BTreeMap<u16, i64>>
where
    S: gimli::UnwindSection<gimli::EndianSlice<'a, gimli::RunTimeEndian>>,
    S::Offset: gimli::UnwindOffset<usize>,
{
    let mut table = fde.rows(section, bases, context).ok()?;
    let mut entry_cfa = None;
    let mut saves = BTreeMap::new();
    while let Some(row) = table.next_row().ok()? {
        if entry_cfa.is_none() {
            // The first row is the state at the function's first address.
            let gimli::CfaRule::RegisterAndOffset { register, offset } = row.cfa() else {
                return None;
            };
            if register.0 != stack_pointer {
                return None;
            }
            entry_cfa = Some(*offset);
        }
        let cfa = entry_cfa?;
        for (register, rule) in row.registers() {
            if let gimli::RegisterRule::Offset(offset) = rule {
                // Saved at CFA + offset, and the CFA is the entry stack
                // pointer plus the constant the first row states.
                saves.insert(register.0, cfa.checked_add(*offset)?);
            }
        }
    }
    Some(saves)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames_of(bytes: &[u8]) -> UnwindFrames {
        let file = object::File::parse(bytes).expect("an object");
        read(&file)
    }

    /// The DWARF fixture is a clang x86-64 ELF; its `.eh_frame` describes every
    /// function. Each frame's first save is the return address (column 16) at
    /// the entry stack pointer itself, and a frame-pointer prologue saves rbp
    /// (column 6) in the eight bytes below it.
    #[test]
    fn every_frame_states_its_extent_and_where_the_return_address_is() {
        let frames = frames_of(include_bytes!("../tests/data/dwarf_prototypes.elf"));
        assert!(!frames.is_empty());
        for frame in frames.frames() {
            assert!(frame.start < frame.end, "{frame:?}");
            assert_eq!(frame.saves.get(&16), Some(&0), "{frame:?}");
            if let Some(rbp) = frame.saves.get(&6) {
                assert_eq!(*rbp, -8, "{frame:?}");
            }
        }
        let first = frames.frames().next().expect("a frame");
        assert_eq!(frames.covering(first.start), Some(first));
        assert_eq!(frames.covering(first.end), frames.at(first.end));
        assert!(
            frames
                .frames()
                .any(|frame| frame.saves.get(&6) == Some(&-8)),
            "a frame-pointer prologue saves rbp: {frames:?}"
        );
    }

    /// `strip --strip-all` keeps `.eh_frame`: the stripped twin states the
    /// same frames.
    #[test]
    fn a_stripped_binary_states_the_same_frames() {
        let full = frames_of(include_bytes!("../tests/data/dwarf_prototypes.elf"));
        let stripped = frames_of(include_bytes!(
            "../tests/data/dwarf_prototypes_stripped.elf"
        ));
        assert_eq!(full, stripped);
    }
}
