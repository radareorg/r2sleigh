//! What each section holds, as the container states it.
//!
//! From the section's own type and flags, and from the program headers that
//! locate the loader's and the unwinder's tables; never from a name, with the
//! one exception Mach-O itself makes: its runtime finds the unwind tables by
//! segment and section name, so that name is the format's statement of them.

use object::read::{Object, ObjectSection, ObjectSegment};
use object::{SectionKind, elf, macho};

use r2abi::statement::SectionRole;

/// The program headers and segments a section's role is read against.
pub(crate) struct Located {
    /// `PT_INTERP`: the interpreter's path, which is the loader's.
    interpreter: Vec<(u64, u64)>,
    /// `PT_GNU_EH_FRAME`, and the address its `eh_frame_ptr` names.
    unwind: Vec<(u64, u64)>,
    eh_frame: Option<u64>,
    /// Each Mach-O segment by name: whether the program may write it once dyld is done.
    writable: Vec<(Vec<u8>, bool)>,
}

impl Located {
    pub(crate) fn of(file: &object::File<'_>) -> Self {
        let mut located = Self {
            interpreter: Vec::new(),
            unwind: Vec::new(),
            eh_frame: None,
            writable: Vec::new(),
        };
        match file {
            object::File::Elf32(elf) => located.elf(elf),
            object::File::Elf64(elf) => located.elf(elf),
            _ => {}
        }
        const SG_READ_ONLY: u32 = 0x10;
        for segment in file.segments() {
            if let object::SegmentFlags::MachO {
                flags, initprot, ..
            } = segment.flags()
            {
                let name = segment.name_bytes().ok().flatten().unwrap_or_default();
                let writable = initprot & macho::VM_PROT_WRITE != 0 && flags & SG_READ_ONLY == 0;
                located.writable.push((name.to_vec(), writable));
            }
        }
        located
    }

    fn elf<'data, E: object::read::elf::FileHeader, R: object::ReadRef<'data>>(
        &mut self,
        file: &object::read::elf::ElfFile<'data, E, R>,
    ) {
        use object::read::elf::ProgramHeader as _;
        let endian = file.endian();
        for header in file.elf_program_headers() {
            let range: (u64, u64) = (header.p_vaddr(endian).into(), header.p_memsz(endian).into());
            match header.p_type(endian) {
                elf::PT_INTERP => self.interpreter.push(range),
                elf::PT_GNU_EH_FRAME => {
                    self.unwind.push(range);
                    let bytes = header.data(endian, file.data()).unwrap_or_default();
                    self.eh_frame =
                        eh_frame_ptr(bytes, range.0, file.is_little_endian(), file.is_64());
                }
                _ => {}
            }
        }
    }

    /// What one section holds.
    pub(crate) fn role(&self, section: &object::read::Section<'_, '_>, code: bool) -> SectionRole {
        if code {
            return SectionRole::Code;
        }
        let start = section.address();
        let end = start.saturating_add(section.size());
        let within = |ranges: &[(u64, u64)]| {
            ranges.iter().any(|(at, size)| {
                start >= *at && end <= at.saturating_add(*size) && section.size() > 0
            })
        };
        match section.flags() {
            object::SectionFlags::Elf { .. } => {
                let unwind =
                    within(&self.unwind) || self.eh_frame.is_some_and(|at| at >= start && at < end);
                match section.kind() {
                    SectionKind::UninitializedData => SectionRole::ZeroFill,
                    SectionKind::Note | SectionKind::Metadata => SectionRole::LoaderMetadata,
                    SectionKind::Elf(kind) => elf_kind(kind),
                    SectionKind::ReadOnlyString => SectionRole::Strings,
                    SectionKind::Data => SectionRole::Data,
                    SectionKind::ReadOnlyData if within(&self.interpreter) => {
                        SectionRole::LoaderMetadata
                    }
                    SectionKind::ReadOnlyData if unwind => SectionRole::Unwind,
                    SectionKind::ReadOnlyData => SectionRole::ReadOnlyData,
                    _ => SectionRole::Other,
                }
            }
            object::SectionFlags::MachO { flags } => {
                let segment = section
                    .segment_name_bytes()
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let name = section.name_bytes().unwrap_or_default();
                match flags & macho::SECTION_TYPE {
                    macho::S_ZEROFILL | macho::S_GB_ZEROFILL => SectionRole::ZeroFill,
                    macho::S_CSTRING_LITERALS => SectionRole::Strings,
                    macho::S_THREAD_LOCAL_REGULAR
                    | macho::S_THREAD_LOCAL_ZEROFILL
                    | macho::S_THREAD_LOCAL_VARIABLES
                    | macho::S_THREAD_LOCAL_VARIABLE_POINTERS
                    | macho::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => SectionRole::Other,
                    // libunwind and dyld find these by segment and section name.
                    _ if segment == b"__TEXT"
                        && matches!(name, b"__eh_frame" | b"__unwind_info") =>
                    {
                        SectionRole::Unwind
                    }
                    _ => {
                        let writable = self
                            .writable
                            .iter()
                            .find(|(named, _)| named.as_slice() == segment)
                            .is_some_and(|(_, writable)| *writable);
                        match writable {
                            true => SectionRole::Data,
                            false => SectionRole::ReadOnlyData,
                        }
                    }
                }
            }
            object::SectionFlags::Coff { characteristics } => {
                use object::pe;
                if characteristics & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                    SectionRole::ZeroFill
                } else if characteristics & pe::IMAGE_SCN_MEM_WRITE != 0 {
                    SectionRole::Data
                } else {
                    SectionRole::ReadOnlyData
                }
            }
            _ => match section.kind() {
                SectionKind::UninitializedData => SectionRole::ZeroFill,
                SectionKind::ReadOnlyString => SectionRole::Strings,
                SectionKind::Data => SectionRole::Data,
                SectionKind::ReadOnlyData => SectionRole::ReadOnlyData,
                _ => SectionRole::Other,
            },
        }
    }
}

/// What an ELF section type the `object` crate leaves unnamed holds.
fn elf_kind(kind: u32) -> SectionRole {
    const SHT_GNU_ATTRIBUTES: u32 = 0x6fff_fff5;
    const SHT_GNU_HASH: u32 = 0x6fff_fff6;
    const SHT_GNU_LIBLIST: u32 = 0x6fff_fff7;
    const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
    const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
    const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
    const SHT_ANDROID_REL: u32 = 0x6000_0001;
    const SHT_ANDROID_RELA: u32 = 0x6000_0002;
    const SHT_ANDROID_RELR: u32 = 0x6fff_ff00;
    match kind {
        // Pointers to functions the loader or start-up calls: the program's data, which the loader writes.
        elf::SHT_INIT_ARRAY | elf::SHT_FINI_ARRAY | elf::SHT_PREINIT_ARRAY => SectionRole::Data,
        SHT_GNU_ATTRIBUTES | SHT_GNU_HASH | SHT_GNU_LIBLIST | SHT_GNU_VERDEF | SHT_GNU_VERNEED
        | SHT_GNU_VERSYM | SHT_ANDROID_REL | SHT_ANDROID_RELA | SHT_ANDROID_RELR => {
            SectionRole::LoaderMetadata
        }
        _ => SectionRole::Other,
    }
}

/// The address `.eh_frame_hdr`'s `eh_frame_ptr` names, in the encodings a linker writes it in.
fn eh_frame_ptr(bytes: &[u8], at: u64, little: bool, is_64: bool) -> Option<u64> {
    const DW_EH_PE_PCREL: u8 = 0x10;
    const DW_EH_PE_DATAREL: u8 = 0x30;
    let (version, encoding) = (*bytes.first()?, *bytes.get(1)?);
    if version != 1 {
        return None;
    }
    let read = |width: usize, signed: bool| -> Option<u64> {
        let field = bytes.get(4..4 + width)?;
        let mut value = 0u64;
        for (index, byte) in field.iter().enumerate() {
            let shift = match little {
                true => 8 * index,
                false => 8 * (width - 1 - index),
            };
            value |= u64::from(*byte) << shift;
        }
        let bits = 8 * width as u32;
        Some(match signed && bits < 64 && value >> (bits - 1) & 1 == 1 {
            true => value | (u64::MAX << bits),
            false => value,
        })
    };
    let value = match encoding & 0x0f {
        0x00 => read(if is_64 { 8 } else { 4 }, false)?,
        0x02 => read(2, false)?,
        0x03 => read(4, false)?,
        0x04 => read(8, false)?,
        0x0a => read(2, true)?,
        0x0b => read(4, true)?,
        0x0c => read(8, true)?,
        _ => return None,
    };
    match encoding & 0x70 {
        0 => Some(value),
        DW_EH_PE_PCREL => Some(at.wrapping_add(4).wrapping_add(value)),
        DW_EH_PE_DATAREL => Some(at.wrapping_add(value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_eh_frame_ptr_is_read_relative_to_its_own_field() {
        // version 1, pcrel|sdata4, then -0x10 from the field at 0x2004.
        let bytes = [1, 0x1b, 0x03, 0x3b, 0xf0, 0xff, 0xff, 0xff];
        assert_eq!(eh_frame_ptr(&bytes, 0x2000, true, true), Some(0x1ff4));
    }
}
