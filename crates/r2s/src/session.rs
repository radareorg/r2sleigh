//! The shell's state: the open binary and the seek cursor.
//!
//! The shell is what opens the file. It parses the container once, hands the
//! engine the bytes and what the container states through `Source`, and keeps
//! the cursor. Everything derived from those -- names, import stubs, what is
//! defined where -- is the engine's.

use r2engine::program::{
    Arch, Container, Entry, EntryKind, Format, Mapping, OpenProgram, Permissions, Relocation,
    Section, Segment, Source, Symbol, SymbolKind,
};
use r2image::Image;

pub struct Session {
    pub program: OpenProgram<Opened>,
    pub path: String,
    /// Where `pd`, `px` and the rest read from when no address is given.
    pub addr: u64,
}

impl Session {
    pub fn open(path: &str) -> Result<Self, String> {
        let image = Image::open(path).map_err(|error| error.to_string())?;
        let program = OpenProgram::of(Opened::of(image));
        Ok(Self {
            addr: program.start().unwrap_or(0),
            program,
            path: path.to_owned(),
        })
    }

    /// The binary as the container states it.
    pub fn image(&self) -> &Image {
        &self.program.source().image
    }

    /// The binary, to be written to.
    pub fn image_mut(&mut self) -> &mut Image {
        &mut self.program.source_mut().image
    }
}

/// An opened binary, as the engine reads it.
pub struct Opened {
    pub image: Image,
    /// What the container states, projected once: a write changes bytes and
    /// never which sections or symbols exist.
    container: Container,
}

impl Opened {
    fn of(image: Image) -> Self {
        let container = container_of(&image);
        Self { image, container }
    }
}

impl Source for Opened {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.image
            .read_upto(vaddr, max)
            .map(std::borrow::Cow::into_owned)
    }

    fn container(&self) -> &Container {
        &self.container
    }

    fn identity(&self) -> u64 {
        self.image.identity()
    }

    fn byte_revision(&self) -> u64 {
        self.image.byte_revision()
    }

    fn written_since(&self, revision: u64, range: &std::ops::Range<u64>) -> bool {
        self.image.written_since(revision, range)
    }
}

/// Where the loader maps the program and what it permits there, sorted and
/// disjoint as the image keeps them: the load segments, or an object's placed
/// sections.
fn segments_of(image: &Image) -> Vec<Segment> {
    image
        .segments()
        .iter()
        .map(|segment| Segment {
            vaddr: segment.vaddr,
            vsize: segment.vsize,
            permissions: Permissions {
                read: segment.permissions.read,
                write: segment.permissions.write,
                execute: segment.permissions.execute,
            },
        })
        .collect()
}

/// What the container states, in the engine's words.
fn container_of(image: &Image) -> Container {
    let arch = image.arch();
    Container {
        format: match image.format() {
            r2image::Format::Elf => Format::Elf,
            r2image::Format::MachO => Format::MachO,
            _ => Format::Other,
        },
        arch: Arch {
            name: arch.name.to_owned(),
            bits: arch.bits,
            endian: match arch.endian {
                r2image::Endian::Little => r2il::Endianness::Little,
                r2image::Endian::Big => r2il::Endianness::Big,
            },
        },
        segments: segments_of(image),
        sections: image
            .sections()
            .iter()
            .map(|section| Section {
                name: section.name.clone(),
                vaddr: section.vaddr,
                vsize: section.vsize,
                is_code: section.is_code,
                loaded: section.loaded,
            })
            .collect(),
        symbols: image
            .symbols()
            .iter()
            .map(|symbol| Symbol {
                name: symbol.name.clone(),
                vaddr: symbol.vaddr,
                size: symbol.size,
                kind: match symbol.kind {
                    r2image::SymbolKind::Function => SymbolKind::Function,
                    r2image::SymbolKind::Data => SymbolKind::Data,
                    r2image::SymbolKind::Section => SymbolKind::Section,
                    r2image::SymbolKind::Other => SymbolKind::Other,
                    r2image::SymbolKind::Mapping(mapping) => SymbolKind::Mapping(match mapping {
                        r2image::Mapping::Arm => Mapping::Arm,
                        r2image::Mapping::Thumb => Mapping::Thumb,
                        r2image::Mapping::Data => Mapping::Data,
                    }),
                },
                defined: symbol.defined,
                thumb: symbol.thumb,
            })
            .collect(),
        relocations: image
            .relocations()
            .iter()
            .map(|relocation| Relocation {
                vaddr: relocation.vaddr,
                symbol: relocation.symbol.clone(),
            })
            .collect(),
        loader_writes: image.loader_writes().to_vec(),
        entries: image
            .entry_points()
            .iter()
            .map(|entry| Entry {
                vaddr: entry.vaddr,
                kind: match entry.kind {
                    r2image::EntryKind::Main => EntryKind::Main,
                    r2image::EntryKind::Init => EntryKind::Init,
                    r2image::EntryKind::Fini => EntryKind::Fini,
                    r2image::EntryKind::Symbol => EntryKind::Symbol,
                    r2image::EntryKind::CMain => EntryKind::CMain,
                    r2image::EntryKind::Declared => EntryKind::Declared,
                },
                thumb: entry.thumb,
            })
            .collect(),
        declared: image.debug_prototypes().prototypes().collect(),
    }
}
