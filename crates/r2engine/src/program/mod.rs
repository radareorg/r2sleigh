//! An open binary, and everything the engine derives from its bytes.
//!
//! The input boundary used to live in the shell: it owned the `Image`, read
//! the container for names, decoded the linkage stubs, indexed what the
//! binary defines, and implemented both `Program` traits over the result. That
//! made every consumer of the engine reimplement the same half-dozen tables,
//! and it made the shell the only thing that knew when they went stale. They
//! belong here, beside the analysis that reads them.

pub mod naming;

// The container's own vocabulary. The engine owns the reading of it, so it
// publishes the words too: every type `Image`'s public API hands back is
// nameable here, and a consumer needs no second dependency to write one down.
pub use r2image::{
    Endian, EntryKind, EntryPoint, Format, Image, ImageArch, ImageError, Relocation, Section,
    Segment, Symbol, SymbolKind,
};

use std::collections::BTreeMap;

use r2sleigh_lift::EmbeddedMachine;

use crate::names::NameDb;
use crate::native::{NativeRefusal, NativeTarget, Prepared};
use crate::query::{Decoders, Memo, Revision};

/// What the binary defines at one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// Whether a function begins here, which is what bounds a body.
    pub function: bool,
    /// Whether this function's code is Thumb rather than ARM.
    pub thumb: bool,
}

/// Everything a native request needs that is not the decoder itself.
pub struct Assembled {
    /// Which architecture and compiler specification this was built for, so a
    /// second instruction set in one program gets its own rather than this one.
    machine: (String, &'static str),
    pub conventions: r2abi::Conventions,
    pub compiler: r2abi::CompilerSpec,
    pub prototypes: r2abi::Prototypes,
    /// The register a call returns through, in the coordinates the lift spells.
    pub link: Option<r2il::Varnode>,
}

/// One open binary: its bytes, its decoders, and the tables read out of both.
pub struct OpenProgram {
    pub image: Image,
    /// What this binary calls each address it names.
    pub names: NameDb,
    /// Which stub stands for which import, by the import's own name.
    pub imports: BTreeMap<u64, String>,
    /// Which import each slot the loader fills stands for. A stub's tail
    /// transfer names the slot it reads rather than any code address, so the
    /// slot has to answer for the import too; only a stub is an entry.
    pub slots: BTreeMap<u64, String>,
    /// What this binary defines at each address, indexed once.
    ///
    /// The engine asks this per call target and per branch target of every
    /// body it walks, and answering it by scanning the symbol table made the
    /// walk cost one pass over every symbol per edge.
    pub defined: BTreeMap<u64, Definition>,
    /// Which revision of the image's bytes the tables above were derived at.
    ///
    /// All of them are read out of the image, and one is *decoded* from it:
    /// the import table comes from lifting the stub section. A patch changes
    /// what those say, and `imports` decides `is_entry`, which is what bounds
    /// every body walk -- so a stale table is not a stale listing, it is a
    /// body that ends in the wrong place.
    derived_at: Option<u64>,
    /// How many times the rebuilt name table has actually differed.
    ///
    /// Separate from the byte revision because most patches rename nothing:
    /// anything that depended only on a name stays good across them, and one
    /// counter for both would throw that away.
    names_revision: u64,
    /// The same, for what the binary defines at each address.
    entries_revision: u64,
    assembled: Option<Assembled>,
    /// What this session has already worked out about one function.
    memo: Memo<Prepared>,
    /// The control for the request in hand: its cancellation, its deadline and
    /// the work it has spent. Held here so a caller can reach it while the
    /// request runs, which is the whole point of having one.
    control: crate::EngineExecutionControl,
    machine: Option<EmbeddedMachine>,
    /// The same instruction set with TMode set. ARM states the mode per
    /// function in the low bit of its symbol, so both decoders are needed at
    /// once and neither is the image's.
    thumb_machine: Option<EmbeddedMachine>,
}

impl OpenProgram {
    pub fn open(path: &str) -> Result<Self, String> {
        Ok(Self::of(Image::open(path).map_err(|e| e.to_string())?))
    }

    pub fn of(image: Image) -> Self {
        Self {
            names: {
                let mut db = naming::of(&image);
                naming::name_strings(&mut db, &image);
                db
            },
            imports: BTreeMap::new(),
            slots: BTreeMap::new(),
            defined: definitions(&image),
            image,
            // The import table needs a decoder, so nothing here is derived yet.
            derived_at: None,
            names_revision: 0,
            entries_revision: 0,
            assembled: None,
            memo: Memo::default(),
            control: crate::EngineExecutionControl::default(),
            machine: None,
            thumb_machine: None,
        }
    }

    /// Make everything derived from the image current.
    ///
    /// The machine is loaded once: which instruction set a file is written in
    /// is a property of the file and no patch changes it. Everything else is
    /// read or decoded out of the bytes, so it is derived again whenever the
    /// image says it is at a different revision.
    ///
    /// Separate from reading the machine so a caller can hold the machine and
    /// the image at once; one method returning a reference out of `&mut self`
    /// would make those two borrows conflict.
    pub fn ensure_current(&mut self) -> Result<(), String> {
        if self.machine.is_none() {
            self.machine = Some(
                r2sleigh_lift::embedded_machine(self.image.arch().name)
                    .map_err(|error| error.to_string())?,
            );
        }
        let revision = self.image.byte_revision();
        if self.derived_at == Some(revision) {
            return Ok(());
        }
        // Taken out and put back so the decoder can be read while the tables it
        // fills are written.
        let machine = self.machine.take().expect("the machine is loaded above");
        let mut names = naming::of(&self.image);
        naming::name_strings(&mut names, &self.image);
        let defined = definitions(&self.image);
        // The import stubs can only be read once there is a decoder.
        let imports = naming::imports(&self.image, &machine.disasm, machine.arch.alignment);
        self.slots = self
            .image
            .relocations()
            .iter()
            .map(|relocation| (relocation.vaddr, relocation.symbol.clone()))
            .collect();
        naming::name_imports(&mut names, self.image.format(), &imports);
        naming::name_slots(&mut names, self.image.format(), &self.slots, &imports);
        // A patch that changed no name and moved no entry leaves everything
        // derived from those still good, so the counters move only on a
        // difference rather than on every write.
        self.names_revision += u64::from(names != self.names);
        self.entries_revision += u64::from(defined != self.defined || imports != self.imports);
        self.names = names;
        self.defined = defined;
        self.imports = imports;
        self.machine = Some(machine);
        // Only where a function says it is Thumb, so a machine with no Thumb
        // code pays nothing for the second specification.
        self.thumb_machine = match self.defined.values().any(|definition| definition.thumb) {
            true => r2sleigh_lift::embedded_machine("arm-thumb").ok(),
            false => None,
        };
        self.derived_at = Some(revision);
        Ok(())
    }

    /// Assemble what a native request needs, once per program and machine.
    ///
    /// All of it is constant while one program is open, and rebuilding it per
    /// command cost two milliseconds -- almost all of it parsing the embedded
    /// prototype table -- on every `pdd`, `pdil`, `afl` and `ax`.
    pub fn ensure_assembled(&mut self, addr: u64) -> Result<(), String> {
        self.ensure_current()?;
        let machine = self
            .machine_at(addr)
            .ok_or("no Sleigh specification for this architecture")?;
        let key = (machine.arch.name.clone(), machine.compiler_spec);
        if self
            .assembled
            .as_ref()
            .is_some_and(|held| held.machine == key)
        {
            return Ok(());
        }
        let bits = self.image.arch().bits;
        let conventions = r2abi::Conventions::for_arch(key.0.as_str(), bits)
            .ok_or_else(|| format!("no calling conventions for {} {bits}", key.0))?;
        let compiler = r2abi::CompilerSpec::parse(machine.compiler_spec);
        // The specification names the register; the architecture says where it
        // lives, and the lift spells writes to it in those coordinates.
        let link = compiler.return_address.as_ref().and_then(|name| {
            machine
                .arch
                .registers
                .iter()
                .find(|register| register.name.eq_ignore_ascii_case(name))
                .map(|register| r2il::Varnode {
                    space: r2il::SpaceId::Register,
                    offset: register.offset,
                    size: register.size,
                    meta: None,
                })
        });
        // The format says which platform's own declarations apply: `_Exit` is
        // declared by the platform, not by the table every target shares.
        let mut prototypes = r2abi::Prototypes::embedded_for(match self.image.format() {
            r2image::Format::Elf => r2abi::Platform::Linux,
            r2image::Format::MachO => r2abi::Platform::Darwin,
            _ => r2abi::Platform::Unknown,
        });
        // What the binary's own debug information says beats the shared table:
        // the table describes what a library is expected to look like, and
        // this describes what this one is.
        prototypes.declare(self.image.debug_prototypes().prototypes());
        self.assembled = Some(Assembled {
            machine: key,
            conventions,
            compiler,
            prototypes,
            link,
        });
        Ok(())
    }

    /// Everything about the machine that does not change between functions.
    ///
    /// Assembled once and handed out, so a caller holds one description of the
    /// program rather than building its own from the parts.
    pub fn target(&self, addr: u64) -> Result<NativeTarget<'_>, String> {
        let machine = self
            .machine_at(addr)
            .ok_or("no Sleigh specification for this architecture")?;
        let assembled = self
            .assembled
            .as_ref()
            .ok_or("the program was not assembled for this address")?;
        Ok(NativeTarget {
            arch: &machine.arch,
            disasm: &machine.disasm,
            cpu: machine.cpu,
            convention: assembled
                .conventions
                .default_convention()
                .ok_or("the convention data names no default")?,
            compiler: &assembled.compiler,
            prototypes: &assembled.prototypes,
        })
    }

    /// One function's analysis, done once per state of this program.
    ///
    /// Every tier is a rendering of this. Asking for the C and then for the
    /// ledger behind it, or for the prepared function and then for its values,
    /// used to walk and prepare the same body twice.
    pub fn analysed(
        &self,
        target: &NativeTarget<'_>,
        entry: u64,
    ) -> Result<std::sync::Arc<Prepared>, NativeRefusal> {
        self.memo.analysed(self.revision(), entry, || {
            crate::native::analysed(target, self, entry)
        })
    }

    /// The control every request against this program runs under.
    pub fn control(&self) -> &crate::EngineExecutionControl {
        &self.control
    }

    /// Start a request, replacing the control the last one ran under.
    ///
    /// A deadline and a cancellation belong to one request, so carrying the
    /// previous request's control into the next would let a stop meant for one
    /// question refuse the next.
    pub fn begin_request(&mut self, control: crate::EngineExecutionControl) {
        self.control = control;
    }

    /// What the memo has been asked and what it holds.
    pub fn memo_stats(&self) -> crate::query::MemoStats {
        self.memo.stats()
    }

    /// What was assembled for the machine at this address.
    pub fn assembled(&self) -> Option<&Assembled> {
        self.assembled.as_ref()
    }

    /// Which state of this program every answer is about.
    pub const fn revision(&self) -> Revision {
        Revision {
            program: self.image.identity(),
            bytes: self.image.byte_revision(),
            names: self.names_revision,
            entries: self.entries_revision,
        }
    }

    /// The decoder the code at this address is written in.
    ///
    /// ARM states the mode per function, in the low bit of the symbol that
    /// names it, so the image has no single answer and the address decides.
    pub fn machine_at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        match self.thumb_at(vaddr) {
            true => self.thumb_machine.as_ref().or(self.machine.as_ref()),
            false => self.machine.as_ref(),
        }
    }

    /// Whether the function containing this address is Thumb.
    pub fn thumb_at(&self, vaddr: u64) -> bool {
        self.defined
            .range(..=vaddr)
            .next_back()
            .is_some_and(|(_, definition)| definition.function && definition.thumb)
    }

    /// How this program spells a word in memory.
    ///
    /// The container states it, and the decoder does not: ARM BE8 puts
    /// little-endian instructions in a big-endian program, so asking the
    /// Sleigh specification gives the wrong answer on exactly the binaries
    /// that have literal pools.
    pub fn endian(&self) -> r2il::Endianness {
        match self.image.arch().endian {
            r2image::Endian::Little => r2il::Endianness::Little,
            r2image::Endian::Big => r2il::Endianness::Big,
        }
    }
}

impl Decoders for OpenProgram {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        self.machine_at(vaddr)
    }
}

impl r2ssa::body::Program for OpenProgram {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.image
            .read_upto(vaddr, max)
            .map(std::borrow::Cow::into_owned)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        // A stub is a function of the program's as much as a body is: control
        // that reaches one has left the function it came from.
        self.imports.contains_key(&vaddr)
            || self
                .defined
                .get(&vaddr)
                .is_some_and(|definition| definition.function)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.assembled.as_ref().and_then(|held| held.link.clone())
    }
}

impl crate::native::Program for OpenProgram {
    fn control(&self) -> crate::EngineExecutionControl {
        // The token and the meter are shared, so this is the request's own
        // control rather than a copy that nothing could stop.
        self.control.clone()
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        // The plain name, with no namespace on it: this keys the prototype
        // table and spells a call, where a listing asks the same entry for
        // `sym.imp.printf`. A slot the loader fills is not in the table --
        // only a stub is an address the program transfers to -- so it is
        // asked for separately.
        self.names
            .text_at(vaddr)
            .map(str::to_owned)
            .or_else(|| self.slots.get(&vaddr).cloned())
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.image.sections().iter().any(|section| {
            section.loaded
                && !section.is_code
                && vaddr >= section.vaddr
                && vaddr - section.vaddr < section.vsize
        })
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.imports
            .get(&vaddr)
            .or_else(|| self.slots.get(&vaddr))
            .cloned()
    }
}

/// What the binary defines at each address, indexed by where it is.
///
/// Names live in the name table; this answers the two questions a walk asks
/// of an address and a name cannot: whether a function begins here, and which
/// instruction set it is written in. The first symbol at an address wins, so
/// the index answers the same way twice over.
fn definitions(image: &Image) -> BTreeMap<u64, Definition> {
    let mut defined = BTreeMap::new();
    // The format's own entry first: a stripped ARM binary has no symbol there,
    // and `e_entry`'s low bit is the only thing that says the entry is Thumb.
    for entry in image.entry_points() {
        defined.entry(entry.vaddr).or_insert_with(|| Definition {
            function: true,
            thumb: entry.thumb,
        });
    }
    for symbol in image.symbols() {
        if !symbol.defined || symbol.name.is_empty() {
            continue;
        }
        defined.entry(symbol.vaddr).or_insert_with(|| Definition {
            function: symbol.kind == r2image::SymbolKind::Function,
            thumb: symbol.thumb,
        });
    }
    defined
}
