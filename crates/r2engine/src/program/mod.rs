//! A program someone opened, and everything the engine derives from it.
//!
//! Whoever opened the binary hands over its bytes and what its container
//! states, through `Source`. The engine derives the rest -- the names, the
//! import stubs decoded out of their bytes, what is defined at each address --
//! and keeps it current as the bytes move. It never opens anything, so the
//! whole derivation runs just as well over a program built from byte literals.

pub mod naming;
mod requests;
pub mod source;

pub use requests::Rendering;

pub use source::{
    Arch, Container, Entry, EntryKind, Format, Relocation, Section, Source, Symbol, SymbolKind,
};

use std::collections::BTreeMap;

use r2sleigh_lift::EmbeddedMachine;

use crate::names::NameDb;
use crate::native::{NativeRefusal, NativeTarget, Prepared};
use crate::query::{Decoders, Memo, Revision};

/// What the binary defines at one address.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Definition {
    /// Whether a function begins here, which is what bounds a body.
    function: bool,
    /// Whether this function's code is Thumb rather than ARM.
    thumb: bool,
}

/// Everything a native request needs that is not the decoder itself.
struct Assembled {
    /// Which architecture and compiler specification this was built for, so a
    /// second instruction set in one program gets its own rather than this one.
    machine: (String, &'static str),
    conventions: r2abi::Conventions,
    compiler: r2abi::CompilerSpec,
    prototypes: r2abi::Prototypes,
    /// The register a call returns through, in the coordinates the lift spells.
    link: Option<r2il::Varnode>,
}

/// One open program: its source, its decoders, and the tables read out of both.
pub struct OpenProgram<S: Source> {
    source: S,
    /// What this binary calls each address it names.
    names: NameDb,
    /// Which stub stands for which import, by the import's own name.
    imports: BTreeMap<u64, String>,
    /// Which import each slot the loader fills stands for. A stub's tail
    /// transfer names the slot it reads rather than any code address, so the
    /// slot has to answer for the import too; only a stub is an entry.
    slots: BTreeMap<u64, String>,
    /// What this binary defines at each address, indexed once.
    ///
    /// The engine asks this per call target and per branch target of every
    /// body it walks, and answering it by scanning the symbol table made the
    /// walk cost one pass over every symbol per edge. Read from the container
    /// alone, so no write moves it.
    defined: BTreeMap<u64, Definition>,
    /// Which revision of the bytes the names and the imports were derived at.
    ///
    /// Both are read out of the bytes, and the imports are *decoded* from
    /// them: the table comes from lifting the stub section. A patch changes
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
    /// The same, for the import stubs, which are the entries a write can move.
    entries_revision: u64,
    assembled: Option<Assembled>,
    /// What this session has already worked out about one function.
    memo: Memo<Prepared>,
    /// Which bytes the derivation in progress has read.
    ///
    /// An answer that recorded this can be kept across a write that missed
    /// every one of them, which is what a patch to another function is.
    /// `None` outside a derivation, so a read nothing will keep -- every line
    /// of every listing -- is not logged at all.
    read: std::cell::RefCell<Option<Vec<std::ops::Range<u64>>>>,
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

impl<S: Source> OpenProgram<S> {
    pub fn of(source: S) -> Self {
        let container = source.container();
        Self {
            names: {
                let mut db = naming::of(&source);
                naming::name_strings(&mut db, &source);
                db
            },
            imports: BTreeMap::new(),
            slots: container
                .relocations
                .iter()
                .map(|relocation| (relocation.vaddr, relocation.symbol.clone()))
                .collect(),
            defined: definitions(container),
            source,
            // The import table needs a decoder, so nothing here is derived yet.
            derived_at: None,
            names_revision: 0,
            entries_revision: 0,
            assembled: None,
            memo: Memo::default(),
            read: std::cell::RefCell::new(None),
            control: crate::EngineExecutionControl::default(),
            machine: None,
            thumb_machine: None,
        }
    }

    /// What was opened.
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// What was opened, to be written to. Everything derived from it is
    /// derived again the next time it is asked for.
    pub const fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// Make everything derived from the bytes current.
    ///
    /// The machine is loaded once: which instruction set a file is written in
    /// is a property of the file and no patch changes it. The names and the
    /// import stubs are read or decoded out of the bytes, so they are derived
    /// again whenever the source says it is at a different revision.
    pub fn ensure_current(&mut self) -> Result<(), String> {
        if self.machine.is_none() {
            self.machine = Some(
                r2sleigh_lift::embedded_machine(&self.source.container().arch.name)
                    .map_err(|error| error.to_string())?,
            );
            // Only where a function says it is Thumb, so a machine with no
            // Thumb code pays nothing for the second specification.
            if self.defined.values().any(|definition| definition.thumb) {
                self.thumb_machine = r2sleigh_lift::embedded_machine("arm-thumb").ok();
            }
        }
        let revision = self.source.byte_revision();
        if self.derived_at == Some(revision) {
            return Ok(());
        }
        let machine = self.machine.as_ref().expect("the machine is loaded above");
        let format = self.source.container().format;
        let mut names = naming::of(&self.source);
        naming::name_strings(&mut names, &self.source);
        // The import stubs can only be read once there is a decoder.
        let imports = naming::imports(&self.source, &machine.disasm, machine.arch.alignment);
        naming::name_imports(&mut names, format, &imports);
        naming::name_slots(&mut names, format, &self.slots, &imports);
        // A patch that renamed nothing and moved no stub leaves everything
        // derived from those still good, so the counters move only on a
        // difference rather than on every write.
        self.names_revision += u64::from(names != self.names);
        self.entries_revision += u64::from(imports != self.imports);
        self.names = names;
        self.imports = imports;
        self.derived_at = Some(revision);
        Ok(())
    }

    /// What this binary calls each address it names, as of the last
    /// `ensure_current`.
    pub const fn names(&self) -> &NameDb {
        &self.names
    }

    /// Which stub stands for which import, as of the last `ensure_current`.
    pub const fn imports(&self) -> &BTreeMap<u64, String> {
        &self.imports
    }

    /// Assemble what a native request needs, once per program and machine.
    ///
    /// All of it is constant while one program is open, and rebuilding it per
    /// command cost two milliseconds -- almost all of it parsing the embedded
    /// prototype table -- on every `pdd`, `pdil`, `afl` and `ax`.
    fn ensure_assembled(&mut self, addr: u64) -> Result<(), String> {
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
        let container = self.source.container();
        let bits = container.arch.bits;
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
        let mut prototypes = r2abi::Prototypes::embedded_for(match container.format {
            Format::Elf => r2abi::Platform::Linux,
            Format::MachO => r2abi::Platform::Darwin,
            Format::Other => r2abi::Platform::Unknown,
        });
        // What the binary's own debug information says beats the shared table:
        // the table describes what a library is expected to look like, and
        // this describes what this one is.
        prototypes.declare(container.declared.iter().cloned());
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
    fn target(&self, addr: u64) -> Result<NativeTarget<'_>, String> {
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
    fn analysed(
        &self,
        target: &NativeTarget<'_>,
        entry: u64,
    ) -> Result<std::sync::Arc<Prepared>, NativeRefusal> {
        self.memo.analysed_since(
            self.revision(),
            entry,
            &|since, range| self.source.written_since(since, range),
            || {
                *self.read.borrow_mut() = Some(Vec::new());
                let analysis = crate::native::analysed(target, self, entry);
                let read = self.read.borrow_mut().take().unwrap_or_default();
                analysis.map(|analysis| (analysis, read))
            },
        )
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

    /// Whether a storage is one of the machine's words.
    ///
    /// What separates `rdx` from `cf` for a reader: a listing that reported
    /// every proved range said `cf in [0x0, 0x1]` on every line that sets a
    /// flag, which is true, proved, and only says that a flag is a flag. The
    /// width comes from the architecture rather than from a number chosen to
    /// look right.
    pub fn is_machine_word(&self, addr: u64, storage: r2ssa::CanonicalStorageId) -> bool {
        storage.space == r2ssa::CanonicalStorageSpace::Register
            && self
                .machine_at(addr)
                .is_some_and(|machine| storage.size == machine.arch.addr_size)
    }

    /// The register a storage names, as this machine spells it.
    ///
    /// The shell prints what the engine proved about a value, and a value is
    /// about a storage; naming it needs the register table, which belongs to
    /// the machine and therefore here.
    pub fn spell_storage(&self, addr: u64, storage: r2ssa::CanonicalStorageId) -> Option<String> {
        let machine = self.machine_at(addr)?;
        machine
            .arch
            .registers
            .iter()
            .find(|register| {
                register.offset == storage.offset
                    && register.size == storage.size
                    && storage.space == r2ssa::CanonicalStorageSpace::Register
            })
            .map(|register| register.name.to_lowercase())
    }

    /// What the memo has been asked and what it holds.
    pub fn memo_stats(&self) -> crate::query::MemoStats {
        self.memo.stats()
    }

    /// Which state of this program every answer is about.
    pub fn revision(&self) -> Revision {
        Revision {
            program: self.source.identity(),
            bytes: self.source.byte_revision(),
            names: self.names_revision,
            entries: self.entries_revision,
        }
    }

    /// The decoder the code at this address is written in.
    ///
    /// ARM states the mode per function, in the low bit of the symbol that
    /// names it, so the image has no single answer and the address decides.
    fn machine_at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        match self.thumb_at(vaddr) {
            true => self.thumb_machine.as_ref().or(self.machine.as_ref()),
            false => self.machine.as_ref(),
        }
    }

    /// Whether the function containing this address is Thumb.
    fn thumb_at(&self, vaddr: u64) -> bool {
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
        self.source.container().arch.endian
    }
}

impl<S: Source> Decoders for OpenProgram<S> {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        self.machine_at(vaddr)
    }
}

impl<S: Source> r2ssa::body::Program for OpenProgram<S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let read = self.source.read(vaddr, max)?;
        // Recorded whole, including what was asked for beyond what is mapped:
        // a write that lands in the unmapped tail cannot happen, and one that
        // lands in the rest is a write this answer read.
        if let Some(log) = self.read.borrow_mut().as_mut() {
            log.push(vaddr..vaddr.saturating_add(read.len() as u64));
        }
        Some(read)
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

impl<S: Source> crate::native::Program for OpenProgram<S> {
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
        self.source.container().sections.iter().any(|section| {
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
fn definitions(container: &Container) -> BTreeMap<u64, Definition> {
    let mut defined = BTreeMap::new();
    // The format's own entry first: a stripped ARM binary has no symbol there,
    // and `e_entry`'s low bit is the only thing that says the entry is Thumb.
    for entry in &container.entries {
        defined.entry(entry.vaddr).or_insert_with(|| Definition {
            function: true,
            thumb: entry.thumb,
        });
    }
    for symbol in &container.symbols {
        if !symbol.defined || symbol.name.is_empty() {
            continue;
        }
        defined.entry(symbol.vaddr).or_insert_with(|| Definition {
            function: symbol.kind == SymbolKind::Function,
            thumb: symbol.thumb,
        });
    }
    defined
}
