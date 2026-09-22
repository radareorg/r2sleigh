//! The shell's state: an open image, its machine, and the seek cursor.
//!
//! The cursor lives here and nowhere else. Every engine call takes its address
//! as an argument, so the query surface below this stays stateless and the
//! shell is a client of it rather than a layer inside it.

#[cfg(feature = "sleigh")]
use r2engine::names::NameDb;
use r2image::Image;

pub struct Session {
    pub image: Image,
    /// What this binary calls each address it names.
    #[cfg(feature = "sleigh")]
    pub names: NameDb,
    /// Which stub stands for which import, by the import's own name.
    #[cfg(feature = "sleigh")]
    pub imports: std::collections::BTreeMap<u64, String>,
    /// Which import each slot the loader fills stands for. A stub's tail
    /// transfer names the slot it reads rather than any code address, so the
    /// slot has to answer for the import too; only a stub is an entry.
    #[cfg(feature = "sleigh")]
    pub slots: std::collections::BTreeMap<u64, String>,
    /// What this binary defines at each address, indexed once.
    ///
    /// The engine asks this per call target and per branch target of every
    /// body it walks, and answering it by scanning the symbol table made the
    /// walk cost one pass over every symbol per edge.
    #[cfg(feature = "sleigh")]
    pub defined: std::collections::BTreeMap<u64, Definition>,
    pub path: String,
    /// Where `pd`, `px` and the rest read from when no address is given.
    pub addr: u64,
    /// Which revision of the image's bytes the tables above were derived at.
    ///
    /// `names`, `imports`, `slots` and `defined` are all read out of the image,
    /// and one of them is *decoded* from it: the import table comes from lifting
    /// the stub section. A patch changes what those say, and `imports` decides
    /// `is_entry`, which is what bounds every body walk -- so a stale table is
    /// not a stale listing, it is a body that ends in the wrong place.
    #[cfg(feature = "sleigh")]
    derived_at: Option<u64>,
    #[cfg(feature = "sleigh")]
    machine: Option<r2sleigh_lift::EmbeddedMachine>,
    /// The same instruction set with TMode set. ARM states the mode per
    /// function in the low bit of its symbol, so both decoders are needed at
    /// once and neither is the image's.
    #[cfg(feature = "sleigh")]
    thumb_machine: Option<r2sleigh_lift::EmbeddedMachine>,
}

impl Session {
    pub fn open(path: &str) -> Result<Self, String> {
        let image = Image::open(path).map_err(|e| e.to_string())?;
        let addr = image
            .entry_points()
            .iter()
            .find(|entry| entry.kind == r2image::EntryKind::Main)
            .or_else(|| image.entry_points().first())
            .map(|entry| entry.vaddr)
            // An object file declares no entry, so start where the code is.
            .or_else(|| {
                image
                    .sections()
                    .iter()
                    .find(|section| section.is_code && section.vsize > 0)
                    .map(|section| section.vaddr)
            })
            .or_else(|| {
                image
                    .segments()
                    .iter()
                    .find(|segment| segment.permissions.execute)
                    .map(|segment| segment.vaddr)
            })
            .unwrap_or(0);
        Ok(Self {
            #[cfg(feature = "sleigh")]
            names: {
                let mut db = crate::names::of(&image);
                crate::names::name_strings(&mut db, &image);
                db
            },
            #[cfg(feature = "sleigh")]
            imports: std::collections::BTreeMap::new(),
            #[cfg(feature = "sleigh")]
            slots: std::collections::BTreeMap::new(),
            #[cfg(feature = "sleigh")]
            defined: definitions(&image),
            // The import table needs a decoder, so nothing here is derived yet.
            #[cfg(feature = "sleigh")]
            derived_at: None,
            image,
            path: path.to_owned(),
            addr,
            #[cfg(feature = "sleigh")]
            machine: None,
            #[cfg(feature = "sleigh")]
            thumb_machine: None,
        })
    }

    /// Make everything this session derives from the image current.
    ///
    /// The machine is loaded once: which instruction set a file is written in is
    /// a property of the file and no patch changes it. Everything else is read
    /// or decoded out of the bytes, so it is derived again whenever the image
    /// says it is at a different revision.
    ///
    /// Separate from reading the machine so a caller can hold the machine and
    /// the image at once; one method returning a reference out of `&mut self`
    /// would make those two borrows conflict.
    #[cfg(feature = "sleigh")]
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
        self.names = crate::names::of(&self.image);
        crate::names::name_strings(&mut self.names, &self.image);
        self.defined = definitions(&self.image);
        // The import stubs can only be read once there is a decoder.
        self.imports = crate::names::imports(&self.image, &machine.disasm, machine.arch.alignment);
        self.slots = self
            .image
            .relocations()
            .iter()
            .map(|relocation| (relocation.vaddr, relocation.symbol.clone()))
            .collect();
        crate::names::name_imports(&mut self.names, self.image.format(), &self.imports);
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

    /// The decoder the code at this address is written in.
    ///
    /// ARM states the mode per function, in the low bit of the symbol that
    /// names it, so the image has no single answer and the address decides.
    #[cfg(feature = "sleigh")]
    pub fn machine_at(&self, vaddr: u64) -> Option<&r2sleigh_lift::EmbeddedMachine> {
        match self.thumb_at(vaddr) {
            true => self.thumb_machine.as_ref().or(self.machine.as_ref()),
            false => self.machine.as_ref(),
        }
    }

    /// Whether the function containing this address is Thumb.
    #[cfg(feature = "sleigh")]
    pub fn thumb_at(&self, vaddr: u64) -> bool {
        self.defined
            .range(..=vaddr)
            .next_back()
            .is_some_and(|(_, definition)| definition.function && definition.thumb)
    }
}

/// What the binary defines at one address.
#[cfg(feature = "sleigh")]
#[derive(Debug, Clone)]
pub struct Definition {
    /// Whether a function begins here, which is what bounds a body.
    pub function: bool,
    /// Whether this function's code is Thumb rather than ARM.
    pub thumb: bool,
}

/// What the binary defines at each address, indexed by where it is.
///
/// Names live in the name table; this answers the two questions a walk asks
/// of an address and a name cannot: whether a function begins here, and which
/// instruction set it is written in. The first symbol at an address wins, so
/// the index answers the same way twice over.
#[cfg(feature = "sleigh")]
fn definitions(image: &Image) -> std::collections::BTreeMap<u64, Definition> {
    let mut defined = std::collections::BTreeMap::new();
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
