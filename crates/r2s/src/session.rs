//! The shell's state: an open image, its machine, and the seek cursor.
//!
//! The cursor lives here and nowhere else. Every engine call takes its address
//! as an argument, so the query surface below this stays stateless and the
//! shell is a client of it rather than a layer inside it.

#[cfg(feature = "sleigh")]
use crate::flags::Flags;
use r2image::Image;

pub struct Session {
    pub image: Image,
    /// What this binary calls each address it names.
    #[cfg(feature = "sleigh")]
    pub flags: Flags,
    pub path: String,
    /// Where `pd`, `px` and the rest read from when no address is given.
    pub addr: u64,
    #[cfg(feature = "sleigh")]
    machine: Option<r2sleigh_lift::EmbeddedMachine>,
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
            flags: Flags::of(&image),
            image,
            path: path.to_owned(),
            addr,
            #[cfg(feature = "sleigh")]
            machine: None,
        })
    }

    /// Load this image's machine if it is not loaded yet.
    ///
    /// Separate from reading it so a caller can hold the machine and the image
    /// at once; one method returning a reference out of `&mut self` would make
    /// those two borrows conflict.
    #[cfg(feature = "sleigh")]
    pub fn ensure_machine(&mut self) -> Result<(), String> {
        if self.machine.is_none() {
            let machine = r2sleigh_lift::embedded_machine(self.image.arch().name)
                .map_err(|error| error.to_string())?;
            // The import stubs can only be read once there is a decoder.
            self.flags.name_imports(&self.image, &machine.disasm);
            self.machine = Some(machine);
        }
        Ok(())
    }

    #[cfg(feature = "sleigh")]
    pub fn machine(&self) -> Option<&r2sleigh_lift::EmbeddedMachine> {
        self.machine.as_ref()
    }

    #[cfg(feature = "sleigh")]
    pub fn decoder(&self) -> Option<&r2sleigh_lift::Disassembler> {
        self.machine.as_ref().map(|machine| &machine.disasm)
    }
}
