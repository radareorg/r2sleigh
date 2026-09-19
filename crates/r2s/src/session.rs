//! The shell's state: an open image, a decoder, and the seek cursor.
//!
//! The cursor lives here and nowhere else. Every engine call takes its address
//! as an argument, so the query surface below this stays stateless and the
//! shell is a client of it rather than a layer inside it.

use r2image::Image;

pub struct Session {
    pub image: Image,
    pub path: String,
    /// Where `pd`, `px` and the rest read from when no address is given.
    pub addr: u64,
    #[cfg(feature = "sleigh")]
    decoder: Option<r2sleigh_lift::Disassembler>,
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
            image,
            path: path.to_owned(),
            addr,
            #[cfg(feature = "sleigh")]
            decoder: None,
        })
    }

    /// Build this image's decoder if it is not built yet.
    ///
    /// Separate from reading it so a caller can hold the decoder and the image
    /// at once; one method returning a reference out of `&mut self` would make
    /// those two borrows conflict.
    #[cfg(feature = "sleigh")]
    pub fn ensure_decoder(&mut self) -> Result<(), String> {
        if self.decoder.is_none() {
            self.decoder = Some(build_decoder(self.image.arch())?);
        }
        Ok(())
    }

    #[cfg(feature = "sleigh")]
    pub fn decoder(&self) -> Option<&r2sleigh_lift::Disassembler> {
        self.decoder.as_ref()
    }
}

#[cfg(feature = "sleigh")]
fn build_decoder(arch: &r2image::ImageArch) -> Result<r2sleigh_lift::Disassembler, String> {
    use r2sleigh_lift::Disassembler;
    let (sla, pspec, name): (&[u8], &str, &str) = match arch.name {
        "x86-64" => (
            sleigh_config::processor_x86::SLA_X86_64,
            sleigh_config::processor_x86::PSPEC_X86_64,
            "x86-64",
        ),
        "x86" => (
            sleigh_config::processor_x86::SLA_X86,
            sleigh_config::processor_x86::PSPEC_X86,
            "x86",
        ),
        "AArch64" => (
            sleigh_config::processor_aarch64::SLA_AARCH64_APPLESILICON,
            sleigh_config::processor_aarch64::PSPEC_AARCH64,
            "aarch64",
        ),
        "ARM" => (
            sleigh_config::processor_arm::SLA_ARM8_LE,
            sleigh_config::processor_arm::PSPEC_ARMT,
            "ARM",
        ),
        other => return Err(format!("no Sleigh specification for {}", other)),
    };
    Disassembler::from_sla(sla, pspec, name).map_err(|e| e.to_string())
}
