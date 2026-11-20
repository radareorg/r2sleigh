//! One call-site table of an LSDA, as GCC's `parse_lsda_header` and `PERSONALITY_FUNCTION` read it
//! (doc/adr-radare2-function-walk.md, "Unwind edges as built"); it fails closed per table.

use std::ops::Range;

use r2abi::frames::{CallSiteRange, LsdaRefusal};

/// `DW_EH_PE_omit` (GCC `libgcc/unwind-pe.h`).
const OMIT: u8 = 0xff;

/// The call-site ranges of the table at `at` (its bytes `bytes`) for the frame covering `frame`, in
/// an image of `pointer`-byte pointers: absolute, sorted by start. O(table bytes).
pub(crate) fn call_sites(
    bytes: &[u8],
    at: u64,
    frame: Range<u64>,
    little: bool,
    pointer: usize,
) -> Result<Box<[CallSiteRange]>, LsdaRefusal> {
    let mut read = Reader {
        bytes,
        at: 0,
        base: at,
        little,
        pointer,
    };
    // `info->Start` is `_Unwind_GetRegionStart`, the frame's first address; LPStart defaults to it.
    let lpstart = match read.byte()? {
        OMIT => frame.start,
        encoding => read.pointer(encoding)?,
    };
    if read.byte()? != OMIT {
        read.uleb()?;
    }
    let encoding = read.byte()?;
    let length = usize::try_from(read.uleb()?).map_err(|_| LsdaRefusal::Malformed)?;
    let end = read.at.checked_add(length).ok_or(LsdaRefusal::Length)?;
    if end > bytes.len() {
        return Err(LsdaRefusal::Length);
    }
    let mut ranges = Vec::new();
    while read.at < end {
        // "all call-site encodings are \"absolute\" displacements": the format bits alone.
        let start = read.offset(encoding)?;
        let len = read.offset(encoding)?;
        let pad = read.offset(encoding)?;
        read.uleb()?;
        let start = frame
            .start
            .checked_add(start)
            .ok_or(LsdaRefusal::Malformed)?;
        let stop = start.checked_add(len).ok_or(LsdaRefusal::Malformed)?;
        if start < frame.start || stop > frame.end {
            return Err(LsdaRefusal::RangeOutsideFrame);
        }
        let pad = match pad {
            0 => None,
            pad => Some(lpstart.checked_add(pad).ok_or(LsdaRefusal::Malformed)?),
        };
        ranges.push(CallSiteRange {
            start,
            end: stop,
            pad,
        });
    }
    if read.at != end {
        return Err(LsdaRefusal::Length);
    }
    ranges.sort_by_key(|range| range.start);
    Ok(ranges.into())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    /// The address of `bytes[0]`, which a pc-relative LPStart is measured from.
    base: u64,
    little: bool,
    /// The image's pointer size, which `DW_EH_PE_absptr` reads (GCC `unwind-pe.h`, `sizeof (void *)`).
    pointer: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, LsdaRefusal> {
        let byte = *self.bytes.get(self.at).ok_or(LsdaRefusal::Malformed)?;
        self.at += 1;
        Ok(byte)
    }

    fn uleb(&mut self) -> Result<u64, LsdaRefusal> {
        let (mut value, mut shift) = (0u64, 0u32);
        loop {
            let byte = self.byte()?;
            if shift >= 64 {
                return Err(LsdaRefusal::Malformed);
            }
            value |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    fn sleb(&mut self) -> Result<u64, LsdaRefusal> {
        let (mut value, mut shift) = (0i64, 0u32);
        loop {
            let byte = self.byte()?;
            if shift >= 64 {
                return Err(LsdaRefusal::Malformed);
            }
            value |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                let sign = match shift < 64 && byte & 0x40 != 0 {
                    true => -1i64 << shift,
                    false => 0,
                };
                return Ok((value | sign) as u64);
            }
        }
    }

    fn fixed(&mut self, width: usize, signed: bool) -> Result<u64, LsdaRefusal> {
        let end = self.at.checked_add(width).ok_or(LsdaRefusal::Malformed)?;
        let field = self.bytes.get(self.at..end).ok_or(LsdaRefusal::Malformed)?;
        self.at = end;
        let mut word = [0u8; 8];
        let value = match self.little {
            true => {
                word[..width].copy_from_slice(field);
                u64::from_le_bytes(word)
            }
            false => {
                word[8 - width..].copy_from_slice(field);
                u64::from_be_bytes(word)
            }
        };
        let unused = 64 - 8 * width as u32;
        Ok(match signed && unused > 0 {
            true => (((value << unused) as i64) >> unused) as u64,
            false => value,
        })
    }

    /// A value in the format bits of `encoding` (`DW_EH_PE_uleb128` to `DW_EH_PE_sdata8`).
    fn offset(&mut self, encoding: u8) -> Result<u64, LsdaRefusal> {
        if encoding & 0x70 != 0 {
            return Err(LsdaRefusal::Malformed);
        }
        self.value(encoding & 0x0f)
    }

    fn value(&mut self, format: u8) -> Result<u64, LsdaRefusal> {
        match format {
            0x01 => self.uleb(),
            0x02 => self.fixed(2, false),
            0x03 => self.fixed(4, false),
            0x00 => self.fixed(self.pointer, false),
            0x04 => self.fixed(8, false),
            0x09 => self.sleb(),
            0x0a => self.fixed(2, true),
            0x0b => self.fixed(4, true),
            0x0c => self.fixed(8, true),
            _ => Err(LsdaRefusal::Malformed),
        }
    }

    /// An LPStart: absolute or pc-relative, never indirect.
    fn pointer(&mut self, encoding: u8) -> Result<u64, LsdaRefusal> {
        let place = self.base.wrapping_add(self.at as u64);
        let value = self.value(encoding & 0x0f)?;
        match encoding & 0xf0 {
            0x00 => Ok(value),
            0x10 => Ok(place.wrapping_add(value)),
            _ => Err(LsdaRefusal::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pumasim `main`'s first two records (`.gcc_except_table` at 0x7684d5): uleb128 offsets, LPStart omitted.
    #[test]
    fn a_record_s_pad_is_measured_from_the_frame_start() {
        let table = [
            0xff, 0xff, 0x01, 0x09, 0x2f, 0x0f, 0x00, 0x00, 0x44, 0x05, 0x90, 0x0b, 0x00,
        ];
        let ranges = call_sites(&table, 0x7684d5, 0x1dc0a0..0x1dc690, true, 8).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            (ranges[0].start, ranges[0].end, ranges[0].pad),
            (0x1dc0cf, 0x1dc0de, None)
        );
        assert_eq!(
            (ranges[1].start, ranges[1].end, ranges[1].pad),
            (0x1dc0e4, 0x1dc0e9, Some(0x1dc630))
        );
    }

    #[test]
    fn a_table_whose_records_overrun_its_length_is_refused() {
        let table = [
            0xff, 0xff, 0x01, 0x05, 0x2f, 0x0f, 0x00, 0x00, 0x44, 0x05, 0x90, 0x0b, 0x00,
        ];
        let read = call_sites(&table, 0, 0x1dc0a0..0x1dc690, true, 8);
        assert_eq!(read, Err(LsdaRefusal::Length));
        let outside = [0xff, 0xff, 0x01, 0x04, 0x2f, 0x0f, 0x00, 0x00];
        let read = call_sites(&outside, 0, 0x1dc0a0..0x1dc0b0, true, 8);
        assert_eq!(read, Err(LsdaRefusal::RangeOutsideFrame));
    }

    /// A 32-bit image's absolute LPStart is four bytes: `absptr` is the image's pointer size.
    #[test]
    fn an_absolute_lpstart_is_the_images_pointer_size() {
        let table = [
            0x00, 0x00, 0x10, 0x00, 0x00, 0xff, 0x01, 0x04, 0x02, 0x05, 0x10, 0x00,
        ];
        let ranges = call_sites(&table, 0x2000, 0x1000..0x1100, true, 4).unwrap();
        assert_eq!(
            (ranges[0].start, ranges[0].end, ranges[0].pad),
            (0x1002, 0x1007, Some(0x1010))
        );
    }
}
