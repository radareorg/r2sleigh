//! `.gnu_debugdata`, GDB's MiniDebugInfo: an xz stream holding an ELF whose `.symtab` lists the
//! functions the dynamic table lacks, decoded whole under a refusing budget (adr-minidebuginfo.md).

use std::io::Write;

/// The most uncompressed bytes the stream's index may state; more is refused before decoding.
pub const BUDGET: u64 = 64 << 20;

/// Why a `.gnu_debugdata` section states no symbols: the whole source is refused, never a part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiniDebugRefusal {
    /// The xz container does not read: its header, footer or index, by what was wrong.
    Container(&'static str),
    /// The index states more uncompressed bytes than [`BUDGET`].
    OverBudget { stated: u64 },
    /// The stream decodes past or short of what its index states, or fails its check.
    Decoding(String),
    /// What it decodes to is no ELF this reads.
    Inner(String),
}

impl std::fmt::Display for MiniDebugRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Container(why) => write!(f, "the xz container does not read: {why}"),
            Self::OverBudget { stated } => {
                write!(
                    f,
                    "the index states {stated} bytes, over the {BUDGET}-byte budget"
                )
            }
            Self::Decoding(why) => write!(f, "the stream does not decode: {why}"),
            Self::Inner(why) => write!(f, "the decoded file is no ELF: {why}"),
        }
    }
}

/// The ELF `.gnu_debugdata` section's inner file, decoded whole, or why it is refused; `None`
/// where there is no such section, which costs one section lookup.
pub(crate) fn decoded_section(
    file: &object::File<'_>,
) -> Option<Result<Vec<u8>, MiniDebugRefusal>> {
    use object::{Object, ObjectSection};
    if !matches!(file, object::File::Elf32(_) | object::File::Elf64(_)) {
        return None;
    }
    let section = file.section_by_name(".gnu_debugdata")?;
    Some(match section.data() {
        Ok(bytes) => decoded(bytes),
        Err(_) => Err(MiniDebugRefusal::Container(
            "the section's bytes are not in the file",
        )),
    })
}

/// The section's inner file, decoded whole, or why it is refused. O(compressed + uncompressed).
pub(crate) fn decoded(section: &[u8]) -> Result<Vec<u8>, MiniDebugRefusal> {
    let records = indexed(section)?;
    let stated = records
        .iter()
        .try_fold(0u64, |total, (_, size)| total.checked_add(*size));
    let stated = stated.ok_or(MiniDebugRefusal::Container("the records overflow"))?;
    if stated > BUDGET {
        return Err(MiniDebugRefusal::OverBudget { stated });
    }
    chunked(section, &records)?;
    let mut out = Bounded {
        bytes: Vec::with_capacity(usize::try_from(stated).unwrap_or_default()),
        limit: usize::try_from(stated).unwrap_or_default(),
    };
    let mut input = section;
    lzma_rs::xz_decompress(&mut input, &mut out)
        .map_err(|error| MiniDebugRefusal::Decoding(error.to_string()))?;
    match out.bytes.len() == out.limit {
        true => Ok(out.bytes),
        false => Err(MiniDebugRefusal::Decoding(format!(
            "{} bytes decoded where the index states {stated}",
            out.bytes.len()
        ))),
    }
}

/// A writer that refuses a byte past the size the index stated.
struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.limit - self.bytes.len() {
            return Err(std::io::Error::other(
                "the stream decodes past its stated size",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const HEADER_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";

/// Each block's unpadded and uncompressed size, as the index the footer points at states them
/// (xz file format 1.2.1: 2.1.2.2, 4, 4.3), read before any block is decoded.
fn indexed(stream: &[u8]) -> Result<Vec<(u64, u64)>, MiniDebugRefusal> {
    let refuse = MiniDebugRefusal::Container;
    if stream.len() < 24 || stream[..6] != HEADER_MAGIC {
        return Err(refuse("no stream header"));
    }
    let footer = &stream[stream.len() - 12..];
    if footer[10..] != FOOTER_MAGIC {
        return Err(refuse("no stream footer where the section ends"));
    }
    // Backward Size: the index's size, stored as size / 4 - 1.
    let backward = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]);
    let index_size = (u64::from(backward) + 1) * 4;
    let index_at = (stream.len() as u64 - 12)
        .checked_sub(index_size)
        .filter(|at| *at >= 12)
        .ok_or(refuse("the footer's index lies outside the stream"))?;
    let mut index = &stream[index_at as usize..stream.len() - 12];
    if index.first() != Some(&0) {
        return Err(refuse("no index indicator"));
    }
    index = &index[1..];
    let count = varint(&mut index).ok_or(refuse("an unreadable record count"))?;
    let mut records = Vec::new();
    for _ in 0..count {
        let unpadded = varint(&mut index).ok_or(refuse("an unreadable record"))?;
        let uncompressed = varint(&mut index).ok_or(refuse("an unreadable record"))?;
        records.push((unpadded, uncompressed));
    }
    Ok(records)
}

/// Every LZMA2 chunk header, walked undecoded: chunks stating other than the index refuse the
/// stream before it allocates (adr-minidebuginfo.md). O(compressed / 64 KiB) headers.
fn chunked(stream: &[u8], records: &[(u64, u64)]) -> Result<(), MiniDebugRefusal> {
    let refuse = MiniDebugRefusal::Container;
    let past = |at: usize| {
        refuse(if at < stream.len() {
            "an LZMA2 control byte no format defines"
        } else {
            "a block runs past the stream"
        })
    };
    let byte = |at: usize| stream.get(at).copied();
    let word = |at: usize| Some(u64::from(u16::from_be_bytes([byte(at)?, byte(at + 1)?])));
    let mut at = 12usize;
    for &(unpadded, uncompressed) in records {
        let header = byte(at).filter(|size| *size != 0).ok_or(past(at))?;
        let mut chunk = at + (usize::from(header) + 1) * 4;
        let mut stated = 0u64;
        loop {
            let (size, next) = match byte(chunk).ok_or(past(chunk))? {
                0x00 => break,
                0x01 | 0x02 => {
                    let size = word(chunk + 1).ok_or(past(chunk))? + 1;
                    (size, chunk + 3 + size as usize)
                }
                control @ 0x80..=0xff => {
                    let low = word(chunk + 1).ok_or(past(chunk))?;
                    let size = ((u64::from(control & 0x1f) << 16) | low) + 1;
                    let packed = word(chunk + 3).ok_or(past(chunk))? as usize + 1;
                    (size, chunk + 5 + usize::from(control >= 0xc0) + packed)
                }
                _ => return Err(past(chunk)),
            };
            stated += size;
            if stated > uncompressed {
                return Err(MiniDebugRefusal::Decoding(format!(
                    "its chunks state more than the {uncompressed} bytes its index states"
                )));
            }
            chunk = next;
        }
        if stated != uncompressed {
            return Err(MiniDebugRefusal::Decoding(format!(
                "its chunks state {stated} bytes where its index states {uncompressed}"
            )));
        }
        let padded = unpadded.checked_next_multiple_of(4);
        let padded = padded.and_then(|padded| usize::try_from(padded).ok());
        at = padded
            .and_then(|padded| at.checked_add(padded))
            .ok_or(past(usize::MAX))?;
    }
    Ok(())
}

/// An xz multibyte integer: seven bits a byte, low first, at most nine bytes.
fn varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for (at, byte) in bytes.iter().enumerate().take(9) {
        value |= u64::from(byte & 0x7f) << (7 * at);
        if byte & 0x80 == 0 {
            *bytes = &bytes[at + 1..];
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream header, an index of one record stating `uncompressed`, and a footer; no block.
    fn stated(uncompressed: u64) -> Vec<u8> {
        let mut stream = HEADER_MAGIC.to_vec();
        stream.extend([0, 1, 0, 0, 0, 0]);
        let mut index = vec![0, 1, 0x40];
        let mut value = uncompressed;
        while value >= 0x80 {
            index.push((value as u8) | 0x80);
            value >>= 7;
        }
        index.push(value as u8);
        while index.len() % 4 != 0 {
            index.push(0);
        }
        index.extend([0; 4]);
        let backward = (index.len() / 4 - 1) as u32;
        stream.extend(&index);
        stream.extend([0; 4]);
        stream.extend(backward.to_le_bytes());
        stream.extend([0, 1]);
        stream.extend(FOOTER_MAGIC);
        stream
    }

    #[test]
    fn an_index_over_the_budget_is_refused_before_any_block_is_read() {
        assert_eq!(
            decoded(&stated(1 << 30)),
            Err(MiniDebugRefusal::OverBudget { stated: 1 << 30 })
        );
        assert_eq!(indexed(&stated(29_696)), Ok(vec![(0x40, 29_696)]));
    }

    /// One block of one uncompressed LZMA2 chunk of 100 bytes, under an index stating 10: the
    /// chunk header says it decodes past the statement, so it is refused before decoding.
    #[test]
    fn a_chunk_stating_more_than_its_index_is_refused_before_decoding() {
        let mut stream = HEADER_MAGIC.to_vec();
        stream.extend([0, 1, 0, 0, 0, 0]);
        stream.extend([1, 0, 0x21, 1, 0, 0, 0, 0]);
        stream.extend([1, 0, 99]);
        stream.extend([b'x'; 100]);
        stream.extend([0, 0, 0, 0]);
        stream.extend([0, 0, 0, 0]);
        let mut index = vec![0, 1, 116, 10, 0, 0, 0, 0];
        index.truncate(8);
        let backward = (index.len() / 4 - 1) as u32;
        stream.extend(&index);
        stream.extend([0; 4]);
        stream.extend(backward.to_le_bytes());
        stream.extend([0, 1]);
        stream.extend(FOOTER_MAGIC);
        assert_eq!(
            decoded(&stream),
            Err(MiniDebugRefusal::Decoding(
                "its chunks state more than the 10 bytes its index states".to_owned()
            ))
        );
    }

    #[test]
    fn a_stream_cut_short_is_refused() {
        let whole = stated(29_696);
        assert_eq!(
            decoded(&whole[..whole.len() - 3]),
            Err(MiniDebugRefusal::Container(
                "no stream footer where the section ends"
            ))
        );
        assert!(decoded(b"not xz at all, and long enough").is_err());
    }
}
