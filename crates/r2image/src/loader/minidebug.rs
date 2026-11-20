//! `.gnu_debugdata`, GDB's MiniDebugInfo: an xz stream holding an ELF whose `.symtab` lists the
//! functions the dynamic table lacks, decoded whole under a refusing budget (adr-minidebuginfo.md).

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

/// The inner file decoded whole, or why it is refused: a dictionary of at most [`BUDGET`] and
/// output past the stated size refused hold the decode to twice the budget. O(input + output).
pub(crate) fn decoded(section: &[u8]) -> Result<Vec<u8>, MiniDebugRefusal> {
    let stated = stated_size(section)?;
    if stated > BUDGET {
        return Err(MiniDebugRefusal::OverBudget { stated });
    }
    let refuse = |why: String| MiniDebugRefusal::Decoding(why);
    let limit = usize::try_from(stated).map_err(|_| refuse("too large here".to_owned()))?;
    let budget = usize::try_from(BUDGET).unwrap_or(usize::MAX);
    let mut decoder = xz4rust::XzDecoder::with_alloc_dict_size(xz4rust::DICT_SIZE_MIN, budget);
    let (mut out, mut buffer) = (Vec::with_capacity(limit), vec![0u8; 1 << 16]);
    let mut input = section;
    // Each step consumes input or yields output, both finite, or it ends the loop.
    loop {
        let step = decoder.decode(input, &mut buffer);
        let step = step.map_err(|error| refuse(error.to_string()))?;
        let (consumed, produced) = (step.input_consumed(), step.output_produced());
        if produced > limit - out.len() {
            return Err(refuse("the stream decodes past its stated size".to_owned()));
        }
        out.extend_from_slice(&buffer[..produced]);
        input = &input[consumed..];
        match step {
            xz4rust::XzNextBlockResult::EndOfStream(..) => break,
            _ if consumed == 0 && produced == 0 => {
                return Err(refuse("the stream ends before its footer".to_owned()));
            }
            _ => {}
        }
    }
    if !input.is_empty() {
        return Err(refuse(format!("{} bytes follow the stream", input.len())));
    }
    match out.len() == limit {
        true => Ok(out),
        false => Err(refuse(format!(
            "{} bytes decoded where the index states {stated}",
            out.len()
        ))),
    }
}

const HEADER_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";

/// The uncompressed size a one-stream xz file's index states, read from its footer back (xz file
/// format 1.2.1: 2.1.2.2, 4, 4.3) before any block is decoded.
fn stated_size(stream: &[u8]) -> Result<u64, MiniDebugRefusal> {
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
    let records = varint(&mut index).ok_or(refuse("an unreadable record count"))?;
    let mut stated = 0u64;
    for _ in 0..records {
        let _unpadded = varint(&mut index).ok_or(refuse("an unreadable record"))?;
        let uncompressed = varint(&mut index).ok_or(refuse("an unreadable record"))?;
        stated = stated
            .checked_add(uncompressed)
            .ok_or(refuse("the records overflow"))?;
    }
    Ok(stated)
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
        assert_eq!(stated_size(&stated(29_696)), Ok(29_696));
    }

    /// `xz --check=crc32` of 100,000 zero bytes: one LZMA2 block, its index at 128.
    const ZEROS: [u8; 152] = [
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x04, 0xc0, 0x5b,
        0xa0, 0x8d, 0x06, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xca, 0xf2,
        0x3c, 0xdc, 0xe1, 0x86, 0x9f, 0x00, 0x53, 0x5d, 0x00, 0x00, 0x6f, 0xfd, 0xff, 0xff, 0xa3,
        0xb7, 0xff, 0x47, 0x3e, 0x48, 0x15, 0x72, 0x39, 0x61, 0x51, 0xb8, 0x92, 0x28, 0xe6, 0xa3,
        0x86, 0x07, 0xf9, 0xee, 0xe4, 0x1e, 0x82, 0xd3, 0x2f, 0xc5, 0x3a, 0x3c, 0x01, 0x4b, 0xb1,
        0x7e, 0xc9, 0x8a, 0x8a, 0x4d, 0x2f, 0xa3, 0x0d, 0xd9, 0x7f, 0xa6, 0xe3, 0x8c, 0x23, 0x11,
        0x53, 0xe0, 0x59, 0x18, 0xc5, 0x75, 0x8a, 0xe2, 0x77, 0xf8, 0xb6, 0x94, 0x7f, 0x0c, 0x6a,
        0xc0, 0xde, 0x74, 0x49, 0x64, 0xe2, 0xe9, 0x5c, 0x53, 0xb2, 0x04, 0xd6, 0xb1, 0xf5, 0x97,
        0x00, 0x00, 0x00, 0x00, 0x7d, 0x95, 0x11, 0xd4, 0x00, 0x01, 0x73, 0xa0, 0x8d, 0x06, 0x00,
        0x00, 0x70, 0x26, 0x7a, 0x25, 0x3e, 0x30, 0x0d, 0x8b, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x59, 0x5a,
    ];

    #[test]
    fn a_stream_decodes_whole_to_its_stated_size() {
        assert_eq!(decoded(&ZEROS), Ok(vec![0; 100_000]));
    }

    /// The index restated as 10 bytes and as no block at all: the decoder streams, so the first
    /// output past the statement refuses before the block is held whole.
    #[test]
    fn a_block_decoding_past_its_index_is_refused_as_it_decodes() {
        let mut understated = ZEROS;
        understated[131..134].copy_from_slice(&[0x8a, 0x80, 0x00]);
        let past = MiniDebugRefusal::Decoding("the stream decodes past its stated size".to_owned());
        assert_eq!(decoded(&understated), Err(past.clone()));
        let mut unlisted = ZEROS;
        unlisted[129] = 0;
        assert_eq!(decoded(&unlisted), Err(past));
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
