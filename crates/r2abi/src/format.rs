//! The operands a printf-family format consumes past its fixed parameters (ISO C17 7.21.6.1, the
//! fprintf conversion specification; POSIX.1-2017 fprintf for `%n$` operands; glibc `%m`).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintfFormatRefusal {
    UnterminatedSpecifier,
    UnsupportedConversion,
    InvalidPosition,
    MixedPositionalAndSequential,
    CountOverflow,
    /// One positional operand read by a floating and an integer conversion.
    ConflictingOperandClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgumentMode {
    Unknown,
    Sequential,
    Positional,
}

fn decimal(bytes: &[u8], cursor: &mut usize) -> Result<Option<usize>, PrintfFormatRefusal> {
    let start = *cursor;
    let mut value = 0usize;
    while let Some(digit) = bytes.get(*cursor).copied().filter(u8::is_ascii_digit) {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(usize::from(digit - b'0')))
            .ok_or(PrintfFormatRefusal::CountOverflow)?;
        *cursor += 1;
    }
    Ok((*cursor != start).then_some(value))
}

fn positional_index(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Option<usize>, PrintfFormatRefusal> {
    let start = *cursor;
    let Some(position) = decimal(bytes, cursor)? else {
        return Ok(None);
    };
    if bytes.get(*cursor) != Some(&b'$') {
        *cursor = start;
        return Ok(None);
    }
    *cursor += 1;
    position
        .checked_sub(1)
        .map(Some)
        .ok_or(PrintfFormatRefusal::InvalidPosition)
}

/// Take one operand and answer its index in the tail.
fn consume_argument(
    position: Option<usize>,
    mode: &mut ArgumentMode,
    sequential_count: &mut usize,
    largest_position: &mut Option<usize>,
) -> Result<usize, PrintfFormatRefusal> {
    match position {
        Some(position) => {
            if *mode == ArgumentMode::Sequential {
                return Err(PrintfFormatRefusal::MixedPositionalAndSequential);
            }
            *mode = ArgumentMode::Positional;
            *largest_position = Some(largest_position.map_or(position, |old| old.max(position)));
            Ok(position)
        }
        None => {
            if *mode == ArgumentMode::Positional {
                return Err(PrintfFormatRefusal::MixedPositionalAndSequential);
            }
            *mode = ArgumentMode::Sequential;
            let index = *sequential_count;
            *sequential_count = sequential_count
                .checked_add(1)
                .ok_or(PrintfFormatRefusal::CountOverflow)?;
            Ok(index)
        }
    }
}

/// The operand classes a format names, by tail index: one operand read as two classes refuses.
#[derive(Default)]
struct Classes {
    floating: u64,
    integer: u64,
    any_floating: bool,
}

impl Classes {
    fn note(&mut self, index: usize, floating: bool) -> Result<(), PrintfFormatRefusal> {
        self.any_floating |= floating;
        let Some(bit) = u32::try_from(index).ok().and_then(|i| 1u64.checked_shl(i)) else {
            return Ok(());
        };
        let (own, other) = match floating {
            true => (&mut self.floating, self.integer),
            false => (&mut self.integer, self.floating),
        };
        *own |= bit;
        match other & bit {
            0 => Ok(()),
            _ => Err(PrintfFormatRefusal::ConflictingOperandClass),
        }
    }
}

/// What a printf-family format says about the arguments it consumes: how many, and which are a
/// floating conversion's, whose operand travels in the convention's floating sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrintfConsumedArguments {
    pub count: usize,
    pub any_floating: bool,
    /// Bit `i` is set where tail operand `i` is floating; an operand past 63 sets only `any_floating`.
    pub floating: u64,
    /// Whether an `L` floating conversion reads a `long double` (7.21.6.1p7), which no 8-byte slot holds.
    pub long_double: bool,
}

/// Count the arguments a complete format consumes: `%%` none, a `*` width or precision one, and
/// a conversion one; positional operands only where every consuming operand is positional.
pub fn printf_consumed_arguments(
    format: &str,
) -> Result<PrintfConsumedArguments, PrintfFormatRefusal> {
    let bytes = format.as_bytes();
    let mut cursor = 0usize;
    let mut mode = ArgumentMode::Unknown;
    let mut sequential_count = 0usize;
    let mut largest_position = None;
    let mut classes = Classes::default();
    let mut long_double = false;

    while cursor < bytes.len() {
        if bytes[cursor] != b'%' {
            cursor += 1;
            continue;
        }
        cursor += 1;
        if bytes.get(cursor) == Some(&b'%') {
            cursor += 1;
            continue;
        }

        let conversion_position = positional_index(bytes, &mut cursor)?;
        while bytes
            .get(cursor)
            .is_some_and(|byte| b"#0- +'I".contains(byte))
        {
            cursor += 1;
        }

        if bytes.get(cursor) == Some(&b'*') {
            cursor += 1;
            let width_position = positional_index(bytes, &mut cursor)?;
            let index = consume_argument(
                width_position,
                &mut mode,
                &mut sequential_count,
                &mut largest_position,
            )?;
            classes.note(index, false)?;
        } else {
            let _ = decimal(bytes, &mut cursor)?;
        }

        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            if bytes.get(cursor) == Some(&b'*') {
                cursor += 1;
                let precision_position = positional_index(bytes, &mut cursor)?;
                let index = consume_argument(
                    precision_position,
                    &mut mode,
                    &mut sequential_count,
                    &mut largest_position,
                )?;
                classes.note(index, false)?;
            } else {
                let _ = decimal(bytes, &mut cursor)?;
            }
        }

        let long = bytes.get(cursor) == Some(&b'L');
        if matches!(
            bytes.get(cursor..cursor.saturating_add(2)),
            Some(b"hh" | b"ll")
        ) {
            cursor += 2;
        } else if bytes
            .get(cursor)
            .is_some_and(|byte| b"hljztLqZ".contains(byte))
        {
            cursor += 1;
        }

        let conversion = bytes
            .get(cursor)
            .copied()
            .ok_or(PrintfFormatRefusal::UnterminatedSpecifier)?;
        cursor += 1;
        match conversion {
            b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'f' | b'F' | b'e' | b'E' | b'g' | b'G'
            | b'a' | b'A' | b'c' | b'C' | b's' | b'S' | b'p' | b'n' | b'b' | b'B' => {
                let floating = matches!(
                    conversion,
                    b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A'
                );
                let index = consume_argument(
                    conversion_position,
                    &mut mode,
                    &mut sequential_count,
                    &mut largest_position,
                )?;
                classes.note(index, floating)?;
                long_double |= long && floating;
            }
            // GNU printf's strerror conversion consumes no operand.
            b'm' if conversion_position.is_none() => {}
            _ => return Err(PrintfFormatRefusal::UnsupportedConversion),
        }
    }

    let count = match mode {
        ArgumentMode::Unknown | ArgumentMode::Sequential => sequential_count,
        ArgumentMode::Positional => largest_position
            .and_then(|position| position.checked_add(1))
            .ok_or(PrintfFormatRefusal::InvalidPosition)?,
    };
    Ok(PrintfConsumedArguments {
        count,
        any_floating: classes.any_floating,
        floating: classes.floating,
        long_double,
    })
}

#[cfg(test)]
mod tests {
    use super::{PrintfFormatRefusal, printf_consumed_arguments};

    fn printf_consumed_argument_count(format: &str) -> Result<usize, PrintfFormatRefusal> {
        printf_consumed_arguments(format).map(|consumed| consumed.count)
    }

    /// A floating conversion is reported, because its operand does not travel
    /// where an integer one does.
    #[test]
    fn floating_conversions_are_named_and_others_are_not() {
        for (format, count, floating) in [
            ("%d items", 1, 0b0),
            ("%s took %6.3f seconds", 2, 0b10),
            ("%5.2f%% saved", 1, 0b1),
            ("%-12.4e", 1, 0b1),
            ("%a", 1, 0b1),
            ("100%% done", 0, 0b0),
            ("%*d", 2, 0b0),
            ("%.*f", 2, 0b10),
            ("%2$f %1$d", 2, 0b10),
        ] {
            let consumed = printf_consumed_arguments(format).expect("format parses");
            assert_eq!(consumed.count, count, "count for {format:?}");
            assert_eq!(consumed.floating, floating, "floating for {format:?}");
            assert_eq!(consumed.any_floating, floating != 0, "any for {format:?}");
        }
    }

    /// An `L` floating conversion is a `long double`, which an integer `L` is not.
    #[test]
    fn a_long_double_conversion_is_named() {
        assert!(printf_consumed_arguments("%Lf").unwrap().long_double);
        assert!(!printf_consumed_arguments("%f %Ld").unwrap().long_double);
    }

    /// A positional operand two conversions read as different classes has no one carrier.
    #[test]
    fn an_operand_read_as_two_classes_refuses() {
        assert_eq!(
            printf_consumed_argument_count("%1$d %1$f"),
            Err(PrintfFormatRefusal::ConflictingOperandClass)
        );
        assert_eq!(printf_consumed_argument_count("%1$d %1$x").unwrap(), 1);
    }

    #[test]
    fn counts_conversion_operands_instead_of_percent_bytes() {
        assert_eq!(printf_consumed_argument_count("done: 100%%").unwrap(), 0);
        assert_eq!(printf_consumed_argument_count("%08.3lld %s").unwrap(), 2);
        assert_eq!(printf_consumed_argument_count("%*.*f").unwrap(), 3);
        assert_eq!(printf_consumed_argument_count("%m").unwrap(), 0);
    }

    #[test]
    fn positional_operands_count_distinct_argument_slots() {
        assert_eq!(printf_consumed_argument_count("%2$*1$d %2$d").unwrap(), 2);
        assert_eq!(
            printf_consumed_argument_count("%1$d %d"),
            Err(PrintfFormatRefusal::MixedPositionalAndSequential)
        );
    }

    #[test]
    fn malformed_or_unknown_specifiers_refuse() {
        assert_eq!(
            printf_consumed_argument_count("value %"),
            Err(PrintfFormatRefusal::UnterminatedSpecifier)
        );
        assert_eq!(
            printf_consumed_argument_count("%Q"),
            Err(PrintfFormatRefusal::UnsupportedConversion)
        );
    }
}
