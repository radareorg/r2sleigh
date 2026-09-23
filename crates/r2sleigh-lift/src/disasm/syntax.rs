//! How a listing spells an instruction, and where the numbers in it sit.
//!
//! Sleigh prints the assembler's own syntax; radare2 prints its own. The two
//! describe the same instruction, so the difference between them is spelling
//! and belongs beside the decoder rather than in whatever happens to be
//! printing a listing. The number spans come from the same pass because they
//! are positions in the spelling this module produces, and nothing downstream
//! can recover them by searching the finished text for a value.

/// A number as one instruction's operand body spells it.
///
/// The span is the point. Naming a literal by its value alone cannot tell two
/// operands of one instruction apart when both hold the same number, which is
/// how a `-0x4` displacement once came out as a symbol's name; a span says
/// which number is being claimed about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberSpan {
    /// Byte offset into the operand body where the spelling starts, sign included.
    pub start: usize,
    /// Byte offset one past the spelling's last character.
    pub end: usize,
    /// What the spelling denotes, sign applied.
    pub value: i128,
}

/// One instruction as a listing spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syntax {
    /// The operation, lower-cased, with no operands.
    pub mnemonic: String,
    /// The operands, exactly as they follow the mnemonic; empty where there are none.
    pub body: String,
    /// How many bytes the instruction occupies.
    pub size: usize,
    /// Every number in `body`, in the order it appears there.
    pub numbers: Vec<NumberSpan>,
}

impl Syntax {
    /// The mnemonic and its operands as one line.
    pub fn text(&self) -> String {
        match self.body.is_empty() {
            true => self.mnemonic.clone(),
            false => format!("{} {}", self.mnemonic, self.body),
        }
    }
}

/// Spell one decoded instruction the way radare2 spells it.
pub fn radare2(mnemonic: &str, body: &str, size: usize, arch: &str) -> Syntax {
    let joined = format!("{mnemonic} {body}");
    let spelled = radare2_text(joined.trim(), arch);
    let (mnemonic, body) = match spelled.find(' ') {
        Some(split) => (spelled[..split].to_owned(), spelled[split + 1..].to_owned()),
        None => (spelled, String::new()),
    };
    let numbers = number_spans(&body);
    Syntax {
        mnemonic,
        body,
        size,
        numbers,
    }
}

/// Every number in an operand body, by where it is written.
///
/// Only the hexadecimal spelling is scanned, because that is the only form
/// this decoder prints a literal in; a bare decimal in a body is part of a
/// register name or a shift count, and neither is an address.
pub fn number_spans(body: &str) -> Vec<NumberSpan> {
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some(found) = body[at..].find("0x") {
        let start = at + found;
        let digits = body[start + 2..]
            .find(|c: char| !c.is_ascii_hexdigit())
            .map_or(body.len() - start - 2, |end| end);
        at = start + 2 + digits;
        let Ok(magnitude) = u64::from_str_radix(&body[start + 2..at], 16) else {
            continue;
        };
        // A minus against the digits, or radare2's `- 0x4` for Sleigh's `+ -0x4`, is the number's sign.
        let before = &body[..start];
        let sign = match (before.ends_with('-'), before.ends_with(" - ")) {
            (true, _) => 1,
            (_, true) => 2,
            _ => 0,
        };
        spans.push(NumberSpan {
            start: start - sign,
            end: at,
            value: match sign {
                0 => i128::from(magnitude),
                _ => -i128::from(magnitude),
            },
        });
    }
    spans
}

/// Radare2 spells an instruction lowercase, with a space after each comma and
/// no `#` before an immediate, where Sleigh keeps the assembler's own prefix.
fn radare2_text(text: &str, arch: &str) -> String {
    let lowered = text.to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut chars = lowered.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '#' {
            continue;
        }
        out.push(c);
        if c == ',' && chars.peek().is_some_and(|next| *next != ' ') {
            out.push(' ');
        }
    }
    // Sleigh writes the x86 memory-operand size as `dword ptr [..]` and a
    // negative displacement as `+ -0x4`; radare2 writes `dword [..]` and
    // `- 0x4`. Same operand, and the two spellings are only spellings.
    let out = out.replace(" ptr [", " [").replace("+ -", "- ");
    let out = bare_effective_address(&out);
    if arch == "ARM" {
        arm_alias(&arm_it_condition(&arm_role_registers(&out)))
    } else {
        x86_condition_alias(&out)
    }
}

/// Sleigh spells a Thumb `it`-predicated operation `add.eq`, where radare2 and Sleigh's own ARM mode write `addeq`.
fn arm_it_condition(text: &str) -> String {
    const CONDITIONS: [&str; 16] = [
        "eq", "ne", "cs", "cc", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
        "le",
    ];
    let head = text.split_whitespace().next().unwrap_or_default();
    let Some((operation, rest)) = head.split_once('.') else {
        return text.to_owned();
    };
    let condition = rest.split('.').next().unwrap_or_default();
    match CONDITIONS.contains(&condition) {
        true => format!("{operation}{rest}{}", &text[head.len()..]),
        false => text.to_owned(),
    }
}

/// Two ARM spellings Sleigh keeps from before the unified syntax.
///
/// `cpy rd, rm` is what `mov rd, rm` was called, and a post-indexed load of one
/// register from the stack pointer is a `pop` of it. Every other ARM
/// disassembler prints the later name.
fn arm_alias(text: &str) -> String {
    if let Some(rest) = text.strip_prefix("cpy ") {
        return format!("mov {rest}");
    }
    if let Some(register) = text
        .strip_prefix("ldr ")
        .and_then(|rest| rest.strip_suffix(", [sp], 0x4"))
    {
        return format!("pop {{{register}}}");
    }
    text.to_owned()
}

/// One x86 condition, two names: the flag it tests and the comparison it came from.
///
/// `jnz` and `jne` are the same opcode; Sleigh prints the flag and radare2
/// prints the comparison. Only the four conditions whose two spellings differ
/// are listed; the rest are already the same word in both.
fn x86_condition_alias(text: &str) -> String {
    const CONDITIONS: [(&str, &str); 4] = [("z", "e"), ("nz", "ne"), ("c", "b"), ("nc", "ae")];
    const VERBS: [&str; 4] = ["j", "set", "cmov", "loop"];
    let head = text.split_whitespace().next().unwrap_or_default();
    for verb in VERBS {
        let Some(condition) = head.strip_prefix(verb) else {
            continue;
        };
        let Some((_, spelled)) = CONDITIONS.iter().find(|(flag, _)| *flag == condition) else {
            continue;
        };
        return format!("{verb}{spelled}{}", &text[head.len()..]);
    }
    text.to_owned()
}

/// radare2 spells the three ARM registers that have a job by that job.
///
/// The procedure call standard gives r11, r12, r13 and r14 the roles of frame
/// pointer, intra-procedure scratch, stack pointer and link register, and
/// every ARM disassembler but Sleigh's prints the role.
fn arm_role_registers(text: &str) -> String {
    const ROLES: [(&str, &str); 5] = [
        ("r11", "fp"),
        ("r12", "ip"),
        ("r13", "sp"),
        ("r14", "lr"),
        ("r15", "pc"),
    ];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('r') {
        out.push_str(&rest[..start]);
        let taken = ROLES.iter().find(|(spelling, _)| {
            rest[start..].starts_with(spelling)
                && !rest[start + spelling.len()..].starts_with(|c: char| c.is_ascii_alphanumeric())
        });
        match taken {
            Some((spelling, role)) => {
                out.push_str(role);
                rest = &rest[start + spelling.len()..];
            }
            None => {
                out.push('r');
                rest = &rest[start + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `lea` loads an address rather than what is there, and radare2 writes that
/// address without the brackets that would say it was read.
///
/// Only where the brackets hold one thing: `lea r8, [0x8f0]` is that address,
/// while `lea rax, [rbp - 0x4]` is a computation and keeps its shape.
fn bare_effective_address(text: &str) -> String {
    let Some(rest) = text.strip_prefix("lea ") else {
        return text.to_owned();
    };
    let Some(open) = rest.find('[') else {
        return text.to_owned();
    };
    let Some(close) = rest.rfind(']') else {
        return text.to_owned();
    };
    let inside = &rest[open + 1..close];
    if close + 1 != rest.len() || inside.contains(' ') || inside.is_empty() {
        return text.to_owned();
    }
    format!("lea {}{}", &rest[..open], inside)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mnemonic_and_its_operands_stay_apart() {
        let syntax = radare2("MOV", "RAX,#0x10", 4, "x86-64");
        assert_eq!(syntax.mnemonic, "mov");
        assert_eq!(syntax.body, "rax, 0x10");
        assert_eq!(syntax.text(), "mov rax, 0x10");
    }

    #[test]
    fn an_instruction_with_no_operands_has_an_empty_body() {
        let syntax = radare2("RET", "", 1, "x86-64");
        assert_eq!(syntax.mnemonic, "ret");
        assert!(syntax.body.is_empty());
        assert_eq!(syntax.text(), "ret");
    }

    #[test]
    fn a_rewrite_that_changes_the_operation_changes_the_mnemonic() {
        let syntax = radare2("cpy", "r0, r1", 4, "ARM");
        assert_eq!(syntax.mnemonic, "mov");
        assert_eq!(syntax.body, "r0, r1");
        let popped = radare2("ldr", "r4, [r13], #0x4", 4, "ARM");
        assert_eq!(popped.text(), "pop {r4}");
    }

    #[test]
    fn an_it_predicated_operation_takes_its_condition_as_a_suffix() {
        assert_eq!(
            radare2("add.eq", "r3,r1,#0x1", 2, "ARM").text(),
            "addeq r3, r1, 0x1"
        );
        assert_eq!(
            radare2("pop.eq.w", "{r8,r9,r11}", 4, "ARM").text(),
            "popeq.w {r8, r9, fp}"
        );
        // A vector element type and an AArch64 condition are not an `it` predicate.
        assert_eq!(
            radare2("vadd.i32", "d0,d1,d2", 4, "ARM").text(),
            "vadd.i32 d0, d1, d2"
        );
        assert_eq!(radare2("b.eq", "0x10", 4, "aarch64").text(), "b.eq 0x10");
    }

    #[test]
    fn a_displacement_carries_its_sign_into_the_span() {
        let syntax = radare2("MOV", "EAX,dword ptr [RBP + -0x4]", 3, "x86-64");
        assert_eq!(syntax.body, "eax, dword [rbp - 0x4]");
        let spans: Vec<i128> = syntax.numbers.iter().map(|span| span.value).collect();
        assert_eq!(spans, vec![-4]);
        let span = syntax.numbers[0];
        assert_eq!(&syntax.body[span.start..span.end], "- 0x4");
    }

    #[test]
    fn two_operands_holding_one_number_are_told_apart() {
        let spans = number_spans("0x40, [0x40]");
        assert_eq!(spans.len(), 2);
        assert_eq!((spans[0].start, spans[0].end), (0, 4));
        assert_eq!((spans[1].start, spans[1].end), (7, 11));
        assert_eq!(spans[0].value, spans[1].value);
    }

    #[test]
    fn a_negative_literal_is_negative_and_spans_its_sign() {
        let spans = number_spans("[sp, -0x8]");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].value, -8);
        assert_eq!(&"[sp, -0x8]"[spans[0].start..spans[0].end], "-0x8");
    }
}
