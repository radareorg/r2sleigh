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

/// Where one token of an operand body is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset into the operand body where the token starts.
    pub start: usize,
    /// Byte offset one past the token's last character.
    pub end: usize,
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
    /// Every register `body` names, in the order it appears there: a word the
    /// specification's register table names, filled in by the decoder that
    /// holds that table ([`register_spans`]).
    pub registers: Vec<Span>,
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

/// Spell one decoded instruction the way radare2 spells it; `bytes` are its encoding (AArch64 aliases read it).
pub fn radare2(mnemonic: &str, body: &str, size: usize, arch: &str, bytes: &[u8]) -> Syntax {
    let joined = format!("{mnemonic} {body}");
    let word = bytes
        .first_chunk::<4>()
        .map(|word| u32::from_le_bytes(*word));
    let spelled = radare2_text(joined.trim(), arch, word);
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
        registers: Vec::new(),
    }
}

/// Every word of an operand body the register table names, ignoring case.
///
/// A word starts with a letter or `_` and runs over letters, digits, `_` and
/// `.`; a number (`0x10`) starts with a digit and is never one. The table is
/// the specification's own, so this is the decoder saying which tokens are
/// registers, not a guess from what a name looks like.
pub fn register_spans(body: &str, registers: &std::collections::BTreeSet<String>) -> Vec<Span> {
    let bytes = body.as_bytes();
    let mut spans = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let c = bytes[at];
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = at;
            while at < bytes.len()
                && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_' || bytes[at] == b'.')
            {
                at += 1;
            }
            if registers.contains(&body[start..at].to_ascii_lowercase()) {
                spans.push(Span { start, end: at });
            }
        } else if c.is_ascii_digit() {
            while at < bytes.len() && bytes[at].is_ascii_alphanumeric() {
                at += 1;
            }
        } else {
            at += 1;
        }
    }
    spans
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
            .unwrap_or(body.len() - start - 2);
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

/// One register as the listing spells it in an operand: lowercase, and on ARM by its role.
pub(crate) fn register_text(name: &str, arch: &str) -> String {
    let lowered = name.to_lowercase();
    match arch {
        "ARM" => arm_role_registers(&lowered),
        _ => lowered,
    }
}

/// Radare2 spells an instruction lowercase, with a space after each comma and
/// no `#` before an immediate, where Sleigh keeps the assembler's own prefix.
fn radare2_text(text: &str, arch: &str, word: Option<u32>) -> String {
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
    // Sleigh writes the x86 memory-operand size as `dword ptr [..]` (`word ptr cs:[..]`) and a
    // negative displacement as `+ -0x4`; radare2 writes `dword [..]` and `- 0x4`.
    let out = out.replace(" ptr ", " ").replace("+ -", "- ");
    match arch {
        "ARM" => {
            // A zero offset says nothing radare2 writes: `[r0, 0x0]` is `[r0]`.
            let out = out.replace(", 0x0]", "]");
            arm_alias(&arm_it_condition(&arm_role_registers(&out)))
        }
        "aarch64" => aarch64_condition(&aarch64_alias(&out, word)),
        _ => {
            // Nor a scale of one: `[rax + rax*0x1]` is `[rax + rax]`.
            let out = out.replace("*0x1]", "]").replace("*0x1 ", " ");
            x86_condition_alias(&out)
        }
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

/// ARM spellings Sleigh keeps from before the unified syntax, as other disassemblers print them: `cpy` is
/// `mov`, a stack load or store of two or more registers `pop` or `push` (Arm ARM), `ldmia` is `ldm`.
fn arm_alias(text: &str) -> String {
    let several = |list: &str| list.contains(',') || list.contains('-');
    if let Some(rest) = text.strip_prefix("cpy ") {
        return format!("mov {rest}");
    }
    if let Some(list) = text
        .strip_prefix("stmdb sp!, ")
        .filter(|list| several(list))
    {
        return format!("push {list}");
    }
    if let Some(list) = text
        .strip_prefix("ldmia sp!, ")
        .filter(|list| several(list))
    {
        return format!("pop {list}");
    }
    if let Some(rest) = text.strip_prefix("ldmia ") {
        return format!("ldm {rest}");
    }
    if let Some(rest) = text.strip_prefix("stmia ") {
        return format!("stm {rest}");
    }
    if let Some(register) = text
        .strip_prefix("ldr ")
        .and_then(|rest| rest.strip_suffix(", [sp], 0x4"))
    {
        return format!("pop {{{register}}}");
    }
    text.to_owned()
}

/// The AArch64 aliases the Arm ARM prefers that Sleigh omits or guards loosely (doc/adr-listing-spelling.md).
/// `word` is the encoding, for a precondition on fields the operands drop.
fn aarch64_alias(text: &str, word: Option<u32>) -> String {
    let (mnemonic, body) = text.split_once(' ').unwrap_or((text, ""));
    let operands: Vec<&str> = body.split(", ").collect();
    let aliased = match (mnemonic, operands.as_slice()) {
        ("bfm", [rd, rn, immr, imms]) => bitfield_move(rd, rn, number(immr), number(imms)),
        ("negs", [rd, _, ..]) if is_zero_register(rd) => Some(format!("cmp {body}")),
        ("mov", [rd, rm, shift]) if is_shift(shift) => {
            Some(format!("orr {rd}, {}, {rm}, {shift}", zero_register(rd)))
        }
        ("mov" | "orr", [rd, .., imm]) => {
            word.and_then(|word| immediate_move(mnemonic, rd, imm, word))
        }
        _ => None,
    };
    aliased.unwrap_or_else(|| text.to_owned())
}

/// BFM is BFI where `imms < immr` (BFC when it reads the zero register) and BFXIL otherwise (Arm ARM).
fn bitfield_move(rd: &str, rn: &str, immr: Option<u64>, imms: Option<u64>) -> Option<String> {
    let (immr, imms) = (immr?, imms?);
    let size = match rd.chars().next()? {
        'w' => 32,
        'x' => 64,
        _ => return None,
    };
    if imms >= immr {
        return Some(format!(
            "bfxil {rd}, {rn}, {immr:#x}, {:#x}",
            imms - immr + 1
        ));
    }
    let (lsb, width) = ((size - immr) % size, imms + 1);
    Some(match is_zero_register(rn) {
        true => format!("bfc {rd}, {lsb:#x}, {width:#x}"),
        false => format!("bfi {rd}, {rn}, {lsb:#x}, {width:#x}"),
    })
}

/// The immediate forms of MOV, which are ORR, MOVZ or MOVN: the alias holds only where no other
/// encoding of the same value would be assembled from it (Arm ARM `MoveWidePreferred`, MOV (wide immediate)).
fn immediate_move(mnemonic: &str, rd: &str, imm: &str, word: u32) -> Option<String> {
    let sf = word >> 31 == 1;
    let (opc, field) = ((word >> 29) & 3, (word >> 23) & 0x3f);
    match field {
        0x24 if opc == 1 && (word >> 5) & 0x1f == 31 => {
            let (n, immr, imms) = ((word >> 22) & 1, (word >> 16) & 0x3f, (word >> 10) & 0x3f);
            Some(match move_wide_preferred(sf, n, immr, imms) {
                true => format!("orr {rd}, {}, {imm}", if sf { "xzr" } else { "wzr" }),
                false => format!("mov {rd}, {imm}"),
            })
        }
        0x25 if mnemonic == "mov" && opc != 3 => {
            let (hw, value) = ((word >> 21) & 3, (word >> 5) & 0xffff);
            let inverted = opc == 0;
            let alias = !(value == 0 && hw != 0) && !(inverted && !sf && value == 0xffff);
            (!alias).then(|| {
                let shift = if hw == 0 {
                    String::new()
                } else {
                    format!(", lsl {:#x}", hw * 16)
                };
                format!(
                    "{} {rd}, {value:#x}{shift}",
                    if inverted { "movn" } else { "movz" }
                )
            })
        }
        _ => None,
    }
}

/// Whether one MOVZ or MOVN writes the bitmask immediate, so that ORR keeps its own spelling.
fn move_wide_preferred(sf: bool, n: u32, immr: u32, imms: u32) -> bool {
    let width = if sf { 64 } else { 32 };
    // The element must be the whole register: N set for 64 bits, `imms<5>` clear for 32.
    if (sf && n == 0) || (!sf && (n == 1 || imms & 0x20 != 0)) {
        return false;
    }
    // At most 16 ones, or at most 16 zeros, that do not cross a halfword once rotated.
    if imms < 16 {
        return (16 - immr % 16) % 16 <= 15 - imms;
    }
    imms + 17 >= width && immr % 16 <= imms + 17 - width
}

/// A Sleigh condition name for the carry flag is `cs` and `cc`; the Arm ARM, binutils and LLVM write `hs` and `lo`.
fn aarch64_condition(text: &str) -> String {
    fn rename(condition: &str) -> &str {
        match condition {
            "cs" => "hs",
            "cc" => "lo",
            other => other,
        }
    }

    let (head, body) = text.split_once(' ').unwrap_or((text, ""));
    let head = match head.split_once('.') {
        Some((verb, condition)) => format!("{verb}.{}", rename(condition)),
        None => head.to_owned(),
    };
    let body = match body.rsplit_once(", ") {
        Some((front, last)) => format!("{front}, {}", rename(last)),
        None => body.to_owned(),
    };
    match body.is_empty() {
        true => head,
        false => format!("{head} {body}"),
    }
}

fn is_zero_register(name: &str) -> bool {
    matches!(name, "wzr" | "xzr")
}

fn zero_register(destination: &str) -> &'static str {
    if destination.starts_with('w') {
        "wzr"
    } else {
        "xzr"
    }
}

fn is_shift(operand: &str) -> bool {
    ["lsl ", "lsr ", "asr ", "ror "]
        .iter()
        .any(|shift| operand.starts_with(shift))
}

fn number(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
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

/// radare2 spells the ARM registers that have a job by that job.
///
/// The procedure call standard gives r10 to r14 the roles of stack limit, frame
/// pointer, intra-procedure scratch, stack pointer and link register, and
/// every ARM disassembler but Sleigh's prints the role.
fn arm_role_registers(text: &str) -> String {
    const ROLES: [(&str, &str); 6] = [
        ("r10", "sl"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mnemonic_and_its_operands_stay_apart() {
        let syntax = radare2("MOV", "RAX,#0x10", 4, "x86-64", &[]);
        assert_eq!(syntax.mnemonic, "mov");
        assert_eq!(syntax.body, "rax, 0x10");
        assert_eq!(syntax.text(), "mov rax, 0x10");
    }

    #[test]
    fn an_instruction_with_no_operands_has_an_empty_body() {
        let syntax = radare2("RET", "", 1, "x86-64", &[]);
        assert_eq!(syntax.mnemonic, "ret");
        assert!(syntax.body.is_empty());
        assert_eq!(syntax.text(), "ret");
    }

    #[test]
    fn a_rewrite_that_changes_the_operation_changes_the_mnemonic() {
        let syntax = radare2("cpy", "r0, r1", 4, "ARM", &[]);
        assert_eq!(syntax.mnemonic, "mov");
        assert_eq!(syntax.body, "r0, r1");
        let popped = radare2("ldr", "r4, [r13], #0x4", 4, "ARM", &[]);
        assert_eq!(popped.text(), "pop {r4}");
    }

    /// Each spelling as radare2's own tests write it (test/db/cmd/cmd_pd).
    #[test]
    fn sleigh_s_spellings_read_as_radare2_writes_them() {
        let text = |mnemonic, body, arch| radare2(mnemonic, body, 4, arch, &[]).text();
        assert_eq!(text("stmdb", "r13!,{r11,r14}", "ARM"), "push {fp, lr}");
        assert_eq!(
            text("stmdb", "r13!,{r8,r10,r11}", "ARM"),
            "push {r8, sl, fp}"
        );
        assert_eq!(text("ldmia", "r13!,{r4,r15}", "ARM"), "pop {r4, pc}");
        // One register is no PUSH or POP alias of LDM and STMDB (Arm ARM; binutils, radare2).
        assert_eq!(text("ldmia", "r13!,{r15}", "ARM"), "ldm sp!, {pc}");
        assert_eq!(text("stmdb", "r13!,{r14}", "ARM"), "stmdb sp!, {lr}");
        assert_eq!(text("ldmia", "r0!,{r1,r2}", "ARM"), "ldm r0!, {r1, r2}");
        assert_eq!(text("ldr", "r0,[r0,#0x0]", "ARM"), "ldr r0, [r0]");
        assert_eq!(text("ldr", "r0,[r0,#0x10]", "ARM"), "ldr r0, [r0, 0x10]");
        assert_eq!(text("LEA", "R8,[0x11e0]", "x86-64"), "lea r8, [0x11e0]");
        let nop = text("NOP", "word ptr CS:[RAX + RAX*0x1]", "x86-64");
        assert_eq!(nop, "nop word cs:[rax + rax]");
        let scaled = text("MOV", "EAX,dword ptr [RAX + RBX*0x10]", "x86-64");
        assert_eq!(scaled, "mov eax, dword [rax + rbx*0x10]");
    }

    #[test]
    fn an_it_predicated_operation_takes_its_condition_as_a_suffix() {
        assert_eq!(
            radare2("add.eq", "r3,r1,#0x1", 2, "ARM", &[]).text(),
            "addeq r3, r1, 0x1"
        );
        assert_eq!(
            radare2("pop.eq.w", "{r8,r9,r11}", 4, "ARM", &[]).text(),
            "popeq.w {r8, r9, fp}"
        );
        // A vector element type and an AArch64 condition are not an `it` predicate.
        assert_eq!(
            radare2("vadd.i32", "d0,d1,d2", 4, "ARM", &[]).text(),
            "vadd.i32 d0, d1, d2"
        );
        assert_eq!(
            radare2("b.eq", "0x10", 4, "aarch64", &[]).text(),
            "b.eq 0x10"
        );
    }

    #[test]
    fn aarch64_text_aliases_stop_at_their_preconditions() {
        let text = |mnemonic, body| radare2(mnemonic, body, 4, "aarch64", &[]).text();
        assert_eq!(text("negs", "xzr, x19, lsl #0x3"), "cmp xzr, x19, lsl 0x3");
        assert_eq!(text("negs", "w1, w2"), "negs w1, w2");
        assert_eq!(text("mov", "x1, x2"), "mov x1, x2");
        assert_eq!(text("mov", "x1, x2, lsl #0x3"), "orr x1, xzr, x2, lsl 0x3");
        assert_eq!(
            text("bfm", "x1, x2, #0x30, #0x1b"),
            "bfi x1, x2, 0x10, 0x1c"
        );
        assert_eq!(text("bfm", "w1, wzr, #0x1, #0x0"), "bfc w1, 0x1f, 0x1");
        assert_eq!(text("bfm", "w1, w2, #0x1, #0x1"), "bfxil w1, w2, 0x1, 0x1");
    }

    #[test]
    fn aarch64_carry_conditions_read_hs_and_lo() {
        let text = |mnemonic, body| radare2(mnemonic, body, 4, "aarch64", &[]).text();
        assert_eq!(text("b.cs", "0x10"), "b.hs 0x10");
        assert_eq!(text("bc.cc", "0x10"), "bc.lo 0x10");
        assert_eq!(text("csel", "w1, w2, w3, cc"), "csel w1, w2, w3, lo");
        assert_eq!(text("cset", "x1, cs"), "cset x1, hs");
        assert_eq!(text("ccmp", "x1, x2, #0x4, cs"), "ccmp x1, x2, 0x4, hs");
        assert_eq!(text("b.ne", "0x10"), "b.ne 0x10");
    }

    /// `move_wide_preferred` is the Arm ARM's test on the encoding; as a test on the value it is
    /// "one MOVZ or one MOVN writes it", and the two agree on every encoding of either width.
    #[test]
    fn a_bitmask_immediate_is_a_move_exactly_when_no_single_wide_move_writes_it() {
        fn bitmask(width: u32, n: u32, immr: u32, imms: u32) -> Option<u64> {
            let combined = (n << 6) | (!imms & 0x3f);
            if combined == 0 {
                return None;
            }
            let len = 31 - combined.leading_zeros();
            let (levels, esize) = ((1u32 << len) - 1, 1u32 << len);
            let (s, r) = (imms & levels, immr & levels);
            if len == 0 || s == levels || esize > width {
                return None;
            }
            let ones = (1u128 << (s + 1)) - 1;
            let rotated = ((ones >> r) | (ones << (esize - r))) & ((1u128 << esize) - 1);
            let mut value = 0u128;
            for at in (0..width).step_by(esize as usize) {
                value |= rotated << at;
            }
            Some(value as u64)
        }
        let encodings = [(false, 32u32), (true, 64)]
            .into_iter()
            .flat_map(|(sf, width)| {
                (0..=1).flat_map(move |n| {
                    (0..64)
                        .flat_map(move |immr| (0..64).map(move |imms| (sf, width, n, immr, imms)))
                })
            });
        let mut checked = 0;
        for (sf, width, n, immr, imms) in encodings {
            let Some(value) = bitmask(width, n, immr, imms).filter(|_| sf || n == 0) else {
                continue;
            };
            let halfwords: Vec<u64> = (0..width / 16)
                .map(|i| (value >> (16 * i)) & 0xffff)
                .collect();
            let one = |wanted: &dyn Fn(u64) -> bool| {
                halfwords.iter().filter(|h| wanted(**h)).count() == 1
            };
            let by_value = one(&|h| h != 0) || one(&|h| h != 0xffff);
            assert_eq!(
                move_wide_preferred(sf, n, immr, imms),
                by_value,
                "{sf} {n} {immr} {imms}"
            );
            checked += 1;
        }
        assert!(checked > 5000, "{checked}");
    }

    #[test]
    fn a_displacement_carries_its_sign_into_the_span() {
        let syntax = radare2("MOV", "EAX,dword ptr [RBP + -0x4]", 3, "x86-64", &[]);
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

    #[test]
    fn a_register_is_a_word_the_table_names_and_a_number_never_is() {
        let table = ["rax", "eax", "rbp", "x0"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let body = "EAX,dword ptr [RBP + -0x4], x0, 0x10, rbpx";
        let words = register_spans(body, &table)
            .iter()
            .map(|span| &body[span.start..span.end])
            .collect::<Vec<_>>();
        assert_eq!(words, ["EAX", "RBP", "x0"]);
    }
}
