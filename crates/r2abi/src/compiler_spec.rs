//! What Ghidra's compiler specification says about the machine.
//!
//! The stack pointer is not in the calling-convention data and not in the
//! processor specification either: Ghidra puts it in the `.cspec`, which also
//! carries the prototype models. radare2 answers the same question from its
//! register profile's `SP` alias, which is one more thing the engine would
//! have to ask radare2 for, so it is read here instead.
//!
//! Only the stack pointer is read today. The prototype models are the other
//! thing worth taking from this file, and they are deliberately not taken yet:
//! calling conventions come from the vendored `cc` data, and two owners for
//! one fact is worse than either owner alone.

use crate::StackAllocation;

/// The machine facts one compiler specification declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerSpec {
    /// The register the stack pointer lives in, spelled as Sleigh spells it.
    pub stack_pointer: Option<String>,
    /// Which way the stack grows. Ghidra's default is towards lower
    /// addresses, and only a few specifications say otherwise.
    pub stack_growth: StackAllocation,
    /// The register a call leaves the return address in, where the machine
    /// uses one. A machine that pushes it names a stack location instead, and
    /// this is then `None`.
    pub return_address: Option<String>,
    /// The registers a call leaves as it found them, as the default prototype
    /// declares them.
    pub unaffected: Vec<String>,
}

impl CompilerSpec {
    pub fn parse(text: &str) -> Self {
        let pointer = element(text, "stackpointer");
        Self {
            stack_pointer: pointer
                .and_then(|element| attribute(element, "register"))
                .map(str::to_owned),
            stack_growth: match pointer.and_then(|element| attribute(element, "growth")) {
                Some("positive") => StackAllocation::Higher,
                _ => StackAllocation::Lower,
            },
            return_address: return_address(text),
            unaffected: unaffected(text),
        }
    }

    /// Whether a call leaves this register as it found it.
    pub fn preserves(&self, register: &str) -> bool {
        self.unaffected
            .iter()
            .any(|name| name.eq_ignore_ascii_case(register))
    }
}

/// The register a call leaves the return address in.
///
/// A machine that pushes it declares a stack location, which names no
/// register and is why this is an option rather than a name.
fn return_address(text: &str) -> Option<String> {
    let start = text.find("<returnaddress>")? + "<returnaddress>".len();
    let end = text[start..].find("</returnaddress>")? + start;
    let body = &text[start..end];
    let register = element(body, "register")?;
    attribute(register, "name").map(str::to_owned)
}

/// The registers the default prototype says a call does not disturb.
fn unaffected(text: &str) -> Vec<String> {
    let Some(start) = text.find("<unaffected>") else {
        return Vec::new();
    };
    let start = start + "<unaffected>".len();
    let Some(end) = text[start..].find("</unaffected>").map(|end| end + start) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut rest = &text[start..end];
    while let Some(index) = rest.find("<register") {
        let Some(close) = rest[index..].find('>').map(|close| close + index) else {
            break;
        };
        if let Some(name) = attribute(&rest[index..close], "name") {
            names.push(name.to_owned());
        }
        rest = &rest[close..];
    }
    names
}

/// The text of the first `<name ...>` tag, up to its closing angle bracket.
fn element<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let open = text.split_once(&format!("<{name}"))?.1;
    Some(open.split_once('>')?.0)
}

/// The value of `name="..."` inside one element's text.
fn attribute<'a>(element: &'a str, name: &str) -> Option<&'a str> {
    let rest = element.split_once(&format!("{name}="))?.1.trim_start();
    let quote = rest.chars().next()?;
    matches!(quote, '"' | '\'')
        .then(|| rest[1..].split(quote).next())
        .flatten()
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stack_pointer_is_read_with_its_default_growth() {
        let spec = CompilerSpec::parse(
            r#"<compiler_spec>
  <global><range space="ram"/></global>
  <stackpointer register="RSP" space="ram"/>
</compiler_spec>"#,
        );
        assert_eq!(spec.stack_pointer.as_deref(), Some("RSP"));
        assert_eq!(spec.stack_growth, StackAllocation::Lower);
    }

    #[test]
    fn a_stack_that_grows_upwards_says_so() {
        let spec = CompilerSpec::parse(
            r#"<stackpointer register="SP" space="INTMEM" growth="positive"/>"#,
        );
        assert_eq!(spec.stack_pointer.as_deref(), Some("SP"));
        assert_eq!(spec.stack_growth, StackAllocation::Higher);
    }

    #[test]
    fn an_explicit_negative_growth_is_the_default_one() {
        let spec =
            CompilerSpec::parse(r#"	<stackpointer register="sp" space="ram"  growth="negative"/>"#);
        assert_eq!(spec.stack_pointer.as_deref(), Some("sp"));
        assert_eq!(spec.stack_growth, StackAllocation::Lower);
    }

    #[test]
    fn a_machine_with_a_link_register_names_it() {
        let spec = CompilerSpec::parse(
            r#"<compiler_spec>
  <stackpointer register="sp" space="ram"/>
  <returnaddress>
    <register name="x30"/>
  </returnaddress>
</compiler_spec>"#,
        );
        assert_eq!(spec.return_address.as_deref(), Some("x30"));
    }

    #[test]
    fn a_machine_that_pushes_the_return_address_names_no_register() {
        let spec = CompilerSpec::parse(
            r#"<returnaddress>
    <varnode space="stack" offset="0" size="8"/>
  </returnaddress>"#,
        );
        assert_eq!(spec.return_address, None);
    }

    #[test]
    fn the_registers_a_call_leaves_alone_are_read() {
        let spec = CompilerSpec::parse(
            r#"<unaffected>
    <register name="x29"/>
    <register name="x30"/>
    <register name="sp"/>
  </unaffected>"#,
        );
        assert_eq!(spec.unaffected, ["x29", "x30", "sp"]);
        assert!(spec.preserves("SP"));
        assert!(!spec.preserves("x0"));
    }

    #[test]
    fn a_specification_declaring_no_stack_pointer_claims_none() {
        let spec = CompilerSpec::parse("<compiler_spec></compiler_spec>");
        assert_eq!(spec.stack_pointer, None);
    }
}
