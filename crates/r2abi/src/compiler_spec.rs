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
}

impl CompilerSpec {
    pub fn parse(text: &str) -> Self {
        let Some(element) = element(text, "stackpointer") else {
            return Self {
                stack_pointer: None,
                stack_growth: StackAllocation::Lower,
            };
        };
        Self {
            stack_pointer: attribute(element, "register").map(str::to_owned),
            stack_growth: match attribute(element, "growth") {
                Some("positive") => StackAllocation::Higher,
                _ => StackAllocation::Lower,
            },
        }
    }
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
    fn a_specification_declaring_no_stack_pointer_claims_none() {
        let spec = CompilerSpec::parse("<compiler_spec></compiler_spec>");
        assert_eq!(spec.stack_pointer, None);
    }
}
