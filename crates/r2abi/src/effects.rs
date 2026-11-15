//! What a cited row states a function does through its parameters, as an upper bound: a parameter
//! no clause names is a value only (ROADMAP D383, data/README.md "Effects").

/// How far an effect reaches from the address its parameter holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Extent {
    /// As many bytes as the parameter at this index holds.
    Arg(u8),
    /// Up to the first zero byte: a string.
    String,
}

/// One clause of a row's effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    /// Reads the memory parameter `at` points to, as far as `extent`.
    Reads { at: u8, extent: Extent },
    /// Writes the memory parameter `at` points to, as far as `extent`.
    Writes { at: u8, extent: Extent },
    /// Ends the lifetime of the block parameter `at` points to.
    Frees { at: u8 },
    /// Returns a new heap block, zeroed or not.
    Allocates { zeroed: bool },
    /// Returns parameter `at`'s value.
    Returns { at: u8 },
}

/// A row's whole effects, in the order the row states them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effects(pub Vec<Effect>);

impl Effects {
    /// `reads(0, 2) writes(1, str) frees(0) allocates(zeroed) returns(0)`; any clause that does
    /// not read refuses the whole key, since a partial upper bound is none.
    pub fn read(text: &str) -> Option<Self> {
        let mut effects = Vec::new();
        let mut rest = text.trim();
        while !rest.is_empty() {
            let open = rest.find('(')?;
            let close = rest.find(')')?;
            let (verb, inside) = (rest[..open].trim(), &rest[open + 1..close]);
            let args = inside.split(',').map(str::trim).collect::<Vec<_>>();
            effects.push(clause(verb, &args)?);
            rest = rest[close + 1..].trim_start();
        }
        Some(Self(effects))
    }
}

fn clause(verb: &str, args: &[&str]) -> Option<Effect> {
    let index = |text: &str| text.parse::<u8>().ok();
    let extent = |text: &str| match text {
        "str" => Some(Extent::String),
        count => index(count).map(Extent::Arg),
    };
    Some(match (verb, args) {
        ("reads", [at, how]) => Effect::Reads {
            at: index(at)?,
            extent: extent(how)?,
        },
        ("writes", [at, how]) => Effect::Writes {
            at: index(at)?,
            extent: extent(how)?,
        },
        ("frees", [at]) => Effect::Frees { at: index(at)? },
        ("allocates", ["zeroed"]) => Effect::Allocates { zeroed: true },
        ("allocates", [""]) => Effect::Allocates { zeroed: false },
        ("returns", [at]) => Effect::Returns { at: index(at)? },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rows_effects_read_as_spelled_and_a_bad_clause_refuses_all() {
        let memcpy = Effects::read("writes(0, 2) reads(1, 2) returns(0)").expect("memcpy");
        assert_eq!(
            memcpy.0,
            [
                Effect::Writes {
                    at: 0,
                    extent: Extent::Arg(2)
                },
                Effect::Reads {
                    at: 1,
                    extent: Extent::Arg(2)
                },
                Effect::Returns { at: 0 },
            ]
        );
        let calloc = Effects::read("allocates(zeroed)").expect("calloc");
        assert_eq!(calloc.0, [Effect::Allocates { zeroed: true }]);
        assert_eq!(
            Effects::read("allocates()").map(|e| e.0),
            Some(vec![Effect::Allocates { zeroed: false }])
        );
        assert_eq!(Effects::read("writes(0) reads(1, 2)"), None);
        assert_eq!(Effects::read("touches(0, 2)"), None);
    }
}
