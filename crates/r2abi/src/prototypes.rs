//! What a library function takes and returns.
//!
//! An import has no body to read an interface off, so a call to one renders
//! with no arguments at all unless something states its prototype. radare2
//! ships that statement for two thousand library functions as `sdb` text, and
//! this reads it: the data is good, and only the lookup had any business being
//! on the other side of an FFI boundary.

use std::collections::BTreeMap;

/// One function's declared interface, in C spellings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototype {
    pub name: String,
    /// One C type spelling per fixed parameter, in order.
    pub parameters: Vec<String>,
    pub returns: String,
    /// Whether arguments continue past the fixed ones.
    pub variadic: bool,
}

/// Every prototype the data declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototypes {
    by_name: BTreeMap<String, Prototype>,
}

const EMBEDDED: &str = include_str!("../data/types.sdb.txt");

impl Prototypes {
    /// The prototypes radare2 ships.
    pub fn embedded() -> Self {
        Self::parse(EMBEDDED)
    }

    pub fn parse(text: &str) -> Self {
        let mut by_name: BTreeMap<String, Prototype> = BTreeMap::new();
        let mut slots: BTreeMap<String, BTreeMap<usize, String>> = BTreeMap::new();
        for line in text.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            let Some(rest) = key.strip_prefix("func.") else {
                continue;
            };
            let Some((name, what)) = rest.rsplit_once('.') else {
                continue;
            };
            let value = value.trim();

            // `func.<name>.arg.<index>=<type>,<parameter name>`, where the
            // parameter name is presentation and the type decides how the call
            // is read.
            if let Some(name) = name.strip_suffix(".arg") {
                let Ok(index) = what.parse::<usize>() else {
                    continue;
                };
                declare(&mut by_name, name);
                let spelling = value.split(',').next().unwrap_or_default().trim();
                slots
                    .entry(name.to_owned())
                    .or_default()
                    .insert(index, spelling.to_owned());
                continue;
            }

            match what {
                "args" => {
                    declare(&mut by_name, name);
                }
                "ret" => declare(&mut by_name, name).returns = value.to_owned(),
                _ => {}
            }
        }

        for (name, positions) in slots {
            let Some(prototype) = by_name.get_mut(&name) else {
                continue;
            };
            for spelling in positions.into_values() {
                // An empty spelling is the ellipsis: everything after it is
                // whatever the caller passes.
                if spelling.is_empty() {
                    prototype.variadic = true;
                    break;
                }
                prototype.parameters.push(spelling);
            }
        }
        Self { by_name }
    }

    pub fn get(&self, name: &str) -> Option<&Prototype> {
        // A linked name carries the platform's own decoration.
        self.by_name
            .get(name)
            .or_else(|| self.by_name.get(name.trim_start_matches('_')))
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// The prototype this name will be filled in for.
fn declare<'a>(by_name: &'a mut BTreeMap<String, Prototype>, name: &str) -> &'a mut Prototype {
    by_name.entry(name.to_owned()).or_insert_with(|| Prototype {
        name: name.to_owned(),
        ..Prototype::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_prototype_reads_whole() {
        let prototypes = Prototypes::embedded();
        let puts = prototypes.get("puts").expect("puts");
        assert_eq!(puts.parameters, ["const char *"]);
        assert_eq!(puts.returns, "int");
        assert!(!puts.variadic);
    }

    #[test]
    fn the_ellipsis_is_variadic_rather_than_a_parameter() {
        let prototypes = Prototypes::embedded();
        let printf = prototypes.get("printf").expect("printf");
        assert_eq!(printf.parameters, ["const char *"]);
        assert!(printf.variadic);
    }

    #[test]
    fn a_decorated_name_finds_its_undecorated_prototype() {
        let prototypes = Prototypes::embedded();
        assert_eq!(
            prototypes.get("_strlen").map(|p| p.returns.as_str()),
            Some("size_t")
        );
    }

    #[test]
    fn the_data_declares_a_few_thousand_functions() {
        let count = Prototypes::embedded().len();
        assert!(count > 500, "{count}");
    }
}
