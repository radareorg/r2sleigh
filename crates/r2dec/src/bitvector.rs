//! The one definition of a carrier wider than any C integer.
//!
//! C has integers up to 128 bits. A machine value wider than that -- an AVX2
//! `YMM`, an SVE `Z` register, a stack object of odd width -- is a
//! `struct r2sleigh_bits_N` holding its `N / 8` bytes, least significant
//! first, which is also how the value lies in memory on the little-endian
//! targets that have one. The struct has no operators. For a carrier wider
//! than 128 bits, every operation a rendering performs on one is one of the
//! helpers below, called by name, and `fold::op_lower::wide` refuses any
//! other operation rather than spell an operator on it. A value of an odd
//! width at or below 128 bits (24, 40, 80 bits) is also declared as a
//! carrier, but has no helpers and no such guard; in the coverage corpus it
//! appears only as a declared stack object, never as an operand.
//!
//! This module is the only statement of that representation, and of which
//! widths a rendering can declare and operate on ([`is_field`]). Which widths
//! are C integers is `r2types`' to state
//! ([`CType::is_integer_width`](r2types::CTypeLike::is_integer_width)), the
//! same fact that makes [`CType::machine_bits`](r2types::CTypeLike::machine_bits)
//! an integer or a carrier, and this module reads it rather than restating
//! it. A rendering that declares a carrier gets its definition from
//! [`carrier_definition`], and a rendering that calls a helper gets the
//! helper's definition from [`BitVectorHelper::definition`], emitted above
//! the function, so the rendering is a translation unit that compiles on its
//! own. There is no second definition to disagree with: the prelude header
//! no longer carries one, and a gate that compiles a rendering compiles what
//! it says.

use serde::{Deserialize, Serialize};

use crate::ast::{CAggregateDef, CExpr, CType};

/// Whether the helpers below operate on a carrier this wide.
///
/// A narrower value is a C integer, and a carrier of any other width is only
/// ever declared, never taken apart, so nothing is claimed about it.
pub(crate) const fn is_supported(width_bits: u32) -> bool {
    matches!(width_bits, 256 | 512)
}

/// Whether a value this wide is wider than every C integer: a carrier,
/// which only the helpers below operate on.
pub(crate) const fn is_wide(width_bits: u32) -> bool {
    width_bits > 128
}

/// Whether a value this wide has a representation a rendering can operate
/// on: a C integer, or a carrier the helpers below support.
///
/// This is both the width a value or parameter may be declared at and the
/// width a helper may take or return as a field, so the two cannot disagree.
pub(crate) const fn is_field(width_bits: u32) -> bool {
    CType::is_integer_width(width_bits) || is_supported(width_bits)
}

/// The tag a carrier of `width_bits` is declared at, which the type
/// spellings `r2types` prints and parses also name.
fn carrier_tag(width_bits: u32) -> String {
    r2types::bit_vector_tag(width_bits)
}

/// The definition of the carrier a rendering declares a value of: its whole
/// bytes, and nothing that would let an operator apply to it.
pub(crate) fn carrier_definition(width_bits: u32) -> Option<CAggregateDef> {
    let bytes = usize::try_from(width_bits.div_ceil(8))
        .ok()
        .filter(|bytes| *bytes > 0)?;
    Some(CAggregateDef {
        is_union: false,
        name: carrier_tag(width_bits),
        members: vec![(
            CType::Array(Box::new(CType::uint(8)), Some(bytes)),
            "bytes".to_string(),
        )],
    })
}

/// One operation on a wide carrier, spelled as a call to a helper the
/// rendering defines.
///
/// Every field is either a C integer or a supported carrier, and every bit
/// offset is a `uint64_t` counted from the carrier's least significant bit. A
/// bit a field would take from beyond the carrier is zero, and one it would
/// put there is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BitVectorHelper {
    /// `field_bits` of the carrier, starting at a bit offset.
    Extract { carrier_bits: u32, field_bits: u32 },
    /// The carrier with `field_bits` replaced, starting at a bit offset.
    Insert { carrier_bits: u32, field_bits: u32 },
    /// A field widened with zeroes to the whole carrier.
    ZeroExtend { field_bits: u32, carrier_bits: u32 },
}

impl BitVectorHelper {
    /// The helper, where both widths are ones it has a representation for
    /// and the field is narrower than the carrier.
    fn checked(self) -> Option<Self> {
        let (carrier, field) = self.widths();
        (is_supported(carrier) && is_field(field) && field < carrier).then_some(self)
    }

    /// `field_bits` of a `carrier_bits` carrier at a bit offset.
    pub(crate) fn extract(carrier_bits: u32, field_bits: u32) -> Option<Self> {
        Self::Extract {
            carrier_bits,
            field_bits,
        }
        .checked()
    }

    /// A `carrier_bits` carrier with `field_bits` replaced at a bit offset.
    pub(crate) fn insert(carrier_bits: u32, field_bits: u32) -> Option<Self> {
        Self::Insert {
            carrier_bits,
            field_bits,
        }
        .checked()
    }

    /// A `field_bits` value zero-extended to a `carrier_bits` carrier.
    pub(crate) fn zero_extend(field_bits: u32, carrier_bits: u32) -> Option<Self> {
        Self::ZeroExtend {
            field_bits,
            carrier_bits,
        }
        .checked()
    }

    /// `(carrier_bits, field_bits)`.
    const fn widths(self) -> (u32, u32) {
        match self {
            Self::Extract {
                carrier_bits,
                field_bits,
            }
            | Self::Insert {
                carrier_bits,
                field_bits,
            }
            | Self::ZeroExtend {
                field_bits,
                carrier_bits,
            } => (carrier_bits, field_bits),
        }
    }

    /// The carriers the helper's definition names, which the rendering must
    /// therefore define.
    pub(crate) fn carriers(self) -> impl Iterator<Item = u32> {
        let (carrier, field) = self.widths();
        std::iter::once(carrier).chain(is_supported(field).then_some(field))
    }

    /// The helper's name.
    pub fn name(self) -> String {
        match self {
            Self::Extract {
                carrier_bits,
                field_bits,
            } => format!("r2sleigh_bits_extract_{carrier_bits}_{field_bits}"),
            Self::Insert {
                carrier_bits,
                field_bits,
            } => format!("r2sleigh_bits_insert_{carrier_bits}_{field_bits}"),
            Self::ZeroExtend {
                field_bits,
                carrier_bits,
            } => format!("r2sleigh_bits_zero_extend_{field_bits}_{carrier_bits}"),
        }
    }

    /// A call to the helper.
    pub(crate) fn call(self, args: Vec<CExpr>) -> CExpr {
        CExpr::call(
            CExpr::External {
                name: self.name(),
                kind: crate::symbol::ExternalKind::BitVector(self),
            },
            args,
        )
    }

    /// The helper's C definition.
    pub(crate) fn definition(self) -> String {
        let name = self.name();
        match self {
            Self::Extract {
                carrier_bits,
                field_bits,
            } => {
                let field = spelled(field_bits);
                let carrier = spelled(carrier_bits);
                format!(
                    "static inline {field} {name}({carrier} carrier, uint64_t at)\n\
                     {{\n\
                     \x20   {field} field = {zero};\n\
                     \x20   for (uint32_t bit = 0; bit < {field_bits}u; ++bit) {{\n\
                     \x20       const uint64_t from = at + bit;\n\
                     \x20       if (from < {carrier_bits}u && ((carrier.bytes[from / 8] >> (from % 8)) & 1) != 0) {{\n\
                     \x20           {set}\n\
                     \x20       }}\n\
                     \x20   }}\n\
                     \x20   return field;\n\
                     }}\n",
                    zero = zero(field_bits),
                    set = set_bit("field", field_bits, "bit"),
                )
            }
            Self::Insert {
                carrier_bits,
                field_bits,
            } => {
                let field = spelled(field_bits);
                let carrier = spelled(carrier_bits);
                format!(
                    "static inline {carrier} {name}({carrier} carrier, {field} field, uint64_t at)\n\
                     {{\n\
                     \x20   for (uint32_t bit = 0; bit < {field_bits}u; ++bit) {{\n\
                     \x20       const uint64_t to = at + bit;\n\
                     \x20       if (to < {carrier_bits}u) {{\n\
                     \x20           const unsigned mask = 1u << (to % 8);\n\
                     \x20           if ({test}) {{\n\
                     \x20               carrier.bytes[to / 8] = (uint8_t)(carrier.bytes[to / 8] | mask);\n\
                     \x20           }} else {{\n\
                     \x20               carrier.bytes[to / 8] = (uint8_t)(carrier.bytes[to / 8] & ~mask);\n\
                     \x20           }}\n\
                     \x20       }}\n\
                     \x20   }}\n\
                     \x20   return carrier;\n\
                     }}\n",
                    test = test_bit("field", field_bits, "bit"),
                )
            }
            Self::ZeroExtend {
                field_bits,
                carrier_bits,
            } => {
                let field = spelled(field_bits);
                let carrier = spelled(carrier_bits);
                format!(
                    "static inline {carrier} {name}({field} field)\n\
                     {{\n\
                     \x20   {carrier} carrier = {zero};\n\
                     \x20   for (uint32_t bit = 0; bit < {field_bits}u; ++bit) {{\n\
                     \x20       if ({test}) {{\n\
                     \x20           {set}\n\
                     \x20       }}\n\
                     \x20   }}\n\
                     \x20   return carrier;\n\
                     }}\n",
                    zero = zero(carrier_bits),
                    test = test_bit("field", field_bits, "bit"),
                    set = set_bit("carrier", carrier_bits, "bit"),
                )
            }
        }
    }
}

/// How a field or carrier of this width is declared.
fn spelled(width_bits: u32) -> String {
    match width_bits {
        128 => "__uint128_t".to_string(),
        bits if CType::is_integer_width(bits) => format!("uint{bits}_t"),
        bits => format!("struct {}", carrier_tag(bits)),
    }
}

/// The zero of a field or carrier of this width.
fn zero(width_bits: u32) -> &'static str {
    if CType::is_integer_width(width_bits) {
        "0"
    } else {
        "{{0}}"
    }
}

/// Whether bit `bit` of `value` is set.
fn test_bit(value: &str, width_bits: u32, bit: &str) -> String {
    if CType::is_integer_width(width_bits) {
        format!("(({value} >> {bit}) & 1) != 0")
    } else {
        format!("(({value}.bytes[{bit} / 8] >> ({bit} % 8)) & 1) != 0")
    }
}

/// Set bit `bit` of `value`.
fn set_bit(value: &str, width_bits: u32, bit: &str) -> String {
    if CType::is_integer_width(width_bits) {
        let ty = spelled(width_bits);
        format!("{value} = ({ty})({value} | (({ty})1 << {bit}));")
    } else {
        format!(
            "{value}.bytes[{bit} / 8] = (uint8_t)({value}.bytes[{bit} / 8] | (1u << ({bit} % 8)));"
        )
    }
}

/// The helpers a function calls, in the order their definitions are emitted.
pub(crate) fn helpers_called(function: &crate::ast::CFunction) -> Vec<BitVectorHelper> {
    let mut helpers = std::collections::BTreeSet::new();
    let mut called = |expr: &CExpr| {
        if let CExpr::External {
            kind: crate::symbol::ExternalKind::BitVector(helper),
            ..
        } = expr
        {
            helpers.insert(*helper);
        }
    };
    for stmt in &function.body {
        stmt.visit_exprs(&mut |root| root.visit(&mut called));
    }
    helpers.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A helper exists only where both widths have a representation and the
    /// field fits the carrier.
    #[test]
    fn a_helper_is_made_only_for_widths_it_can_represent() {
        assert!(BitVectorHelper::extract(256, 32).is_some());
        assert!(BitVectorHelper::insert(512, 256).is_some());
        assert!(BitVectorHelper::zero_extend(128, 256).is_some());
        assert!(BitVectorHelper::extract(192, 32).is_none());
        assert!(BitVectorHelper::insert(256, 24).is_none());
        assert!(BitVectorHelper::zero_extend(512, 256).is_none());
        assert!(BitVectorHelper::insert(256, 256).is_none());
    }

    /// A helper whose field is itself a carrier names both carriers, so the
    /// rendering defines both.
    #[test]
    fn a_wide_field_names_its_own_carrier() {
        let helper = BitVectorHelper::insert(512, 256).expect("wide field");
        assert_eq!(helper.carriers().collect::<Vec<_>>(), vec![512, 256]);
        let helper = BitVectorHelper::extract(256, 64).expect("integer field");
        assert_eq!(helper.carriers().collect::<Vec<_>>(), vec![256]);
    }
}
