//! The vocabulary a calling convention is stated in, shared by the compiler specification's
//! reading (`r2sleigh_lift::profile`) and the ABI rows (doc/adr-call-boundary.md).

/// The class of value a parameter or result location carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlotClass {
    /// An integer or a pointer: a cspec `pentry` with no class stated.
    Integer,
    /// `metatype="float"` or `storage="float"`.
    Float,
    /// A location in the caller's argument area.
    Stack,
    /// `storage="hiddenret"`: the pointer to a result the caller allocates (AAPCS64 x8).
    HiddenReturn,
}

/// How a value narrower than its location fills the rest of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Extension {
    Zero,
    Sign,
    /// Extended by the sign of the value's type to the size of `int`.
    IntType,
    /// Extended as a floating-point value is (`extension="float"`).
    Float,
    /// The bytes above the value hold nothing the convention states.
    Unspecified,
}
