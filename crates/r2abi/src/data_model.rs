//! The target's C data model: `long`, pointers, plain `char`'s sign, `wchar_t`'s sign and width.
//! One cited row per architecture and [`CLibrary`] (doc/adr-call-boundary.md, "The C data model").

use crate::CLibrary;
use crate::types::{ScalarKind, Width};

/// What one target makes of the widths and signs a C spelling leaves open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CDataModel {
    pub pointer_bits: u32,
    pub long_bits: u32,
    /// The storage a `long double` occupies, where this model states it.
    pub long_double_bits: Option<u32>,
    /// `Signed` or `Unsigned`; `None` where no row states it.
    pub plain_char: Option<ScalarKind>,
    /// `wchar_t`'s sign and bits; `None` where no row states them.
    pub wide_char: Option<(ScalarKind, u32)>,
    /// The bits of the Linux kernel's `__kernel_mode_t` here ([`KERNEL_MODE_CITATION`]); `None` where no row states it.
    pub kernel_mode_bits: Option<u32>,
    /// The documents that state this row; empty for a model no row states.
    pub citation: &'static str,
}

impl CDataModel {
    /// `long` and pointers as wide as each other, and no sign stated. Nothing
    /// here states `long double`: its format and class are the convention's.
    pub const fn unix(pointer_bits: u32) -> Self {
        Self {
            pointer_bits,
            long_bits: pointer_bits,
            long_double_bits: None,
            plain_char: None,
            wide_char: None,
            kernel_mode_bits: None,
            citation: "",
        }
    }

    /// The cited row for an architecture, its address width and its C library.
    pub fn of(arch: &str, bits: u32, library: CLibrary) -> Option<&'static CDataModel> {
        use CLibrary::{Bionic, Glibc, LibSystem, Ucrt};
        match (crate::family(arch), bits, library) {
            (Some("x86"), 64, Glibc | Bionic | LibSystem) => Some(&SYSV_X86_64),
            (Some("x86"), 64, Ucrt) => Some(&MICROSOFT_X64),
            (Some("x86"), 32, Glibc | Bionic) => Some(&SYSV_I386),
            (Some("arm"), 64, Glibc | Bionic) => Some(&AAPCS64),
            (Some("arm"), 64, LibSystem) => Some(&APPLE_ARM64),
            (Some("arm"), 32, Glibc | Bionic) => Some(&AAPCS32),
            (Some("riscv"), 64, Glibc) => Some(&RISCV_LP64),
            _ => None,
        }
    }

    pub fn bits(&self, width: Width) -> Option<u32> {
        match width {
            Width::Bits(bits) => Some(bits),
            Width::Long => Some(self.long_bits),
            Width::Pointer => Some(self.pointer_bits),
            Width::LongDouble => self.long_double_bits,
            Width::WideChar => self.wide_char.map(|(_, bits)| bits),
            Width::KernelMode => self.kernel_mode_bits,
        }
    }

    /// What a scalar's bits mean here: the kind itself, or the sign this model
    /// states for plain `char` and `wchar_t`.
    pub fn kind(&self, kind: ScalarKind) -> Option<ScalarKind> {
        match kind {
            ScalarKind::PlainChar => self.plain_char,
            ScalarKind::WideChar => self.wide_char.map(|(sign, _)| sign),
            stated => Some(stated),
        }
    }
}

const fn row(
    bits: (u32, u32),
    plain_char: ScalarKind,
    wide_char: (ScalarKind, u32),
    citation: &'static str,
) -> CDataModel {
    CDataModel {
        pointer_bits: bits.0,
        long_bits: bits.1,
        long_double_bits: None,
        plain_char: Some(plain_char),
        wide_char: Some(wide_char),
        kernel_mode_bits: None,
        citation,
    }
}

use ScalarKind::{Signed, Unsigned};

/// Where each row's `kernel_mode_bits` is read from.
pub const KERNEL_MODE_CITATION: &str = "Linux include/uapi/asm-generic/posix_types.h: `typedef \
    unsigned int __kernel_mode_t`, overridden to `unsigned short` by \
    arch/x86/include/uapi/asm/posix_types_32.h and arch/arm/include/uapi/asm/posix_types.h; \
    bionic libc/include/sys/types.h: `typedef __kernel_mode_t __mode_t; typedef __mode_t mode_t`";

const SYSV_X86_64: CDataModel = CDataModel {
    kernel_mode_bits: Some(32),
    ..row(
        (64, 64),
        Signed,
        (Signed, 32),
        "System V AMD64 psABI 1.0, section 3.1.2, Figure 3.1 \"Scalar Types\": char is a signed \
         byte, long and pointers 8 bytes; wchar_t is int, the __WCHAR_TYPE__ of every \
         x86-64 Linux, Android and Darwin compiler",
    )
};

const MICROSOFT_X64: CDataModel = row(
    (64, 32),
    Signed,
    (Unsigned, 16),
    "Microsoft, \"Data Type Ranges\": char is signed by default (/J makes it unsigned), \
     long is 4 bytes, wchar_t is unsigned short (2 bytes); x64 pointers are 8 bytes",
);

const SYSV_I386: CDataModel = CDataModel {
    kernel_mode_bits: Some(16),
    ..row(
        (32, 32),
        Signed,
        (Signed, 32),
        "System V i386 psABI 1.1, \"Fundamental Types\": char is a signed byte, long and \
         pointers 4 bytes; wchar_t is a 32-bit signed integer, the __WCHAR_TYPE__ of every \
         i386 Linux and Android compiler",
    )
};

const AAPCS64: CDataModel = CDataModel {
    kernel_mode_bits: Some(32),
    ..row(
        (64, 64),
        Unsigned,
        (Unsigned, 32),
        "AAPCS64, \"Arm C and C++ language mappings\": char is an unsigned byte and wchar_t \
         an unsigned int; LP64 makes long and pointers 8 bytes",
    )
};

const APPLE_ARM64: CDataModel = row(
    (64, 64),
    Signed,
    (Signed, 32),
    "Apple, \"Writing ARM64 code for Apple platforms\": char and wchar_t are signed \
     types, where AAPCS64 makes them unsigned; wchar_t is 4 bytes, long and pointers 8",
);

const AAPCS32: CDataModel = CDataModel {
    kernel_mode_bits: Some(16),
    ..row(
        (32, 32),
        Unsigned,
        (Unsigned, 32),
        "AAPCS32, \"Arm C and C++ language mappings\": char is an unsigned byte and wchar_t \
         an unsigned int on Linux; long and pointers 4 bytes",
    )
};

const RISCV_LP64: CDataModel = CDataModel {
    kernel_mode_bits: Some(32),
    ..row(
        (64, 64),
        Unsigned,
        (Signed, 32),
        "RISC-V ELF psABI, \"C/C++ type details\": char is unsigned and wchar_t a signed \
         32-bit integer; LP64 makes long and pointers 8 bytes",
    )
};
