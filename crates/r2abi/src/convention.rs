//! The vocabulary a calling convention is stated in, shared by the compiler specification's
//! reading (`r2sleigh_lift::profile`) and the ABI rows (doc/adr-call-boundary.md).

use crate::Kernel;
use crate::platform::{EntryStack, RegisterSaveArea, SaveAreaAnchor, StackGuard};

/// The class of value a parameter or result location carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
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

/// A register an ABI document names, as radare2 spells it; the engine resolves it once, when it
/// builds the convention's model, and a name that does not resolve fails the conformance test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegName(pub &'static str);

/// One calling convention a function can run under: the key of its [`ConventionRow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum ConventionId {
    SysVAmd64,
    Win64,
    I386Cdecl,
    Aapcs64,
    AppleArm64,
    Aapcs32,
    RiscVLp64,
    /// Go's register-based ABIInternal.
    GoAmd64,
    GoArm64,
    /// Go's stack-based ABI0.
    GoAmd64Abi0,
    GoArm64Abi0,
    /// ABIInternal under a toolchain whose pclntab does not say which functions keep ABI0.
    GoAmd64Unstated,
    GoArm64Unstated,
}

impl ConventionId {
    pub const ALL: [Self; 13] = [
        Self::SysVAmd64,
        Self::Win64,
        Self::I386Cdecl,
        Self::Aapcs64,
        Self::AppleArm64,
        Self::Aapcs32,
        Self::RiscVLp64,
        Self::GoAmd64,
        Self::GoArm64,
        Self::GoAmd64Abi0,
        Self::GoArm64Abi0,
        Self::GoAmd64Unstated,
        Self::GoArm64Unstated,
    ];

    /// The name radare2 gives the convention, which `afi` prints and `diff_r2.py` compares.
    pub const fn radare2_name(self) -> &'static str {
        match self {
            Self::SysVAmd64 => "amd64",
            Self::Win64 => "ms",
            Self::I386Cdecl => "cdecl",
            Self::Aapcs64 | Self::AppleArm64 => "arm64",
            Self::Aapcs32 => "arm32",
            Self::RiscVLp64 => "rvg",
            Self::GoAmd64 | Self::GoArm64 | Self::GoAmd64Unstated | Self::GoArm64Unstated => {
                "golang"
            }
            Self::GoAmd64Abi0 | Self::GoArm64Abi0 => "golang_abi0",
        }
    }

    /// What the ABI states of this convention that no compiler specification does.
    pub const fn row(self) -> &'static ConventionRow {
        match self {
            Self::SysVAmd64 => &SYSTEM_V_AMD64,
            Self::Win64 => &MICROSOFT_X64,
            Self::I386Cdecl => &I386_CDECL,
            Self::Aapcs64 => &AAPCS64,
            Self::AppleArm64 => &AAPCS64_DARWIN,
            Self::Aapcs32 => &AAPCS32,
            Self::RiscVLp64 => &RISCV_LP64,
            Self::GoAmd64 => &GO_AMD64,
            Self::GoArm64 => &GO_ARM64,
            Self::GoAmd64Abi0 => &GO_AMD64_ABI0,
            Self::GoArm64Abi0 => &GO_ARM64_ABI0,
            Self::GoAmd64Unstated => &GO_AMD64_UNSTATED,
            Self::GoArm64Unstated => &GO_ARM64_UNSTATED,
        }
    }

    /// The convention a program for this architecture runs under on this kernel, where no fact
    /// about one function says otherwise.
    pub fn default_for(arch: &str, bits: u32, kernel: Kernel) -> Option<Self> {
        match (crate::family(arch), bits, kernel) {
            (Some("x86"), 64, Kernel::Windows) => Some(Self::Win64),
            (Some("x86"), 64, _) => Some(Self::SysVAmd64),
            (Some("x86"), 32, _) => Some(Self::I386Cdecl),
            (Some("arm"), 64, Kernel::Darwin) => Some(Self::AppleArm64),
            (Some("arm"), 64, _) => Some(Self::Aapcs64),
            (Some("arm"), 32, _) => Some(Self::Aapcs32),
            (Some("riscv"), 64, _) => Some(Self::RiscVLp64),
            _ => None,
        }
    }

    /// The Go convention by toolchain version; `None` (no build information, before Go 1.13) is ABI0.
    /// Registers: Go 1.17 on amd64 Linux, macOS and Windows, Go 1.18 on arm64 and amd64 everywhere.
    pub fn go(arch: &str, bits: u32, kernel: Kernel, version: Option<(u32, u32)>) -> Option<Self> {
        let at_least = |minor: u32| version.is_some_and(|version| version >= (1, minor));
        let first_systems = matches!(kernel, Kernel::Linux | Kernel::Darwin | Kernel::Windows);
        match (crate::family(arch), bits) {
            (Some("x86"), 64) if at_least(18) || at_least(17) && first_systems => {
                Some(Self::GoAmd64)
            }
            (Some("x86"), 64) => Some(Self::GoAmd64Abi0),
            (Some("arm"), 64) if at_least(18) => Some(Self::GoArm64),
            (Some("arm"), 64) => Some(Self::GoArm64Abi0),
            _ => None,
        }
    }

    /// Go's stack-based ABI0 here: what an assembly function keeps beside ABIInternal.
    pub fn go_abi0(arch: &str, bits: u32) -> Option<Self> {
        match (crate::family(arch), bits) {
            (Some("x86"), 64) => Some(Self::GoAmd64Abi0),
            (Some("arm"), 64) => Some(Self::GoArm64Abi0),
            _ => None,
        }
    }

    /// ABIInternal, refusing: for a function whose ABI the toolchain does not state.
    pub fn go_unstated(arch: &str, bits: u32) -> Option<Self> {
        match (crate::family(arch), bits) {
            (Some("x86"), 64) => Some(Self::GoAmd64Unstated),
            (Some("arm"), 64) => Some(Self::GoArm64Unstated),
            _ => None,
        }
    }
}

/// Which compiler specification a convention reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toolchain {
    /// The toolchain the container names: Windows' for a PE, Apple's for a Mach-O where the
    /// language has one, the usual one otherwise.
    Container,
    /// A compiler by its `.ldefs` id.
    Compiler(&'static str),
}

/// The specification and the prototype in it a convention reads; `None` is its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cspec {
    pub toolchain: Toolchain,
    pub prototype: Option<&'static str>,
}

/// Which side of the boundary an override speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Input,
    Output,
}

/// A compiler specification claim the ABI contradicts or omits, with the words that say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecOverride {
    /// Registers a result may be returned in that the specification's `<output>` omits.
    Results {
        class: SlotClass,
        lanes: &'static [RegName],
        citation: &'static str,
    },
    /// How a narrower value of a class fills its register, where the specification says otherwise.
    Extension {
        side: Side,
        class: SlotClass,
        extension: Extension,
        citation: &'static str,
    },
}

/// What an ABI states of a calling convention that no compiler specification does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConventionRow {
    pub id: ConventionId,
    pub cspec: Cspec,
    /// The register a frame-keeping function holds its frame base in.
    pub frame_pointer: Option<RegName>,
    /// How many bytes past the stack pointer a function may use without moving it.
    pub red_zone: u32,
    /// The register a call hands a variadic callee its count of vector arguments in (SysV `al`).
    pub count_register: Option<RegName>,
    /// Where a variadic prologue saves argument register `i`, and what its `va_list` holds of it.
    pub save_area: Option<RegisterSaveArea>,
    /// The caller-allocated area a callee may store its register arguments in (Microsoft x64).
    pub home: Option<HomeArea>,
    /// The entry stack pointer's residue modulo an alignment.
    pub entry_stack: Option<EntryStack>,
    /// The lowest stack pointer a function may run with, where the runtime keeps one (Go).
    pub stack_bound: Option<StackGuard>,
    /// What its boundaries carry that no call boundary states, which refuses every function.
    pub refused: Option<&'static str>,
    pub overrides: &'static [SpecOverride],
    /// That the result lanes are every lane a result comes back in, and how they pair; none where
    /// no document states the set complete, so no result of the convention is ever `void`.
    pub results: Option<ResultSet>,
    /// The documents that state these.
    pub citation: &'static str,
}

/// A convention's result lanes as one complete set (doc/adr-result-side.md, "The lane set").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultSet {
    /// `(lane, first)`: the lane holds a result only beside `first`.
    pub follows: &'static [(RegName, RegName)],
    /// The lanes that hold nothing at entry (the x87 stack is empty on entry).
    pub empty: &'static [RegName],
    pub citation: &'static str,
}

/// That the `localrange` above the return address is one home per shared position, `step` bytes
/// each, in position order; where it lies is the specification's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeArea {
    pub step: u32,
}

const USUAL: Cspec = Cspec {
    toolchain: Toolchain::Container,
    prototype: None,
};

const SYSV_RESULTS: SpecOverride = SpecOverride::Results {
    class: SlotClass::Float,
    lanes: &[
        RegName("xmm0"),
        RegName("xmm1"),
        RegName("st0"),
        RegName("st1"),
    ],
    citation: "System V AMD64 psABI 1.0, section 3.2.3, \"Returning of Values\": \"If the class \
               is SSE, the next available vector register of the sequence %xmm0, %xmm1 is \
               used\"; \"If the class is X87, the value is returned on the X87 stack in %st0 \
               together with %st1\"; \"If the class is COMPLEX_X87, the real part of the value \
               is returned in %st0 and the imaginary part in %st1\"",
};

const SYSTEM_V_AMD64: ConventionRow = ConventionRow {
    id: ConventionId::SysVAmd64,
    cspec: USUAL,
    red_zone: 128,
    frame_pointer: Some(RegName("rbp")),
    count_register: Some(RegName("al")),
    save_area: Some(RegisterSaveArea {
        anchor: SaveAreaAnchor::Base,
        offset_field: -16,
        offset_width: 4,
        stack_field: -8,
    }),
    home: None,
    refused: None,
    entry_stack: Some(EntryStack {
        alignment: 16,
        residue: 8,
    }),
    stack_bound: None,
    overrides: &[SYSV_RESULTS],
    results: Some(ResultSet {
        follows: &[
            (RegName("rdx"), RegName("rax")),
            (RegName("xmm1"), RegName("xmm0")),
            (RegName("st1"), RegName("st0")),
        ],
        empty: &[RegName("st0"), RegName("st1")],
        citation: "System V AMD64 psABI 1.0, section 3.2.3, \"Returning of Values\": \"If the class \
                   is INTEGER, the next available register of the sequence %rax, %rdx is used\"; \
                   \"If the class is SSE, the next available vector register of the sequence \
                   %xmm0, %xmm1 is used\"; \"If the class is COMPLEX_X87, the real part of the \
                   value is returned in %st0 and the imaginary part in %st1\"; a class MEMORY \
                   result is returned through the hidden pointer, in %rax; Figure 3.4 makes \
                   %st0 to %st7 temporaries, so a callee finds the x87 stack empty: what a body \
                   holds there it wrote",
    }),
    citation: "System V AMD64 psABI 1.0, section 3.2.2: \"The 128-byte area beyond the \
               location pointed to by %rsp is considered to be reserved and shall not be \
               modified by signal or interrupt handlers\"; section 3.5.7: \"%al is used as \
               hidden argument to specify the number of vector registers used\"; Figure 3.4: %rbp \"callee-saved register; optionally used as frame pointer\"; section 3.2.2: \"the value (%rsp + 8) is always a multiple of 16 when control is transferred to the function entry point\"; section 3.5.7, Figure 3.33: the register save area holds %rdi at offset 0 to %r9 at 40, and \"reg_save_area: The element points to the start of the register save area\"; Figure 3.34: the va_list is {unsigned int gp_offset; unsigned int fp_offset; void *overflow_arg_area; void *reg_save_area;} (overflow_arg_area at offset 8, reg_save_area at 16), and \"gp_offset: The element holds the offset in bytes from reg_save_area to the place where the next available general purpose argument register is saved\"",
};

const MICROSOFT_X64: ConventionRow = ConventionRow {
    id: ConventionId::Win64,
    cspec: Cspec {
        toolchain: Toolchain::Compiler("windows"),
        prototype: None,
    },
    red_zone: 0,
    frame_pointer: Some(RegName("rbp")),
    count_register: None,
    save_area: None,
    home: Some(HomeArea { step: 8 }),
    refused: None,
    entry_stack: Some(EntryStack {
        alignment: 16,
        residue: 8,
    }),
    stack_bound: None,
    overrides: &[],
    results: Some(ResultSet {
        follows: &[],
        empty: &[],
        citation: "Microsoft x64 software conventions, \"Return values\": \"A scalar return value \
                   that can fit into 64 bits, including the __m64 type, is returned through RAX. \
                   Non-scalar types including floats, doubles, and vector types such as __m128 \
                   ... are returned in XMM0\"; otherwise the caller passes a pointer, returned in RAX",
    }),
    citation: "Microsoft x64 software conventions, \"Stack usage\": the convention \
               defines no red zone; its register usage table lists RBP as nonvolatile and usable as a frame pointer; \"Stack allocation\": \"The stack will always be maintained 16-byte aligned, except within the prolog (for example, after the return address is pushed)\"; \"The caller is responsible for allocating space for the parameters to the callee. The caller must always allocate sufficient space to store four register parameters, even if the callee doesn't take that many parameters\", the area directly above the return address; \"Varargs\": \"It's the callee's responsibility to dump arguments that have their address taken\"; Windows SDK vadefs.h: _crt_va_arg on _M_X64 steps the char * va_list by sizeof(__int64) per argument",
};

const I386_CDECL: ConventionRow = ConventionRow {
    id: ConventionId::I386Cdecl,
    cspec: USUAL,
    red_zone: 0,
    frame_pointer: Some(RegName("ebp")),
    count_register: None,
    save_area: None,
    home: None,
    refused: None,
    entry_stack: Some(EntryStack {
        alignment: 16,
        residue: 12,
    }),
    stack_bound: None,
    overrides: &[],
    results: None,
    citation: "System V i386 ABI 1.1, \"Function Calling Sequence\": the convention \
               defines no red zone; its register table gives %ebp the frame pointer role; \"The end of the input argument area shall be aligned on a 16 byte boundary\", so %esp + 4 is a multiple of 16 at entry",
};

const AAPCS64_INTEGER_UNSPECIFIED: [SpecOverride; 2] = [
    SpecOverride::Extension {
        side: Side::Input,
        class: SlotClass::Integer,
        extension: Extension::Unspecified,
        citation: "AAPCS64, section 6.8.2 \"Parameter passing rules\", C.16: an argument narrower \
                   than 8 bytes is placed \"as if the argument was copied to the least \
                   significant bits of a 64-bit register and the remaining bits filled with \
                   unspecified values\"; AARCH64.cspec's extension=\"zero\" says otherwise",
    },
    SpecOverride::Extension {
        side: Side::Output,
        class: SlotClass::Integer,
        extension: Extension::Unspecified,
        citation: "AAPCS64, section 6.9 \"Result return\": a result is returned in the registers \
                   an identical first argument would be passed in, so C.16 leaves the bits \
                   above it unspecified",
    },
];

const AAPCS64: ConventionRow = ConventionRow {
    id: ConventionId::Aapcs64,
    cspec: USUAL,
    red_zone: 0,
    frame_pointer: Some(RegName("x29")),
    count_register: None,
    save_area: Some(RegisterSaveArea {
        anchor: SaveAreaAnchor::End,
        offset_field: 16,
        offset_width: 4,
        stack_field: -8,
    }),
    home: None,
    refused: None,
    entry_stack: Some(EntryStack {
        alignment: 16,
        residue: 0,
    }),
    stack_bound: None,
    overrides: &AAPCS64_INTEGER_UNSPECIFIED,
    results: Some(ResultSet {
        follows: &[
            (RegName("x1"), RegName("x0")),
            (RegName("q1"), RegName("q0")),
            (RegName("q2"), RegName("q1")),
            (RegName("q3"), RegName("q2")),
        ],
        empty: &[],
        citation: "AAPCS64, section 6.9 \"Result return\": a result is returned in the registers \
                   an identical first argument would be passed in (x0 and x1, or v0 to v3 for an \
                   HFA or HVA, consecutive from v0); otherwise through the memory x8 addresses",
    }),
    citation: "AAPCS64, \"Universal stack constraints\": \"A process may only access \
               (for reading or writing) the closed interval of the entire stack delimited \
               by [SP, stack-base - 1]\"; its general-purpose register table names r29 FP, the frame pointer; \"Universal stack constraints\": \"SP mod 16 = 0\"; Appendix \"Variable argument lists\": the general register save area holds x0 to x7 in order, and \"__gr_top: set to the address of the byte immediately following the general register argument save area\"; the va_list is {void *__stack; void *__gr_top; void *__vr_top; int __gr_offs; int __vr_offs;} (__stack at offset 0, __gr_top at 8), and \"__gr_offs: set to 0 - ((8 - named_gr) * 8)\"",
};

const AAPCS64_DARWIN: ConventionRow = ConventionRow {
    id: ConventionId::AppleArm64,
    cspec: Cspec {
        toolchain: Toolchain::Compiler("apple"),
        prototype: None,
    },
    save_area: None,
    overrides: &[
        SpecOverride::Extension {
            side: Side::Input,
            class: SlotClass::Integer,
            extension: Extension::IntType,
            citation: "Apple, \"Writing ARM64 code for Apple platforms\": \"The general ABI \
                       specifies that it is the callee's responsibility to sign or zero-extend \
                       arguments having fewer than 32 bits, and that any unused bits in a \
                       register are unspecified. In iOS, however, the caller must perform such \
                       extensions, up to 32 bits\"",
        },
        AAPCS64_INTEGER_UNSPECIFIED[1],
    ],
    citation: "Apple, \"Writing ARM64 code for Apple platforms\": \"the caller places \
               the arguments for the variadic portion of a function on the stack\", so the \
               prologue saves no register area; where the tail goes is AARCH64_apple.cspec's",
    ..AAPCS64
};

const AAPCS32: ConventionRow = ConventionRow {
    id: ConventionId::Aapcs32,
    cspec: USUAL,
    red_zone: 0,
    frame_pointer: Some(RegName("r11")),
    count_register: None,
    save_area: None,
    home: None,
    refused: None,
    entry_stack: Some(EntryStack {
        alignment: 8,
        residue: 0,
    }),
    stack_bound: None,
    overrides: &[],
    results: None,
    citation: "AAPCS32, \"Universal stack constraints\": \"A process may only access \
               (for reading or writing) the closed interval of the entire stack delimited \
               by [SP, stack-base - 1]\"; AAPCS32 leaves the frame pointer to the platform, and GCC in ARM state keeps it in r11, the APCS fp; \"Public interfaces\": \"SP mod 8 = 0\"",
};

const RISCV_LP64: ConventionRow = ConventionRow {
    id: ConventionId::RiscVLp64,
    cspec: USUAL,
    red_zone: 0,
    frame_pointer: Some(RegName("s0")),
    count_register: None,
    save_area: None,
    home: None,
    refused: None,
    entry_stack: Some(EntryStack {
        alignment: 16,
        residue: 0,
    }),
    stack_bound: None,
    overrides: &[],
    results: None,
    citation: "RISC-V ELF psABI, \"Integer Calling Convention\": the convention defines \
               no red zone; \"Register Convention\": x8 \"s0/fp Saved register/frame pointer\"; \"the stack pointer shall be aligned to a 128-bit boundary upon procedure entry\"",
};

const GO_INTERNAL: Cspec = Cspec {
    toolchain: Toolchain::Compiler("golang"),
    prototype: Some("abi-internal"),
};

const GO_ABI0: Cspec = Cspec {
    toolchain: Toolchain::Compiler("golang"),
    prototype: Some("abi0"),
};

const GO_AMD64: ConventionRow = ConventionRow {
    id: ConventionId::GoAmd64,
    cspec: GO_INTERNAL,
    red_zone: 0,
    count_register: None,
    save_area: None,
    frame_pointer: Some(RegName("rbp")),
    home: None,
    refused: None,
    entry_stack: Some(EntryStack {
        alignment: 8,
        residue: 0,
    }),
    stack_bound: Some(StackGuard {
        register: RegName("r14"),
        offset: 16,
        width: 8,
        citation: "Go internal ABI (src/cmd/compile/abi-internal.md), amd64: \"R14 | Current \
                   goroutine | Same | Same\"; runtime/runtime2.go: `type g struct { stack stack; \
                   stackguard0 uintptr` after `type stack struct { lo, hi uintptr }`, so 16 bytes in",
    }),
    overrides: &[],
    results: None,
    citation: "Go internal ABI (src/cmd/compile/abi-internal.md), amd64: \"RBP | Frame pointer \
               | Same | Same\"; it defines no red zone; amd64: \"The stack pointer, RSP, grows down and is always aligned to 8 bytes\"",
};

const GO_ARM64: ConventionRow = ConventionRow {
    id: ConventionId::GoArm64,
    frame_pointer: Some(RegName("x29")),
    entry_stack: Some(EntryStack {
        alignment: 16,
        residue: 0,
    }),
    stack_bound: Some(StackGuard {
        register: RegName("x28"),
        offset: 16,
        width: 8,
        citation: "Go internal ABI (src/cmd/compile/abi-internal.md), arm64: \"R28 | Current \
                   goroutine | Same | Same\"; runtime/runtime2.go: `stackguard0` 16 bytes into `g`",
    }),
    results: None,
    citation: "Go internal ABI (src/cmd/compile/abi-internal.md), arm64: \"R29 | Frame pointer \
               | Same | Same\"; it defines no red zone; arm64: \"The stack pointer, RSP, grows down and is always aligned to 16 bytes\"",
    ..GO_AMD64
};

/// Go's stack-based ABI0: results come back in the caller's frame, where no boundary reads them.
const GO_ABI0_REFUSED: &str = "Go ABI0 returns results on the stack, which no call boundary states";

const GO_AMD64_ABI0: ConventionRow = ConventionRow {
    id: ConventionId::GoAmd64Abi0,
    cspec: GO_ABI0,
    home: None,
    refused: Some(GO_ABI0_REFUSED),
    ..GO_AMD64
};

const GO_ARM64_ABI0: ConventionRow = ConventionRow {
    id: ConventionId::GoArm64Abi0,
    cspec: GO_ABI0,
    home: None,
    refused: Some(GO_ABI0_REFUSED),
    ..GO_ARM64
};

const GO_UNSTATED_REFUSED: &str = "the toolchain states no function's ABI: an assembly body keeps ABI0, which pclntab marks from Go 1.18";

const GO_AMD64_UNSTATED: ConventionRow = ConventionRow {
    id: ConventionId::GoAmd64Unstated,
    home: None,
    refused: Some(GO_UNSTATED_REFUSED),
    ..GO_AMD64
};

const GO_ARM64_UNSTATED: ConventionRow = ConventionRow {
    id: ConventionId::GoArm64Unstated,
    home: None,
    refused: Some(GO_UNSTATED_REFUSED),
    ..GO_ARM64
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Each row is its own id's, and every row cites what it states.
    #[test]
    fn every_row_is_keyed_by_its_own_id_and_cites_its_overrides() {
        for id in ConventionId::ALL {
            let row = id.row();
            assert_eq!(row.id, id);
            assert!(!row.citation.is_empty(), "{id:?}");
            for item in row.overrides {
                let citation = match item {
                    SpecOverride::Results { citation, .. }
                    | SpecOverride::Extension { citation, .. } => citation,
                };
                assert!(!citation.is_empty(), "{id:?}");
            }
        }
    }

    /// x86-64's call pushes a return address onto a 16-byte-aligned stack; AArch64's pushes none.
    #[test]
    fn a_convention_states_the_entry_stack_pointer_s_alignment() {
        let entry = |arch, bits, platform| {
            ConventionId::default_for(arch, bits, platform).and_then(|id| id.row().entry_stack)
        };
        let stack = |alignment, residue| Some(EntryStack { alignment, residue });
        assert_eq!(entry("x86", 64, Kernel::Linux), stack(16, 8));
        assert_eq!(entry("x86", 64, Kernel::Windows), stack(16, 8));
        assert_eq!(entry("arm", 64, Kernel::Linux), stack(16, 0));
        let go = ConventionId::go("x86", 64, Kernel::Linux, Some((1, 20)));
        assert_eq!(go.and_then(|id| id.row().entry_stack), stack(8, 0));
    }

    /// The register ABI arrived in Go 1.17 on three amd64 ports and in 1.18 everywhere else.
    #[test]
    fn a_go_function_s_convention_follows_its_toolchain() {
        let name = |arch, platform, version| {
            ConventionId::go(arch, 64, platform, version).map(ConventionId::radare2_name)
        };
        assert_eq!(name("x86", Kernel::Linux, Some((1, 17))), Some("golang"));
        assert_eq!(
            name("x86", Kernel::Unknown, Some((1, 17))),
            Some("golang_abi0")
        );
        assert_eq!(name("x86", Kernel::Unknown, Some((1, 18))), Some("golang"));
        assert_eq!(
            name("x86", Kernel::Linux, Some((1, 14))),
            Some("golang_abi0")
        );
        assert_eq!(name("x86", Kernel::Linux, None), Some("golang_abi0"));
        assert_eq!(
            name("arm", Kernel::Darwin, Some((1, 17))),
            Some("golang_abi0")
        );
        assert_eq!(name("arm", Kernel::Darwin, Some((1, 21))), Some("golang"));
        assert_eq!(name("riscv", Kernel::Linux, Some((1, 21))), None);
        let abi0 = ConventionId::go("x86", 64, Kernel::Linux, None).expect("ABI0");
        assert!(abi0.row().refused.is_some());
    }

    /// What no compiler specification states is the platform's: the red zone is System V's
    /// alone among x86-64 ABIs, and only Apple's arm64 ABI saves no variadic register area.
    #[test]
    fn each_platform_states_its_own_convention() {
        let x64 = |platform| ConventionId::default_for("x86-64", 64, platform).expect("an id");
        assert_eq!(x64(Kernel::Linux), ConventionId::SysVAmd64);
        assert_eq!(x64(Kernel::Linux).radare2_name(), "amd64");
        assert_eq!(x64(Kernel::Linux).row().red_zone, 128);
        assert_eq!(x64(Kernel::Darwin).row().red_zone, 128);
        assert_eq!(x64(Kernel::Windows).radare2_name(), "ms");
        assert_eq!(x64(Kernel::Windows).row().red_zone, 0);
        let arm64 = |platform| ConventionId::default_for("aarch64", 64, platform).expect("an id");
        assert_eq!(
            arm64(Kernel::Linux).row().save_area,
            Some(RegisterSaveArea {
                anchor: SaveAreaAnchor::End,
                offset_field: 16,
                offset_width: 4,
                stack_field: -8,
            })
        );
        assert_eq!(arm64(Kernel::Darwin), ConventionId::AppleArm64);
        assert_eq!(arm64(Kernel::Darwin).row().save_area, None);
        assert_eq!(x64(Kernel::Windows).row().save_area, None);
        assert_eq!(arm64(Kernel::Darwin).radare2_name(), "arm64");
        assert!(ConventionId::default_for("mips", 32, Kernel::Linux).is_none());
    }

    /// The cspec's AArch64 `extension="zero"` is overridden by the ABI, cited; Apple's caller
    /// extends to 32 bits (decided 2026-11-09).
    #[test]
    fn the_aarch64_extension_claims_are_cited_overrides() {
        let extension = |id: ConventionId, at: Side| {
            id.row().overrides.iter().find_map(|item| match *item {
                SpecOverride::Extension {
                    side,
                    class: SlotClass::Integer,
                    extension,
                    ..
                } if side == at => Some(extension),
                _ => None,
            })
        };
        assert_eq!(
            extension(ConventionId::Aapcs64, Side::Input),
            Some(Extension::Unspecified)
        );
        assert_eq!(
            extension(ConventionId::AppleArm64, Side::Input),
            Some(Extension::IntType)
        );
        assert_eq!(
            extension(ConventionId::AppleArm64, Side::Output),
            Some(Extension::Unspecified)
        );
        assert_eq!(extension(ConventionId::SysVAmd64, Side::Input), None);
    }
}
