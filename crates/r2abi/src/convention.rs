//! The vocabulary a calling convention is stated in, shared by the compiler specification's
//! reading (`r2sleigh_lift::profile`) and the ABI rows (doc/adr-call-boundary.md).

use crate::Kernel;
use crate::platform::{
    EntryStack, PlatformRegister, RegisterDuty, RegisterSaveArea, SaveAreaAnchor, StackGuard,
};

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
    /// A register the specification's `unaffected` and the document disagree on; `kept` says
    /// whether the convention's preserved set holds it (D476).
    Preserved {
        register: RegName,
        kept: bool,
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
    pub count_register: Option<CountRegister>,
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
    /// Every register a call leaves as it found it; none where no document states one, so no
    /// register survives a call (doc/adr-call-boundary.md, "Lower bounds and upper bounds").
    pub preserved: Option<PreservedSet>,
    /// The documents that state these.
    pub citation: &'static str,
}

/// A count register, with the passages stating that a global function's call reads no other byte of
/// the register holding it (D431).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountRegister {
    pub register: RegName,
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

/// The registers a document states a callee keeps, as `PlatformRegister`s are stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreservedSet {
    pub registers: &'static [PreservedRegister],
    pub citation: &'static str,
}

/// One preserved register; `bits` are the bits the duty covers, `None` the whole register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreservedRegister {
    pub register: RegName,
    pub bits: Option<u64>,
}

impl PreservedSet {
    /// Whether the set holds `register` whole or in part.
    pub fn holds(&self, register: RegName) -> bool {
        self.registers.iter().any(|held| held.register == register)
    }
    /// `held` as a callee-saved platform row, which states the bytes its `bits` cover.
    pub fn row(&self, held: &PreservedRegister) -> PlatformRegister {
        PlatformRegister {
            register: held.register.0,
            duty: RegisterDuty::CalleeSaved,
            bits: held.bits,
            citation: self.citation,
        }
    }
}

/// Whole registers by name.
macro_rules! whole {
    ($($name:literal),* $(,)?) => {
        &[$(PreservedRegister { register: RegName($name), bits: None }),*]
    };
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

const SYSV_PRESERVED: PreservedSet = PreservedSet {
    registers: whole!["rbx", "rsp", "rbp", "r12", "r13", "r14", "r15"],
    citation: "System V AMD64 psABI 1.0 (x86-psABIs/x86-64-ABI 74b6f30f), section 3.2.1: \
               \"Registers %rbp, %rbx and %r12 through %r15 belong to the calling function and \
               the called function is required to preserve their values\"; Figure 3.4: %rsp \
               \"stack pointer\", preserved across function calls \"Yes\"; the x87 control word, \
               MXCSR's control bits and DF are `r2abi::platform` rows",
};

const WIN64_PRESERVED: PreservedSet = PreservedSet {
    registers: whole![
        "rbx", "rbp", "rdi", "rsi", "rsp", "r12", "r13", "r14", "r15", "xmm6", "xmm7", "xmm8",
        "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    ],
    citation: "Microsoft x64 calling convention (MicrosoftDocs/cpp-docs af4947c4, \
               docs/build/x64-calling-convention.md), \"Caller/callee saved registers\": \"The x64 \
               ABI considers registers RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15, and \
               XMM6-XMM15 nonvolatile. They must be saved and restored by a function that uses \
               them\"; x64-software-conventions.md: \"XMM6:XMM15, YMM6:YMM15 | Nonvolatile (XMM), \
               Volatile (upper half of YMM)\"; DF is an `r2abi::platform` row",
};

/// Windows' x64 and i386 specifications list the thread block's segment base; no document does.
const NO_SEGMENT_DOCUMENT: &str = "Microsoft x64 software conventions (MicrosoftDocs/cpp-docs \
    af4947c4): the \"Register volatility and preservation\" table and \"Caller/callee saved \
    registers\" name no segment register, so the specification's GS_OFFSET and FS_OFFSET \
    survive a call by no document";

const MS_CONTROL_EXCEPTED: &str = "Microsoft x64 calling convention (cpp-docs af4947c4), \
    \"FPCSR\" and \"MXCSR\": the control fields are nonvolatile, but \"There are two exceptions \
    to the rules about the nonvolatility of the control flags: In functions where the documented \
    purpose of the given function is to modify the nonvolatile FPCSR flags\" (and MXCSR flags), \
    so no call keeps them unconditionally";

const I386_PRESERVED: PreservedSet = PreservedSet {
    registers: whole!["ebx", "esi", "edi", "ebp", "esp"],
    citation: "System V i386 ABI 1.1 (x86-psABIs/i386-ABI 9137bb3d), \"Registers\" table: %ebx \
               \"callee-saved register\", %esp \"stack pointer\", %ebp \"callee-saved register; \
               optionally used as frame pointer\", %esi and %edi \"callee-saved register\", each \
               preserved across function calls \"Yes\"; DF is an `r2abi::platform` row",
};

const I386_CONTROL_UNOWNED: &str = "System V i386 ABI 1.1 (i386-ABI 9137bb3d): \"The control \
    bits of the MXCSR register are callee-saved (preserved across calls)\" and \"the x87 control \
    word is callee-saved\"; `r2abi::platform` states these for x86-64 only, so the model keeps \
    them on no i386 boundary (a lower bound)";

const AAPCS64_PRESERVED: PreservedSet = PreservedSet {
    registers: whole![
        "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "sp", "d8",
        "d9", "d10", "d11", "d12", "d13", "d14", "d15",
    ],
    citation: "AAPCS64 (ARM-software/abi-aa 2024Q3), 6.1.1 \"General-purpose Registers\": \"A \
               subroutine invocation must preserve the contents of the registers r19-r29 and \
               SP\"; 6.1.2 \"SIMD and Floating-Point registers\": \"Registers v8-v15 must be \
               preserved by a callee across subroutine calls ... only the bottom 64 bits of each \
               value stored in v8-v15 need to be preserved\", d8 to d15",
};

const APPLE_ARM64_PRESERVED: PreservedSet = PreservedSet {
    citation: "Apple, \"Writing ARM64 code for Apple platforms\": \"Apple platforms diverge from \
               the standard 64-bit ARM architecture in a few specific ways. Apart from these \
               small differences, iOS, tvOS, and macOS adhere to the rest of the 64-bit ARM \
               specification\", and none of the differences names a callee-saved register (x18, \
               \"The platforms reserve register x18\", is an `r2abi::platform` row); so AAPCS64 \
               6.1.1 and 6.1.2: r19-r29, SP and the bottom 64 bits of v8-v15",
    ..AAPCS64_PRESERVED
};

const AAPCS32_PRESERVED: PreservedSet = PreservedSet {
    registers: whole![
        "r4", "r5", "r6", "r7", "r8", "r10", "r11", "sp", "d8", "d9", "d10", "d11", "d12", "d13",
        "d14", "d15",
    ],
    citation: "AAPCS32 (ARM-software/abi-aa 2024Q3), 6.1.1 \"Core registers\": \"A subroutine \
               must preserve the contents of the registers r4-r8, r10, r11 and SP (and r9 in PCS \
               variants that designate r9 as v6)\"; 6.1.2.1 \"VFP register usage conventions\": \
               \"Registers s16-s31 (d8-d15, q4-q7) must be preserved across subroutine calls\"",
};

const RISCV_PRESERVED: PreservedSet = PreservedSet {
    registers: whole![
        "sp", "gp", "tp", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
        "fs0", "fs1", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11",
    ],
    citation: "RISC-V psABI 1.0 (riscv-non-isa/riscv-elf-psabi-doc v1.0, riscv-cc.adoc), \
               \"Integer Register Convention\": sp preserved across calls \"Yes\", s0-s11 \
               \"Yes\", and \"procedures should not modify the integer registers tp and gp\"; \
               \"Hardware Floating-point Calling Convention\" (riscv64-fp.cspec's): \
               \"Floating-point registers fs0-fs11 shall be preserved across procedure calls, \
               provided they hold values no more than ABI_FLEN bits wide\"",
};

const GO_AMD64_PRESERVED: PreservedSet = PreservedSet {
    registers: whole!["rsp", "rbp", "r14"],
    citation: "Go internal ABI (golang/go go1.22.0, src/cmd/compile/abi-internal.md), amd64: \
               \"There are no callee-save registers\"; \"RSP | Stack pointer | Same | Same\", \
               \"RBP | Frame pointer | Same | Same\", \"R14 | Current goroutine | Same | Same\"",
};

const GO_AMD64_SCRATCH: [SpecOverride; 2] = [
    SpecOverride::Preserved {
        register: RegName("r15"),
        kept: false,
        citation: "Go internal ABI (go1.22.0), amd64: \"R15 is a scratch register except in \
                   dynamically linked binaries\"",
    },
    SpecOverride::Preserved {
        register: RegName("xmm15"),
        kept: false,
        citation: "Go internal ABI (go1.22.0), amd64: \"X15 | Zero value (*) | Same | \
                   Scratch\", \"(*) Except on Plan 9, where X15 is a scratch register\"",
    },
];

const GO_AMD64_ABI0_PRESERVED: PreservedSet = PreservedSet {
    registers: whole!["rsp", "rbp", "r14"],
    citation: "Go internal ABI (go1.22.0), amd64: \"ABIInternal and ABI0 functions are able to \
               call each other through transparent ABI wrappers\", and R14 and X15 \"will have \
               to be restored on transitions from ABI0 code to ABIInternal code\": a call reaches \
               ABI0 code only through a wrapper, so the caller finds RSP, RBP and R14 as it left \
               them; the row refuses every ABI0 body, so it is read only at such a call",
};

const GO_ARM64_PRESERVED: PreservedSet = PreservedSet {
    registers: whole!["sp", "x29", "x28", "x18"],
    citation: "Go internal ABI (go1.22.0, src/cmd/compile/abi-internal.md), arm64: \"RSP | Stack \
               pointer | Same | Same\", \"R29 | Frame pointer | Same | Same\", \"R28 | Current \
               goroutine | Same | Same\", \"R18 | Reserved (not used) | Same | Same\"; \"These \
               register meanings are compatible with Go's stack-based calling convention\", so \
               ABI0 keeps them too",
};

const SYSTEM_V_AMD64: ConventionRow = ConventionRow {
    id: ConventionId::SysVAmd64,
    // gcc's, which every x86-64 container but a PE reads anyway; a PE's `sysv_abi` function too.
    cspec: Cspec {
        toolchain: Toolchain::Compiler("gcc"),
        prototype: None,
    },
    red_zone: 128,
    frame_pointer: Some(RegName("rbp")),
    count_register: Some(CountRegister {
        register: RegName("al"),
        citation: "System V AMD64 psABI 1.0 (x86-psABIs/x86-64-ABI 74b6f30f), section 3.2, \
                   \"Function Calling Sequence\": \"The standard calling sequence requirements \
                   apply only to global functions\"; section 3.2.3, \"Parameter Passing\": %al \
                   \"is used as hidden argument to specify the number of vector registers \
                   used\", and its footnote: \"Note that the rest of %rax is undefined, only the \
                   contents of %al is defined\"; Figure 3.4: %rax is a \"temporary register; with \
                   variable arguments passes information about the number of vector registers \
                   used; 1st return register\"",
    }),
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
    preserved: Some(SYSV_PRESERVED),
    citation: "System V AMD64 psABI 1.0, section 3.2.2: \"The 128-byte area beyond the \
               location pointed to by %rsp is considered to be reserved and shall not be \
               modified by signal or interrupt handlers\"; Figure 3.4: %rbp \"callee-saved register; optionally used as frame pointer\"; section 3.2.2: \"the value (%rsp + 8) is always a multiple of 16 when control is transferred to the function entry point\"; section 3.5.7, Figure 3.33: the register save area holds %rdi at offset 0 to %r9 at 40, and \"reg_save_area: The element points to the start of the register save area\"; Figure 3.34: the va_list is {unsigned int gp_offset; unsigned int fp_offset; void *overflow_arg_area; void *reg_save_area;} (overflow_arg_area at offset 8, reg_save_area at 16), and \"gp_offset: The element holds the offset in bytes from reg_save_area to the place where the next available general purpose argument register is saved\"",
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
    overrides: &[
        SpecOverride::Preserved {
            register: RegName("gs_base"),
            kept: false,
            citation: NO_SEGMENT_DOCUMENT,
        },
        SpecOverride::Preserved {
            register: RegName("cwd"),
            kept: false,
            citation: MS_CONTROL_EXCEPTED,
        },
        SpecOverride::Preserved {
            register: RegName("mxcsr"),
            kept: false,
            citation: MS_CONTROL_EXCEPTED,
        },
    ],
    results: Some(ResultSet {
        follows: &[],
        empty: &[],
        citation: "Microsoft x64 software conventions, \"Return values\": \"A scalar return value \
                   that can fit into 64 bits, including the __m64 type, is returned through RAX. \
                   Non-scalar types including floats, doubles, and vector types such as __m128 \
                   ... are returned in XMM0\"; otherwise the caller passes a pointer, returned in RAX",
    }),
    preserved: Some(WIN64_PRESERVED),
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
    overrides: &[
        SpecOverride::Preserved {
            register: RegName("fs_base"),
            kept: false,
            citation: NO_SEGMENT_DOCUMENT,
        },
        SpecOverride::Preserved {
            register: RegName("cwd"),
            kept: false,
            citation: I386_CONTROL_UNOWNED,
        },
        SpecOverride::Preserved {
            register: RegName("mxcsr"),
            kept: false,
            citation: I386_CONTROL_UNOWNED,
        },
    ],
    results: None,
    preserved: Some(I386_PRESERVED),
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

/// AARCH64_win.cspec names no return address, so its `unaffected` x30 is no link it drops.
const AAPCS64_LINK: SpecOverride = SpecOverride::Preserved {
    register: RegName("x30"),
    kept: false,
    citation: "AAPCS64 (abi-aa 2024Q3), 6.1.1: the registers a subroutine invocation must \
               preserve are \"r19-r29 and SP\"; r30 is \"LR\", \"The Link Register\"",
};

const AAPCS64_OVERRIDES: [SpecOverride; 3] = [
    AAPCS64_INTEGER_UNSPECIFIED[0],
    AAPCS64_INTEGER_UNSPECIFIED[1],
    AAPCS64_LINK,
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
    overrides: &AAPCS64_OVERRIDES,
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
    preserved: Some(AAPCS64_PRESERVED),
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
        AAPCS64_LINK,
    ],
    preserved: Some(APPLE_ARM64_PRESERVED),
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
    overrides: &[
        SpecOverride::Preserved {
            register: RegName("r9"),
            kept: false,
            citation: "AAPCS32 (abi-aa 2024Q3), 6.1.1: \"The role of register r9 is platform \
                       specific\"; it is preserved only \"in PCS variants that designate r9 \
                       as v6\", which no row here states",
        },
        SpecOverride::Preserved {
            register: RegName("pc"),
            kept: false,
            citation: "AAPCS32 (abi-aa 2024Q3), 6.1.1 names the registers a subroutine must \
                       preserve, and the program counter is not one",
        },
        SpecOverride::Preserved {
            register: RegName("lr"),
            kept: false,
            citation: "AAPCS32 (abi-aa 2024Q3), 6.1.1: a subroutine must preserve \"r4-r8, r10, \
                       r11 and SP\"; r14 is \"LR\", \"The Link Register\"; ARM_win.cspec names no \
                       return address, so its `unaffected` lr is no link it drops",
        },
    ],
    results: None,
    preserved: Some(AAPCS32_PRESERVED),
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
    preserved: Some(RISCV_PRESERVED),
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
    overrides: &GO_AMD64_SCRATCH,
    results: None,
    preserved: Some(GO_AMD64_PRESERVED),
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
    overrides: &[],
    results: None,
    preserved: Some(GO_ARM64_PRESERVED),
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
    overrides: &[],
    preserved: Some(GO_AMD64_ABI0_PRESERVED),
    ..GO_AMD64
};

const GO_ARM64_ABI0: ConventionRow = ConventionRow {
    id: ConventionId::GoArm64Abi0,
    cspec: GO_ABI0,
    home: None,
    refused: Some(GO_ABI0_REFUSED),
    preserved: Some(GO_ARM64_PRESERVED),
    ..GO_ARM64
};

const GO_UNSTATED_REFUSED: &str = "the toolchain states no function's ABI: an assembly body keeps ABI0, which pclntab marks from Go 1.18";

const GO_AMD64_UNSTATED: ConventionRow = ConventionRow {
    id: ConventionId::GoAmd64Unstated,
    home: None,
    refused: Some(GO_UNSTATED_REFUSED),
    overrides: &GO_AMD64_SCRATCH,
    preserved: Some(GO_AMD64_PRESERVED),
    ..GO_AMD64
};

const GO_ARM64_UNSTATED: ConventionRow = ConventionRow {
    id: ConventionId::GoArm64Unstated,
    home: None,
    refused: Some(GO_UNSTATED_REFUSED),
    overrides: &[],
    preserved: Some(GO_ARM64_PRESERVED),
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
                    | SpecOverride::Extension { citation, .. }
                    | SpecOverride::Preserved { citation, .. } => citation,
                };
                assert!(!citation.is_empty(), "{id:?}");
            }
        }
    }

    /// D476: every row states its preserved set, and a `Preserved` override's `kept` says whether
    /// the set holds the register, so the set and its named differences have one owner.
    #[test]
    fn every_row_cites_its_preserved_set_and_its_named_differences_agree_with_it() {
        for id in ConventionId::ALL {
            let row = id.row();
            let set = row
                .preserved
                .unwrap_or_else(|| panic!("{id:?}: a cited set"));
            assert!(
                !set.citation.is_empty() && !set.registers.is_empty(),
                "{id:?}"
            );
            let named = row.overrides.iter().filter_map(|item| match *item {
                SpecOverride::Preserved { register, kept, .. } => Some((register, kept)),
                _ => None,
            });
            for (register, kept) in named {
                assert_eq!(set.holds(register), kept, "{id:?}: {register:?}");
            }
        }
        let sysv = ConventionId::SysVAmd64.row().preserved.expect("SysV's set");
        assert!(sysv.holds(RegName("rbx")) && !sysv.holds(RegName("rcx")));
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
