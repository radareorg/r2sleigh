//! What a language runtime's routines do at a call, where no body proves it: models keyed by the
//! routine's name, which stays a hint the caller weighs (doc/adr-language-profile.md, item 4).

/// Whether a call to the routine named `name` re-enters its caller at the caller's entry instead of
/// returning: Go's stack growth.
///
/// cmd/internal/obj/x86/obj6.go and arm64/obj7.go `stacksplit`: the prologue's failing compare
/// calls `runtime.morestack` (`morestack_noctxt` without a closure context) and then jumps to the
/// function's start; runtime/stack.go `newstack` grows the stack and resumes after the call.
pub fn reenters_caller(name: &str) -> bool {
    matches!(
        routine(name),
        "runtime.morestack" | "runtime.morestack_noctxt"
    )
}

/// The routine a symbol names: radare2's `sym.`, Mach-O's leading underscore on every defined
/// symbol, and Go's ABI0 wrapper suffix taken off.
fn routine(name: &str) -> &str {
    let name = name.strip_prefix("sym.").unwrap_or(name);
    let name = name.strip_prefix('_').unwrap_or(name);
    name.strip_suffix(".abi0").unwrap_or(name)
}

/// Whether a call to the routine named `name` never comes back: Go's compiler ends the calling
/// block there (cmd/compile/internal/ssagen/ssa.go: the `throw`/`gopanic` list, `rtcall(.., false,
/// ..)` targets, `BoundsCheckFunc` and `panicBounds`), with the older bounds shims' names.
pub fn exits(name: &str) -> bool {
    const EXITS: [&str; 51] = [
        "block",
        "goPanicIndex",
        "goPanicIndexU",
        "goPanicSlice3Acap",
        "goPanicSlice3AcapU",
        "goPanicSlice3Alen",
        "goPanicSlice3AlenU",
        "goPanicSlice3B",
        "goPanicSlice3BU",
        "goPanicSlice3C",
        "goPanicSlice3CU",
        "goPanicSliceAcap",
        "goPanicSliceAcapU",
        "goPanicSliceAlen",
        "goPanicSliceAlenU",
        "goPanicSliceB",
        "goPanicSliceBU",
        "goPanicSliceConvert",
        "gopanic",
        "panicBounds",
        "panicExtend",
        "panicIndex",
        "panicIndexU",
        "panicSlice3Acap",
        "panicSlice3AcapU",
        "panicSlice3Alen",
        "panicSlice3AlenU",
        "panicSlice3B",
        "panicSlice3BU",
        "panicSlice3C",
        "panicSlice3CU",
        "panicSliceAcap",
        "panicSliceAcapU",
        "panicSliceAlen",
        "panicSliceAlenU",
        "panicSliceB",
        "panicSliceBU",
        "panicSliceConvert",
        "panicdivide",
        "panicdottypeE",
        "panicdottypeI",
        "panicmakeslicecap",
        "panicmakeslicelen",
        "panicnildottype",
        "panicoverflow",
        "panicrangestate",
        "panicshift",
        "panicunsafeslicelen",
        "panicunsafeslicenilptr",
        "panicunsafestringlen",
        "panicunsafestringnilptr",
    ];
    routine(name)
        .strip_prefix("runtime.")
        .is_some_and(|routine| {
            matches!(
                routine,
                "throw" | "throwinit" | "panicwrap" | "panicSimdImm"
            ) || EXITS.binary_search(&routine).is_ok()
        })
}

/// A personality routine whose language-specific data area is GCC's call-site table: header, then
/// records of start, length, landing pad and action (doc/adr-radare2-function-walk.md, "Unwind edges as built").
#[derive(Debug, PartialEq, Eq)]
pub struct Personality {
    pub name: &'static str,
    pub citation: &'static str,
}

/// The routines that read that table, one cited row each.
pub const PERSONALITIES: [Personality; 2] = [
    Personality {
        name: "__gcc_personality_v0",
        citation: "GCC 14.2.0 libgcc/unwind-c.c, PERSONALITY_FUNCTION: \"p = read_encoded_value (0, \
                   info.call_site_encoding, p, &cs_start); ... if (cs_lp) landing_pad = info.LPStart + cs_lp;\"",
    },
    Personality {
        name: "__gxx_personality_v0",
        citation: "GCC 14.2.0 libstdc++-v3/libsupc++/eh_personality.cc, parse_lsda_header and \
                   PERSONALITY_FUNCTION: \"if (ip < info.Start + cs_start + cs_len) { if (cs_lp) \
                   landing_pad = info.LPStart + cs_lp;\"",
    },
];

/// The row of the personality an import binds, its symbol version taken off; the name is a declaration.
pub fn personality(import: &str) -> Option<&'static Personality> {
    let name = import.split('@').next().unwrap_or(import);
    PERSONALITIES.iter().find(|row| row.name == name)
}

#[cfg(test)]
mod tests {
    use super::{exits, personality, reenters_caller};

    #[test]
    fn only_a_cited_personality_states_a_call_site_table() {
        assert!(personality("__gxx_personality_v0@CXXABI_1.3").is_some());
        assert!(personality("__gcc_personality_v0").is_some());
        assert!(personality("__gxx_personality_seh0").is_none());
        assert!(personality("rust_eh_personality").is_none());
    }

    #[test]
    fn go_s_compiler_ends_a_block_after_a_runtime_panic() {
        assert!(exits("runtime.throw"));
        assert!(exits("sym.runtime.gopanic"));
        // Mach-O states every defined symbol with a leading underscore.
        assert!(exits("_runtime.throw"));
        assert!(reenters_caller("sym._runtime.morestack_noctxt"));
        assert!(exits("runtime.panicIndex.abi0"));
        assert!(exits("runtime.goPanicSliceAlenU"));
        assert!(exits("runtime.panicBounds"));
        assert!(!exits("runtime.morestack_noctxt"));
        assert!(!exits("runtime.fatalthrow"));
        assert!(!exits("main.throw"));
        assert!(!exits("gopanic"));
    }

    #[test]
    fn go_stack_growth_re_enters_its_caller() {
        assert!(reenters_caller("runtime.morestack_noctxt.abi0"));
        assert!(reenters_caller("sym.runtime.morestack"));
        assert!(!reenters_caller("runtime.morestackc"));
        assert!(!reenters_caller("morestack"));
    }
}
