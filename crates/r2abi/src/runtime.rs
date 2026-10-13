//! What a language runtime's routines do at a call, where no body proves it: models keyed by the
//! routine's name, which stays a hint the caller weighs (doc/adr-language-profile.md, item 4).

/// Whether a call to the routine named `name` re-enters its caller at the caller's entry instead of
/// returning: Go's stack growth.
///
/// cmd/internal/obj/x86/obj6.go and arm64/obj7.go `stacksplit`: the prologue's failing compare
/// calls `runtime.morestack` (`morestack_noctxt` without a closure context) and then jumps to the
/// function's start; runtime/stack.go `newstack` grows the stack and resumes after the call.
pub fn reenters_caller(name: &str) -> bool {
    let name = name.strip_prefix("sym.").unwrap_or(name);
    let name = name.strip_suffix(".abi0").unwrap_or(name);
    matches!(name, "runtime.morestack" | "runtime.morestack_noctxt")
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
    let name = name.strip_prefix("sym.").unwrap_or(name);
    let name = name.strip_suffix(".abi0").unwrap_or(name);
    name.strip_prefix("runtime.").is_some_and(|routine| {
        matches!(
            routine,
            "throw" | "throwinit" | "panicwrap" | "panicSimdImm"
        ) || EXITS.binary_search(&routine).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::{exits, reenters_caller};

    #[test]
    fn go_s_compiler_ends_a_block_after_a_runtime_panic() {
        assert!(exits("runtime.throw"));
        assert!(exits("sym.runtime.gopanic"));
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
