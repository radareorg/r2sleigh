//! The staged decompiler (ROADMAP D) through the open program: D1 writes the control, certified,
//! around D2's statements, with D3 spelling each term; a call is still a gap.

use crate::common;

use common::{BASE, CALLER, FORKED, GLIBC, Literal, ONE, PLT_CALLER, PLT_STUB, STUB, TWO, opened};
use r2engine::program::OpenProgram;

#[test]
fn the_staged_pipeline_renders_a_leaf_function_s_values() {
    let rendering = opened()
        .rendered(FORKED)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    // `test edi, edi; je L` is the test on the parameter; the merge is one variable both arms
    // assign, so it is one assignment of the value the test selects.
    assert!(
        text.contains("rax_3 = (uint8_t)((uint32_t)arg0 == (uint32_t)0U) ? 0x1000 : 5;"),
        "{text}"
    );
    assert!(
        text.contains("return r2sleigh_carrier_u64((uint64_t)((uint64_t)rax_3 + (uint64_t)8U));"),
        "{text}"
    );
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
    // The proof line every rendering opens with, from the obligation ledger the staged pipeline closes.
    assert!(
        text.contains("/* r2dec proof: no individual construct is marked;")
            && text.contains("13 source obligations: 10 rendered, 3 elided, 0 refused;"),
        "{text}"
    );
    let closure = rendering
        .response
        .obligation_ledger
        .expect("a ledger")
        .close();
    assert!(closure.total > 0, "{text}");
    assert_eq!(closure.gapped, 0, "every obligation is rendered: {text}");
    // Each written line names the instructions it stands for, all of them `forked`'s.
    let r2engine::EngineRendering::Function(rendered) = &rendering.response.output else {
        panic!("nothing rendered: {text}");
    };
    let lines = rendered.emission().lines();
    assert!(!lines.is_empty(), "{text}");
    for line in lines {
        assert!(
            line.addrs
                .iter()
                .all(|addr| (FORKED..FORKED + 0x15).contains(addr)),
            "{line:?}\n{text}"
        );
    }
}

#[test]
fn a_described_call_is_written_from_the_callsite_facts() {
    let rendering = opened()
        .rendered(CALLER)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    // `call one; ret`: the result register the call leaves is what `caller` returns.
    assert!(text.contains("r2sleigh_result_u32 one(void);"), "{text}");
    assert!(text.contains("rax_1 = (uint64_t)one();"), "{text}");
    assert!(
        text.contains("return r2sleigh_carrier_u32((uint32_t)rax_1);"),
        "{text}"
    );
    // `one` returns, so nothing may tell C otherwise; its return push writes nothing.
    assert!(!text.contains("noreturn"), "{text}");
    assert!(!text.contains("r2sleigh_store"), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
    let r2engine::EngineRendering::Function(rendered) = &rendering.response.output else {
        panic!("nothing rendered: {text}");
    };
    let links = rendered.emission().links();
    assert!(
        links
            .iter()
            .any(|link| link.ident == "one" && link.addr == Some(ONE)),
        "{links:?}"
    );
}

/// `mov edi, 1; call exit; mov eax, 7; ret`: the walk gives the call's block no successor, as the
/// library's declaration of `exit` says, so the call is declared `noreturn` and ends the text there.
#[test]
fn a_call_the_block_graph_never_returns_from_is_declared_noreturn() {
    let mut program = OpenProgram::of(Literal::new().importing("exit").running_on(GLIBC));
    let call = i32::try_from(STUB as i64 - (TWO + 10) as i64).expect("near");
    let mut code = vec![0xbf, 0x01, 0, 0, 0, 0xe8];
    code.extend_from_slice(&call.to_le_bytes());
    code.extend_from_slice(&[0xb8, 0x07, 0, 0, 0, 0xc3]);
    program.source_mut().write(TWO, &code);
    let rendering = program.rendered(TWO).expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    assert!(
        text.contains("__attribute__((noreturn)) void exit(int32_t);"),
        "{text}"
    );
    // `1` is an `int` the declaration holds, so it is passed as the number.
    assert!(text.contains("exit(1);"), "{text}");
    // Nothing follows the call: no trap stands for the edge the block does not have, and no return.
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(
        !text
            .lines()
            .any(|line| line.trim_start().starts_with("return")),
        "{text}"
    );
}

/// `L: test rdi, rdi; je D; mov rdx, rax; mov rax, rcx; mov rcx, rdx; sub rdi, 1; jmp L;
/// D: sub rax, rcx; ret`: the merges swap on the back edge, each copy reading what the other writes.
#[test]
fn merges_that_swap_copy_through_a_temporary() {
    const SWAPS: &[u8] = &[
        0x48, 0x89, 0xf0, 0x48, 0x89, 0xd1, 0x48, 0x85, 0xff, 0x74, 0x0f, 0x48, 0x89, 0xc2, 0x48,
        0x89, 0xc8, 0x48, 0x89, 0xd1, 0x48, 0x83, 0xef, 0x01, 0xeb, 0xec, 0x48, 0x29, 0xc8, 0xc3,
    ];
    let program = Literal::of_code(SWAPS, &[("swaps", BASE, SWAPS.len() as u64)]).running_on(GLIBC);
    let rendering = OpenProgram::of(program)
        .rendered(BASE)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    assert!(text.contains("_next = "), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
}

/// A cache-line flush before the jump is an effect no declaration states, so the body is rendered, not
/// declared away as the import's stub.
#[test]
fn an_effect_before_the_jump_keeps_a_stub_a_body() {
    let mut program = OpenProgram::of(Literal::plt_fenced());
    let text = program
        .rendered(PLT_STUB)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!text.contains("import stub at"), "{text}");
}

/// A stub is one jump through the slot the loader fills with `_Exit`. r2engine's route decides it
/// once, and the rendering is the import's declaration, never a body forwarding through it.
#[test]
fn an_import_stub_is_its_import_s_declaration() {
    let mut program = OpenProgram::of(Literal::plt());
    let text = program
        .rendered(PLT_STUB)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(
        text.contains(&format!("import stub at {PLT_STUB:#x}")) && text.contains("`_Exit`"),
        "{text}"
    );
    assert!(!text.contains("return"), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
}

/// A function that reaches the stub after a test of its own is a body: a branch or a return on
/// another path is not the import's declaration, and the C keeps both paths.
#[test]
fn a_guarded_wrapper_of_a_stub_is_a_body_not_the_stub() {
    let mut program = OpenProgram::of(Literal::plt_guarded_wrapper());
    let text = program
        .rendered(PLT_CALLER)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!text.contains("import stub at"), "{text}");
    assert!(text.contains("free("), "{text}");
    assert!(text.contains("if ("), "{text}");
}

/// The stub's argument is a value the wrapper computes, so the wrapper is not the import: calling
/// it passes what it computes from, and the C says so.
#[test]
fn a_wrapper_that_computes_the_stub_s_argument_is_a_body_not_the_stub() {
    let mut program = OpenProgram::of(Literal::plt_computing_wrapper());
    let text = program
        .rendered(PLT_CALLER)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!text.contains("import stub at"), "{text}");
    // zlib's `zcalloc(opaque, items, size)`: `opaque` is a hole, the product its two read slots.
    assert!(
        text.contains("(r2sleigh_unread_u64 arg0, int32_t arg1, int32_t arg2)"),
        "{text}"
    );
    assert!(
        text.contains("malloc(") && text.contains("arg1 * "),
        "{text}"
    );
}

/// One jump to the stub, with nothing else, is still a jump to another function: only the stub
/// itself jumps through the loader's slot, so this one is a body that calls the import.
#[test]
fn a_function_that_only_jumps_to_a_stub_is_a_body_not_the_stub() {
    let mut program = OpenProgram::of(Literal::plt_forwarding_to("free"));
    let text = program
        .rendered(PLT_CALLER)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!text.contains("import stub at"), "{text}");
    // The parameter handed to `free` is its `void *` (D262).
    assert!(text.contains("free(arg0);"), "{text}");
}

/// The container states a stub of `free` whose jump goes through the slot bound to `malloc`: a body, not a
/// `free` declared with `malloc`'s types.
#[test]
fn a_stub_whose_jump_goes_to_another_import_is_a_body_not_the_stated_stub() {
    let mut program = OpenProgram::of(Literal::plt_declaring("free", "malloc"));
    let text = program
        .rendered(PLT_STUB)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(
        !text.contains("import stub at") && !text.contains("extern"),
        "{text}"
    );
    assert!(text.contains("r2sleigh_residual"), "{text}");
}

/// A stub the container states, whose jump goes through the slot bound to the same import, is that import's
/// declaration.
#[test]
fn a_stub_the_container_states_is_its_import_s_declaration_where_its_jump_agrees() {
    let mut program = OpenProgram::of(Literal::plt_declaring("_Exit", "_Exit"));
    let text = program
        .rendered(PLT_STUB)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(
        text.contains(&format!("import stub at {PLT_STUB:#x}")) && text.contains("`_Exit`"),
        "{text}"
    );
}
