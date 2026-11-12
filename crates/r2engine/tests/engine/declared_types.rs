//! What a declaration states about a slot reaches the rendering: a counted tail passes exactly the
//! arguments its library body reads, and a structure a stripped parameter lays out is spelled
//! (ROADMAP D261 to D264, S28).

use crate::common;

use common::{Literal, PLT_CALLER, plt_then};
use r2engine::program::{Libc, OpenProgram, PlatformEvidence};

fn rendered(literal: Literal, at: u64) -> String {
    OpenProgram::of(literal)
        .rendered(at)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// `f(path) { return open(path, 0); }` after `.plt`.
const OPEN_READING: [u8; 0x32] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0x31, 0xf6, // 1024 xor esi, esi
    0x31, 0xc0, // 1026 xor eax, eax
    0xe8, 0xe3, 0xff, 0xff, 0xff, // 1028 call stub
    0x48, 0x83, 0xc4, 0x08, // 102d add rsp, 8
    0xc3, // 1031 ret
]);

/// `f(path) { return open(path, O_CREAT | O_WRONLY, 0644); }` after `.plt`.
const OPEN_CREATING: [u8; 0x3a] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0xbe, 0x41, 0x00, 0x00, 0x00, // 1024 mov esi, 0x41
    0xba, 0xa4, 0x01, 0x00, 0x00, // 1029 mov edx, 0644
    0x31, 0xc0, // 102e xor eax, eax
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1030 call stub
    0x48, 0x83, 0xc4, 0x08, // 1035 add rsp, 8
    0xc3, // 1039 ret
]);

/// `f(path, flags) { return open(path, flags); }` after `.plt`: the flag is the caller's own.
const OPEN_FORWARDING: [u8; 0x30] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0x31, 0xc0, // 1024 xor eax, eax
    0xe8, 0xe5, 0xff, 0xff, 0xff, // 1026 call stub
    0x48, 0x83, 0xc4, 0x08, // 102b add rsp, 8
    0xc3, // 102f ret
]);

/// `f(name) { return prctl(PR_SET_NAME, name); }` after `.plt`.
const PRCTL_NAMING: [u8; 0x38] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0x48, 0x89, 0xfe, // 1024 mov rsi, rdi
    0xbf, 0x0f, 0x00, 0x00, 0x00, // 1027 mov edi, 15
    0x31, 0xc0, // 102c xor eax, eax
    0xe8, 0xdd, 0xff, 0xff, 0xff, // 102e call stub
    0x48, 0x83, 0xc4, 0x08, // 1033 add rsp, 8
    0xc3, // 1037 ret
]);

fn on(libc: Libc, import: &str, code: &'static [u8]) -> String {
    let literal = Literal::plt_wrapped(import, code);
    rendered(
        literal.running_on(&[PlatformEvidence::Interpreter(libc)]),
        PLT_CALLER,
    )
}

/// glibc's `open` reads its mode only under `__OPEN_NEEDS_MODE` (glibc 2.39 `<fcntl.h>`,
/// `open64.c`): a constant flag without `O_CREAT` passes two arguments, one with it three.
#[test]
fn a_constant_flag_counts_the_mode_open_reads() {
    let reading = on(Libc::Glibc, "open", &OPEN_READING);
    let arguments = common::call_arguments(&reading, "open");
    assert_eq!(arguments.map(|a| a.len()), Some(2), "{reading}");
    let creating = on(Libc::Glibc, "open", &OPEN_CREATING);
    let arguments = common::call_arguments(&creating, "open").unwrap_or_default();
    assert_eq!(arguments.len(), 3, "{creating}");
    assert!(
        arguments[2].contains("0x1a4") || arguments[2].contains("420"),
        "{creating}"
    );
}

/// A flag the call does not fix counts nothing, and a library whose body nobody cited states only
/// `...`: both calls stay residual.
#[test]
fn an_uncounted_open_tail_stays_residual() {
    let forwarding = on(Libc::Glibc, "open", &OPEN_FORWARDING);
    assert_eq!(
        common::call_arguments(&forwarding, "open"),
        None,
        "{forwarding}"
    );
    let bionic = on(Libc::Bionic, "open", &OPEN_CREATING);
    assert_eq!(common::call_arguments(&bionic, "open"), None, "{bionic}");
}

/// glibc declares `int prctl(int, ...)` and its body reads by option, which no row counts: the
/// call is residual (RULING 2.2), where radare2's five fixed parameters rendered it.
#[test]
fn prctl_states_only_its_ellipsis() {
    let naming = on(Libc::Glibc, "prctl", &PRCTL_NAMING);
    assert_eq!(common::call_arguments(&naming, "prctl"), None, "{naming}");
}

/// pigz `free_pool` stripped, cut down: `free(pool->head->link); return pool->made;` after `.plt`.
/// The field at 8 is solved a pointer to a word of no stated sign, which left the structure the
/// parameter's accesses lay out undefined and the parameter `uint64_t` (D74).
const POOL: [u8; 0x3f] = plt_then(&[
    0x55, // 1020 push rbp
    0x53, // 1021 push rbx
    0x48, 0x83, 0xec, 0x08, // 1022 sub rsp, 8
    0x48, 0x89, 0xfd, // 1026 mov rbp, rdi
    0x48, 0x8b, 0x5f, 0x08, // 1029 mov rbx, [rdi + 8]
    0x48, 0x8b, 0x3b, // 102d mov rdi, [rbx]
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1030 call stub (free)
    0x8b, 0x45, 0x1c, // 1035 mov eax, [rbp + 0x1c]
    0x48, 0x83, 0xc4, 0x08, // 1038 add rsp, 8
    0x5b, // 103c pop rbx
    0x5d, // 103d pop rbp
    0xc3, // 103e ret
]);

#[test]
fn a_stripped_parameter_whose_accesses_lay_out_a_structure_points_to_it() {
    let text = rendered(Literal::plt_wrapped("free", &POOL), PLT_CALLER);
    let at = format!("fcn_{PLT_CALLER:x}(");
    let header = text
        .lines()
        .find(|line| line.contains(&at))
        .unwrap_or_default();
    assert!(header.contains("(struct "), "{text}");
    assert!(text.contains("->f_1c"), "{text}");
}
