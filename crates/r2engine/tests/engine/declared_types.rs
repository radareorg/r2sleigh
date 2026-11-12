//! What a declaration states about a slot reaches the rendering: declared pointers, a counted tail,
//! a stripped parameter's structure (ROADMAP D261 to D264, S28).

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
    // The path handed on is the declared `const char *`, plain `char` and never `int8_t` (D262).
    assert!(reading.contains("(const char* arg0)"), "{reading}");
    let creating = on(Libc::Glibc, "open", &OPEN_CREATING);
    let arguments = common::call_arguments(&creating, "open").unwrap_or_default();
    assert_eq!(arguments.len(), 3, "{creating}");
    assert!(
        arguments[2].contains("0x1a4") || arguments[2].contains("420"),
        "{creating}"
    );
}

/// A flag the call does not fix counts nothing, and bionic and musl, whose bodies nobody cited,
/// state only `...`: each call stays residual (RULING 2.3).
#[test]
fn an_uncounted_open_tail_stays_residual() {
    let forwarding = on(Libc::Glibc, "open", &OPEN_FORWARDING);
    assert_eq!(
        common::call_arguments(&forwarding, "open"),
        None,
        "{forwarding}"
    );
    for libc in [Libc::Bionic, Libc::Musl] {
        let other = on(libc, "open", &OPEN_CREATING);
        assert_eq!(common::call_arguments(&other, "open"), None, "{other}");
        assert!(
            other.contains("variadic, its argument count unproven"),
            "{other}"
        );
    }
}

/// glibc declares `int prctl(int, ...)` and its body reads by option, which no row counts: the
/// call is residual (RULING 2.2), where radare2's five fixed parameters rendered it.
#[test]
fn prctl_states_only_its_ellipsis() {
    let naming = on(Libc::Glibc, "prctl", &PRCTL_NAMING);
    assert_eq!(common::call_arguments(&naming, "prctl"), None, "{naming}");
}

/// pigz `free_pool` stripped, cut down: `free(pool->head->link); return pool->made;`. The field at
/// 8 was a pointer to a word of no stated sign, so the structure stayed undefined (D74).
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

/// `f(stream) { return fclose(stream); }` after `.plt`, stripped.
const CLOSING: [u8; 0x2e] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1024 call stub
    0x48, 0x83, 0xc4, 0x08, // 1029 add rsp, 8
    0xc3, // 102d ret
]);

/// A stripped caller's parameter handed unchanged to `fclose(FILE *)` is that pointer, at the
/// library row's basis (D71 A2); radare2 and the parent printed `uint64_t arg0`.
#[test]
fn a_parameter_handed_to_a_declared_pointer_is_that_pointer() {
    let text = on(Libc::Glibc, "fclose", &CLOSING);
    let at = format!("fcn_{PLT_CALLER:x}(");
    let header = text
        .lines()
        .find(|line| line.contains(&at))
        .unwrap_or_default();
    let parameters = common::parameters(header);
    assert_eq!(parameters.len(), 1, "{text}");
    assert!(parameters[0].0.contains("FILE"), "{text}");
}

/// `f(p) { return memset(p, 0, (size_t)p); }` after `.plt`: one value at a declared pointer and a
/// declared `size_t`.
const MEMSET_SELF: [u8; 0x33] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0x48, 0x89, 0xfa, // 1024 mov rdx, rdi
    0x31, 0xf6, // 1027 xor esi, esi
    0xe8, 0xe2, 0xff, 0xff, 0xff, // 1029 call stub
    0x48, 0x83, 0xc4, 0x08, // 102e add rsp, 8
    0xc3, // 1032 ret
]);

/// `f(p) { return fputs((const char *)p, (FILE *)p); }` after `.plt`: two declared pointees.
const FPUTS_SELF: [u8; 0x31] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0x48, 0x89, 0xfe, // 1024 mov rsi, rdi
    0xe8, 0xe4, 0xff, 0xff, 0xff, // 1027 call stub
    0x48, 0x83, 0xc4, 0x08, // 102c add rsp, 8
    0xc3, // 1030 ret
]);

/// `f(x) { return g(x); }` and `g(x) { return x + 1; }`: `g`'s slot is a recovered width.
const RECOVERED_CALLEE: [u8; 0x18] = [
    0x48, 0x83, 0xec, 0x08, // 1000 sub rsp, 8
    0xe8, 0x07, 0x00, 0x00, 0x00, // 1004 call g
    0x48, 0x83, 0xc4, 0x08, // 1009 add rsp, 8
    0xc3, // 100d ret
    0xcc, 0xcc, // 100e
    0x48, 0x89, 0xf8, // 1010 g: mov rax, rdi
    0x48, 0x83, 0xc0, 0x01, // 1013 add rax, 1
    0xc3, // 1017 ret
];

fn header_parameters(text: &str, name: &str) -> Vec<(String, String)> {
    let at = format!("{name}(");
    let header = text
        .lines()
        .find(|line| line.contains(&at))
        .unwrap_or_default();
    common::parameters(header)
}

/// Default deny (D262): a value a declaration also types as no pointer keeps its width; two
/// declared pointees meet at `void *`; a slot only a recovered width bounds stays that width.
#[test]
fn a_declared_pointer_types_a_parameter_only_where_no_declaration_disputes_it() {
    let memset = on(Libc::Glibc, "memset", &MEMSET_SELF);
    let parameters = header_parameters(&memset, &format!("fcn_{PLT_CALLER:x}"));
    assert_eq!(
        parameters.first().map(|p| p.0.as_str()),
        Some("uint64_t"),
        "{memset}"
    );
    let fputs = on(Libc::Glibc, "fputs", &FPUTS_SELF);
    let parameters = header_parameters(&fputs, &format!("fcn_{PLT_CALLER:x}"));
    assert_eq!(
        parameters.first().map(|p| p.0.as_str()),
        Some("void*"),
        "{fputs}"
    );
    let functions = [("f", 0x1000, 14), ("g", 0x1010, 8)];
    let recovered = rendered(Literal::of_code(&RECOVERED_CALLEE, &functions), 0x1000);
    let parameters = header_parameters(&recovered, "f");
    assert_eq!(
        parameters.first().map(|p| p.0.as_str()),
        Some("uint64_t"),
        "{recovered}"
    );
}

/// `f(path) { struct stat buf; return stat(path, &buf); }` after `.plt`.
const STATTING: [u8; 0x37] = plt_then(&[
    0x48, 0x81, 0xec, 0x98, 0x00, 0x00, 0x00, // 1020 sub rsp, 0x98
    0x48, 0x89, 0xe6, // 1027 mov rsi, rsp
    0xe8, 0xe1, 0xff, 0xff, 0xff, // 102a call stub
    0x48, 0x81, 0xc4, 0x98, 0x00, 0x00, 0x00, // 102f add rsp, 0x98
    0xc3, // 1036 ret
]);

/// POSIX `int stat(const char *, struct stat *)` (D263): the record is declared incomplete, the
/// path passes as the caller's own `const char *`, and the buffer as the frame's address.
#[test]
fn a_cited_record_pointer_is_declared_and_passed() {
    let text = on(Libc::Glibc, "stat", &STATTING);
    assert!(text.contains("struct stat;"), "{text}");
    assert!(
        text.contains("int32_t stat(const char*, struct stat*);"),
        "{text}"
    );
    let arguments = common::call_arguments(&text, "stat").unwrap_or_default();
    assert_eq!(arguments.len(), 2, "{text}");
    assert_eq!(arguments[0], "arg0", "{text}");
    assert!(arguments[1].contains("frame"), "{text}");
}

/// find `check_option_combinations`, cut down: `while (p) p = p->next; strlen((char *)p);`. The
/// argument merges the entry value and a load, so no declared slot types the parameter (D262).
const NULL_HANDED_ON: [u8; 0x3c] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0x48, 0x85, 0xff, // 1024 test rdi, rdi
    0x74, 0x09, // 1027 je 0x1032
    0x48, 0x8b, 0x7f, 0x08, // 1029 mov rdi, [rdi + 8]
    0x48, 0x85, 0xff, // 102d test rdi, rdi
    0x75, 0xf7, // 1030 jne 0x1029
    0xe8, 0xd9, 0xff, 0xff, 0xff, // 1032 call stub
    0x48, 0x83, 0xc4, 0x08, // 1037 add rsp, 8
    0xc3, // 103b ret
]);

#[test]
fn a_declared_pointer_types_only_the_entry_value_itself() {
    let text = on(Libc::Glibc, "strlen", &NULL_HANDED_ON);
    let parameters = header_parameters(&text, &format!("fcn_{PLT_CALLER:x}"));
    assert_eq!(parameters.len(), 1, "{text}");
    assert!(!parameters[0].0.contains("char"), "{text}");
}
