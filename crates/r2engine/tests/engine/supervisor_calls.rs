//! A supervisor call is named against the kernel's syscall table only where it is the platform's
//! system-call instruction; a hypercall or a secure-monitor call states no number.

use crate::common::{BASE, Literal};
use r2engine::program::{OpenProgram, Syscall};

/// AArch64 `mov x8, #93` (Linux `exit`), then `enters`, then `ret`.
fn enters_with_exit_number(enters: u32) -> &'static [u8] {
    let words = [0xd280_0ba8u32, enters, 0xd65f_03c0];
    Box::leak(words.iter().flat_map(|word| word.to_le_bytes()).collect())
}

fn listed(enters: u32) -> Vec<Syscall> {
    let code = enters_with_exit_number(enters);
    let literal = Literal::of_code(code, &[("quit", BASE, 12)]).in_aarch64();
    OpenProgram::of(literal)
        .syscalls()
        .expect("the sites are listed")
}

/// `hvc #0` enters a hypervisor: the site is listed, its number register is not read.
#[test]
fn a_hypercall_is_listed_with_no_number_and_no_name() {
    let calls = listed(0xd400_0002);
    let sites = calls
        .iter()
        .map(|call| (call.address, call.number, call.name.as_deref()));
    assert_eq!(sites.collect::<Vec<_>>(), [(BASE + 4, None, None)]);
}

/// `smc #0` enters a secure monitor, which no syscall table states either.
#[test]
fn a_secure_monitor_call_is_listed_with_no_number_and_no_name() {
    let calls = listed(0xd400_0003);
    let sites = calls
        .iter()
        .map(|call| (call.address, call.number, call.name.as_deref()));
    assert_eq!(sites.collect::<Vec<_>>(), [(BASE + 4, None, None)]);
}

/// `svc #0` is the system-call instruction: x8 holds 93, Linux's `exit`.
#[test]
fn a_system_call_is_still_named_by_its_number() {
    let calls = listed(0xd400_0001);
    let sites = calls
        .iter()
        .map(|call| (call.address, call.number, call.name.as_deref()));
    assert_eq!(
        sites.collect::<Vec<_>>(),
        [(BASE + 4, Some(93), Some("exit"))]
    );
}
