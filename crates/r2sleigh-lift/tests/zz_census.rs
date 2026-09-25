//! SCRATCH (not for commit): lift every encoding in CENSUS_IN and write the ops to CENSUS_OUT.
#![cfg(feature = "x86")]

use std::io::Write;

use r2sleigh_lift::{Disassembler, TrustedSleighProfile};

#[test]
#[ignore]
fn census() {
    let input = std::env::var("CENSUS_IN").expect("CENSUS_IN");
    let output = std::env::var("CENSUS_OUT").expect("CENSUS_OUT");
    let disassembler =
        Disassembler::from_trusted_profile(TrustedSleighProfile::X86_64).expect("x86-64");
    let text = std::fs::read_to_string(input).expect("input");
    let mut out = std::io::BufWriter::new(std::fs::File::create(output).expect("output"));
    for line in text.lines() {
        let bytes: Vec<u8> = (0..line.len() / 2)
            .map(|at| u8::from_str_radix(&line[2 * at..2 * at + 2], 16).expect("hex"))
            .collect();
        let mut padded = [0u8; 32];
        padded[..bytes.len()].copy_from_slice(&bytes);
        match disassembler.lift(&padded, 0x1000) {
            Ok(block) => writeln!(out, "{line}\t{:?}", block.ops).expect("write"),
            Err(error) => writeln!(out, "{line}\tERR {error}").expect("write"),
        }
    }
}
