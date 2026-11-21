#!/usr/bin/env python3
"""Unit tests for the differential's judged disagreements.

Pure Python; no binary runs.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import time
import tomllib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import diff_r2  # noqa: E402

TABLE = """
[[judged]]
command = "pd"
binaries = "arm*"
r2 = 'push \\{'
r2s = 'stmdb sp!'
verdict = "r2-right"
reason = "alias"

[[judged]]
command = "iS"
binaries = "*"
values = ["0x70000001"]
verdict = "unfilled"
reason = "processor-specific type"

[[judged]]
command = "ie"
binaries = "*"
columns = ["vhaddr"]
verdict = "r2s-right"
reason = "a column radare2 leaves empty"

[[judged]]
command = "px"
binaries = "gone"
verdict = "r2s-right"
reason = "nothing matches this"
"""


def judgments():
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "judged.toml"
        path.write_text(TABLE)
        return diff_r2.load_judgments(path)


class Judged(unittest.TestCase):
    def test_a_listing_pair_is_judged_by_both_lines_and_the_binary(self):
        table = judgments()
        pair = ("lines", ("0x10 push {fp, lr}", "0x10 stmdb sp!, {fp, lr}"))
        self.assertIsNotNone(diff_r2.judgment_for(table, "arm1.bin", "pd 8", pair))
        self.assertIsNone(diff_r2.judgment_for(table, "x86.bin", "pd 8", pair))
        other = ("lines", ("0x10 push {fp, lr}", "0x10 push {fp, lr}, extra"))
        self.assertIsNone(diff_r2.judgment_for(table, "arm1.bin", "pd 8", other))

    def test_a_value_is_judged_only_by_its_listed_values(self):
        table = judgments()
        self.assertIsNotNone(diff_r2.judgment_for(table, "any", "iS", ("value", (0x70000001, "type", "1 0x70000001"))))
        self.assertIsNone(diff_r2.judgment_for(table, "any", "iS", ("value", (0x70000002, "type", "1 0x70000002"))))

    def test_a_column_judgment_covers_only_values_in_its_columns(self):
        table = judgments()
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "ie", ("value", (0x468, "vhaddr", "0x10 0x468"))))
        self.assertIsNone(diff_r2.judgment_for(table, "a", "ie", ("value", (0x468, "paddr", "0x468 0x10"))))

    def test_a_value_takes_the_column_its_header_names(self):
        lines = ["paddr      vaddr      phaddr     vhaddr     type", "0x10 0x1000 0x18 0x100018 program"]
        self.assertEqual(diff_r2.columns(lines)[0x100018][0][0], "vhaddr")
        self.assertEqual(diff_r2.columns(lines)[0x10][0][0], "paddr")

    def test_each_occurrence_of_a_value_is_its_own_disagreement(self):
        ours = "paddr vaddr phaddr vhaddr type\n0x10 0x1000 0x18 0x10 program\n"
        found = diff_r2.differences("ie", "values", ours, "0x1000 0x18\n")
        self.assertEqual([item[1][1] for item in found], ["paddr", "vhaddr"])

    def test_a_value_in_another_column_than_radare2s_is_a_disagreement(self):
        header = "paddr      vaddr      phaddr     vhaddr     type\n"
        theirs = header + "0x10 0x1000 0x18 0x100018 program\n"
        swapped = header + "0x10 0x1000 0x100018 0x18 program\n"
        found = diff_r2.differences("ie", "values", swapped, theirs)
        self.assertEqual([(item[1][0], item[1][1]) for item in found], [(0x18, "vhaddr"), (0x100018, "phaddr")])
        self.assertEqual(diff_r2.differences("ie", "values", theirs, theirs), [])

    def test_a_column_radare2_does_not_name_is_compared_with_every_value(self):
        ours = "paddr vaddr extra\n0x10 0x1000 0x18\n"
        self.assertEqual(diff_r2.differences("ie", "values", ours, "paddr vaddr\n0x18 0x1000\n0x10 0x0\n"), [])

    def test_values_only_radare2_reports_are_counted_by_column(self):
        header = "nth paddr vaddr bind type size lib name\n"
        theirs = header + "1 0x3b0 0x4011b0 NONE FUNC 0 imp.ExitProcess\n2 0x3b4 0x4011b4 NONE FUNC 0 imp.printf\n"
        ours = header + "1 0x3b0 0x4011b0 NONE FUNC 0 imp.ExitProcess\n"
        missed = diff_r2.radare2_only(diff_r2.normalise(ours), diff_r2.normalise(theirs))
        self.assertEqual(missed, [("paddr", 0x3B4), ("vaddr", 0x4011B4)])
        self.assertEqual(diff_r2.radare2_only(diff_r2.normalise(theirs), diff_r2.normalise(theirs)), [])

    def test_the_ratchet_names_each_count_that_moved(self):
        baseline = {"pe": {"is": 243, "refused": 10}, "elf": {"is": 4}}
        measured = {"pe": {"is": 240, "refused": 10}, "elf": {"is": 5}, "mach0": {"is": 1}}
        self.assertEqual(
            diff_r2.ratchet(baseline, measured),
            [("elf", "is", 4, 5), ("mach0", "is", None, 1), ("pe", "is", 243, 240)],
        )

    def test_a_fill_judgment_covers_only_radare2s_fill_past_what_r2s_shows(self):
        fill = '[[judged]]\ncommand = "px"\nbinaries = "*"\nfill = "ff"\nverdict = "r2s-right"\nreason = "fill"\n'
        table = diff_r2.load_judgments(None, tomllib.loads(fill))
        line = "0x08000050  0300 0058 c003 5fd6 ffff ffff ffff ffff  ...X.._........."
        prefix = "0x08000050  0300 0058 c003 5fd6                      ...X.._."
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (line, prefix))))
        filler = "0x08000060  ffff ffff ffff ffff ffff ffff ffff ffff  ................"
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (filler, None))))
        other = "0x08000050  0300 0058 c003 5fd7                      ...X.._."
        self.assertIsNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (line, other))))
        real = "0x08000050  0300 0058 c003 5fd6 0000 ffff ffff ffff  ...X.._........."
        self.assertIsNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (real, prefix))))
        self.assertIsNone(diff_r2.judgment_for(table, "a", "px 64", ("lines", (line, line.replace("0x0800", "0x0900")))))

    def test_a_value_judgment_can_require_radare2s_row_holding_the_value(self):
        table = diff_r2.load_judgments(None, tomllib.loads(
            '[[judged]]\ncommand = "is"\nbinaries = "*"\ncolumns = ["vaddr"]\nr2 = \'^\\d+ 0x0+8 0x\'\n'
            'r2s = \'^\\d+ -+ 0x0+8 \'\nverdict = "r2s-right"\nreason = "tls offset"\n'
        ))
        header = "nth paddr vaddr bind type size lib name\n"
        theirs = header + "1 0x00000008 0x00400008 LOOS TLS 8 tid\n"
        ours = header + "1 ---------- 0x00000008 10 NOTYPE 8 tid\n"
        (found,) = diff_r2.differences("is", "values", ours, theirs)
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "is", found))
        moved = theirs.replace("0x00000008 0x00400008", "0x00000010 0x00400008")
        (found,) = diff_r2.differences("is", "values", ours, moved)
        self.assertIsNone(diff_r2.judgment_for(table, "a", "is", found))

    def test_a_rounded_judgment_covers_only_radare2s_value_rounded_up_in_the_same_row(self):
        table = diff_r2.load_judgments(None, tomllib.loads(
            '[[judged]]\ncommand = "iS"\nbinaries = "*"\ncorpus = "pe"\ncolumns = ["vsize"]\nkey = "vaddr"\n'
            'verdict = "r2s-right"\nreason = "aligned"\n'
        ))
        header = "nth paddr size vaddr vsize perm flags type name\n"
        theirs = header + "0 0x400 0x1000 0x401000 0x1000 -r-x 0x60000020 ---- .text\n"
        (found,) = diff_r2.differences("iS", "values", header + "1 0x400 0x1000 0x401000 0xe2d -r-x 0x60000020 .text\n", theirs)
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "iS", found, "pe"))
        self.assertIsNone(diff_r2.judgment_for(table, "a", "iS", found, "elf"))
        elsewhere = header + "1 0x400 0x1000 0x402000 0xe2d -r-x 0x60000020 .text\n"
        (found,) = [item for item in diff_r2.differences("iS", "values", elsewhere, theirs) if item[1][1] == "vsize"]
        self.assertIsNone(diff_r2.judgment_for(table, "a", "iS", found, "pe"))
        self.assertTrue(diff_r2.rounded(0x174, 0x200))
        self.assertFalse(diff_r2.rounded(0x174, 0x300))
        self.assertFalse(diff_r2.rounded(0x1000, 0x1000))

    def test_a_listing_line_shows_its_bytes(self):
        self.assertEqual(diff_r2.dumped("pd", "0x412c9      ff             invalid"), ("0x412c9", "ff"))
        self.assertEqual(diff_r2.dumped("px", "0x10  6162 6364                                abcd"), ("0x10", "61626364"))

    def test_radare2_loads_as_an_x86_64_host_then_takes_the_files_architecture(self):
        argv = diff_r2.radare2_argv("/usr/bin/radare2", "s entry0;pd 8", "bin")
        self.assertEqual(argv[argv.index("asm.arch=x86") - 1], "-e")
        script = argv[argv.index("-c") + 1]
        self.assertTrue(script.startswith("e asm.arch=`i~^arch[1]`;e asm.bits=`i~^bits[1]`;"))
        self.assertTrue(script.endswith("s entry0;pd 8"))
        self.assertEqual(argv[-1], "bin")

    def test_both_tools_name_by_flag_spellings(self):
        theirs = diff_r2.radare2_argv("/usr/bin/radare2", "afl", "bin")
        for key in ("asm.demangle=false", "bin.demangle=false"):
            self.assertEqual(theirs[theirs.index(key) - 1], "-e")
        ours = diff_r2.r2s_argv("r2s", "afl", "bin")
        self.assertEqual(ours[ours.index("asm.demangle=false") - 1], "-e")
        self.assertEqual(ours[-3:], ["-c", "afl", "bin"])

    def test_two_different_invalid_bytes_stay_different(self):
        def out(byte):
            script = "import sys; sys.stdout.buffer.write(bytes([{}]))".format(byte)
            return diff_r2.run([sys.executable, "-c", script], 10)[0]

        self.assertNotEqual(out(0xFF), out(0xFE))

    def test_a_judgment_nothing_matched_is_left_unmatched(self):
        table = judgments()
        diff_r2.judgment_for(table, "arm1.bin", "pd 8", ("lines", ("push {r4}", "stmdb sp!, {r4}")))
        self.assertEqual([j["reason"] for j in table if j["matched"] == 0][-1], "nothing matches this")

    def test_the_table_names_the_radare2_it_was_judged_against(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "judged.toml"
            path.write_text('radare2 = "6.2.4"\n' + TABLE)
            pinned, table = diff_r2.load_table(path)
        self.assertEqual(pinned, "6.2.4")
        self.assertEqual(len(table), 4)
        self.assertEqual(diff_r2.release("radare2 6.2.4 +38388 abi:152 @ linux-x86-64\n"), "6.2.4")
        self.assertIsNone(diff_r2.release(""))

    def test_an_unknown_verdict_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "judged.toml"
            path.write_text(TABLE.replace('"unfilled"', '"maybe"'))
            with self.assertRaises(ValueError):
                diff_r2.load_judgments(path)

    def test_every_listing_line_that_differs_is_one_disagreement(self):
        found = diff_r2.differences("pd 8", "exact", "0x1 nop\n0x2 ret\n", "0x1 nop\n0x2 leave\n0x3 ret\n")
        self.assertEqual(
            found, [("lines", ("0x2 leave", "0x2 ret")), ("lines", ("0x3 ret", None))]
        )

    def test_a_posture_key_both_print_with_two_values_is_a_disagreement_and_one_radare2_alone_is_unfilled(self):
        mine = "file     x\nstatic   false\nrelro    full\n"
        other = "file     y\nnx       true\nrelro    full\nstatic   true\n"
        found = diff_r2.differences("i", "pairs", mine, other)
        self.assertEqual(found, [("lines", ("static true", "static false"))])
        _, _, missed = diff_r2.compare("b", "i", "pairs", mine, other, [])
        self.assertEqual(missed, [("nx", None)])


# The side a register is missing from, as a judgment's `lacking` names radare2's.
RADARE2_LACKS = "r2"


def sample(*rows, arch="x86-64"):
    return json.dumps({"arch": arch, "rows": list(rows)})


def ours(addr, opcode, reads=(), writes=(), il=("RAX = COPY 0x1:8",), size=2, raw="31c0", **extra):
    row = {"addr": addr, "opcode": opcode, "mnemonic": opcode.split()[0], "size": size, "bytes": raw}
    if "refused" in extra:
        row["refused"] = extra["refused"]
    else:
        row.update(reads=list(reads), writes=list(writes))
    if il:
        row["il"] = list(il)
    return row


def theirs(addr, opcode, inputs=(), written=(), size=2, raw="31c0", **memory):
    row = {"addr": addr, "opcode": opcode, "mnemonic": opcode.split()[0], "size": size, "bytes": raw}
    row.update(I=list(inputs), W=list(written), **memory)
    return row


class Registers(unittest.TestCase):
    def differences(self, mine, other, arch="x86-64"):
        return diff_r2.register_differences(sample(*mine, arch=arch), json.dumps(other))

    def test_each_register_one_side_lacks_is_one_disagreement(self):
        (wide, rax, eax) = self.differences(
            [ours(0x10, "xor eax, eax", reads=["eax"], writes=["cf", "rax"])],
            [theirs(0x10, "xor eax, eax", inputs=["eax", "rax"], written=["eax", "cf"])],
        )
        # radare2's `I` and `W` against r2s's reads and writes; the side named is the one lacking it.
        self.assertEqual(wide[1][:4], (0x10, "reads", "rax", "r2s"))
        self.assertEqual(rax[1][:3], (0x10, "writes", "rax"))
        self.assertEqual(rax[1][3], RADARE2_LACKS)
        self.assertEqual(eax[1][:4], (0x10, "writes", "eax", "r2s"))
        self.assertEqual(wide[1][6]["ours"], "eax")
        self.assertEqual(wide[1][6]["theirs"], "eax rax")

    def test_an_instruction_read_differently_compares_no_registers(self):
        found = self.differences(
            [ours(0x10, "push rbx", reads=["rbx"], size=1, raw="53"), ours(0x11, "pop rbx", writes=["rbx"])],
            [theirs(0x10, "push rbx", size=2, raw="5300"), theirs(0x11, "invalid")],
        )
        self.assertEqual([(item[0], item[1][1]) for item in found], [("instruction", "size"), ("instruction", "decode")])

    def test_two_invalid_bytes_agree_and_an_address_radare2_skipped_is_missing(self):
        found = self.differences(
            [ours(0x10, "invalid", refused="the bytes are not an instruction", il=()), ours(0x12, "nop")],
            [theirs(0x10, "invalid")],
        )
        self.assertEqual([(item[1][0], item[1][1]) for item in found], [(0x12, "missing")])

    def test_a_refusal_and_esil_that_never_reached_memory_compare_no_registers(self):
        found = self.differences(
            [
                ours(0x10, "cpuid", refused="an operation is unimplemented", il=("UNIMPLEMENTED",)),
                ours(0x12, "add byte [rax], al", reads=["rax"], writes=["cf"], il=("uniq:0x1[1] = LOAD [ram]RAX",)),
                ours(0x14, "mov eax, dword [rbx]", reads=["rbx"], writes=["rax"], il=("EAX = LOAD [ram]RBX",)),
            ],
            [
                theirs(0x10, "cpuid"),
                theirs(0x12, "add byte [rax], al", inputs=["rax", "al"]),
                theirs(0x14, "mov eax, dword [rbx]", inputs=["rbx"], written=["rax"], **{"@R": [4096]}),
            ],
        )
        self.assertEqual([item[1][1] for item in found], ["refused", "halted"])
        self.assertEqual(found[0][1][6]["refused"], "an operation is unimplemented")

    def test_radare2s_pairs_are_read_by_their_fence(self):
        fence = diff_r2.FENCE
        text = "\n".join([
            fence, '[{"addr": 16, "opcode": "nop", "size": 1, "bytes": "90"}]', '{"I": [], "W": ["rip"]}',
            fence, "ERROR: nothing",
            fence, '[{"addr": 18, "opcode": "ret", "size": 1, "bytes": "c3"}]', '{"I": ["rsp"], "W": ["rsp"], "@R": [8]}',
        ])
        rows = diff_r2.radare2_rows(text)
        self.assertEqual([row["addr"] for row in rows], [16, 18])
        self.assertEqual((rows[1]["I"], rows[1]["@R"], rows[0]["@W"]), (["rsp"], [8], []))

    def test_the_sample_is_the_stated_entries_and_spaced_function_symbols(self):
        lines = [
            "paddr      vaddr      phaddr     vhaddr     type",
            "0x00000c90 0x00400c90 0x00000018 0x00400018 program",
            "nth paddr      vaddr      bind   type   size lib name",
        ] + [
            "{}   0x{:08x} 0x{:08x} LOCAL  FUNC   0        f{}".format(n, n, 0x401000 + n * 16, n) for n in range(12)
        ] + ["99  0x00004200 0x00405000 NONE   FUNC   0    KERNEL32.dll imp.WriteProcessMemory"]
        entries = diff_r2.sampled_entries(lines)
        self.assertEqual(entries[0], 0x400C90)
        self.assertEqual(entries[1:], [0x401000, 0x401030, 0x401060, 0x401090])
        self.assertNotIn(0x405000, entries)

    def test_a_register_judgment_reads_its_fields_side_and_sets(self):
        table = diff_r2.load_judgments(None, tomllib.loads(
            '[[judged]]\ncommand = "aoj"\nbinaries = "*"\narch = \'^x86-64$\'\nfields = ["writes"]\n'
            'register = \'e(ax|cx)\'\nlacking = "r2s"\nours = \'\\br{suffix}\\b\'\nverdict = "deliberate"\nreason = "zext"\n'
        ))
        (_, eax) = self.differences(
            [ours(0x10, "add eax, ecx", reads=["eax", "ecx"], writes=["rax"])],
            [theirs(0x10, "add eax, ecx", inputs=["eax", "ecx"], written=["eax"])],
        )
        self.assertIsNotNone(diff_r2.judgment_for(table, "a", "aoj", eax))
        (_, ecx) = self.differences(
            [ours(0x10, "add eax, ecx", reads=["eax", "ecx"], writes=["rax"])],
            [theirs(0x10, "add eax, ecx", inputs=["eax", "ecx"], written=["ecx"])],
        )
        # ecx is lacked, but r2s writes no rcx: the zero-extension does not explain it.
        self.assertIsNone(diff_r2.judgment_for(table, "a", "aoj", ecx))
        (_, eax) = self.differences(
            [ours(0x10, "add eax, ecx", reads=["eax", "ecx"], writes=["rax"])],
            [theirs(0x10, "add eax, ecx", inputs=["eax", "ecx"], written=["eax"])],
            arch="x86",
        )
        self.assertIsNone(diff_r2.judgment_for(table, "a", "aoj", eax))


def session(**answers):
    """A fenced session: each keyword `verb_address` (or `verb`) to its lines."""
    text = []
    for name, lines in answers.items():
        verb, _, address = name.partition("_")
        text += [" ".join([diff_r2.SESSION_FENCE, verb, address or "0x0"])] + lines
    return diff_r2.fenced("\n".join(text))


def afl(*rows):
    return ["0x{:08x}    1     16 {}".format(address, name) for address, name in rows]


class Analysis(unittest.TestCase):
    def facts(self, verb, ours, theirs):
        context = diff_r2.context_of(ours, theirs)
        return diff_r2.fact_differences(verb, ours, theirs, context)

    def test_an_entry_r2s_lists_alone_is_a_disagreement_and_one_radare2_lists_alone_is_also_unfilled(self):
        found, missed = self.facts(
            "afl",
            session(
                afl=afl((0x10, "main"), (0x20, "fcn.00000020")),
                aflj=['[{"addr": 32, "confidence": "called"}]'],
                fde=["20 2f"],
                iS=["nth paddr size vaddr vsize perm flags type name", "1 0x10 0x20 0x00000010 0x20 -r-x 0x6 PROGBITS .text"],
                refs_0x30=["main 0x12 [CALL:--x] call sym.helper", "main 0x18 [CODE:--x] jmp sym.helper"],
            ),
            session(afl=afl((0x10, "main"), (0x30, "sym.helper"), (0x14, "fcn.00000014"))),
        )
        self.assertEqual([(item[1][2], item[1][3]) for item in found], [(0x14, "r2s"), (0x20, "r2"), (0x30, "r2s")])
        # An entry radare2 lists inside an r2s function's extent names that function.
        self.assertEqual(found[0][1][4], "<missing> refs=none inside=0x10 in=.text:-r-x")
        # A row shows its section, basis and the FDE starting there; the lacking side what references it.
        self.assertEqual(found[1][1][4:6], ("0x00000020 1 16 fcn.00000020 in=.text basis=called fde=0x20-0x2f", "<missing> refs=none"))
        self.assertEqual(found[2][1][4:6], ("<missing> refs=CALL:call,CODE:jmp in=none", "0x00000030 1 16 sym.helper"))
        self.assertEqual(missed, [("afl", 0x14), ("afl", 0x30)])

    def test_a_block_either_side_lacks_is_a_disagreement_shown_beside_the_other_sides_block_there(self):
        found, missed = self.facts(
            "afb",
            session(afb_0x10=["0x00000010 0x00000018 8 j 0x18", "0x00000018 0x00000020 8"]),
            session(afb_0x10=["0x00000010 0x00000018 00:0000 8 j 0x18", "0x00000018 0x00000024 00:0000 12"]),
        )
        self.assertEqual([(item[1][2], item[1][3]) for item in found], [((0x18, 8), "r2"), ((0x18, 12), "r2s")])
        # A size disagreement shows both rows at the address.
        self.assertEqual(found[0][1][5], "0x00000018 0x00000024 00:0000 12")
        self.assertEqual(missed, [])

    def test_noreturn_disagrees_when_r2s_proves_it_alone_or_radare2_states_it_and_r2s_does_not(self):
        def one(mine, theirs):
            found, _ = self.facts("afi", session(afi_0x10=mine), session(afi_0x10=theirs))
            return [(item[1][3], item[1][4]) for item in found]

        self.assertEqual(one(["noreturn: true"], ["noreturn: false"]), [("r2", "noreturn: true")])
        self.assertEqual(one(["noreturn: unproven (uncited row)"], ["noreturn: true"]), [("r2s", "noreturn: unproven (uncited row)")])
        self.assertEqual(one(["args: 0"], ["noreturn: true"]), [("r2s", "<absent>")])
        self.assertEqual(one(["noreturn: unproven (no return reached)"], ["noreturn: false"]), [])
        self.assertEqual(one(["noreturn: true (assuming go-runtime)"], ["noreturn: true"]), [])

    def test_frame_offsets_are_from_the_entry_stack_pointer_and_registers_whole(self):
        variables = {
            "reg": [{"name": "arg1", "kind": "reg", "type": "int64_t", "ref": "rdi"}],
            "sp": [{"name": "var_10h", "kind": "var", "type": "int64_t", "ref": {"base": "rsp", "offset": 16}}],
            "bp": [
                {"name": "var_8h", "kind": "var", "type": "int64_t", "ref": {"base": "rbp", "offset": -8}},
                {"name": "arg_10h", "kind": "arg", "type": "int64_t", "ref": {"base": "rbp", "offset": 16}},
            ],
        }
        theirs = session(
            afi_0x10=["stackframe: 48"],
            afvj_0x10=[json.dumps(variables)],
            # -delta for a var at or below 0, delta - 0x6a for an argument (6.2.4 cmd_anal.inc.c:2005).
            afvf_0x10=["0x00000010  var_8h:    int64_t", "0xffffffffffffff9e  arg_10h:   int64_t"],
        )
        mine = session(afv_0x10=[
            "arg void* arg0 @ edi",
            "arg int64_t arg1 @ entry.sp+0x8",
            "var uint64_t stack_m16 @ entry.sp-0x10",
            "var uint64_t stack_m32 @ entry.sp-0x20",
            "var uint32_t frame_m4 @ fp-0x4",
        ])
        found, _ = self.facts("afv", mine, theirs)
        # edi is rdi; the sp var is at 16 - 48, the bp var at -8 - 8 and the bp argument at 16 - 8;
        # fp-0x4 states no entry offset, so it is counted unplaced and not compared.
        self.assertEqual(found, [])
        sides = [side for _, _, side in diff_r2.analysis_facts("afv", mine, theirs).values()]
        self.assertEqual(sorted(sides), ["equal"] * 4 + ["unplaced"])
        self.assertEqual(
            diff_r2.their_frame(json.dumps(variables), theirs[("afvf", 0x10)], 48),
            {
                ("register", "rdi"): "arg int64_t arg1 @ rdi",
                ("offset", -32): "var int64_t var_10h @ rsp+0x10",
                ("offset", -16): "var int64_t var_8h @ rbp-0x8",
                ("offset", 8): "arg int64_t arg_10h @ rbp+0x10",
            },
        )

    def test_a_bp_var_whose_delta_two_offsets_explain_is_unstated(self):
        variables = {"bp": [{"name": "var_8h", "kind": "var", "type": "int64_t", "ref": {"base": "rbp", "offset": 8}}]}
        # 0x10 is -delta (delta -0x10, bp at +0x18) or delta - 0x6a (delta 0x7a, bp at -0x72): no other var decides.
        frame = diff_r2.their_frame(json.dumps(variables), ["0x00000010  var_8h:    int64_t"], 0)
        self.assertEqual(list(frame), [("unstated", "var_8h")])

    def test_a_reference_r2s_states_alone_is_a_disagreement_and_one_radare2_states_alone_unfilled(self):
        found, missed = self.facts(
            "axt",
            session(
                afl=afl((0x10, "main"), (0x20, "fcn.20")),
                axt_0x40=["main 0x10 [CALL:--x] call sym.imp.puts", "fcn.20 0x24 [CALL:--x] call sym.imp.puts"],
            ),
            session(afl=afl((0x10, "main")), axt_0x40=["main 0x10 [CALL:--x] call sym.imp.puts", "(nofunc) 0x30 [DATA:r--] mov rax, 0x40"]),
        )
        self.assertEqual([(item[1][2], item[1][3]) for item in found], [(0x24, "r2")])
        # radare2's side names the r2s function the reference lies in, which radare2 does not list.
        self.assertEqual(found[0][1][5], "<missing> from=0x20 listed=no")
        self.assertEqual(missed, [("axt", 0x30)])

    def test_the_sample_is_the_entry_points_both_list_and_spaced_common_entries(self):
        ours = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90}
        theirs = ours - {0x30} | {0x100}
        self.assertEqual(diff_r2.analysis_sample({0x90, 0x200}, ours, theirs), [0x90, 0x10, 0x20, 0x40, 0x50])
        lines = ["4   0x00001050 0x00401050 GLOBAL FUNC   16       imp.printf",
                 "5   ---------- ---------- GLOBAL FUNC   0        imp.__libc_start_main",
                 "6   0x00001166 0x00401166 GLOBAL FUNC   12       get_global_var"]
        self.assertEqual(diff_r2.import_slots(lines), {0x401050})

    def test_a_fact_judgment_reads_the_side_lacking_both_rows_and_the_function(self):
        table = diff_r2.load_judgments(None, tomllib.loads(
            '[[judged]]\ncommand = "afl"\nbinaries = "*"\nlacking = "r2s"\nr2s = \'^<missing> refs=none$\'\n'
            'function = \'sym\\.imp\\.\'\nverdict = "unfilled"\nreason = "stubs"\n'
        ))
        found, _ = self.facts(
            "afl", session(afl=afl((0x10, "main"))), session(afl=afl((0x10, "main"), (0x20, "sym.imp.puts"), (0x30, "fcn.30"))),
        )
        covered = [diff_r2.judgment_for(table, "a", "afl", item) is not None for item in found]
        self.assertEqual(covered, [True, False])

    def test_the_table_judges_a_frame_fact_by_its_witness_and_an_unjudged_fact_turns_the_gate_red(self):
        # 0pack 0x5f8290: radare2's var at entry.sp-0x80 lies inside r2s's va_list save area.
        _, table = diff_r2.load_table(pathlib.Path(__file__).resolve().parent / "diff_r2_judged.toml")
        variables = {"reg": [], "bp": [], "sp": [
            {"name": "var_38h", "kind": "var", "type": "int64_t", "ref": {"base": "rsp", "offset": 0x38}}]}
        theirs = session(afl=afl((0x5F8290, "sym.construct")), afi_0x5f8290=["stackframe: 184"],
                         afvj_0x5f8290=[json.dumps(variables)], afvf_0x5f8290=[])

        def ours(*frame):
            return session(arch=["x86-64"], afl=afl((0x5F8290, "sym.construct")), afv_0x5f8290=list(frame))

        def unjudged(mine):
            found, unjudged, _ = diff_r2.compare("0pack", "afv", "frame", mine, theirs, table, "elf")
            return len(found), len(unjudged)

        witnessed = ours("var struct r2sleigh_bits_704 stack_m136 @ entry.sp-0x88")
        self.assertEqual(unjudged(witnessed), (2, 0))
        # The same fact with no r2s object holding it is a class no entry judges.
        bare = ours()
        self.assertEqual(unjudged(bare), (1, 1))
        args = type("Args", (), {"jobs": 1, "timeout": 1, "verbose": False})()
        answered = {"witnessed": witnessed, "bare": bare}
        real = diff_r2.answers
        diff_r2.answers = lambda binary, *_: (None, {"aa": None, "afv": (answered[binary.stem], theirs)})
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                tally = {
                    name: diff_r2.grade("elf", [pathlib.Path(name)], [("afv", "frame")], None, None, table, args)[0]
                    for name in answered
                }
        finally:
            diff_r2.answers = real
        self.assertEqual((tally["witnessed"]["afv"]["unjudged"], tally["bare"]["afv"]["unjudged"]), (0, 1))

    def test_frame_and_reference_rows_are_read_as_the_shared_definition(self):
        # Sleigh's low lane of xmm0 is xmm0; a demangled caller's name holds spaces.
        self.assertEqual(diff_r2.frame_key("xmm0_qa"), ("register", "xmm0"))
        row = "method.QVariant.toString() const 0x2fb764 [CALL:--x] call sym.dtor"
        self.assertEqual(list(diff_r2.reference_rows([row])), [0x2FB764])
        # An r2s offset an unstated radare2 bp var may hold (-0x10 or 0x7a) is not compared.
        variables = {"bp": [{"name": "var_8h", "kind": "var", "type": "int64_t", "ref": {"base": "rbp", "offset": -8}}]}
        theirs = session(afvj_0x10=[json.dumps(variables)], afvf_0x10=["0x00000010  var_8h:    int64_t"])
        mine = session(afv_0x10=["var struct Bar* f @ entry.sp-0x10", "var struct Foo* g @ entry.sp-0x20"])
        sides = {key: side for (_, key), (_, _, side) in diff_r2.analysis_facts("afv", mine, theirs).items()}
        self.assertEqual(sides[("offset", -16)], "unplaced")
        self.assertEqual(sides[("offset", -32)], "r2s")


MISSED = """
[[missed]]
command = "afl"
binaries = ["dwarf_go_tree"]
values = ["0x45c60c"]
verdict = "r2s-right"
reason = "0x45c60c lies inside runtime.duffzero (FUNC 0x45c5d0, 305 bytes)"
r2_line = "libr/core/canal.c:552-554"
"""


class Notes(unittest.TestCase):
    """A note row is analysis, dropped on both sides whatever rail or flow lane draws before it (D581)."""

    def test_a_rail_prefixed_note_row_drops_on_both_sides(self):
        ours = "\u2502   ;-- 7 bytes in no block ; ? 0x00400fb2..\n            0x00400f43      4883ec18       sub rsp, 0x18\n"
        theirs = "\u2502 ;-- case 0:                ; from 0x00400f75\n\u2502           0x00400f43      4883ec18       sub rsp, 0x18\n"
        listing = diff_r2.normalise("            0x00400f43      4883ec18       sub rsp, 0x18\n", strip_trailing=True)
        self.assertEqual(len(listing), 1)
        self.assertEqual(diff_r2.normalise(ours, strip_trailing=True), listing)
        self.assertEqual(diff_r2.normalise(theirs, strip_trailing=True), listing)
        lanes = "\u2502 ; CODE XREF from main @ 0x400e72(x)\n| ;-- case 1:\n"
        self.assertEqual(diff_r2.normalise(lanes, strip_trailing=True), [])

    def test_an_instruction_with_a_marked_note_keeps_its_instruction(self):
        line = "            0x00400f5b      e890fcffff     call sym.imp.__isoc99_sscanf ; ! args: the import has no declaration\n"
        bare = "            0x00400f5b      e890fcffff     call sym.imp.__isoc99_sscanf\n"
        self.assertEqual(diff_r2.normalise(line, strip_trailing=True), diff_r2.normalise(bare, strip_trailing=True))
        self.assertEqual(len(diff_r2.normalise(line, strip_trailing=True)), 1)


class Missed(unittest.TestCase):
    """A radare2-only value judged by a `[[missed]]` entry leaves the ratchet (ROADMAP D541)."""

    def table(self, text=MISSED):
        return diff_r2.load_missed(None, tomllib.loads(text))

    def graded(self, table, theirs):
        ours = session(arch=["x86-64"], afl=afl((0x45C5D0, "sym.runtime.duffzero")))
        args = type("Args", (), {"jobs": 1, "timeout": 1, "verbose": False})()
        real = diff_r2.answers
        diff_r2.answers = lambda binary, *_: (None, {"aa": None, "afl": (ours, theirs)})
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return diff_r2.grade("elf", [pathlib.Path("dwarf_go_tree")], [("afl", "entries")], None, None, [], args, table)[0]
        finally:
            diff_r2.answers = real

    def test_a_radare2_only_value_with_its_entry_leaves_the_ratchet(self):
        table = self.table()
        theirs = session(afl=afl((0x45C5D0, "sym.runtime.duffzero"), (0x45C60C, "fcn.0045c60c"), (0x500000, "fcn.00500000")))
        tally = self.graded(table, theirs)["afl"]
        self.assertEqual((tally["r2-only"], tally["r2-judged"]), (1, 1))
        self.assertEqual(diff_r2.unmatched_misses(table), [])

    def test_a_radare2_only_value_judged_r2s_right_without_its_radare2_line_is_refused(self):
        with self.assertRaises(ValueError):
            self.table(MISSED.replace('r2_line = "libr/core/canal.c:552-554"\n', ""))
        # r2-right and unfilled name an open ROADMAP row instead.
        with self.assertRaises(ValueError):
            self.table(MISSED.replace('"r2s-right"', '"unfilled"').replace("r2_line", "row_line"))
        self.assertEqual(len(self.table(MISSED.replace('"r2s-right"', '"unfilled"') + 'row = "D542"\n')), 1)
        # A value is listed, never a pattern.
        with self.assertRaises(ValueError):
            self.table(MISSED.replace('"0x45c60c"', '"0x45c6*"'))

    def test_a_deliberate_radare2_only_value_names_radare2s_line(self):
        deliberate = MISSED.replace('"r2s-right"', '"deliberate"')
        self.assertEqual(len(self.table(deliberate)), 1)
        with self.assertRaises(ValueError):
            self.table(deliberate.replace('r2_line = "libr/core/canal.c:552-554"\n', 'row = "D506"\n'))

    def test_a_listed_value_the_run_did_not_report_fails(self):
        table = self.table()
        tally = self.graded(table, session(afl=afl((0x45C5D0, "sym.runtime.duffzero"))))["afl"]
        self.assertEqual((tally["r2-only"], tally["r2-judged"]), (0, 0))
        self.assertEqual(diff_r2.unmatched_misses(table), [("afl", "dwarf_go_tree", 0x45C60C)])



class Sessions(unittest.TestCase):
    def test_a_session_that_ended_before_its_deadline_fired_is_reaped_once(self):
        # The deadline fires on a child that already exited; end() is still its one reaper.
        session = diff_r2.Session([sys.executable, "-c", "pass"], 0.05)
        session.send([])
        time.sleep(0.3)
        took, _, ended = session.end()
        self.assertEqual(ended, "done")
        self.assertGreaterEqual(took, 0.05)


if __name__ == "__main__":
    unittest.main()
