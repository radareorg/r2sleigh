#!/usr/bin/env python3
"""Check that a benchmark cell is paired to a rendering by address.

The adapter runs only on the benchmark host, where `decbench` is installed, so
importing it here means standing in for that package. The stubs below carry no
behaviour: every function under test is pure, and what is being checked is the
identity a result is filed under, which is where the pairing defect lived.
"""

import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def _install_decbench_stubs() -> None:
    if "decbench" in sys.modules:
        return

    def module(name: str) -> types.ModuleType:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        return mod

    module("decbench")
    module("decbench.decompilers")
    base = module("decbench.decompilers.base")
    base.Decompiler = type("Decompiler", (), {})
    base.DecompilerConfig = type("DecompilerConfig", (), {})
    raw = module("decbench.decompilers.raw")
    raw.common = module("decbench.decompilers.raw.common")
    registry = module("decbench.decompilers.registry")
    registry.register_decompiler = lambda *args, **kwargs: (lambda cls: cls)
    models = module("decbench.models")
    decompilation = module("decbench.models.decompilation")
    models.decompilation = decompilation
    for name in ("DecompilationResult", "DecompilerMetadata", "FunctionDecompilation"):
        setattr(decompilation, name, type(name, (), {}))


_install_decbench_stubs()

import r2sleigh_raw  # noqa: E402


class RequestedNameTests(unittest.TestCase):
    def test_address_pairs_a_cell_no_name_rule_could_reach(self):
        # DecBench spells a function it has no source name for as `sub_401165`;
        # radare2 calls the same address `fcn.00401165`. No prefix rule turns
        # one into the other, which is why 118 of 118 such cells went unpaired.
        requested = r2sleigh_raw._requested_by_address([("sub_401165", 0x401165)])
        self.assertEqual(
            r2sleigh_raw._requested_name(requested, 0x401165), "sub_401165"
        )
        self.assertNotEqual(r2sleigh_raw._source_name("fcn.00401165"), "sub_401165")

    def test_first_of_two_names_at_one_address_wins(self):
        requested = r2sleigh_raw._requested_by_address(
            [("main", 0x2460), ("main.cold", 0x2460)]
        )
        self.assertEqual(r2sleigh_raw._requested_name(requested, 0x2460), "main")

    def test_a_second_address_is_tried_when_the_first_misses(self):
        # The file address and radare2's virtual address differ on a PIE, and
        # the benchmark may have asked at either.
        requested = r2sleigh_raw._requested_by_address([("usage", 0x1149)])
        self.assertEqual(
            r2sleigh_raw._requested_name(requested, 0x101149, 0x1149), "usage"
        )

    def test_no_request_means_no_name(self):
        self.assertIsNone(r2sleigh_raw._requested_by_address(None))
        self.assertIsNone(r2sleigh_raw._requested_name(None, 0x1000))
        self.assertIsNone(
            r2sleigh_raw._requested_name(
                r2sleigh_raw._requested_by_address([("usage", 0x1149)]), 0x2000
            )
        )


class SourceNameTests(unittest.TestCase):
    def test_stacked_flag_prefixes_all_come_off(self):
        self.assertEqual(r2sleigh_raw._source_name("dbg.sym.readError"), "readError")
        self.assertEqual(r2sleigh_raw._source_name("readError"), "readError")

    def test_retitle_rewrites_the_name_inside_the_body(self):
        code = "void dbg_readError(void) { dbg_readError(); }"
        self.assertEqual(
            r2sleigh_raw._retitle(code, "dbg.readError", "readError"),
            "void readError(void) { readError(); }",
        )

    def test_retitle_leaves_a_body_that_already_agrees(self):
        code = "void usage(void) { }"
        self.assertEqual(r2sleigh_raw._retitle(code, "usage", "usage"), code)


class ProofCensusTests(unittest.TestCase):
    """A rendering is fully proven only when it holds no residual at all."""

    def test_every_residual_is_a_gap_whether_or_not_a_comment_names_it(self):
        # An unproven return and an unassigned read print no gap comment; a
        # marked gap does, and it says what it stands for.
        code = "\n".join(
            [
                "uint64_t dispatch(int64_t RDI_0)",
                "{",
                "    uint64_t x = *(uint64_t*)(r2sleigh_residual_u64(1) + 40);",
                "    r2sleigh_residual_void(2); /* r2dec gap: OpaqueUserOp at 0x1000:3 covering 2 ops (lower) */",
                "    r2sleigh_residual_void(3); /* r2dec gap: UnresolvedBranchCondition at 0x1010 (structure) */",
                "    return r2sleigh_residual_u64(4);",
                "}",
            ]
        )
        self.assertEqual(
            r2sleigh_raw._residuals(code),
            [
                {"kind": "residual_u64", "site": "1", "ops": "0"},
                {"kind": "OpaqueUserOp", "site": "2", "ops": "2"},
                {"kind": "UnresolvedBranchCondition", "site": "3", "ops": "0"},
                {"kind": "residual_u64", "site": "4", "ops": "0"},
            ],
        )
        self.assertEqual(r2sleigh_raw._residuals("int f(void)\n{\n    return 0;\n}"), [])

    def test_a_refusal_from_either_renderer_is_declined(self):
        self.assertEqual(
            r2sleigh_raw._refusal_cause("/* r2dec refused classify: native render refusal: x */"),
            "native render refusal: x",
        )
        self.assertEqual(
            r2sleigh_raw._refusal_cause("/* r2sleigh refused f: route */"), "route"
        )
        self.assertIsNone(r2sleigh_raw._refusal_cause("int f(void) { return 0; }"))


class NativeRouteTests(unittest.TestCase):
    """The native route reads the engine's own listing, not radare2's analysis."""

    LISTING = "\n".join(
        [
            "file     /bin/ls",
            "format   Elf",
            "baddr    0x00400000",
            "entry    0x00005ae0",
            "nth vaddr      size type name",
            "-" * 60,
            "0   0x00015c80   17 FUNC _obstack_begin",
            "1   0x00015ca0    0 FUNC _empty",
            "2   0x00017168    1 OBJ  a_global",
            "3   0x00015cc0  251 FUNC _obstack_newchunk",
        ]
    )

    def _route(self):
        route = r2sleigh_raw.RawR2SleighNativeDecompiler.__new__(
            r2sleigh_raw.RawR2SleighNativeDecompiler
        )
        route._ask = lambda binary, commands, timeout: r2sleigh_raw._R2Run(
            stdout=self.LISTING, returncode=0, timeout=timeout
        )
        return route

    def test_it_asks_for_the_engines_own_rendering(self):
        route = r2sleigh_raw.RawR2SleighNativeDecompiler
        self.assertEqual(route._render_command(route), "pdd")
        # Nothing swaps an architecture: there is no radare2 in the process.
        self.assertEqual(route._prologue(route), [])

    def test_it_reads_the_load_base_and_only_sized_functions(self):
        functions, baddr, _ = self._route()._discover(Path("/bin/ls"), 1.0)
        self.assertEqual(baddr, 0x400000)
        self.assertEqual(
            functions,
            [("_obstack_begin", 0x15C80), ("_obstack_newchunk", 0x15CC0)],
        )


if __name__ == "__main__":
    unittest.main()
