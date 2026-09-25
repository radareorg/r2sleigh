#!/usr/bin/env python3
"""The DecBench backend asks for exactly its targets and files every one.

The backend runs inside DecBench, which is not a dependency of this
repository, so when it is not importable the few names the backend uses are
stood in for below. The stand-ins carry no behaviour the tests depend on
except ``dump_progress`` (it pickles, as DecBench's does) and the target
filter (it keeps integer addresses, as DecBench's does). With DecBench
installed the real modules are used.

r2s is replaced by ``tests/equiv/testdata/stub_r2s.py``, which answers
``pddj`` per the contract and fails on request in each way r2s can.
"""

from __future__ import annotations

import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
STUB = REPO / "tests" / "equiv" / "testdata" / "stub_r2s.py"
STRIPPED = REPO / "tests" / "fixtures" / "hashes_gcc_x64_O2_stripped"
sys.path.insert(0, str(HERE))

REGISTERED: list[str] = []


def _install_decbench_stand_ins() -> None:
    try:
        import decbench.decompilers.registry  # noqa: F401

        return
    except ImportError:
        pass

    def module(name: str) -> types.ModuleType:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
        return mod

    class Model:
        def __init__(self, **values):
            self.__dict__.update(values)

    module("decbench")
    module("decbench.decompilers")
    base = module("decbench.decompilers.base")

    class Decompiler:
        def __init__(self, config=None):
            self.config = config

        @property
        def id(self):
            return self.name

    base.Decompiler = Decompiler
    base.DecompilerConfig = Model
    raw = module("decbench.decompilers.raw")
    common = module("decbench.decompilers.raw.common")
    raw.common = common
    common.addr_targets_of = lambda names: {
        int(x) for x in (names or ()) if isinstance(x, int) and not isinstance(x, bool)
    }
    common.elf_text_ranges = lambda path: None
    common.should_skip_function = lambda name, addr, text, targets: (
        not name or name in {"_start", "frame_dummy", "__libc_csu_init"}
    )
    common.extract_metrics = lambda code: {"gotos": code.count("goto "), "bools": 0}

    def dump_progress(path, result):
        if path is not None:
            Path(path).write_bytes(pickle.dumps(result))

    common.dump_progress = dump_progress
    registry = module("decbench.decompilers.registry")

    def register_decompiler(name):
        def wrap(cls):
            REGISTERED.append(name)
            return cls

        return wrap

    registry.register_decompiler = register_decompiler
    module("decbench.models")
    models = module("decbench.models.decompilation")
    for name in ("DecompilationResult", "DecompilerMetadata", "FunctionDecompilation",
                 "LineMapping", "VariableInfo"):
        # Named where they live, so a partial result pickles like DecBench's.
        setattr(models, name, type(name, (Model,), {"__module__": models.__name__}))


_install_decbench_stand_ins()

import r2sleigh_raw  # noqa: E402

TARGETS = [0x401150, 0x401160, 0x4011F0, 0x401210, 0x401230, 0x401290]


class Backend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = {
            "R2SLEIGH_R2S_BIN": str(STUB),
            "STUB_R2S_MODE": "minimal",
            "STUB_R2S_FAULTS": "",
            "STUB_R2S_STATE": self.tmp.name,
            "R2SLEIGH_REFUSAL_CENSUS_DIR": self.tmp.name,
            "R2SLEIGH_FUNCTION_TIMEOUT": "30",
        }
        self.saved = {key: os.environ.get(key) for key in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tmp.cleanup()

    def decompile(self, binary=STRIPPED, **kwargs):
        return r2sleigh_raw.R2sDecompiler().decompile_binary(Path(binary), **kwargs)

    def test_it_renders_exactly_its_targets_at_their_own_addresses(self):
        # D1, D2: a stripped binary has no symbol to find a function by; the
        # DWARF low_pc set is the contract, and r2s addresses are file space.
        result = self.decompile(function_names=set(TARGETS))
        rendered = sorted(f.address for f in result.functions.values())
        self.assertEqual(rendered, TARGETS)
        for function in result.functions.values():
            self.assertEqual(function.name, f"fcn_{function.address:08x}")
            self.assertIn(f"void {function.name}(void)", function.decompiled_code)
        extra = result.decompiler.extra
        self.assertEqual((extra["requested"], extra["rendered"], extra["declined"]), (6, 6, 0))
        self.assertEqual(extra["requested_from"], "targets")

    def test_a_failed_statement_is_a_typed_decline_in_a_completed_batch(self):
        # D3: stderr merged, `r2s: ...` inside the markers, exit 1 is no crash.
        os.environ["STUB_R2S_FAULTS"] = f"error@{TARGETS[1]:x}"
        result = self.decompile(function_names=set(TARGETS))
        causes = result.decompiler.extra["decline_causes"]
        self.assertEqual(causes, {f"0x{TARGETS[1]:x}": f"r2s: nothing mapped at 0x{TARGETS[1]:x}"})
        self.assertEqual(len(result.functions), 5)
        self.assertEqual(result.decompiler.extra["processes"], 1)
        self.assertEqual(result.decompiler.failed_functions, [f"0x{TARGETS[1]:x}"])

    def test_a_crash_costs_one_function_and_every_answer_is_checkpointed(self):
        # D4: abort on the third of six; r2s restarts at the fourth, and the
        # progress pickle grows by one function per answer.
        os.environ["STUB_R2S_FAULTS"] = f"abort@{TARGETS[2]:x}"
        sizes: list[int] = []
        original = r2sleigh_raw.common.dump_progress

        def spy(path, result):
            sizes.append(len(result.functions) + len(result.decompiler.extra["decline_causes"]))
            original(path, result)

        r2sleigh_raw.common.dump_progress = spy
        try:
            progress = Path(self.tmp.name) / "progress.pkl"
            result = self.decompile(function_names=set(TARGETS), progress_path=progress)
        finally:
            r2sleigh_raw.common.dump_progress = original
        self.assertEqual(sizes, [1, 2, 3, 4, 5, 6])
        causes = result.decompiler.extra["decline_causes"]
        self.assertEqual(list(causes), [f"0x{TARGETS[2]:x}"])
        self.assertIn("SIGABRT", causes[f"0x{TARGETS[2]:x}"])
        self.assertIn(f"0x{TARGETS[2]:x}", causes[f"0x{TARGETS[2]:x}"])
        self.assertEqual(sorted(f.address for f in result.functions.values()),
                         TARGETS[:2] + TARGETS[3:])
        saved = pickle.loads(progress.read_bytes())
        self.assertEqual(len(saved.functions), 5)
        self.assertEqual(result.decompiler.extra["processes"], 2)

    def test_thousands_of_targets_are_one_process_and_every_one_is_filed(self):
        # The sailr set's large binaries have thousands of functions. As one -c
        # script that many addresses passed Linux's 128 KiB argv cap, Popen
        # raised, and the whole binary was lost with nothing filed.
        targets = {0x400000 + 16 * n for n in range(2500)}
        result = self.decompile(function_names=targets)
        extra = result.decompiler.extra
        self.assertEqual((extra["requested"], extra["rendered"], extra["declined"]),
                         (2500, 2500, 0))
        self.assertEqual({f.address for f in result.functions.values()}, targets)
        self.assertEqual(extra["processes"], 1)

    def test_two_functions_of_one_name_are_two_declines(self):
        # Static functions of different compile units share a name; each is
        # its own decline, and the count still closes.
        os.environ["STUB_R2S_MODE"] = "refuse"
        result = self.decompile(functions=[("helper", TARGETS[0]), ("helper", TARGETS[1])])
        extra = result.decompiler.extra
        self.assertEqual((extra["requested"], extra["declined"]), (2, 2))
        self.assertEqual(extra["decline_causes"], {
            f"helper@0x{TARGETS[0]:x}": "refused: stub refuses",
            f"helper@0x{TARGETS[1]:x}": "refused: stub refuses",
        })
        self.assertEqual(result.decompiler.failed_functions, ["helper", "helper"])

    def test_a_malformed_answer_is_a_decline_not_a_lost_binary(self):
        os.environ["STUB_R2S_FAULTS"] = f"elsewhere@{TARGETS[1]:x}"
        result = self.decompile(function_names=set(TARGETS[:3]))
        causes = result.decompiler.extra["decline_causes"]
        self.assertEqual(list(causes), [f"0x{TARGETS[1]:x}"])
        self.assertIn("breaks its contract", causes[f"0x{TARGETS[1]:x}"])
        self.assertEqual(len(result.functions), 2)

    def test_a_refusal_is_declined_with_its_reason(self):
        os.environ["STUB_R2S_MODE"] = "refuse"
        result = self.decompile(function_names={TARGETS[0]})
        self.assertEqual(result.functions, {})
        self.assertEqual(result.decompiler.extra["decline_causes"],
                         {f"0x{TARGETS[0]:x}": "refused: stub refuses"})

    @unittest.skipUnless(shutil.which("gcc"), "needs gcc to build an unstripped binary")
    def test_a_binary_with_symbols_or_dwarf_is_refused_whole(self):
        # D5: the evaluated file's own DWARF must never reach a scored rendering.
        binary = Path(self.tmp.name) / "hashes"
        subprocess.run(["gcc", "-g", "-O1", str(REPO / "tests" / "corpus" / "hashes.c"),
                        "-o", str(binary)], check=True, capture_output=True)
        result = self.decompile(binary=binary, function_names=set(TARGETS[:2]))
        self.assertEqual(result.functions, {})
        causes = set(result.decompiler.extra["decline_causes"].values())
        self.assertEqual(len(causes), 1)
        self.assertIn(".debug_info and .symtab", causes.pop())
        self.assertEqual(result.decompiler.extra["fail_closed"], [".debug_info", ".symtab"])

    def test_variables_and_lines_come_from_pddj(self):
        # D6: the structured answer, not a parse of the C.
        result = self.decompile(function_names={TARGETS[0]})
        function = next(iter(result.functions.values()))
        param, local = function.variables
        self.assertEqual((param.name, param.kind, param.arg_index), ("a0", "arg", 0))
        self.assertEqual((local.name, local.kind, local.stack_offset), ("i", "stack", -0x14))
        self.assertEqual(function.metadata["residual"], 0)

    def test_a_named_request_renames_the_definition(self):
        result = self.decompile(functions=[("usage", TARGETS[0])])
        self.assertEqual(list(result.functions), ["usage"])
        code = result.functions["usage"].decompiled_code
        self.assertIn("void usage(void)", code)
        self.assertNotIn("fcn_", code)

    def test_with_no_targets_it_renders_what_afl_finds(self):
        os.environ["STUB_R2S_AFL"] = "0x401150 main,0x401160 -,0x401170 _start"
        try:
            result = self.decompile()
        finally:
            os.environ.pop("STUB_R2S_AFL", None)
        self.assertEqual(sorted(f.address for f in result.functions.values()),
                         [0x401150, 0x401160])
        self.assertEqual(result.decompiler.extra["requested_from"], "afl")

    def test_only_the_native_backend_is_registered(self):
        if REGISTERED:
            self.assertEqual(REGISTERED, ["r2sleigh_native"])
        self.assertFalse(hasattr(r2sleigh_raw, "RawR2SleighDecompiler"))


class Helpers(unittest.TestCase):
    def test_stack_locations(self):
        self.assertEqual(r2sleigh_raw.stack_offset("stack-0x14"), -0x14)
        self.assertEqual(r2sleigh_raw.stack_offset("[rbp-20]"), -20)
        self.assertEqual(r2sleigh_raw.stack_offset("sp+8"), 8)
        self.assertIsNone(r2sleigh_raw.stack_offset("rdi"))

    def test_section_names_of_a_stripped_binary(self):
        names = r2sleigh_raw.elf_section_names(STRIPPED)
        self.assertIn(".text", names)
        self.assertEqual(r2sleigh_raw.leaked_sections(STRIPPED), [])


if __name__ == "__main__":
    unittest.main()
