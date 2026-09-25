#!/usr/bin/env python3
"""The ESIL differential runs end to end, with radare2 and the CLI stood in for.

Neither radare2 nor a built ``r2sleigh`` is needed: two stand-ins on ``PATH``
answer the commands the script sends. What is pinned is the plumbing -- the
window is decoded once, the r2sleigh side is read from the CLI's ESIL output
by address and evaluated with the program counter past the instruction, and
agreeing states report no divergence while a disagreeing register does.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import esil_differential  # noqa: E402

FAKE_R2 = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys
    argv = sys.argv[1:]
    script = open(argv[argv.index("-i") + 1]).read().splitlines()
    sleigh_session = any(line.startswith('"ae ') for line in script)
    for line in script:
        if line.startswith('"aoj'):
            count = int(line.strip('"').split()[1])
            print(json.dumps([{"addr": 0x1000 + i, "size": 1, "opcode": "nop",
                               "bytes": "90", "type": "nop", "esil": ""}
                              for i in range(count)]))
        elif line.startswith("?e "):
            print(line[3:])
        elif line.startswith("aer ") and "=" not in line:
            reg = line.split()[1]
            differ = os.environ.get("FAKE_DIFFER") == reg and sleigh_session
            print("0x1" if differ else "0x0")
''')

FAKE_R2SLEIGH = textwrap.dedent('''\
    #!/usr/bin/env python3
    import sys
    argv = sys.argv[1:]
    start = int(argv[argv.index("--addr") + 1], 16)
    count = int(argv[argv.index("-n") + 1])
    for i in range(count):
        print(f"# 0x{start + i:x}: nop (size=1)")
        print("0,rax,=")
''')


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        bin_dir = Path(self.tmp.name)
        for name, text in (("r2", FAKE_R2), ("r2sleigh", FAKE_R2SLEIGH)):
            path = bin_dir / name
            path.write_text(text)
            path.chmod(0o755)
        self.saved_path = os.environ["PATH"]
        os.environ["PATH"] = f"{bin_dir}{os.pathsep}{self.saved_path}"
        self.r2sleigh = str(bin_dir / "r2sleigh")

    def tearDown(self):
        os.environ["PATH"] = self.saved_path
        os.environ.pop("FAKE_DIFFER", None)
        self.tmp.cleanup()

    def run_script(self) -> tuple[int, dict]:
        argv = ["esil_differential.py", "--binary", "/bin/true", "--arch", "x86",
                "--count", "3", "--trials", "1", "--json", "--r2sleigh", self.r2sleigh]
        saved = sys.argv
        sys.argv = argv
        out = io.StringIO()
        try:
            with redirect_stdout(out):
                code = esil_differential.main()
        finally:
            sys.argv = saved
        return code, json.loads(out.getvalue())

    def test_agreeing_states_report_nothing(self):
        code, report = self.run_script()
        self.assertEqual(code, 0)
        self.assertEqual(report["instructions"], 3)
        self.assertEqual(report["steps_compared"], 3)

    def test_a_disagreeing_register_is_a_divergence(self):
        os.environ["FAKE_DIFFER"] = "rax"
        code, report = self.run_script()
        self.assertNotEqual(code, 0)
        self.assertEqual(report["steps_compared"], 3)
        self.assertTrue(report["divergences"])

    def test_the_lift_side_reads_its_esil_by_address(self):
        lifted = esil_differential.parse_sleigh_esil(
            "# 0x1000: xor eax, eax (size=2)\n0,eax,=\n# 0x1002: ret (size=1)\nrsp,[8],rip,=\n")
        self.assertEqual(lifted, {0x1000: ["0,eax,="], 0x1002: ["rsp,[8],rip,="]})
        step = esil_differential.Instruction(addr=0x1000, size=2, opcode="xor", bytes="31c0")
        script = esil_differential.emulation_script([step], "x86", 1, lifted)
        self.assertIn("aer rip=0x1002", script)
        self.assertIn('"ae 0,eax,="', script)
        self.assertNotIn("aes", script)


if __name__ == "__main__":
    unittest.main()
