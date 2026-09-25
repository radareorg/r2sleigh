#!/usr/bin/env python3
"""Install this tree's DecBench backend into a DecBench checkout.

    tests/decbench/install_backend.py <decbench checkout>

Copies ``r2sleigh_raw.py`` and the batch runner it shares with the
equivalence gate (``tests/equiv/r2s_batch.py``) into
``decbench/decompilers/raw/`` and adds the backend to that package's import
list, so every DecBench process -- including the ``decompile_one.py``
subprocess the official ``scripts/run_benchmark.py`` starts per binary --
registers ``r2sleigh_native``. Idempotent. Prints the sha256 of each copied
file, which is how a run shows the backend it measured came from this tree.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = {
    "r2sleigh_raw.py": HERE / "r2sleigh_raw.py",
    "r2s_batch.py": HERE.parent / "equiv" / "r2s_batch.py",
}
IMPORT = "    r2sleigh_raw,  # noqa: F401  (installed from the r2sleigh tree)\n"


def install(checkout: Path) -> list[str]:
    raw = checkout / "decbench" / "decompilers" / "raw"
    init = raw / "__init__.py"
    if not init.exists():
        raise SystemExit(f"{checkout} is not a DecBench checkout (no {init})")
    lines = []
    for name, source in FILES.items():
        target = raw / name
        shutil.copyfile(source, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        lines.append(f"{digest}  {target}")
    text = init.read_text(encoding="utf-8")
    if "r2sleigh_raw" not in text:
        anchor = "from decbench.decompilers.raw import (\n"
        if anchor not in text:
            raise SystemExit(f"cannot find the backend import list in {init}")
        text = text.replace(anchor, anchor + IMPORT, 1)
        init.write_text(text, encoding="utf-8")
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 64
    for line in install(Path(argv[1])):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
