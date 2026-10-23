#!/usr/bin/env python3
"""Why `type_match` fails: one verdict per DWARF variable, recomputed with DecBench's own matcher.

    PYTHONPATH=<decbench> DECBENCH_NO_CACHE=1 <venv>/bin/python type_causes.py collect \
        --run <results tree> --decompilers r2sleigh_native,angr --out rows.jsonl [--project zlib]
    <venv>/bin/python type_causes.py report rows.jsonl [--vs angr]
    python3 type_causes.py widths rows.jsonl [--dec r2sleigh_native]

`collect` re-runs `TypeMatchMetric` over a checkpointed run (`<run>/checkpoints/*.pkl`) and records, for every
ground-truth variable of every function, the DWARF type, the variable it was matched to, the stage that matched it
and the verdict. It asserts that the recomputed tp/fp/fn of each function equal the checkpoint's stored value, so
the classes below sum to the metric. `report` groups the verdicts by cause and ranks them by how many functions
would turn perfect if only that cause were fixed.

type_match counts only `DW_TAG_formal_parameter` and `DW_TAG_variable` (with any DW_AT_location), never the return
type; a decompiled variable with no source partner costs nothing; signedness is stripped by `normalize_type`.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pickle
import re
import sys
from pathlib import Path

INT_WIDTH = {
    "char": 1, "int8_t": 1, "uint8_t": 1, "byte": 1, "bool": 1, "_Bool": 1,
    "short": 2, "int16_t": 2, "uint16_t": 2,
    "int": 4, "int32_t": 4, "uint32_t": 4, "uint": 4, "unsigned": 4, "float": 4,
    "long": 8, "int64_t": 8, "uint64_t": 8, "size_t": 8, "ssize_t": 8, "intptr_t": 8,
    "uintptr_t": 8, "double": 8, "ulong": 8, "long long": 8,
}
QUAL = re.compile(r"\b(const|volatile|unsigned|signed|register|static|extern|restrict)\b")


def dec_kind(type_str: str, size: int | None) -> str:
    """Coarse kind of a decompiler-printed type: ptr_*, int<width>, bool, float, struct, void, other."""
    t = QUAL.sub("", type_str or "").replace("long long", "long").strip()
    t = re.sub(r"\s+", " ", t)
    if "(*)" in t or "FUNCTION" in t:
        return "funcptr"
    if "*" in t:
        pointee = t.replace("*", "").strip()
        if t.count("*") > 1:
            return "ptr_ptr"
        if pointee in ("void", ""):
            return "ptr_void"
        if pointee in ("char", "int8_t", "uint8_t", "byte"):
            return "ptr_char"
        if pointee.startswith(("struct ", "union ")) or re.match(r"^(struct|s)_\w+$", pointee):
            return "ptr_struct"
        if pointee in ("float", "double"):
            return "ptr_float"
        return "ptr_int"
    if t in ("bool", "_Bool"):
        return "bool"
    if t in ("float", "double"):
        return "float"
    if t.startswith(("struct ", "union ")):
        return "struct"
    if t == "void":
        return "void"
    w = INT_WIDTH.get(t) or (size if size in (1, 2, 4, 8) else None)
    return f"int{w}" if w else "other"


def _ref(die):
    attr = die.attributes["DW_AT_type"]
    return die.dwarfinfo.get_DIE_from_refaddr(attr.value + die.cu.cu_offset)


def gt_kind(dwarfinfo, identity: str) -> str:
    """Coarse kind of a ground-truth variable's DWARF type, from its DIE (`identity` = `dwarf:0x<offset>`)."""
    try:
        die = dwarfinfo.get_DIE_from_refaddr(int(identity.split(":0x")[1], 16))
        if "DW_AT_abstract_origin" in die.attributes:
            attr = die.attributes["DW_AT_abstract_origin"]
            die = dwarfinfo.get_DIE_from_refaddr(attr.value + die.cu.cu_offset)
        return _type_kind(die, 0)
    except Exception:  # noqa: BLE001
        return "unknown"


def _strip(die):
    while die.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type"):
        if "DW_AT_type" not in die.attributes:
            return None
        die = _ref(die)
    return die


def _type_kind(holder, depth: int) -> str:
    if "DW_AT_type" not in holder.attributes:
        return "void"
    t = _strip(_ref(holder))
    if t is None:
        return "void"
    tag = t.tag
    if tag == "DW_TAG_pointer_type":
        if depth:
            return "ptr"
        inner = _type_kind(t, 1)
        if inner in ("void",):
            return "ptr_void"
        if inner in ("int1", "char"):
            return "ptr_char"
        if inner in ("struct", "union"):
            return "ptr_struct"
        if inner == "ptr":
            return "ptr_ptr"
        if inner in ("func", "funcptr"):
            return "funcptr"
        if inner in ("float", "double"):
            return "ptr_float"
        if inner.startswith("int") or inner == "bool":
            return "ptr_int"
        return "ptr_other"
    if tag == "DW_TAG_base_type":
        enc = t.attributes["DW_AT_encoding"].value if "DW_AT_encoding" in t.attributes else 0
        size = t.attributes["DW_AT_byte_size"].value if "DW_AT_byte_size" in t.attributes else 0
        name = t.attributes["DW_AT_name"].value.decode() if "DW_AT_name" in t.attributes else ""
        if enc == 2:
            return "bool"
        if enc == 4:
            return "float"
        if depth and size == 1 and enc in (6, 8):
            return "char"
        return f"int{size}"
    if tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
        return "struct"
    if tag == "DW_TAG_union_type":
        return "union"
    if tag == "DW_TAG_enumeration_type":
        return "enum"
    if tag == "DW_TAG_array_type":
        return "array"
    if tag == "DW_TAG_subroutine_type":
        return "func"
    return "other"


def decl_path(dwarfinfo, die) -> bytes:
    """The file a DIE is declared in, from its CU's line-program file table (DWARF 5 is 0-based, earlier 1-based)."""
    lp = dwarfinfo.line_program_for_CU(die.cu)
    version = lp.header["version"]
    entry = lp["file_entry"][die.attributes["DW_AT_decl_file"].value - (0 if version >= 5 else 1)]
    dirs = lp["include_directory"]
    slot = entry.dir_index if version >= 5 else entry.dir_index - 1
    directory = dirs[slot] if 0 <= slot < len(dirs) else b""
    return directory + b"/" + entry.name


def system_declared(dwarfinfo, identity: str) -> bool:
    """Is the variable's type (a typedef or struct on its chain) declared under /usr/include or the compiler's headers?

    Such a name (`FILE`, `struct stat`, `DIR`) is stated by a C library's prototypes, so a decompiler can spell it;
    a project's own struct is not.
    """
    try:
        die = dwarfinfo.get_DIE_from_refaddr(int(identity.split(":0x")[1], 16))
        if "DW_AT_abstract_origin" in die.attributes:
            attr = die.attributes["DW_AT_abstract_origin"]
            die = dwarfinfo.get_DIE_from_refaddr(attr.value + die.cu.cu_offset)
        seen = 0
        while "DW_AT_type" in die.attributes and seen < 16:
            die = _ref(die)
            seen += 1
            if "DW_AT_decl_file" in die.attributes and die.tag in (
                    "DW_TAG_typedef", "DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_enumeration_type"):
                path = decl_path(dwarfinfo, die)
                if path.startswith((b"/usr/include", b"/usr/lib/gcc")):
                    return True
            if die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_base_type"):
                break
        return False
    except Exception:  # noqa: BLE001
        return False


def group(kind: str) -> str:
    if kind.startswith("ptr") or kind == "funcptr":
        return "ptr"
    if kind.startswith("int"):
        return "int"
    return kind


def fp_class(gt: str, dk: str) -> str:
    """Cause of a type mismatch between a matched pair, from the two kinds."""
    gg, dg = group(gt), group(dk)
    if gg == "ptr" and dg == "int":
        return "fp:pointer_as_integer"
    if gg == "int" and dg == "ptr":
        return "fp:integer_as_pointer"
    if gg == "ptr" and dg == "ptr":
        return "fp:wrong_pointee" if gt != "funcptr" else "fp:function_pointer"
    if gg == "int" and dg == "int":
        return "fp:integer_width"
    if gg in ("struct", "union", "array"):
        return "fp:aggregate_by_value"
    if gg == "enum":
        return "fp:enum"
    if gg == "bool" or dg == "bool":
        return "fp:bool"
    if gg == "float" or dg == "float":
        return "fp:float"
    return "fp:other"


PRIMITIVE = {"char", "short", "int", "long long", "float", "double", "bool", "void", "long double"}


def expressible(forms) -> bool:
    """Can a decompiler working from a stripped binary spell any of these forms?

    A form is expressible when, without its `*` and `[n]`, it is a C primitive. A struct, union or typedef-to-
    struct form (`z_stream_s*`, `z_streamp`) names a type the binary does not carry.
    """
    return any(re.sub(r"(\s*\*|\[\d*\])+$", "", f).strip() in PRIMITIVE for f in forms)


def collect(args) -> None:
    os.environ["DECBENCH_NO_CACHE"] = "1"
    import decbench.metrics  # noqa: F401
    from decbench.metrics import type_match as tm
    from decbench.metrics import variable_match as vm
    from decbench.models.project import OptimizationLevel, Project
    from decbench.pipeline.executor import PipelineConfig, PipelineExecutor
    from decbench.results_store import gather_project_tomls
    from decbench.utils import binfmt

    run = Path(args.run)
    decs = args.decompilers.split(",")
    opts = [OptimizationLevel(v) for v in args.opt_levels.split(",")]

    class Recording(tm.TypeMatchMetric):
        def __init__(self):
            super().__init__()
            self.detail: dict[str, dict] = {}
            self._name = ""
            self._dwarf = None

        def compute_for_function(self, decompiled, *a, **kw):
            self._name = decompiled.name
            return super().compute_for_function(decompiled, *a, **kw)

        def _compute_uncached(self, gt_vars, source_evidence, source_types, decompiled_evidence,
                              decompiled_by_id, calibration_shift, source_result, *rest):
            value = super()._compute_uncached(
                gt_vars, source_evidence, source_types, decompiled_evidence, decompiled_by_id,
                calibration_shift, source_result, *rest)
            result = vm.match_variables(source_evidence, decompiled_evidence,
                                        stack_shift_hint=calibration_shift, **self.variable_match_policy)
            matched = {m.source_id: m for m in result.matches}
            unobservable = set(result.unobservable_source)
            weights = vm._address_weights(source_evidence, decompiled_evidence)
            src_ev = {v.identity: v for v in source_evidence}
            dec_args = {v.arg_index for v in decompiled_evidence if v.arg_index is not None}
            rows = []
            for gv in gt_vars:
                ident = str(gv.get("identity"))
                gk = gt_kind(self._dwarf, ident)
                row = {"name": gv.get("name"), "is_arg": bool(gv.get("is_arg")), "arg_index": gv.get("arg_index"),
                       "expressible": expressible(gv.get("type", [])),
                       "system_type": system_declared(self._dwarf, ident),
                       "stack": bool(gv.get("rbp_offset")), "gt_kind": gk,
                       "n_addr": len(src_ev[ident].addresses) if ident in src_ev else 0}
                m = matched.get(ident)
                if m is None:
                    if ident in unobservable:
                        row["verdict"] = "fn:unobservable"
                    elif gv.get("is_arg") and gv.get("arg_index") not in dec_args:
                        row["verdict"] = "fn:param_absent"
                    elif gv.get("is_arg"):
                        row["verdict"] = "fn:param_unmatched"
                    else:
                        ev = src_ev[ident]
                        scores = [vm._weighted_dice(ev, d, weights) for d in decompiled_evidence]
                        overlap = [s for s in scores if s > 0]
                        row["best_dice"] = max(scores, default=0.0)
                        row["n_overlap"] = len(overlap)
                        where = "stack" if gv.get("rbp_offset") else "register"
                        floor = self.variable_match_policy["min_overlap"]
                        if not overlap:
                            row["verdict"] = f"fn:{where}_local_no_overlap"
                        elif row["best_dice"] < floor:
                            row["verdict"] = f"fn:{where}_local_dice_below_min"
                        else:
                            row["verdict"] = f"fn:{where}_local_ambiguous_or_taken"
                else:
                    dv = decompiled_by_id[m.decompiled_id]
                    dk = dec_kind(dv.type, dv.size)
                    expected = set(source_types[ident])
                    norm = tm.normalize_type(dv.type)
                    usize = tm._uncommitted_size(dv)
                    ok = bool(expected & norm) or (usize is not None and bool(tm._SIZE_SCALARS.get(usize, set()) & expected))
                    row.update({"stage": m.stage, "dec_type": dv.type, "dec_name": dv.name, "dec_kind": dk,
                                "gt_forms": sorted(expected)[:6]})
                    row["verdict"] = "tp" if ok else (fp_class(gk, dk) if row["expressible"] else (
                        "fp:library_named_type" if row["system_type"] else "fp:project_named_type"))
                rows.append(row)
            self.detail[self._name] = rows
            tpn = sum(r["verdict"] == "tp" for r in rows)
            fpn = sum(r["verdict"].startswith("fp:") for r in rows)
            fnn = sum(r["verdict"].startswith("fn:") for r in rows)
            assert (tpn, fpn, fnn) == (value.metadata["tp"], value.metadata["fp"], value.metadata["fn"]), \
                (self._name, (tpn, fpn, fnn), value.metadata)
            return value

    out = open(args.out, "w")
    for toml in gather_project_tomls():
        if args.project and toml.stem not in args.project:
            continue
        ck_path = run / "checkpoints" / f"{toml.stem}.pkl"
        if not ck_path.exists():
            continue
        ck = pickle.loads(ck_path.read_bytes())
        project = Project.from_toml(toml)
        cfg = PipelineConfig(output_dir=run, optimization_levels=opts)
        PipelineExecutor(cfg)._discover_existing_binaries([project], run)
        for opt in opts:
            sources = list(project.preprocessed_sources.get(opt, {}).values())
            for b in project.compiled_binaries.get(opt, []):
                per_dec = (ck["decompile"].get(opt) or {}).get(b.stem) or {}
                stored_eval = (ck["evaluate"].get(opt) or {}).get(b.stem) or {}
                universe = None
                for dec in decs:
                    result = per_dec.get(dec)
                    if result is None:
                        continue
                    stored = stored_eval.get(dec, {}).get("type_match")
                    metric = Recording()
                    metric._dwarf = binfmt.dwarf_info(result.binary_path)
                    res = metric.compute_for_binary(result, preprocessed_sources=sources)
                    for name, val in res.function_results.items():
                        if stored is not None:
                            old = stored.function_results.get(name)
                            assert old is not None and abs(old.value - val.value) < 1e-9, (b.stem, dec, name, old, val)
                        out.write(json.dumps({
                            "project": project.name, "opt": opt.value, "binary": b.stem, "function": name,
                            "dec": dec, "correspondence": val.metadata.get("correspondence"),
                            "value": val.value, "tp": val.metadata["tp"], "fp": val.metadata["fp"],
                            "fn": val.metadata["fn"], "vars": metric.detail.get(name, []),
                            "address": int(result.functions[name].address),
                            "signature": (result.functions[name].metadata or {}).get("signature"),
                            "dec_params": sum(1 for v in result.functions[name].variables if v.kind == "arg"),
                            "dec_vars": len(result.functions[name].variables),
                        }) + "\n")
                    out.flush()
                    print(project.name, opt.value, b.stem, dec, len(res.function_results), file=sys.stderr, flush=True)
    out.close()


CAPS = ("fn:unobservable", "fp:project_named_type")


def classes_of(row) -> set:
    return {v["verdict"] for v in row["vars"] if v["verdict"] != "tp"}


def greedy(items, label="") -> list:
    """Fix classes one at a time, each time the one that makes most functions perfect; (class, newly perfect)."""
    sets = [classes_of(r) for r in items if r["value"] < 1.0]
    fixed: set = set()
    steps = []
    remaining = [c for c in {c for st in sets for c in st} if c not in CAPS]
    while remaining:
        best, gain = None, 0
        for c in remaining:
            g = sum(1 for st in sets if st <= fixed | {c} and not st <= fixed)
            if g > gain:
                best, gain = c, g
        if best is None:
            break
        fixed.add(best)
        remaining.remove(best)
        steps.append((best, gain))
    return steps


def report(args) -> None:
    rows = [json.loads(line) for line in open(args.rows)]
    by_dec = collections.defaultdict(dict)
    for r in rows:
        by_dec[r["dec"]][(r["project"], r["opt"], r["binary"], r["function"])] = r
    for dec, table in by_dec.items():
        n = len(table)
        perfect = sum(1 for r in table.values() if r["value"] == 1.0)
        legacy = sum(1 for r in table.values() if r["correspondence"] != "address")
        print(f"== {dec}: {n} scored functions, {perfect} perfect, {legacy} scored on the legacy name rule")
        verdicts = collections.Counter(v["verdict"] for r in table.values() for v in r["vars"])
        total = sum(verdicts.values())
        print(f"variables {total}: " + ", ".join(f"{k}={c}" for k, c in verdicts.most_common()))
        capped_obs = sum(1 for r in table.values() if any(v["verdict"] == "fn:unobservable" for v in r["vars"]))
        capped_name = sum(1 for r in table.values() if any(v["verdict"] == "fp:project_named_type" for v in r["vars"]))
        capped_any = sum(1 for r in table.values() if classes_of(r) & set(CAPS))
        nonexp = sum(1 for r in table.values() if any(not v.get("expressible", True) for v in r["vars"]))
        print(f"capped: unobservable {capped_obs}; project-named type (fp) {capped_name}; any cap {capped_any}; "
              f"a GT variable no stripped decompiler can spell {nonexp}; reachable {n - capped_any}")
        sole = collections.Counter()
        involved = collections.Counter()
        for r in table.values():
            if r["value"] == 1.0:
                continue
            classes = classes_of(r)
            for c in classes:
                involved[c] += 1
            if len(classes) == 1:
                sole[next(iter(classes))] += 1
        print(f"-- {dec}: class, functions involved, functions where it is the only cause")
        for c, k in involved.most_common():
            print(f"  {c:55s} {k:6d} {sole.get(c, 0):6d}")
        print(f"-- {dec}: greedy order of fixing (class, functions newly perfect)")
        cum = 0
        for c, g in greedy(table.values()):
            cum += g
            print(f"  {c:55s} +{g:5d} (cumulative {cum})")
    if "angr" in by_dec and "r2sleigh_native" in by_dec:
        a, r = by_dec["angr"], by_dec["r2sleigh_native"]
        common = set(a) & set(r)
        ap = [k for k in common if a[k]["value"] == 1.0]
        rp = [k for k in common if r[k]["value"] == 1.0]
        print(f"== both scored {len(common)}; angr perfect {len(ap)}; r2s perfect {len(rp)}; "
              f"both {len(set(ap) & set(rp))}; angr only {len(set(ap) - set(rp))}; r2s only {len(set(rp) - set(ap))}")
        cnt = collections.Counter()
        solo = collections.Counter()
        for k in set(ap) - set(rp):
            cs = classes_of(r[k])
            for c in cs:
                cnt[c] += 1
            if len(cs) == 1:
                solo[next(iter(cs))] += 1
        print("-- functions angr gets perfect and r2s does not: r2s class, involved, only cause")
        for c, k in cnt.most_common():
            print(f"  {c:55s} {k:6d} {solo.get(c, 0):6d}")
        cnt = collections.Counter()
        for k in set(rp) - set(ap):
            for c in classes_of(a[k]):
                cnt[c] += 1
        print("-- functions r2s gets perfect and angr does not: angr class, involved")
        for c, k in cnt.most_common():
            print(f"  {c:55s} {k:6d}")


def kind_width(kind: str | None) -> int | None:
    m = re.fullmatch(r"int(\d+)", kind or "")
    return int(m.group(1)) if m else None


def width_direction(gt: str | None, dec: str | None) -> str:
    """The decompiled width against the source's: wider, narrower, same, or unknown for a kind with no width."""
    g, d = kind_width(gt), kind_width(dec)
    if g is None or d is None:
        return "unknown"
    return "wider" if d > g else "narrower" if d < g else "same"


def argument_split(rows, dec: str, verdict: str) -> dict:
    """How one verdict divides between parameters and locals, for one decompiler.

    `variables` counts the variables with the verdict; `direction` (integer width only) says whether the
    decompiled width is wider or narrower than the source's, over all of them and over those in only-cause
    functions. `only_cause` and `involved` count functions (not perfect) by whether the verdict's variables in
    them are all parameters, all locals or both; the first is the report's "only cause" (no other class in the
    function), the second every function with the verdict.
    """
    out = {"variables": {"param": 0, "local": 0}}
    if verdict == "fp:integer_width":
        out["direction"] = {
            scope: {w: dict.fromkeys(("wider", "narrower", "same", "unknown"), 0) for w in ("param", "local")}
            for scope in ("all", "only_cause")
        }
    for scope in ("only_cause", "involved"):
        out[scope] = {"functions": 0, "params_only": 0, "locals_only": 0, "mixed": 0}
    for r in rows:
        if r["dec"] != dec or r["value"] == 1.0:
            continue
        hits = [v for v in r["vars"] if v["verdict"] == verdict]
        if not hits:
            continue
        sole = classes_of(r) == {verdict}
        for v in hits:
            where = "param" if v["is_arg"] else "local"
            out["variables"][where] += 1
            if "direction" in out:
                way = width_direction(v.get("gt_kind"), v.get("dec_kind"))
                out["direction"]["all"][where][way] += 1
                if sole:
                    out["direction"]["only_cause"][where][way] += 1
        shape = {bool(v["is_arg"]) for v in hits}
        key = "mixed" if len(shape) == 2 else "params_only" if shape == {True} else "locals_only"
        for scope in ["involved"] + (["only_cause"] if sole else []):
            out[scope]["functions"] += 1
            out[scope][key] += 1
    return out


def share(n: int, of: int) -> str:
    return f"{n} ({100 * n / of:.1f}%)" if of else f"{n} (n/a)"


def widths(args) -> None:
    """Parameters against locals for the integer-width and pointer-as-integer verdicts (the D70 M1 table)."""
    with open(args.rows) as handle:
        rows = [json.loads(line) for line in handle]
    for verdict in ("fp:integer_width", "fp:pointer_as_integer"):
        split = argument_split(rows, args.dec, verdict)
        v = split["variables"]
        print(f"== {args.dec} {verdict}: variables {v['param'] + v['local']}: parameters {v['param']}, locals {v['local']}")
        for scope, by_where in split.get("direction", {}).items():
            for where, count in by_where.items():
                print(f"  {scope:10s} {where:5s} decompiled width against source: "
                      + ", ".join(f"{k} {c}" for k, c in count.items()))
        for scope, label in (("only_cause", "only cause"), ("involved", "involved")):
            s = split[scope]
            n = s["functions"]
            print(f"  functions {label} {n}: parameters only {share(s['params_only'], n)}, "
                  f"locals only {share(s['locals_only'], n)}, mixed {share(s['mixed'], n)}")
            print(f"    parameters in {share(s['params_only'] + s['mixed'], n)}, locals in {share(s['locals_only'] + s['mixed'], n)}")


def universe(args) -> None:
    """Which functions angr scored for type_match that r2s did not, and why (from the checkpoints)."""
    import decbench.metrics  # noqa: F401

    counts = collections.Counter()
    causes = collections.Counter()
    examples = collections.defaultdict(list)
    for ck_path in sorted(Path(args.run, "checkpoints").glob("*.pkl")):
        ck = pickle.loads(ck_path.read_bytes())
        for opt, binaries in ck["decompile"].items():
            for stem, per_dec in binaries.items():
                ev = ck["evaluate"][opt].get(stem, {})
                angr_tm = ev.get("angr", {}).get("type_match")
                r2s = per_dec.get("r2sleigh_native")
                r2s_tm = ev.get("r2sleigh_native", {}).get("type_match")
                if angr_tm is None or r2s is None:
                    continue
                declined = r2s.decompiler.extra.get("decline_causes", {})
                for name in angr_tm.function_results:
                    key = (ck_path.stem, opt.value, stem, name)
                    if r2s_tm is not None and name in r2s_tm.function_results:
                        counts["scored"] += 1
                    elif name in r2s.functions:
                        counts["decompiled, no type_match row"] += 1
                        examples["decompiled, no type_match row"].append(key)
                    else:
                        counts["not decompiled"] += 1
                        angr_fn = per_dec["angr"].functions.get(name)
                        label = hex(int(angr_fn.address)) if angr_fn is not None else name
                        cause = next((c for k, c in declined.items() if k == label or k.startswith(label + "@")),
                                     "no decline recorded")
                        cause = re.sub(r"0x[0-9a-f]+", "0x..", cause)[:110]
                        causes[cause] += 1
                        examples[cause].append(key)
    print(dict(counts), "universe", sum(counts.values()))
    for cause, k in causes.most_common(25):
        print(f"  {k:5d}  {cause}   e.g. {examples[cause][0]}")
    for key in examples["decompiled, no type_match row"][:5]:
        print("  no row:", key)


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--run", required=True)
    c.add_argument("--decompilers", default="r2sleigh_native,angr")
    c.add_argument("--opt-levels", default="O2,O2-noinline")
    c.add_argument("--project", action="append")
    c.add_argument("--out", required=True)
    r = sub.add_parser("report")
    r.add_argument("rows")
    u = sub.add_parser("universe")
    u.add_argument("--run", required=True)
    w = sub.add_parser("widths")
    w.add_argument("rows")
    w.add_argument("--dec", default="r2sleigh_native")
    args = p.parse_args()
    {"collect": collect, "report": report, "universe": universe, "widths": widths}[args.cmd](args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
