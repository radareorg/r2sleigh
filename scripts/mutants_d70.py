#!/usr/bin/env python3
"""D70's mutation target: each mutant of the source-gold gate, its C type model, the DWARF entry rule and the
`pddj` contract is applied to the tree, the tests that should kill it run, and the file is restored. A mutant that
survives is expected to, and says why (ROADMAP D70, "Mutation").

  mutants_d70.py [--check] [NAME...]    run (or only --check that every edit applies once) the named mutants, else all

Run from the repository root with the files below unmodified. Exit 1 where a mutant lives that should die, or dies that
should live."""

import os
import shutil
import subprocess
import sys

TYPES = "python3 scripts/test_c_types.py"
GATE = "python3 scripts/test_differential_truth.py"
EQUIV = "cd tests/equiv && python3 -m unittest test_equiv.RangesTests test_equiv.PlacementTests test_equiv.ContractTests"
DECBENCH = "cd tests/decbench && python3 -m unittest test_type_causes"

C = "scripts/c_types.py"
G = "scripts/differential_truth.py"
D = "tests/equiv/dwarf.py"
B = "tests/equiv/r2s_batch.py"
T = "tests/decbench/type_causes.py"

INT_NAMES = {
    "int8_t": (1, True), "uint8_t": (1, False), "int16_t": (2, True), "uint16_t": (2, False),
    "int32_t": (4, True), "uint32_t": (4, False), "int64_t": (8, True), "uint64_t": (8, False),
    "intmax_t": (8, True), "uintmax_t": (8, False), "size_t": (8, False), "ssize_t": (8, True),
    "intptr_t": (8, True), "uintptr_t": (8, False), "ptrdiff_t": (8, True),
}


def m(name, path, old, new, tests=(TYPES, GATE), must_die=True, why=""):
    """A mutant with one edit."""
    return (name, [(path, old, new)], list(tests), must_die, why)


# A mutant of the same size as its file, written in the second the file was compiled, would run the old bytecode.
NO_BYTECODE = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

# (name, edits, tests that run in order, whether it must die, why it may live)
MUTANTS = []

# The integer names a prototype may spell: each row's sign and width.
for _name, (_width, _signed) in INT_NAMES.items():
    MUTANTS.append(m(f"int-name-{_name}-sign", C, f'"{_name}": ({_width}, {_signed})', f'"{_name}": ({_width}, {not _signed})'))
    MUTANTS.append(m(f"int-name-{_name}-width", C, f'"{_name}": ({_width}, {_signed})', f'"{_name}": ({_width * 2}, {_signed})'))

MUTANTS += [
    # The words of a declaration.
    m("word-bool-not-a-type", C, 'TYPE_WORDS = {"void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "bool"}',
      'TYPE_WORDS = {"void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool"}'),
    m("word-restrict-not-a-qualifier", C, 'QUALIFIER_WORDS = {"const", "volatile", "restrict", "__restrict", "__restrict__"}',
      'QUALIFIER_WORDS = {"const", "volatile", "__restrict", "__restrict__"}'),
    m("word-dunder-restrict-not-a-qualifier", C, 'QUALIFIER_WORDS = {"const", "volatile", "restrict", "__restrict", "__restrict__"}',
      'QUALIFIER_WORDS = {"const", "volatile", "restrict", "__restrict__"}'),
    m("word-dunder-restrict-dunder-not-a-qualifier", C, 'QUALIFIER_WORDS = {"const", "volatile", "restrict", "__restrict", "__restrict__"}',
      'QUALIFIER_WORDS = {"const", "volatile", "restrict", "__restrict"}'),
    m("word-static-not-ignored", C, 'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}',
      'IGNORED_WORDS = {"extern", "inline", "register", "auto", "__inline", "__inline__"}'),
    m("word-extern-not-ignored", C, 'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}',
      'IGNORED_WORDS = {"static", "inline", "register", "auto", "__inline", "__inline__"}'),
    m("word-inline-not-ignored", C, 'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}',
      'IGNORED_WORDS = {"static", "extern", "register", "auto", "__inline", "__inline__"}'),
    m("word-register-not-ignored", C, 'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}',
      'IGNORED_WORDS = {"static", "extern", "inline", "auto", "__inline", "__inline__"}'),
    m("word-auto-not-ignored", C, 'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}',
      'IGNORED_WORDS = {"static", "extern", "inline", "register", "__inline", "__inline__"}'),
    m("word-dunder-inline-not-ignored", C, 'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}',
      'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline__"}'),
    m("word-dunder-inline-dunder-not-ignored", C, 'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}',
      'IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline"}'),
    m("word-union-not-a-tag", C, 'TAG_WORDS = {"struct", "union", "enum"}', 'TAG_WORDS = {"struct", "enum"}'),
    m("word-enum-not-a-tag", C, 'TAG_WORDS = {"struct", "union", "enum"}', 'TAG_WORDS = {"struct", "union"}'),
    m("word-struct-not-a-tag", C, 'TAG_WORDS = {"struct", "union", "enum"}', 'TAG_WORDS = {"union", "enum"}'),
    m("tokens-no-ellipsis", C, r'(\.\.\.)|', ''),
    m("tokens-no-number", C, r'|(\d+)', ''),
    m("tokens-no-semicolon", C, r'[*()\[\],;]', r'[*()\[\],]'),
    m("tokens-no-comma", C, r'[*()\[\],;]', r'[*()\[\];]'),
    m("tokens-no-square", C, r'[*()\[\],;]', r'[*()\,;]'),
    m("tokens-trailing-garbage-read", C, "        if found is None:\n            raise ParseError", "        if found is None and False:\n            raise ParseError"),
    m("name-regex-allows-a-number", C, 'NAME = re.compile(r"[A-Za-z_]\\w*")', 'NAME = re.compile(r"\\w+")'),
    m("name-keywords-allowed", C, "    return bool(NAME.fullmatch(word)) and word not in KEYWORDS", "    return bool(NAME.fullmatch(word))"),
    m("name-type-word-allowed", C, "KEYWORDS = TYPE_WORDS | QUALIFIER_WORDS | IGNORED_WORDS | TAG_WORDS", "KEYWORDS = QUALIFIER_WORDS | IGNORED_WORDS | TAG_WORDS"),
    m("name-qualifier-allowed", C, "KEYWORDS = TYPE_WORDS | QUALIFIER_WORDS | IGNORED_WORDS | TAG_WORDS", "KEYWORDS = TYPE_WORDS | IGNORED_WORDS | TAG_WORDS"),
    m("name-storage-word-allowed", C, "KEYWORDS = TYPE_WORDS | QUALIFIER_WORDS | IGNORED_WORDS | TAG_WORDS", "KEYWORDS = TYPE_WORDS | QUALIFIER_WORDS | TAG_WORDS"),
    m("name-tag-word-allowed", C, "KEYWORDS = TYPE_WORDS | QUALIFIER_WORDS | IGNORED_WORDS | TAG_WORDS", "KEYWORDS = TYPE_WORDS | QUALIFIER_WORDS | IGNORED_WORDS"),
    m("declarator-name-in-an-abstract-one", C, "        elif named and is_name(self.peek()):", "        elif is_name(self.peek()):"),
    m("declarator-name-never", C, "        elif named and is_name(self.peek()):", "        elif False and is_name(self.peek()):"),
    m("declarator-name-anything", C, "        elif named and is_name(self.peek()):", "        elif named and self.peek():"),
    m("declarator-group-unfinished-is-fine", C, "        base = nested.declarator(base, named)\n        nested.finish()", "        base = nested.declarator(base, named)"),
    m("declarator-group-named-always", C, "        base = nested.declarator(base, named)\n", "        base = nested.declarator(base, True)\n"),
    m("declarator-group-never-named", C, "        base = nested.declarator(base, named)\n", "        base = nested.declarator(base, False)\n"),
    m("parameters-void-stays-a-parameter", C, "        if NO_VALUE in params:\n            if len(params) > 1 or variadic:", "        if False:\n            if len(params) > 1 or variadic:"),
    m("parameters-void-beside-others-is-fine", C, "            if len(params) > 1 or variadic:", "            if variadic:"),
    m("parameters-void-beside-an-ellipsis-is-fine", C, "            if len(params) > 1 or variadic:", "            if len(params) > 1:"),
    m("parameters-void-is-a-parameter-when-first", C, "        if NO_VALUE in params:", "        if params[:1] == [NO_VALUE]:"),
    m("parameters-void-pointer-is-no-parameter", C, "        if NO_VALUE in params:", "        if any(param.kind == VOID for param in params):", (TYPES, GATE), False,
      "equivalent on valid C: a qualified lone `void` is not a parameter list, and `void*` has kind pointer"),
    m("parameters-named-not-allowed", C, "                    params.append(self.declarator(self.specifiers(), named=True))", "                    params.append(self.declarator(self.specifiers(), named=False))"),
    m("type-unfinished-is-fine", C, "    ty = parser.declarator(parser.specifiers(), named=False)\n    parser.finish()\n    return ty", "    ty = parser.declarator(parser.specifiers(), named=False)\n    return ty"),
    m("base-bool-has-a-width", C, '    if "_Bool" in words or "bool" in words:\n        return CType(BOOL)', '    if "_Bool" in words or "bool" in words:\n        return CType(BOOL, width=1)'),
    m("dwarf-bool-has-a-width", C, "    if encoding == 2:\n        return CType(BOOL)", "    if encoding == 2:\n        return CType(BOOL, width=size)"),
    # What a parameter or a result is.
    m("decay-array-stays", C, "    if ty.kind == ARRAY:\n        ty = pointer(ty.target)\n    elif", "    if False:\n        ty = pointer(ty.target)\n    elif"),
    m("decay-function-stays", C, "    elif ty.kind == FUNC:\n        ty = pointer(ty)", "    elif False:\n        ty = pointer(ty)"),
    m("decay-keeps-const", C, "    return replace(ty, const=False, volatile=False)\n\n\n@dataclass(frozen=True)\nclass Prototype", "    return replace(ty, volatile=False)\n\n\n@dataclass(frozen=True)\nclass Prototype"),
    m("decay-keeps-volatile", C, "    return replace(ty, const=False, volatile=False)\n\n\n@dataclass(frozen=True)\nclass Prototype", "    return replace(ty, const=False)\n\n\n@dataclass(frozen=True)\nclass Prototype"),
    # The parser.
    m("parser-take-past-the-end", C, '        if self.at >= len(self.tokens):\n            raise ParseError("the text ends inside a declaration")\n', ''),
    m("parser-expect-anything", C, "        if self.take() != token:\n            raise ParseError", "        if self.take() != token and False:\n            raise ParseError"),
    m("specifiers-const-lost", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            elif word in IGNORED_WORDS:', '                volatile |= word == "volatile"\n            elif word in IGNORED_WORDS:'),
    m("specifiers-volatile-lost", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            elif word in IGNORED_WORDS:', '                const |= word == "const"\n            elif word in IGNORED_WORDS:'),
    m("specifiers-const-for-any-qualifier", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            elif word in IGNORED_WORDS:', '                const = True\n                volatile |= word == "volatile"\n            elif word in IGNORED_WORDS:'),
    m("specifiers-volatile-for-any-qualifier", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            elif word in IGNORED_WORDS:', '                const |= word == "const"\n                volatile = True\n            elif word in IGNORED_WORDS:'),
    m("specifiers-ignored-word-ends-them", C, "            elif word in IGNORED_WORDS:\n                pass", "            elif word in IGNORED_WORDS:\n                break"),
    m("specifiers-tag-without-its-name", C, '                tag = f"{word} {self.identifier()}"\n                continue', '                tag = word\n                continue'),
    m("specifiers-tag-ends-nothing", C, '                tag = f"{word} {self.identifier()}"\n                continue', '                tag = f"{word} {self.identifier()}"'),
    m("specifiers-second-name-is-a-type", C, "and not (words or tag or typedef):", "and not (words or tag):"),
    m("specifiers-name-after-a-keyword-is-a-type", C, "and not (words or tag or typedef):", "and not (tag or typedef):"),
    m("specifiers-name-after-a-tag-is-a-type", C, "and not (words or tag or typedef):", "and not (words or typedef):"),
    m("specifiers-no-type-is-fine", C, '        if not (words or tag or typedef):\n            raise ParseError("no type")', '        if False:\n            raise ParseError("no type")'),
    m("specifiers-type-lost-const", C, "        return replace(base_type(words, tag, typedef), const=const, volatile=volatile)", "        return replace(base_type(words, tag, typedef), volatile=volatile)"),
    m("specifiers-type-lost-volatile", C, "        return replace(base_type(words, tag, typedef), const=const, volatile=volatile)", "        return replace(base_type(words, tag, typedef), const=const)"),
    m("declarator-pointer-const-lost", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            base = CType(PTR', '                volatile |= word == "volatile"\n            base = CType(PTR'),
    m("declarator-pointer-volatile-lost", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            base = CType(PTR', '                const |= word == "const"\n            base = CType(PTR'),
    m("declarator-pointer-const-always", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            base = CType(PTR', '                const = True\n                volatile |= word == "volatile"\n            base = CType(PTR'),
    m("declarator-pointer-volatile-always", C, '                const |= word == "const"\n                volatile |= word == "volatile"\n            base = CType(PTR', '                const |= word == "const"\n                volatile = True\n            base = CType(PTR'),
    m("declarator-pointer-qualifiers-ignored", C, "            while self.peek() in QUALIFIER_WORDS:\n                word = self.take()", "            while False:\n                word = self.take()"),
    m("declarator-pointer-const-dropped-from-type", C, "            base = CType(PTR, target=base, const=const, volatile=volatile)", "            base = CType(PTR, target=base, volatile=volatile)"),
    m("declarator-pointer-volatile-dropped-from-type", C, "            base = CType(PTR, target=base, const=const, volatile=volatile)", "            base = CType(PTR, target=base, const=const)"),
    m("declarator-group-only-after-star", C, 'if self.peek() == "(" and self.peek(1) in ("*", "("):', 'if self.peek() == "(" and self.peek(1) in ("*",):'),
    m("declarator-group-only-after-paren", C, 'if self.peek() == "(" and self.peek(1) in ("*", "("):', 'if self.peek() == "(" and self.peek(1) in ("(",):'),
    m("declarator-never-a-group", C, 'if self.peek() == "(" and self.peek(1) in ("*", "("):', 'if False:'),
    m("declarator-no-array-suffix", C, '        while self.peek() in ("[", "("):\n            if self.peek() == "[":', '        while self.peek() in ("(",):\n            if self.peek() == "[":'),
    m("declarator-no-function-suffix", C, '        while self.peek() in ("[", "("):\n            if self.peek() == "[":', '        while self.peek() in ("[",):\n            if self.peek() == "[":'),
    m("declarator-array-count-lost", C, '                count = int(self.take()) if self.peek().isdigit() else None', '                count = None'),
    m("declarator-array-count-always-read", C, '                count = int(self.take()) if self.peek().isdigit() else None', '                count = int(self.take())'),
    m("declarator-array-count-not-consumed", C, '                count = int(self.take()) if self.peek().isdigit() else None\n                self.expect("]")', '                count = int(self.peek()) if self.peek().isdigit() else None\n                self.expect("]")'),
    m("declarator-suffixes-left-to-right", C, "        for kind, detail in reversed(suffixes):", "        for kind, detail in suffixes:"),
    m("declarator-array-as-function", C, '            if kind == "array":\n                base = CType(ARRAY, target=base, count=detail)', '            if kind == "array":\n                base = CType(FUNC, target=base, params=(), variadic=False)'),
    m("declarator-function-variadic-lost", C, "                base = CType(FUNC, target=base, params=params, variadic=variadic)", "                base = CType(FUNC, target=base, params=params)"),
    m("declarator-function-params-lost", C, "                base = CType(FUNC, target=base, params=params, variadic=variadic)", "                base = CType(FUNC, target=base, variadic=variadic)"),
    m("group-depth-counts-nothing", C, '            depth += token == "("', '            depth += False'),
    m("group-depth-counts-close-as-open", C, '            depth -= token == ")"', '            depth -= token == "("'),
    m("group-includes-its-close", C, "        return self.tokens[start:self.at - 1]", "        return self.tokens[start:self.at]"),
    m("parameters-ellipsis-is-a-parameter", C, '                if self.peek() == "...":\n                    self.take()\n                    variadic = True', '                if self.peek() == "...":\n                    self.take()'),
    m("parameters-ellipsis-never", C, '                if self.peek() == "...":', '                if False:'),
    m("parameters-one-only", C, '                if self.peek() != ",":\n                    break\n                self.take()', '                break'),
    m("parameters-not-decayed", C, "        return tuple(decay(param) for param in params), variadic", "        return tuple(params), variadic"),
    m("parameters-empty-list-reads-one", C, '        if self.peek() != ")":\n            while True:', '        if True:\n            while True:'),
    m("finish-ignores-the-rest", C, "        if self.at != len(self.tokens):\n            raise ParseError(f\"unread text", "        if False:\n            raise ParseError(f\"unread text"),
    # The base type of a set of words.
    m("base-tag-lost", C, "    if tag:\n        return CType(NAMED, name=tag)", "    if False:\n        return CType(NAMED, name=tag)"),
    m("base-typedef-lost", C, "    if typedef:\n        return integer(*INT_NAMES[typedef]) if typedef in INT_NAMES else CType(NAMED, name=typedef)", "    if False:\n        return integer(*INT_NAMES[typedef]) if typedef in INT_NAMES else CType(NAMED, name=typedef)"),
    m("base-typedef-always-named", C, "return integer(*INT_NAMES[typedef]) if typedef in INT_NAMES else CType(NAMED, name=typedef)", "return CType(NAMED, name=typedef)"),
    m("base-void-lost", C, '    if "void" in words:\n        return NO_VALUE', '    if False:\n        return NO_VALUE'),
    m("base-bool-lost", C, '    if "_Bool" in words or "bool" in words:', '    if "_Bool" in words:'),
    m("base-bool-keyword-lost", C, '    if "_Bool" in words or "bool" in words:', '    if "bool" in words:'),
    m("base-float-width", C, "        return CType(FLOAT, width=4)", "        return CType(FLOAT, width=8)"),
    m("base-double-width", C, "CType(FLOAT, width=16 if \"long\" in words else 8)", "CType(FLOAT, width=8)"),
    m("base-long-double-width", C, "CType(FLOAT, width=16 if \"long\" in words else 8)", "CType(FLOAT, width=16)"),
    m("base-unsigned-lost", C, 'signed = False if "unsigned" in words else True if "signed" in words else None', 'signed = True if "signed" in words else None'),
    m("base-signed-lost", C, 'signed = False if "unsigned" in words else True if "signed" in words else None', 'signed = False if "unsigned" in words else None'),
    m("base-char-sign-always-known", C, '    if "char" in words:\n        return integer(1, signed)', '    if "char" in words:\n        return integer(1, signed is not False)'),
    m("base-char-width", C, '        return integer(1, signed)', '        return integer(2, signed)'),
    m("base-short-width", C, 'width = 2 if "short" in words else 8 if "long" in words else 4', 'width = 4 if "short" in words else 8 if "long" in words else 4'),
    m("base-long-width", C, 'width = 2 if "short" in words else 8 if "long" in words else 4', 'width = 2 if "short" in words else 4 if "long" in words else 4'),
    m("base-int-width", C, 'width = 2 if "short" in words else 8 if "long" in words else 4', 'width = 2 if "short" in words else 8 if "long" in words else 8'),
    m("base-plain-int-unsigned", C, "    return integer(width, signed is not False)", "    return integer(width, signed is True)"),
    m("base-unsigned-int-signed", C, "    return integer(width, signed is not False)", "    return integer(width, True)"),
    # The prototype of a header.
    m("prototype-semicolon-unread", C, '    if parser.peek() == ";":\n        parser.take()\n', ''),
    m("prototype-result-not-decayed", C, "    return Prototype(name, decay(ret), params, variadic)", "    return Prototype(name, ret, params, variadic)"),
    m("prototype-variadic-lost", C, "    return Prototype(name, decay(ret), params, variadic)", "    return Prototype(name, decay(ret), params, False)"),
    m("prototype-name-any-word", C, "    name = parser.identifier()\n    params, variadic = parser.parameters()", "    name = parser.take()\n    params, variadic = parser.parameters()"),
    # The spelling.
    m("spell-pointer-const-lost", C, '        qualifiers = (" const" if ty.const else "") + (" volatile" if ty.volatile else "")', '        qualifiers = (" volatile" if ty.volatile else "")'),
    m("spell-pointer-volatile-lost", C, '        qualifiers = (" const" if ty.const else "") + (" volatile" if ty.volatile else "")', '        qualifiers = (" const" if ty.const else "")'),
    m("spell-function-pointer-ungrouped", C, "        grouped = f\"({star}{inner})\" if ty.target.kind in (FUNC, ARRAY) else star + inner", "        grouped = star + inner"),
    m("spell-array-pointer-ungrouped", C, "ty.target.kind in (FUNC, ARRAY)", "ty.target.kind in (FUNC,)"),
    m("spell-function-pointer-grouped-only-for-arrays", C, "ty.target.kind in (FUNC, ARRAY)", "ty.target.kind in (ARRAY,)"),
    m("spell-array-count-lost", C, "return declare(ty.target, f\"{inner}[{'' if ty.count is None else ty.count}]\")", "return declare(ty.target, f\"{inner}[]\")"),
    m("spell-array-unbounded-as-zero", C, "'' if ty.count is None else ty.count", "0 if ty.count is None else ty.count"),
    m("spell-function-variadic-lost", C, "        params = [spell(param) for param in ty.params] + ([\"...\"] if ty.variadic else [])", "        params = [spell(param) for param in ty.params]"),
    m("spell-function-no-params-empty", C, "{', '.join(params) or 'void'}", "{', '.join(params)}"),
    m("spell-function-params-joined-tight", C, "{', '.join(params) or 'void'}", "{','.join(params) or 'void'}"),
    m("spell-const-lost", C, '    words = [word for word, on in (("const", ty.const), ("volatile", ty.volatile)) if on]', '    words = [word for word, on in (("volatile", ty.volatile),) if on]'),
    m("spell-volatile-lost", C, '    words = [word for word, on in (("const", ty.const), ("volatile", ty.volatile)) if on]', '    words = [word for word, on in (("const", ty.const),) if on]'),
    m("spell-volatile-before-const", C, '(("const", ty.const), ("volatile", ty.volatile))', '(("volatile", ty.volatile), ("const", ty.const))'),
    m("spell-star-spaced", C, '"" if not inner or inner.startswith("*") else " "', '"" if not inner else " "'),
    m("spell-paren-tight", C, '"" if not inner or inner.startswith("*") else " "', '""'),
    m("spell-bracket-spaced-wrongly", C, '"" if not inner or inner.startswith("*") else " "', '"" if not inner or inner.startswith("*") or inner.startswith("[") else " "'),
    m("spell-char-name", C, '"char" if ty.signed is None else', '"int8_t" if ty.signed is None else'),
    m("spell-unsigned-prefix", C, "f\"{'' if ty.signed else 'u'}int{ty.width * 8}_t\"", "f\"{'u' if ty.signed else ''}int{ty.width * 8}_t\""),
    m("spell-width-in-bits", C, "f\"{'' if ty.signed else 'u'}int{ty.width * 8}_t\"", "f\"{'' if ty.signed else 'u'}int{ty.width}_t\""),
    m("spell-float-name", C, '{4: "float", 8: "double"}.get(ty.width, "long double")', '{4: "float", 8: "double"}.get(ty.width, "double")'),
    m("spell-double-name", C, '{4: "float", 8: "double"}.get(ty.width, "long double")', '{4: "float", 8: "float"}.get(ty.width, "long double")'),
    m("spell-void-name", C, '{VOID: "void", BOOL: "bool"}.get(ty.kind) or ty.name', '{VOID: "void"}.get(ty.kind) or ty.name'),
    m("spell-bool-name", C, '{VOID: "void", BOOL: "bool"}.get(ty.kind) or ty.name', '{BOOL: "bool"}.get(ty.kind) or ty.name'),
    # Qualifiers.
    m("unqualified-keeps-const", C, "    ty = replace(ty, const=False, volatile=False)\n    if ty.target is not None:", "    ty = replace(ty, volatile=False)\n    if ty.target is not None:"),
    m("unqualified-keeps-volatile", C, "    ty = replace(ty, const=False, volatile=False)\n    if ty.target is not None:", "    ty = replace(ty, const=False)\n    if ty.target is not None:"),
    m("unqualified-top-level-only", C, "        ty = replace(ty, target=unqualified(ty.target))", "        pass"),
    m("unqualified-params-kept", C, "        ty = replace(ty, params=tuple(unqualified(param) for param in ty.params))", "        pass"),
    # The buckets.
    m("classify-void-pair", C, '    if (expected.kind == VOID) != (actual.kind == VOID):', '    if expected.kind == VOID and actual.kind != VOID:'),
    m("classify-void-first-lost", C, '    if (expected.kind == VOID) != (actual.kind == VOID):\n        return "void_vs_value"', '    if False:\n        return "void_vs_value"'),
    m("classify-pointer-mismatch-lost", C, '    if (expected.kind == PTR) != (actual.kind == PTR):\n        return "pointer_as_integer" if expected.kind == PTR else "integer_as_pointer"', '    if False:\n        return "pointer_as_integer"'),
    m("classify-pointer-as-integer-flipped", C, 'return "pointer_as_integer" if expected.kind == PTR else "integer_as_pointer"', 'return "integer_as_pointer" if expected.kind == PTR else "pointer_as_integer"'),
    m("classify-qualifier-always", C, 'return "qualifier" if unqualified(expected) == unqualified(actual) else "pointee"', 'return "qualifier"'),
    m("classify-pointee-always", C, 'return "qualifier" if unqualified(expected) == unqualified(actual) else "pointee"', 'return "pointee"'),
    m("classify-qualifier-top-only", C, 'return "qualifier" if unqualified(expected) == unqualified(actual) else "pointee"', 'return "qualifier" if replace(expected.target, const=False, volatile=False) == replace(actual.target, const=False, volatile=False) else "pointee"'),
    m("classify-width-flipped", C, 'return "width_wider" if actual.width > expected.width else "width_narrower"', 'return "width_wider" if actual.width < expected.width else "width_narrower"'),
    m("classify-width-ignored", C, "        if expected.width != actual.width:\n            return", "        if False:\n            return"),
    m("classify-sign-needs-one-known", C, "if expected.signed is not None and actual.signed is not None and expected.signed != actual.signed:", "if (expected.signed is not None or actual.signed is not None) and expected.signed != actual.signed:"),
    m("classify-sign-of-unknown", C, "if expected.signed is not None and actual.signed is not None and expected.signed != actual.signed:", "if expected.signed != actual.signed:"),
    m("classify-sign-lost", C, "if expected.signed is not None and actual.signed is not None and expected.signed != actual.signed:", "if False:"),
    m("classify-ints-only", C, "    if expected.kind == actual.kind == INT:", "    if expected.kind == actual.kind:"),
    m("integer-class-floats", C, "    return ty.kind in (INT, BOOL, PTR) and ty.width <= 8", "    return ty.kind in (INT, BOOL, PTR, FLOAT) and ty.width <= 8"),
    m("integer-class-bool", C, "    return ty.kind in (INT, BOOL, PTR) and ty.width <= 8", "    return ty.kind in (INT, PTR) and ty.width <= 8"),
    m("integer-class-pointer", C, "    return ty.kind in (INT, BOOL, PTR) and ty.width <= 8", "    return ty.kind in (INT, BOOL) and ty.width <= 8"),
    m("integer-class-int", C, "    return ty.kind in (INT, BOOL, PTR) and ty.width <= 8", "    return ty.kind in (BOOL, PTR) and ty.width <= 8"),
    m("integer-class-wide", C, "    return ty.kind in (INT, BOOL, PTR) and ty.width <= 8", "    return ty.kind in (INT, BOOL, PTR)"),
    m("integer-class-aggregates", C, "    return ty.kind in (INT, BOOL, PTR) and ty.width <= 8", "    return ty.kind in (INT, BOOL, PTR, NAMED) and ty.width <= 8"),
    # DWARF types.
    m("dwarf-nesting-unbounded", C, "    if depth > 32:", "    if depth > 3200:"),
    m("dwarf-nesting-one-short", C, "    if depth > 32:", "    if depth > 29:"),
    m("dwarf-chain-unbounded", C, "        if steps > 64:", "        if steps > 6400:"),
    m("dwarf-chain-one-short", C, "        if steps > 64:", "        if steps > 60:"),
    m("dwarf-missing-die-is-void", C, '        if die is None:\n            raise NotExpressible(f"no DIE at {offset:#x}")', '        if die is None:\n            return NO_VALUE'),
    m("dwarf-const-lost", C, '            const |= die.tag == "DW_TAG_const_type"\n', ''),
    m("dwarf-volatile-lost", C, '            volatile |= die.tag == "DW_TAG_volatile_type"\n', ''),
    m("dwarf-const-for-volatile", C, '            const |= die.tag == "DW_TAG_const_type"', '            const = True'),
    m("dwarf-volatile-for-const", C, '            volatile |= die.tag == "DW_TAG_volatile_type"', '            volatile = True'),
    m("dwarf-typedef-opaque", C, '        elif die.tag == "DW_TAG_typedef":\n            alias = alias or die.text("DW_AT_name") or ""', '        elif die.tag == "DW_TAG_typedef":\n            break'),
    m("dwarf-alias-innermost", C, '            alias = alias or die.text("DW_AT_name") or ""', '            alias = die.text("DW_AT_name") or ""'),
    m("dwarf-restrict-opaque", C, '        elif die.tag not in ("DW_TAG_restrict_type", "DW_TAG_atomic_type"):', '        elif die.tag not in ("DW_TAG_atomic_type",):'),
    m("dwarf-atomic-opaque", C, '        elif die.tag not in ("DW_TAG_restrict_type", "DW_TAG_atomic_type"):', '        elif die.tag not in ("DW_TAG_restrict_type",):'),
    m("dwarf-qualified-void-const-lost", C, "        return replace(NO_VALUE, const=const, volatile=volatile)", "        return NO_VALUE"),
    m("dwarf-qualifiers-lost", C, "    return replace(shape_of_dwarf(dwarf, die, alias, depth), const=const, volatile=volatile)", "    return shape_of_dwarf(dwarf, die, alias, depth)"),
    m("dwarf-qualifier-const-lost", C, "    return replace(shape_of_dwarf(dwarf, die, alias, depth), const=const, volatile=volatile)", "    return replace(shape_of_dwarf(dwarf, die, alias, depth), volatile=volatile)"),
    m("dwarf-qualifier-volatile-lost", C, "    return replace(shape_of_dwarf(dwarf, die, alias, depth), const=const, volatile=volatile)", "    return replace(shape_of_dwarf(dwarf, die, alias, depth), const=const)"),
    m("dwarf-size-from-nothing", C, '    size = die.number("DW_AT_byte_size") or 0\n', '    size = 0\n'),
    m("dwarf-enum-size-default", C, 'integer(size or 4, from_dwarf', 'integer(size or 8, from_dwarf'),
    m("dwarf-enum-signed-default", C, "if underlying is not None else False)", "if underlying is not None else True)"),
    m("dwarf-enum-underlying-ignored", C, "from_dwarf(dwarf, underlying, depth + 1).signed if underlying is not None else False", "False"),
    m("dwarf-enum-width-from-underlying", C, 'integer(size or 4, from_dwarf', 'integer(size, from_dwarf'),
    m("dwarf-pointer-kinds", C, 'if die.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type"):', 'if die.tag in ("DW_TAG_pointer_type",):'),
    m("dwarf-union-keyword", C, 'keyword = "union" if die.tag == "DW_TAG_union_type" else "struct"', 'keyword = "struct"'),
    m("dwarf-class-is-a-struct", C, 'if die.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):', 'if die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):'),
    m("dwarf-anonymous-struct-nameless", C, 'else alias or f"{keyword} <anonymous>")', 'else f"{keyword} <anonymous>")'),
    m("dwarf-anonymous-type-nameless", C, 'else alias or f"{keyword} <anonymous>")', 'else alias)'),
    m("dwarf-tag-after-alias", C, 'name=f"{keyword} {tag}" if tag else alias', 'name=alias or f"{keyword} {tag}" if tag else alias'),
    m("dwarf-array-bound-off-by-one", C, "None if upper is None else upper + 1", "None if upper is None else upper"),
    m("dwarf-array-count-ignored", C, "counts.append(counted if counted is not None else None if upper is None else upper + 1)", "counts.append(None if upper is None else upper + 1)"),
    m("dwarf-array-dimensions-reversed", C, "        for count in reversed(counts or [None]):", "        for count in counts or [None]:"),
    m("dwarf-array-without-subrange-has-none", C, "        for count in reversed(counts or [None]):", "        for count in reversed(counts):"),
    m("dwarf-array-element-void", C, '        element = from_dwarf(dwarf, die.ref("DW_AT_type"), depth + 1)\n        counts = []', '        element = NO_VALUE\n        counts = []'),
    m("dwarf-subroutine-params-decay-lost", C, '            decay(from_dwarf(dwarf, child.ref("DW_AT_type"), depth + 1))\n            for child in die.children if child.tag == "DW_TAG_formal_parameter"', '            from_dwarf(dwarf, child.ref("DW_AT_type"), depth + 1)\n            for child in die.children if child.tag == "DW_TAG_formal_parameter"'),
    m("dwarf-subroutine-variadic-lost", C, "        return CType(FUNC, target=from_dwarf(dwarf, die.ref(\"DW_AT_type\"), depth + 1), params=params, variadic=variadic)", "        return CType(FUNC, target=from_dwarf(dwarf, die.ref(\"DW_AT_type\"), depth + 1), params=params)"),
    m("dwarf-subroutine-result-void", C, "        return CType(FUNC, target=from_dwarf(dwarf, die.ref(\"DW_AT_type\"), depth + 1), params=params, variadic=variadic)", "        return CType(FUNC, target=NO_VALUE, params=params, variadic=variadic)"),
    m("dwarf-unknown-tag-is-void", C, "    raise NotExpressible(die.tag)", "    return NO_VALUE"),
    m("dwarf-float-width", C, "        return CType(FLOAT, width=size)", "        return CType(FLOAT, width=8)"),
    m("dwarf-plain-char-by-name", C, '    if encoding in (6, 8) and die.text("DW_AT_name") == "char":', '    if encoding in (6, 8):'),
    m("dwarf-plain-char-any-encoding", C, '    if encoding in (6, 8) and die.text("DW_AT_name") == "char":', '    if encoding in (6,) and die.text("DW_AT_name") == "char":'),
    m("dwarf-signed-char-encoding", C, "    if encoding in (5, 6):\n        return integer(size, True)", "    if encoding in (5,):\n        return integer(size, True)"),
    m("dwarf-unsigned-char-encoding", C, "    if encoding in (7, 8, 0x10):\n        return integer(size, False)", "    if encoding in (7, 0x10):\n        return integer(size, False)"),
    m("dwarf-utf-encoding", C, "    if encoding in (7, 8, 0x10):\n        return integer(size, False)", "    if encoding in (7, 8):\n        return integer(size, False)"),
    m("dwarf-unsigned-encoding", C, "    if encoding in (7, 8, 0x10):\n        return integer(size, False)", "    if encoding in (8, 0x10):\n        return integer(size, False)"),
    m("dwarf-signed-encoding", C, "    if encoding in (5, 6):\n        return integer(size, True)", "    if encoding in (6,):\n        return integer(size, True)"),
    m("dwarf-unknown-encoding-is-an-integer", C, '    raise NotExpressible(f"base type encoding {encoding}")', '    return integer(size, True)'),
    m("dwarf-boolean-encoding", C, "    if encoding == 2:\n        return CType(BOOL", "    if encoding == 3:\n        return CType(BOOL"),
    m("dwarf-float-encoding", C, "    if encoding == 4:\n        return CType(FLOAT", "    if encoding == 3:\n        return CType(FLOAT"),
]

# The gate.
MUTANTS += [
    m("ask-stderr-merged", G, "        capture_output=True, text=True, errors=\"replace\", timeout=1800, check=False,", "        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors=\"replace\", timeout=1800, check=False,", (GATE,)),
    m("ask-all-stderr", G, "line + \"\\n\" for line in proc.stderr.splitlines() if line.startswith(r2s_batch.ERROR_PREFIX)", "line + \"\\n\" for line in proc.stderr.splitlines()", (GATE,)),
    m("ask-no-stderr", G, "    return r2s_batch.parse_pddj(address, declines + proc.stdout)", "    return r2s_batch.parse_pddj(address, proc.stdout)", (GATE,)),
    m("ask-no-stdout", G, "    return r2s_batch.parse_pddj(address, declines + proc.stdout)", "    return r2s_batch.parse_pddj(address, declines)", (GATE,)),
    m("ask-stdout-first", G, "    return r2s_batch.parse_pddj(address, declines + proc.stdout)", "    return r2s_batch.parse_pddj(address, proc.stdout + declines)", (GATE,), False,
      "equivalent: parse_pddj separates the `r2s:` lines from the payload by their prefix, wherever they sit"),
    m("ask-timeout-is-a-refusal", G, 'return r2s_batch.Answer(address, "crash", cause="harness: r2s ran past its deadline")', 'return r2s_batch.Answer(address, "decline", cause="harness: r2s ran past its deadline", refusal="deadline")', (GATE,)),
    m("ask-no-shell-is-uncaught", G, "    except OSError as error:\n        return r2s_batch.Answer", "    except KeyError as error:\n        return r2s_batch.Answer", (GATE,)),
    m("ask-command-address", G, 'f"s {address:#x}; pddj"', 'f"s {address}; pddj"', (GATE,)),
    m("r2s-quiet-lost", G, '[r2s_bin, "-q", "-c", commands, str(binary)]', '[r2s_bin, "-c", commands, str(binary)]', (GATE,)),
    m("r2s-deadline-shorter", G, "timeout=1800", "timeout=1", (GATE,)),
    m("listing-key-error-uncaught", G, "except (json.JSONDecodeError, TypeError, KeyError) as error:", "except (json.JSONDecodeError, TypeError) as error:", (GATE,)),
    m("listing-type-error-uncaught", G, "except (json.JSONDecodeError, TypeError, KeyError) as error:", "except (json.JSONDecodeError, KeyError) as error:", (GATE,)),
    m("listing-json-error-uncaught", G, "except (json.JSONDecodeError, TypeError, KeyError) as error:", "except (TypeError, KeyError) as error:", (GATE,)),
    m("listing-timeout-uncaught", G, "    except (subprocess.TimeoutExpired, OSError) as error:\n        raise Unreadable(binary, \"aflj\"", "    except (OSError,) as error:\n        raise Unreadable(binary, \"aflj\"", (GATE,)),
    m("listing-oserror-uncaught", G, "    except (subprocess.TimeoutExpired, OSError) as error:\n        raise Unreadable(binary, \"aflj\"", "    except (subprocess.TimeoutExpired,) as error:\n        raise Unreadable(binary, \"aflj\"", (GATE,)),
    m("listing-address-any", G, "        if not all(isinstance(row[\"addr\"], int) for row in rows):\n            raise TypeError(\"an address that is no number\")\n", "", (GATE,)),
    m("listing-name-lost", G, "        return {row[\"addr\"]: row[\"name\"] for row in rows}", "        return {row[\"addr\"]: \"\" for row in rows}", (GATE,)),
    m("dwarf-os-error-uncaught", G, "    except (OSError, RuntimeError) as error:\n        raise Unreadable(binary, \"readelf\"", "    except (RuntimeError,) as error:\n        raise Unreadable(binary, \"readelf\"", (GATE,)),
    m("dwarf-runtime-error-uncaught", G, "    except (OSError, RuntimeError) as error:\n        raise Unreadable(binary, \"readelf\"", "    except (OSError,) as error:\n        raise Unreadable(binary, \"readelf\"", (GATE,)),
    m("dwarf-prefix-ignored", G, "    target = dataclasses.replace(X86_64, binutils_prefix=binutils_prefix)", "    target = X86_64", (GATE,)),
    m("signatures-refusal-is-unreadable", G, "        if answer.refusal is not None:\n            continue\n", "", (GATE,)),
    m("signatures-unreadable-skipped", G, "        if not answer.ok:\n            unreadable[f\"{addr:#x}\"] = answer.cause\n            continue\n", "        if not answer.ok:\n            continue\n", (GATE,)),
    m("signatures-noproto-skipped", G, "            unreadable[f\"{addr:#x}\"] = f\"signature {record['signature']!r} is no prototype ({error})\"\n            continue", "            continue", (GATE,)),
    m("signatures-definition-unchecked", G, "        if proto.name != record[\"definition\"]:", "        if False:", (GATE,)),
    m("signatures-definition-wrong-field", G, "        if proto.name != record[\"definition\"]:", "        if proto.name != record[\"name\"]:", (GATE,)),
    m("signatures-unreadable-not-raised", G, "    if unreadable:\n        raise Unreadable(binary, \"pddj\", unreadable)", "    if False:\n        raise Unreadable(binary, \"pddj\", unreadable)", (GATE,)),
    m("signatures-marker-is-the-count", G, "        out[addr] = Seen(proto, bool(record[\"residuals\"]))", "        out[addr] = Seen(proto, record[\"proof\"][\"residual\"] > 0)", (GATE,)),
    m("signatures-marker-is-either", G, "        out[addr] = Seen(proto, bool(record[\"residuals\"]))", "        out[addr] = Seen(proto, bool(record[\"residuals\"]) or record[\"proof\"][\"residual\"] > 0)", (GATE,)),
    m("signatures-marker-never", G, "        out[addr] = Seen(proto, bool(record[\"residuals\"]))", "        out[addr] = Seen(proto, False)", (GATE,)),
    m("signatures-marker-always", G, "        out[addr] = Seen(proto, bool(record[\"residuals\"]))", "        out[addr] = Seen(proto, True)", (GATE,)),
    m("signatures-marker-is-the-code", G, "        out[addr] = Seen(proto, bool(record[\"residuals\"]))", "        out[addr] = Seen(proto, \"residual\" in record[\"code\"])", (GATE,)),
    m("declared-return-unreadable-kept", G, "            return Slot(c_types.decay(c_types.from_dwarf(dwarf, offset)))", "            return Slot(c_types.from_dwarf(dwarf, offset))", (GATE,)),
    m("declared-not-expressible-uncaught", G, "        except c_types.NotExpressible as error:", "        except KeyError as error:", (GATE,)),
    m("declared-reason-lost", G, "            return Slot(None, f\"{CANNOT_STATE} ({error})\")", "            return Slot(None, CANNOT_STATE)", (GATE,)),
    m("declared-no-type-parameter-is-void", G, "slot = typed(param.type_offset) if param.type_offset is not None else Slot(None, f\"{CANNOT_STATE} (no type)\")", "slot = typed(param.type_offset)", (GATE,)),
    m("declared-position-ignored", G, "        if slot.expected is not None and not positioned:\n            slot = Slot(None, AFTER_ONE_NOT)", "        if False:\n            slot = Slot(None, AFTER_ONE_NOT)", (GATE,)),
    m("declared-class-ignored", G, "        elif slot.expected is not None and not c_types.integer_class(slot.expected):\n            slot = Slot(None, NOT_IN_REGISTER)", "        elif False:\n            slot = Slot(None, NOT_IN_REGISTER)", (GATE,)),
    m("declared-positions-never-end", G, "        positioned = slot.expected is not None", "        positioned = True", (GATE,)),
    m("declared-unreadable-keeps-position", G, "        positioned = slot.expected is not None", "        positioned = slot.expected is not None or slot.why.startswith(CANNOT_STATE)", (GATE,)),
    m("score-missing-is-wrong", G, "            elif seen is None:\n                counts[\"missing\"] += 1", "            elif seen is None:\n                counts[\"silently_wrong\"] += 1", (GATE,)),
    m("score-unreadable-counted-as-missing", G, "            if slot.expected is None:\n                tally.unreadable[slot.why] += 1", "            if slot.expected is None:\n                counts[\"missing\"] += 1", (GATE,)),
    m("score-unreadable-uncounted", G, "                tally.unreadable[slot.why] += 1", "                pass", (GATE,)),
    m("score-unreadable-by-one-reason", G, "                tally.unreadable[slot.why] += 1", "                tally.unreadable[\"unreadable\"] += 1", (GATE,)),
    m("score-unreadable-presence", G, "        if seen is not None and source.ret.expected is not None:", "        if seen is not None:", (GATE,)),
    m("score-presence-of-missing", G, "        if seen is not None and source.ret.expected is not None:", "        if source.ret.expected is not None:", (GATE,)),
    m("score-extra-parameter-index", G, "seen.proto.params[index] if seen and index < len(seen.proto.params) else None", "seen.proto.params[index] if seen and index <= len(seen.proto.params) else None", (GATE,)),
    m("score-parameter-index-shifted", G, "seen.proto.params[index] if seen and index < len(seen.proto.params) else None", "seen.proto.params[index - 1] if seen and index < len(seen.proto.params) else None", (GATE,)),
    m("score-return-of-the-parameter", G, "[(\"return\", \"return\", source.ret, seen.proto.ret if seen else None)]", "[(\"return\", \"return\", source.ret, seen.proto.params[0] if seen and seen.proto.params else None)]", (GATE,)),
    m("score-label-lost-index", G, "(f\"parameter {index}\", \"parameter\", slot,", "(\"parameter\", \"parameter\", slot,", (GATE,)),
    m("score-role-return", G, "(f\"parameter {index}\", \"parameter\", slot,", "(f\"parameter {index}\", \"return\", slot,", (GATE,)),
    m("judge-equal-is-wrong", G, "        if actual == expected:\n            counts[\"correct\"] += 1\n            return", "        if False:\n            counts[\"correct\"] += 1\n            return", (GATE,)),
    m("judge-marked-flipped", G, "        how = \"marked\" if seen.marked else \"silent\"", "        how = \"silent\" if seen.marked else \"marked\"", (GATE,)),
    m("judge-counter-flipped", G, "        counts[\"marked_wrong\" if seen.marked else \"silently_wrong\"] += 1", "        counts[\"silently_wrong\" if seen.marked else \"marked_wrong\"] += 1", (GATE,)),
    m("judge-silent-key-unsorted-kind", G, "        by_kind[kind] = by_kind.get(kind, 0) + 1", "        by_kind[kind] = 1", (GATE,)),
    m("judge-marked-also-silent", G, "        if not seen.marked:\n            # A silent error", "        if True:\n            # A silent error", (GATE,)),
    m("judge-silent-key-expected-first", G, "f\"{label}: expected {c_types.spell(expected)!r}, said {c_types.spell(actual)!r}\"", "f\"{label}: expected {c_types.spell(actual)!r}, said {c_types.spell(expected)!r}\"", (GATE,)),
    m("judge-silent-key-unquoted", G, "f\"{label}: expected {c_types.spell(expected)!r}, said {c_types.spell(actual)!r}\"", "f\"{label}: expected {c_types.spell(expected)}, said {c_types.spell(actual)}\"", (GATE,)),
    m("judge-bucket-of-the-actual", G, "        kind = c_types.classify(expected, actual)", "        kind = c_types.classify(actual, expected)", (GATE,)),
    m("judge-bucket-of-the-wrong-role", G, "        by_kind = tally.wrong.setdefault(how, {}).setdefault(role, {})", "        by_kind = tally.wrong.setdefault(how, {}).setdefault(\"return\", {})", (GATE,)),
    m("presence-void-key", G, "{'void' if gone[0] else 'value'}_to_", "{'value' if gone[0] else 'void'}_to_", (GATE,)),
    m("presence-void-target-key", G, "_to_{'void' if gone[1] else 'value'}", "_to_{'value' if gone[1] else 'void'}", (GATE,)),
    m("presence-always-silent", G, "        cell[\"silent\"] += not seen.marked", "        cell[\"silent\"] += 1", (GATE,)),
    m("presence-marked-is-silent", G, "        cell[\"silent\"] += not seen.marked", "        cell[\"silent\"] += seen.marked", (GATE,)),
    m("presence-silent-for-agreement", G, "    if gone[0] != gone[1]:", "    if True:", (GATE,)),
    m("presence-total-uncounted", G, "    cell[\"total\"] += 1\n", "", (GATE,)),
    m("presence-void-is-a-value-kind", G, "    gone = (expected.kind == c_types.VOID, actual.kind == c_types.VOID)", "    gone = (expected.kind == c_types.VOID, actual.kind != c_types.PTR)", (GATE,)),
    m("cause-opener-last", G, "words[0].lower() not in PLACEHOLDERS", "words[-1].lower() not in PLACEHOLDERS", (GATE,)),
    m("cause-case-sensitive", G, "words[0].lower() not in PLACEHOLDERS", "words[0] not in PLACEHOLDERS", (GATE,)),
    m("cause-not-a-string-is-a-cause", G, "words = re.findall(r\"\\w+\", cause) if isinstance(cause, str) else []", "words = re.findall(r\"\\w+\", str(cause))", (GATE,)),
    m("cause-one-word-is-a-cause", G, "MIN_CAUSE_WORDS = 3", "MIN_CAUSE_WORDS = 1", (GATE,)),
    m("cause-two-words-is-a-cause", G, "MIN_CAUSE_WORDS = 3", "MIN_CAUSE_WORDS = 2", (GATE,)),
    m("cause-four-words-needed", G, "MIN_CAUSE_WORDS = 3", "MIN_CAUSE_WORDS = 4", (GATE,)),
    m("cause-no-todo", G, 'PLACEHOLDERS = {"todo", "tbd", "fixme", "xxx", "wip"}', 'PLACEHOLDERS = {"tbd", "fixme", "xxx", "wip"}', (GATE,)),
    m("cause-no-tbd", G, 'PLACEHOLDERS = {"todo", "tbd", "fixme", "xxx", "wip"}', 'PLACEHOLDERS = {"todo", "fixme", "xxx", "wip"}', (GATE,)),
    m("cause-no-fixme", G, 'PLACEHOLDERS = {"todo", "tbd", "fixme", "xxx", "wip"}', 'PLACEHOLDERS = {"todo", "tbd", "xxx", "wip"}', (GATE,)),
    m("cause-no-xxx", G, 'PLACEHOLDERS = {"todo", "tbd", "fixme", "xxx", "wip"}', 'PLACEHOLDERS = {"todo", "tbd", "fixme", "wip"}', (GATE,)),
    m("cause-no-wip", G, 'PLACEHOLDERS = {"todo", "tbd", "fixme", "xxx", "wip"}', 'PLACEHOLDERS = {"todo", "tbd", "fixme", "xxx"}', (GATE,)),
    m("ordered-roles-unsorted", G, "    return {role: dict(sorted(kinds.items())) for role, kinds in sorted(tally.items())}", "    return {role: dict(sorted(kinds.items())) for role, kinds in tally.items()}", (GATE,)),
    m("ordered-kinds-unsorted", G, "    return {role: dict(sorted(kinds.items())) for role, kinds in sorted(tally.items())}", "    return {role: dict(kinds.items()) for role, kinds in sorted(tally.items())}", (GATE,)),
    m("refuse-exit-1", G, "    print(f\"refusing to score: {message}\", file=sys.stderr)\n    return 2", "    print(f\"refusing to score: {message}\", file=sys.stderr)\n    return 1", (GATE,)),
    m("main-no-dwarf-function-is-fine", G, "        if not placed and not unplaced:\n            return refuse", "        if False:\n            return refuse", (GATE,)),
    m("main-no-dwarf-function-needs-both", G, "        if not placed and not unplaced:\n            return refuse", "        if not placed or not unplaced:\n            return refuse", (GATE,)),
    m("main-stripped-dwarf-is-fine", G, "        if stripped_placed or stripped_unplaced:\n            return refuse", "        if False:\n            return refuse", (GATE,)),
    m("main-stripped-placed-only", G, "        if stripped_placed or stripped_unplaced:", "        if stripped_placed:", (GATE,)),
    m("main-stripped-unplaced-only", G, "        if stripped_placed or stripped_unplaced:", "        if stripped_unplaced:", (GATE,)),
    m("main-stripped-dwarf-is-the-debug-build", G, "read_dwarf(args.stripped_build, args.binutils_prefix)", "read_dwarf(args.debug_build, args.binutils_prefix)", (GATE,)),
    m("main-shared-entries-graded", G, "        placed = [sub for sub in placed if shared[sub.low_pc] == 1]", "        placed = [sub for sub in placed]", (GATE,)),
    m("main-shared-entries-unnamed", G, "        unplaced += [Unplaced(sub.name, 0, f\"it shares its entry address {sub.low_pc:#x} with another function\")\n                     for sub in placed if shared[sub.low_pc] > 1]", "", (GATE,)),
    m("main-shared-by-three-only", G, "for sub in placed if shared[sub.low_pc] > 1]", "for sub in placed if shared[sub.low_pc] > 2]", (GATE,)),
    m("main-unlisted-graded", G, "        graded = [sub for sub in placed if sub.low_pc in called]", "        graded = [sub for sub in placed]", (GATE,)),
    m("main-nothing-graded-is-fine", G, "        if not graded:\n            return refuse", "        if False:\n            return refuse", (GATE,)),
    m("main-recovered-nothing-is-fine", G, "        if not recovered:\n            return refuse", "        if False:\n            return refuse", (GATE,)),
    m("main-unlisted-in-stripped-asked", G, "[addr for addr in sorted(truth) if addr in stripped]", "sorted(truth)", (GATE,)),
    m("main-debug-listing-is-the-stripped", G, "        stripped = listing(args.stripped_build, args.r2s)", "        stripped = called", (GATE,)),
    m("main-unreadable-cap-lower", G, "for where, cause in causes[:10]:", "for where, cause in causes[:3]:", (GATE,)),
    m("main-unreadable-cap-higher", G, "for where, cause in causes[:10]:", "for where, cause in causes[:20]:", (GATE,)),
    m("main-unreadable-more-lost", G, "        if len(causes) > 10:", "        if len(causes) > 100:", (GATE,)),
    m("main-unreadable-more-at-ten", G, "        if len(causes) > 10:", "        if len(causes) >= 10:", (GATE,), False, "equivalent in effect: at exactly ten the line would say '... and 0 more', and no test has exactly ten"),
    m("main-unreadable-unsorted", G, "        causes = sorted(unreadable.causes.items())", "        causes = list(unreadable.causes.items())", (GATE,), False, "the causes are filled in sorted address order already; sorting is for a caller that does not"),
    m("main-unreadable-where-lost", G, "{' ' + where if where else ''}", "", (GATE,)),
    m("main-unreadable-where-always", G, "{' ' + where if where else ''}", "{' ' + where}", (GATE,)),
    m("report-dwarf-count-placed-only", G, "\"functions_in_dwarf\": len(placed) + len(unplaced),", "\"functions_in_dwarf\": len(placed),", (GATE,)),
    m("report-truth-count", G, "\"functions_in_truth\": len(truth),", "\"functions_in_truth\": len(placed),", (GATE,)),
    m("report-recovered-count", G, "\"functions_recovered\": len(recovered),", "\"functions_recovered\": len(stripped),", (GATE,)),
    m("report-without-entry-unsorted", G, "sorted(f\"{gone.name}: {gone.why}\" for gone in unplaced)", "[f\"{gone.name}: {gone.why}\" for gone in unplaced]", (GATE,)),
    m("report-without-entry-no-reason", G, "f\"{gone.name}: {gone.why}\"", "f\"{gone.name}\"", (GATE,)),
    m("report-unlisted-unsorted", G, "sorted(sub.name for sub in placed if sub.low_pc not in called)", "[sub.name for sub in placed if sub.low_pc not in called]", (GATE,)),
    m("report-unlisted-listed", G, "sorted(sub.name for sub in placed if sub.low_pc not in called)", "sorted(sub.name for sub in placed if sub.low_pc in called)", (GATE,)),
    m("report-without-dwarf-unsorted", G, "\"without_dwarf\": sorted(name for addr, name in called.items() if addr not in entries),", "\"without_dwarf\": [name for addr, name in called.items() if addr not in entries],", (GATE,)),
    m("report-without-dwarf-all", G, "if addr not in entries),", "if True),", (GATE,)),
    m("report-unreadable-unsorted", G, "dict(sorted(tally.unreadable.items()))", "dict(tally.unreadable.items())", (GATE,)),
    m("report-recovery-over-asserted", G, "round(buckets[\"correct\"] / facts, 4)", "round(buckets[\"correct\"] / asserted, 4)", (GATE,)),
    m("report-recovery-unrounded", G, "round(buckets[\"correct\"] / facts, 4)", "buckets[\"correct\"] / facts", (GATE,)),
    m("report-recovery-of-nothing", G, "if facts else 0.0,", "if facts else 1.0,", (GATE,)),
    m("report-soundness-over-facts", G, "round(1 - buckets[\"silently_wrong\"] / asserted, 4)", "round(1 - buckets[\"silently_wrong\"] / facts, 4)", (GATE,)),
    m("report-soundness-of-marked", G, "round(1 - buckets[\"silently_wrong\"] / asserted, 4)", "round(1 - (buckets[\"silently_wrong\"] + buckets[\"marked_wrong\"]) / asserted, 4)", (GATE,)),
    m("report-soundness-asserted-with-missing", G, "    asserted = buckets[\"correct\"] + buckets[\"silently_wrong\"]", "    asserted = buckets[\"correct\"] + buckets[\"silently_wrong\"] + buckets[\"missing\"]", (GATE,)),
    m("report-soundness-asserted-with-marked", G, "    asserted = buckets[\"correct\"] + buckets[\"silently_wrong\"]", "    asserted = buckets[\"correct\"] + buckets[\"silently_wrong\"] + buckets[\"marked_wrong\"]", (GATE,)),
    m("report-soundness-of-nothing", G, "if asserted else 1.0,", "if asserted else 0.0,", (GATE,)),
    m("report-silent-buckets-marked", G, "\"silent_buckets\": ordered(tally.wrong.get(\"silent\", {})),", "\"silent_buckets\": ordered(tally.wrong.get(\"marked\", {})),", (GATE,)),
    m("report-marked-buckets-silent", G, "\"marked_buckets\": ordered(tally.wrong.get(\"marked\", {})),", "\"marked_buckets\": ordered(tally.wrong.get(\"silent\", {})),", (GATE,)),
    m("report-json-indent", G, "        args.json.write_text(json.dumps(report, indent=2) + \"\\n\")", "        args.json.write_text(json.dumps(report) + \"\\n\")", (GATE,), False, "the test reads the file back as JSON: the indent is for people"),
    m("report-json-not-written", G, "    if args.json:\n        args.json.write_text", "    if False:\n        args.json.write_text", (GATE,)),
    m("baseline-missing-file-is-read", G, "        if args.baseline and args.baseline.exists()", "        if args.baseline", (GATE,)),
    m("baseline-accept-needs-no-path", G, "    if args.accept_baseline and args.baseline:", "    if args.accept_baseline:", (GATE,)),
    m("baseline-accept-carries-every-cause", G, "        why = {fact: cause for fact, cause in recorded.get(\"why\", {}).items() if cause_is_stated(cause)}", "        why = dict(recorded.get(\"why\", {}))", (GATE,)),
    m("baseline-accept-keeps-fixed-causes", G, "{**report, \"why\": {fact: why[fact] for fact in silent if fact in why}}", "{**report, \"why\": why}", (GATE,)),
    m("baseline-accept-exit-0", G, "        return 1 if uncaused else 0\n\n    # A recorded", "        return 0\n\n    # A recorded", (GATE,)),
    m("baseline-accept-uncaused-unnamed", G, "        for fact in uncaused:\n            print(f\"NO CAUSE: {fact}\", file=sys.stderr)\n        return 1 if uncaused else 0", "        return 1 if uncaused else 0", (GATE,)),
    m("baseline-accept-unwritten", G, "        args.baseline.write_text(\n            json.dumps(", "        (lambda text: None)(\n            json.dumps(", (GATE,)),
    m("baseline-accept-announcement-lost", G, "        print(f\"baseline accepted: {args.baseline}\", file=sys.stderr)\n", "", (GATE,)),
    m("baseline-set-not-multiset", G, "    known = Counter(recorded.get(\"silent\", []))\n    new_silent = sorted((Counter(silent) - known).elements())", "    known = set(recorded.get(\"silent\", []))\n    new_silent = sorted(fact for fact in silent if fact not in known)", (GATE,)),
    m("baseline-fixed-set-not-multiset", G, "    fixed = sorted((known - Counter(silent)).elements())", "    fixed = sorted(set(known) - set(silent))", (GATE,)),
    m("baseline-new-silent-unsorted", G, "new_silent = sorted((Counter(silent) - known).elements())", "new_silent = list((Counter(silent) - known).elements())", (GATE,), False, "Counter keeps insertion order, which is the report's; sorting makes it independent of that"),
    m("baseline-no-baseline-prints-nothing", G, "    known = Counter(recorded.get(\"silent\", []))\n    new_silent = sorted((Counter(silent) - known).elements())", "    known = Counter(recorded.get(\"silent\", []))\n    new_silent = sorted((Counter(silent) - known).elements()) if recorded else []", (GATE,)),
    m("baseline-new-silent-ignored", G, "    return 1 if new_silent or uncaused else 0", "    return 1 if uncaused else 0", (GATE,)),
    m("baseline-uncaused-ignored", G, "    return 1 if new_silent or uncaused else 0", "    return 1 if new_silent else 0", (GATE,)),
    m("baseline-uncaused-of-the-fixed-only", G, "    uncaused = sorted(fact for fact in known if not cause_is_stated(causes.get(fact)))", "    uncaused = sorted(fact for fact in known if fact in silent and not cause_is_stated(causes.get(fact)))", (GATE,)),
    m("baseline-fixed-printed-as-new", G, "        print(f\"no longer silent: {fact}\", file=sys.stderr)", "        print(f\"SILENT ERROR: {fact}\", file=sys.stderr)", (GATE,)),
    m("baseline-fixed-unnamed", G, "    for fact in fixed:\n        print(f\"no longer silent: {fact}\", file=sys.stderr)\n", "", (GATE,)),
    m("baseline-new-unnamed", G, "    for fact in new_silent:\n        print(f\"SILENT ERROR: {fact}\", file=sys.stderr)\n", "", (GATE,)),
    m("baseline-uncaused-unnamed", G, "    for fact in uncaused:\n        print(f\"NO CAUSE: {fact}\", file=sys.stderr)\n    if fixed", "    if fixed", (GATE,)),
    m("baseline-rerecord-hint-lost", G, "    if fixed and not new_silent:\n        print(\"re-record the baseline with --accept-baseline\", file=sys.stderr)\n", "", (GATE,)),
    m("baseline-rerecord-hint-always", G, "    if fixed and not new_silent:", "    if fixed:", (GATE,)),
    m("baseline-rerecord-hint-without-fixed", G, "    if fixed and not new_silent:", "    if not new_silent:", (GATE,)),
]

# The DWARF reader's entry rule and range lists.
MUTANTS += [
    m("ranges-pattern-offset-width", D, "(?P<offset>[0-9a-f]{8})", "(?P<offset>[0-9a-f]{9})", (EQUIV,)),
    m("ranges-pattern-short-address", D, "(?P<begin>[0-9a-f]{8,16})", "(?P<begin>[0-9a-f]{16})", (EQUIV,), False, "equivalent here: readelf prints every address in 16 digits; the pattern accepts a short one for a 32-bit target"),
    m("ranges-pattern-base-row", D, "(?:(?P<base>\\(base address\\))|[0-9a-f]{8,16})", "(?:[0-9a-f]{8,16})", (EQUIV,)),
    m("ranges-pattern-end-row", D, "(?:(?P<end><End of list>)|", "(?:", (EQUIV,)),
    m("ranges-section-rnglists", D, "debug_(?:ranges|rnglists) section", "debug_(?:ranges) section", (EQUIV,)),
    m("ranges-section-ranges", D, "debug_(?:ranges|rnglists) section", "debug_(?:rnglists) section", (EQUIV,)),
    m("ranges-section-any-contents", D, "            in_ranges = bool(_RANGE_SECTION.match(line))", "            in_ranges = True", (EQUIV,)),
    m("ranges-section-not-counted", D, "            section += 1\n", "", (EQUIV,)),
    m("ranges-kind-base-is-a-range", D, "        kind = \"end\" if row.group(\"end\") else \"base\" if row.group(\"base\") else \"range\"", "        kind = \"end\" if row.group(\"end\") else \"range\"", (EQUIV,)),
    m("ranges-kind-end-is-a-range", D, "        kind = \"end\" if row.group(\"end\") else \"base\" if row.group(\"base\") else \"range\"", "        kind = \"base\" if row.group(\"base\") else \"range\"", (EQUIV,)),
    m("ranges-continuation-lost", D, "        if at and rows[at - 1][:2] == (part, offset):\n            continue\n", "", (EQUIV,)),
    m("ranges-continuation-across-sections", D, "        if at and rows[at - 1][:2] == (part, offset):", "        if at and rows[at - 1][1] == offset:", (EQUIV,)),
    m("ranges-base-rows-kept", D, "        while index < len(rows) and rows[index][2] == \"base\":\n            index += 1\n", "", (EQUIV,)),
    m("ranges-end-rows-skipped", D, "        while index < len(rows) and rows[index][2] == \"base\":", "        while index < len(rows) and rows[index][2] in (\"base\", \"end\"):", (EQUIV,)),
    m("ranges-duplicate-answers-kept", D, "if index < len(rows) and rows[index][2] == \"range\" and rows[index][3] not in found:", "if index < len(rows) and rows[index][2] == \"range\":", (EQUIV,)),
    m("ranges-empty-list-has-an-entry", D, "    return {offset: tuple(begins) for offset, begins in firsts.items() if begins}", "    return {offset: tuple(begins) for offset, begins in firsts.items()}", (EQUIV,)),
    m("ranges-second-range", D, "found.append(rows[index][3])", "found.append(rows[index][3] + 1)", (EQUIV,)),
    m("ranges-offset-decimal", D, "int(row.group(\"offset\"), 16)", "int(row.group(\"offset\"), 10)", (EQUIV,)),
    m("ranges-begin-decimal", D, "int(row.group(\"begin\") or \"0\", 16)", "int(row.group(\"begin\") or \"0\", 10)", (EQUIV,)),
    m("forms-lost", D, "            if attr.group(1) not in current.attrs and value != raw:\n                current.forms[attr.group(1)] = _FORM.match(raw).group(0).strip()[1:-1]\n", "", (EQUIV,)),
    m("forms-of-the-last-duplicate", D, "            if attr.group(1) not in current.attrs and value != raw:", "            if value != raw:", (EQUIV,)),
    m("forms-with-parens", D, "_FORM.match(raw).group(0).strip()[1:-1]", "_FORM.match(raw).group(0).strip()", (EQUIV,)),
    m("placed-needs-low-pc", D, "not {\"DW_AT_low_pc\", \"DW_AT_ranges\"} & die.attrs.keys()", "\"DW_AT_low_pc\" not in die.attrs", (EQUIV,)),
    m("placed-needs-ranges", D, "not {\"DW_AT_low_pc\", \"DW_AT_ranges\"} & die.attrs.keys()", "\"DW_AT_ranges\" not in die.attrs", (EQUIV,)),
    m("placed-takes-every-subprogram", D, "if die.tag != \"DW_TAG_subprogram\" or not {\"DW_AT_low_pc\", \"DW_AT_ranges\"} & die.attrs.keys():", "if die.tag != \"DW_TAG_subprogram\":", (EQUIV,)),
    m("placed-unplaced-nameless", D, "                    named, _ = self._attr_via_origin(die, \"DW_AT_name\")\n                    unplaced.append(Unplaced(named.text(\"DW_AT_name\") or \"\", die.offset, why))", "                    unplaced.append(Unplaced(die.text(\"DW_AT_name\") or \"\", die.offset, why))", (EQUIV,)),
    m("placed-unplaced-wrong-offset", D, "unplaced.append(Unplaced(named.text(\"DW_AT_name\") or \"\", die.offset, why))", "unplaced.append(Unplaced(named.text(\"DW_AT_name\") or \"\", 0, why))", (EQUIV,)),
    m("placed-unsorted", D, "        found.sort(key=lambda s: (s.low_pc, s.name))\n        unplaced.sort", "        unplaced.sort", (EQUIV,)),
    m("placed-unplaced-unsorted", D, "        unplaced.sort(key=lambda u: (u.name, u.offset))\n", "", (EQUIV,)),
    m("placed-unplaced-by-offset", D, "        unplaced.sort(key=lambda u: (u.name, u.offset))", "        unplaced.sort(key=lambda u: (u.offset, u.name))", (EQUIV,)),
    m("placed-found-by-name", D, "        found.sort(key=lambda s: (s.low_pc, s.name))\n        unplaced.sort", "        found.sort(key=lambda s: (s.name, s.low_pc))\n        unplaced.sort", (EQUIV,)),
    m("entry-pc-address-forms", D, "            if not die.forms.get(\"DW_AT_entry_pc\", \"\").startswith(\"addr\"):", "            if False:", (EQUIV,)),
    m("entry-pc-form-default-address", D, "die.forms.get(\"DW_AT_entry_pc\", \"\").startswith(\"addr\")", "die.forms.get(\"DW_AT_entry_pc\", \"addr\").startswith(\"addr\")", (EQUIV,)),
    m("entry-pc-only-addr", D, "die.forms.get(\"DW_AT_entry_pc\", \"\").startswith(\"addr\")", "die.forms.get(\"DW_AT_entry_pc\", \"\") == \"addr\"", (EQUIV,)),
    m("entry-pc-ignored", D, "        if \"DW_AT_entry_pc\" in die.attrs:", "        if False:", (EQUIV,)),
    m("entry-pc-after-low-pc", D, "        if \"DW_AT_entry_pc\" in die.attrs:", "        if \"DW_AT_entry_pc\" in die.attrs and \"DW_AT_low_pc\" not in die.attrs:", (EQUIV,)),
    m("entry-pc-source-name", D, "            source = \"DW_AT_entry_pc\"", "            source = \"DW_AT_low_pc\"", (EQUIV,)),
    m("entry-low-pc-ignored", D, "        elif \"DW_AT_low_pc\" in die.attrs:", "        elif False:", (EQUIV,)),
    m("entry-low-pc-source-name", D, "            source = \"DW_AT_low_pc\"", "            source = \"DW_AT_entry_pc\"", (EQUIV,)),
    m("entry-address-not-hex", D, "                entry = int(die.text(source) or \"\", 16)", "                entry = int(die.text(source) or \"\", 10)", (EQUIV,)),
    m("entry-address-error-uncaught", D, "            except ValueError:\n                return None, f\"its {source} is not an address\"", "            except KeyError:\n                return None, f\"its {source} is not an address\"", (EQUIV,)),
    m("entry-address-error-reason", D, "return None, f\"its {source} is not an address\"", "return None, \"its address is not an address\"", (EQUIV,)),
    m("entry-ranges-only-first", D, "            offset = die.number(\"DW_AT_ranges\")\n            begins = self.ranges.get(offset, ()) if offset is not None else ()", "            offset = die.number(\"DW_AT_ranges\")\n            begins = self.ranges.get(offset, ()) if offset is not None else (0x1,)", (EQUIV,)),
    m("entry-ranges-offset-none-is-zero", D, "begins = self.ranges.get(offset, ()) if offset is not None else ()", "begins = self.ranges.get(offset or 0, ())", (EQUIV,), False, "equivalent in the tests: no fixture holds a list at offset 0 beside a DIE whose ranges are not a number"),
    m("entry-ranges-ambiguous-first", D, "            if len(begins) != 1:", "            if len(begins) < 1:", (EQUIV,)),
    m("entry-ranges-two-answers-fine", D, "            if len(begins) != 1:", "            if len(begins) == 0:", (EQUIV,)),
    m("entry-ranges-empty-fine", D, "            if len(begins) != 1:", "            if len(begins) > 1:", (EQUIV,)),
    m("entry-ranges-last-answer", D, "            entry = begins[0]", "            entry = begins[-1]", (EQUIV,), False, "equivalent: a list that reaches here holds exactly one answer"),
    m("entry-ranges-reason", D, "return None, \"its DW_AT_ranges list has no one readable first range\"", "return None, \"its ranges\"", (EQUIV,)),
    m("entry-tombstone-zero", D, "TOMBSTONES = frozenset({0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})", "TOMBSTONES = frozenset({1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})", (EQUIV,)),
    m("entry-tombstone-one", D, "TOMBSTONES = frozenset({0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})", "TOMBSTONES = frozenset({0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})", (EQUIV,)),
    m("entry-tombstone-32", D, "TOMBSTONES = frozenset({0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})", "TOMBSTONES = frozenset({0, 1, 0xFFFFFFFFFFFFFFFF})", (EQUIV,)),
    m("entry-tombstone-64", D, "TOMBSTONES = frozenset({0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})", "TOMBSTONES = frozenset({0, 1, 0xFFFFFFFF})", (EQUIV,)),
    m("entry-tombstone-ignored", D, "        if entry in TOMBSTONES:", "        if False:", (EQUIV,)),
    m("entry-tombstone-reason", D, "return None, f\"its code was discarded by the linker (address {entry:#x})\"", "return None, \"its code was discarded by the linker\"", (EQUIV,)),
    m("subprogram-name-from-the-die", D, "            name=named.text(\"DW_AT_name\") or \"\",\n            low_pc=low_pc,", "            name=die.text(\"DW_AT_name\") or \"\",\n            low_pc=low_pc,", (EQUIV,), False, "equivalent for the gate's tests; the names through an origin are the equivalence gate's (DwarfTests, which needs gcc)"),
    m("readelf-ranges-not-asked", D, "\"--debug-dump=info\", \"--debug-dump=Ranges\", str(binary)", "\"--debug-dump=info\", str(binary)", (EQUIV,)),
    m("readelf-ranges-not-parsed", D, "        return cls(units, index, parse_ranges(proc.stdout))", "        return cls(units, index)", (EQUIV,)),
    m("readelf-failure-ignored", D, "        if proc.returncode != 0:\n            raise RuntimeError", "        if False:\n            raise RuntimeError", (EQUIV,)),
]

# The `pddj` contract.
MUTANTS += [
    m("contract-residuals-not-required", B, "    \"links\": list,\n    \"residuals\": list,\n}", "    \"links\": list,\n}", (EQUIV,)),
    m("contract-residuals-entries-unchecked", B, "        if not (isinstance(entry, dict) and _count(entry.get(\"site\")) and isinstance(entry.get(\"cause\"), str)):", "        if False:", (EQUIV,)),
    m("contract-residuals-site-unchecked", B, "isinstance(entry, dict) and _count(entry.get(\"site\")) and isinstance(entry.get(\"cause\"), str)", "isinstance(entry, dict) and isinstance(entry.get(\"cause\"), str)", (EQUIV,)),
    m("contract-residuals-site-any-int", B, "_count(entry.get(\"site\")) and isinstance(entry.get(\"cause\"), str)", "isinstance(entry.get(\"site\"), int) and isinstance(entry.get(\"cause\"), str)", (EQUIV,)),
    m("contract-residuals-cause-unchecked", B, "isinstance(entry, dict) and _count(entry.get(\"site\")) and isinstance(entry.get(\"cause\"), str)", "isinstance(entry, dict) and _count(entry.get(\"site\"))", (EQUIV,)),
    m("contract-residuals-entry-not-a-dict", B, "isinstance(entry, dict) and _count(entry.get(\"site\"))", "_count(entry.get(\"site\"))", (EQUIV,)),
    m("contract-residuals-first-only", B, "            problems.append(f\"`residuals` entry {entry!r:.80} is not a site with a cause\")\n            break", "            problems.append(f\"`residuals` entry {entry!r:.80} is not a site with a cause\")", (EQUIV,)),
    m("contract-proof-counter-any-int", B, "            if not _count(proof.get(counter)):", "            if not isinstance(proof.get(counter), int):", (EQUIV,)),
    m("contract-proof-counter-nonnegative", B, "    return isinstance(value, int) and not isinstance(value, bool) and value >= 0", "    return isinstance(value, int) and value >= 0", (EQUIV,)),
    m("contract-proof-counter-negative", B, "    return isinstance(value, int) and not isinstance(value, bool) and value >= 0", "    return isinstance(value, int) and not isinstance(value, bool)", (EQUIV,)),
]

# DecBench's reading of its rows.
MUTANTS += [
    m("widths-kind-prefix", T, 'm = re.fullmatch(r"int(\\d+)", kind or "")', 'm = re.fullmatch(r"(\\d+)", kind or "")', (DECBENCH,)),
    m("widths-kind-search", T, 'm = re.fullmatch(r"int(\\d+)", kind or "")', 'm = re.search(r"int(\\d+)", kind or "")', (DECBENCH,), False, "equivalent: no kind in a row has text around `intN`"),
    m("widths-kind-none", T, 'return int(m.group(1)) if m else None', 'return int(m.group(1)) if m else 0', (DECBENCH,)),
    m("widths-direction-flipped", T, 'return "wider" if d > g else "narrower" if d < g else "same"', 'return "wider" if d < g else "narrower" if d > g else "same"', (DECBENCH,)),
    m("widths-direction-unknown-same", T, 'return "unknown"\n    return "wider"', 'return "same"\n    return "wider"', (DECBENCH,)),
    m("widths-direction-unknown-needs-both", T, "    if g is None or d is None:", "    if g is None and d is None:", (DECBENCH,)),
    m("widths-direction-source-only", T, "    if g is None or d is None:", "    if g is None:", (DECBENCH,)),
    m("widths-direction-decompiled-only", T, "    if g is None or d is None:", "    if d is None:", (DECBENCH,)),
    m("widths-equal-is-wider", T, 'return "wider" if d > g else "narrower" if d < g else "same"', 'return "wider" if d >= g else "narrower" if d < g else "same"', (DECBENCH,)),
    m("widths-equal-is-narrower", T, 'return "wider" if d > g else "narrower" if d < g else "same"', 'return "wider" if d > g else "narrower" if d <= g else "same"', (DECBENCH,)),
    m("widths-perfect-function-counted", T, 'if r["dec"] != dec or r["value"] == 1.0:', 'if r["dec"] != dec:', (DECBENCH,)),
    m("widths-other-decompiler-counted", T, 'if r["dec"] != dec or r["value"] == 1.0:', 'if r["value"] == 1.0:', (DECBENCH,)),
    m("widths-only-perfect-skipped", T, 'if r["dec"] != dec or r["value"] == 1.0:', 'if r["dec"] != dec or r["value"] >= 0.5:', (DECBENCH,)),
    m("widths-sole-any", T, "sole = classes_of(r) == {verdict}", "sole = verdict in classes_of(r)", (DECBENCH,)),
    m("widths-is-arg-flipped", T, 'where = "param" if v["is_arg"] else "local"', 'where = "local" if v["is_arg"] else "param"', (DECBENCH,)),
    m("widths-shape-mixed", T, 'key = "mixed" if len(shape) == 2 else "params_only" if shape == {True} else "locals_only"', 'key = "mixed" if len(shape) == 2 else "locals_only" if shape == {True} else "params_only"', (DECBENCH,)),
    m("widths-shape-never-mixed", T, 'key = "mixed" if len(shape) == 2 else', 'key = "mixed" if len(shape) == 3 else', (DECBENCH,)),
    m("widths-direction-only-in-sole", T, 'if sole:\n                    out["direction"]["only_cause"]', 'if True:\n                    out["direction"]["only_cause"]', (DECBENCH,)),
    m("widths-direction-never-in-sole", T, 'if sole:\n                    out["direction"]["only_cause"]', 'if False:\n                    out["direction"]["only_cause"]', (DECBENCH,)),
    m("widths-involved-skipped", T, 'for scope in ["involved"] + (["only_cause"] if sole else []):', 'for scope in (["only_cause"] if sole else []):', (DECBENCH,)),
    m("widths-only-cause-skipped", T, 'for scope in ["involved"] + (["only_cause"] if sole else []):', 'for scope in ["involved"]:', (DECBENCH,)),
    m("widths-only-cause-always", T, 'for scope in ["involved"] + (["only_cause"] if sole else []):', 'for scope in ["involved", "only_cause"]:', (DECBENCH,)),
    m("widths-direction-for-every-verdict", T, 'if verdict == "fp:integer_width":\n        out["direction"]', 'if True:\n        out["direction"]', (DECBENCH,)),
    m("widths-direction-for-none", T, 'if verdict == "fp:integer_width":\n        out["direction"]', 'if False:\n        out["direction"]', (DECBENCH,)),
    m("widths-direction-cell-missing", T, '("wider", "narrower", "same", "unknown")', '("wider", "narrower", "same")', (DECBENCH,)),
    m("widths-share-of-nothing", T, 'return f"{n} ({100 * n / of:.1f}%)" if of else f"{n} (n/a)"', 'return f"{n} ({100 * n / of:.1f}%)"', (DECBENCH,)),
    m("widths-share-precision", T, ':.1f}%)" if of else', ':.0f}%)" if of else', (DECBENCH,)),
    m("widths-share-of-the-whole", T, 'return f"{n} ({100 * n / of:.1f}%)" if of else', 'return f"{n} ({100 * n / (of + 1):.1f}%)" if of else', (DECBENCH,)),
    m("widths-params-in-line", T, "f\"    parameters in {share(s['params_only'] + s['mixed'], n)}, locals in {share(s['locals_only'] + s['mixed'], n)}\")", "f\"    parameters in {share(s['params_only'], n)}, locals in {share(s['locals_only'], n)}\")", (DECBENCH,)),
    m("widths-params-in-without-mixed", T, "f\"    parameters in {share(s['params_only'] + s['mixed'], n)}, locals in", "f\"    parameters in {share(s['params_only'], n)}, locals in", (DECBENCH,)),
    m("widths-locals-in-without-mixed", T, "locals in {share(s['locals_only'] + s['mixed'], n)}\")", "locals in {share(s['locals_only'], n)}\")", (DECBENCH,)),
    m("widths-only-the-first-verdict", T, 'for verdict in ("fp:integer_width", "fp:pointer_as_integer"):', 'for verdict in ("fp:integer_width",):', (DECBENCH,)),
    m("widths-only-the-second-verdict", T, 'for verdict in ("fp:integer_width", "fp:pointer_as_integer"):', 'for verdict in ("fp:pointer_as_integer",):', (DECBENCH,)),
    m("widths-heading-sum", T, "variables {v['param'] + v['local']}: parameters {v['param']}, locals {v['local']}", "variables {v['param']}: parameters {v['param']}, locals {v['local']}", (DECBENCH,)),
    m("widths-label-involved", T, '(("only_cause", "only cause"), ("involved", "involved"))', '(("only_cause", "only cause"), ("involved", "involved"))', (DECBENCH,), False, "the edit is its own text: a no-op, so the mutant is the original"),
    m("widths-label-only-cause", T, '(("only_cause", "only cause"), ("involved", "involved"))', '(("only_cause", "only"), ("involved", "involved"))', (DECBENCH,)),
    m("widths-scope-order", T, '(("only_cause", "only cause"), ("involved", "involved"))', '(("involved", "involved"), ("only_cause", "only cause"))', (DECBENCH,)),
]


def run(name, edits, tests, must_die, why, check):
    files = {path for path, _, _ in edits}
    originals = {path: open(path).read() for path in files}
    for path, old, new in edits:
        if originals[path].count(old) != 1:
            return f"{name}: the edit's old text occurs {originals[path].count(old)} times in {path}", False
        if old == new and must_die:
            return f"{name}: the edit changes nothing", False
    if check:
        return f"{name}: applies", True
    text = dict(originals)
    for path, old, new in edits:
        text[path] = text[path].replace(old, new, 1)
    try:
        for path in files:
            open(path, "w").write(text[path])
        killer = None
        for command in tests:
            done = subprocess.run(command, shell=True, capture_output=True, text=True, env=NO_BYTECODE)
            if done.returncode != 0:
                killer = command
                break
    finally:
        for path in files:
            open(path, "w").write(originals[path])
    died = killer is not None
    verdict = f"killed by `{killer}`" if died else f"survived {len(tests)} test commands" + (f" ({why})" if why else "")
    return f"{name}: {verdict}", died == must_die


def main():
    args = sys.argv[1:]
    check = "--check" in args
    names = [a for a in args if not a.startswith("--")]
    touched = sorted({p for _, e, *_ in MUTANTS for p, _, _ in e})
    for path in touched:
        shutil.rmtree(os.path.join(os.path.dirname(path), "__pycache__"), ignore_errors=True)
    if not check and subprocess.run(["git", "diff", "--quiet", "--"] + touched).returncode:
        sys.exit("a file a mutant edits has changes: commit or restore them first")
    bad = 0
    seen_names = set()
    for name, edits, tests, must_die, why in MUTANTS:
        if name in seen_names:
            sys.exit(f"two mutants are named {name}")
        seen_names.add(name)
        if names and name not in names:
            continue
        line, ok = run(name, edits, tests, must_die, why, check)
        print(("ok   " if ok else "WRONG"), line, flush=True)
        bad += not ok
    print(f"{len(MUTANTS) if not names else len(names)} mutants, {bad} wrong")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    main()
