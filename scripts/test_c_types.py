#!/usr/bin/env python3
"""Unit tests for the C type model the source-gold gate compares with: the declarator parser, the spelling, the
buckets and the reading of DWARF. Pure Python; the DWARF is readelf text kept in tests/equiv/testdata/dwarf."""

from __future__ import annotations

import dataclasses
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tests" / "equiv"))
import c_types as ct  # noqa: E402
import dwarf  # noqa: E402

FIXTURES = HERE.parent / "tests" / "equiv" / "testdata" / "dwarf"
GCC = "GNU C17 13.3.0 -mtune=generic -march=x86-64 -g -O2"
# What readelf prints of a DW_FORM_ref_sig8: a DIE of a type unit, which is in no list of this dump.
SIGNATURE = ": 0x7cbb7a52356be670"


ATTRIBUTES = {"name": "DW_AT_name", "size": "DW_AT_byte_size", "encoding": "DW_AT_encoding", "type": "DW_AT_type",
              "count": "DW_AT_count", "upper": "DW_AT_upper_bound", "declaration": "DW_AT_declaration",
              "vector": "DW_AT_GNU_vector", "signature": "DW_AT_signature"}
# The form readelf names for each attribute the graph writes: a size, a bound or an encoding is a constant.
FORMS = {"size": "data1", "count": "data1", "upper": "data1", "encoding": "data1", "type": "ref4",
         "declaration": "flag_present", "signature": "ref_sig8"}
# (name, DW_ATE_ encoding) of each integer, as gcc names it.
BASE_TYPES = {
    (1, None): ("char", 6), (1, True): ("signed char", 6), (1, False): ("unsigned char", 8),
    (2, True): ("short int", 5), (2, False): ("short unsigned int", 7),
    (4, True): ("int", 5), (4, False): ("unsigned int", 7),
    (8, True): ("long int", 5), (8, False): ("long unsigned int", 7),
    (16, True): ("__int128", 5), (16, False): ("__int128 unsigned", 7),
}


class Graph:
    """A DIE graph written from C types: the inverse of `ct.from_dwarf`, so a type can be put through it."""

    def __init__(self) -> None:
        self.index: dict[int, dwarf.Die] = {}
        self.next = 0x30
        self.written: dict[ct.CType, int | None] = {}

    def die(self, tag: str, children: tuple[dwarf.Die, ...] = (), **attrs: object) -> int:
        offset, self.next = self.next, self.next + 0x10
        values = {ATTRIBUTES[key]: (SIGNATURE if value == dwarf.UNRESOLVED else f"<0x{value:x}>") if key == "type" else str(value)
                  for key, value in attrs.items() if value is not None}
        forms = {ATTRIBUTES[key]: FORMS[key] for key, value in attrs.items() if value is not None and key in FORMS}
        node = dwarf.Die(offset, tag, 1, attrs=values, forms=forms, children=list(children))
        self.index[offset] = node
        return offset

    def child(self, tag: str, **attrs: object) -> dwarf.Die:
        offset = self.die(tag, **attrs)
        return self.index[offset]

    def write(self, ty: ct.CType) -> int | None:
        """The offset of a DIE for `ty`, None for void."""
        if ty not in self.written:
            self.written[ty] = self.build(ty)
        return self.written[ty]

    def build(self, ty: ct.CType) -> int | None:
        if ty.const or ty.volatile:
            inner = self.write(dataclasses.replace(ty, const=False, volatile=False))
            if ty.volatile:
                inner = self.die("DW_TAG_volatile_type", type=inner)
            return self.die("DW_TAG_const_type", type=inner) if ty.const else inner
        if ty.kind == ct.VOID:
            return None
        if ty.kind == ct.INT:
            name, encoding = BASE_TYPES[(ty.width, ty.signed)]
            return self.die("DW_TAG_base_type", name=name, size=ty.width, encoding=f"{encoding}\t(encoding)")
        if ty.kind == ct.BOOL:
            return self.die("DW_TAG_base_type", name="_Bool", size=1, encoding="2\t(boolean)")
        if ty.kind == ct.FLOAT:
            return self.die("DW_TAG_base_type", name="double", size=ty.width, encoding="4\t(float)")
        if ty.kind == ct.NAMED:
            keyword, _, tag = ty.name.partition(" ")
            return self.die(f"DW_TAG_{'union' if keyword == 'union' else 'structure'}_type", name=tag, size=16)
        if ty.kind == ct.PTR:
            return self.die("DW_TAG_pointer_type", size=8, type=self.write(ty.target))
        if ty.kind == ct.ARRAY:
            bound = self.child("DW_TAG_subrange_type", upper=None if ty.count is None else ty.count - 1)
            return self.die("DW_TAG_array_type", (bound,), type=self.write(ty.target))
        children = tuple(self.child("DW_TAG_formal_parameter", type=self.write(param)) for param in ty.params)
        if ty.variadic:
            children += (self.child("DW_TAG_unspecified_parameters"),)
        return self.die("DW_TAG_subroutine_type", children, type=self.write(ty.target))

    def subprogram(self, proto: ct.Prototype, entry: int, **states: object) -> dwarf.Subprogram:
        """A function as gcc's DWARF states it: prototyped, and its own (`states` overrides `producer`, `prototyped`, `instance`)."""
        return dwarf.Subprogram(
            name=proto.name, low_pc=entry, unit="t.c", external=True, return_type=self.write(proto.ret),
            parameters=[dwarf.Parameter(f"p{index}", self.write(param)) for index, param in enumerate(proto.params)],
            variadic=proto.variadic, **{"producer": GCC, "prototyped": True, "instance": False, **states})

    def dwarf(self) -> dwarf.Dwarf:
        return dwarf.Dwarf([], self.index)


def one(text: str) -> ct.CType:
    return ct.parse_type(text)


class Integers(unittest.TestCase):
    # Every integer spelling a prototype may use, with the (bytes, signed) an LP64 target gives it.
    ROWS = [
        ("char", 1, None), ("signed char", 1, True), ("unsigned char", 1, False),
        ("short", 2, True), ("short int", 2, True), ("signed short", 2, True), ("unsigned short", 2, False),
        ("unsigned short int", 2, False),
        ("int", 4, True), ("signed", 4, True), ("signed int", 4, True), ("unsigned", 4, False), ("unsigned int", 4, False),
        ("long", 8, True), ("long int", 8, True), ("signed long", 8, True), ("unsigned long", 8, False),
        ("long unsigned int", 8, False), ("long long", 8, True), ("unsigned long long", 8, False),
        ("long long int", 8, True),
        ("int8_t", 1, True), ("uint8_t", 1, False), ("int16_t", 2, True), ("uint16_t", 2, False),
        ("int32_t", 4, True), ("uint32_t", 4, False), ("int64_t", 8, True), ("uint64_t", 8, False),
        ("intmax_t", 8, True), ("uintmax_t", 8, False), ("size_t", 8, False), ("ssize_t", 8, True),
        ("intptr_t", 8, True), ("uintptr_t", 8, False), ("ptrdiff_t", 8, True),
    ]

    def test_every_spelling_is_one_integer(self) -> None:
        for text, width, signed in self.ROWS:
            with self.subTest(text=text):
                self.assertEqual(one(text), ct.integer(width, signed))

    def test_two_spellings_of_one_integer_are_equal(self) -> None:
        for left, right in [("unsigned long", "size_t"), ("size_t", "uint64_t"), ("long", "intptr_t"),
                            ("long long", "int64_t"), ("unsigned", "uint32_t"), ("signed char", "int8_t")]:
            with self.subTest(left=left, right=right):
                self.assertEqual(one(left), one(right))

    def test_plain_char_is_not_signed_char_or_unsigned_char(self) -> None:
        self.assertEqual(len({one("char"), one("signed char"), one("unsigned char")}), 3)

    def test_the_other_scalars(self) -> None:
        self.assertEqual(one("_Bool"), ct.CType(ct.BOOL))
        self.assertEqual(one("bool"), one("_Bool"))
        self.assertEqual(one("float"), ct.CType(ct.FLOAT, width=4))
        self.assertEqual(one("double"), ct.CType(ct.FLOAT, width=8))
        self.assertEqual(one("long double"), ct.CType(ct.FLOAT, width=16))
        self.assertEqual(one("void"), ct.NO_VALUE)
        self.assertEqual(one("struct pair"), ct.CType(ct.NAMED, name="struct pair"))
        self.assertEqual(one("union u"), ct.CType(ct.NAMED, name="union u"))
        self.assertEqual(one("enum color"), ct.CType(ct.NAMED, name="enum color"))
        self.assertEqual(one("FILE"), ct.CType(ct.NAMED, name="FILE"))
        self.assertNotEqual(one("struct pair"), one("union pair"))


class Qualifiers(unittest.TestCase):
    def test_const_and_volatile_belong_to_what_they_qualify(self) -> None:
        pointee = one("const uint8_t*")
        self.assertTrue(pointee.target.const and not pointee.const)
        own = one("uint8_t* const")
        self.assertTrue(own.const and not own.target.const)
        self.assertTrue(one("volatile int*").target.volatile)
        self.assertEqual(one("char const*"), one("const char*"))
        self.assertNotEqual(one("const char*"), one("char*"))
        self.assertNotEqual(one("volatile char*"), one("char*"))
        self.assertNotEqual(one("volatile char*"), one("const char*"))

    def test_restrict_and_storage_words_are_no_part_of_the_type(self) -> None:
        for word in ("restrict", "__restrict", "__restrict__"):
            with self.subTest(word=word):
                self.assertEqual(one(f"char* {word}"), one("char*"))
                self.assertEqual(one(f"{word} char*"), one("char*"))
        for word in ("static", "extern", "inline", "register", "auto", "__inline", "__inline__"):
            with self.subTest(word=word):
                self.assertEqual(one(f"{word} char*"), one("char*"))
                self.assertEqual(one(f"char {word} *"), one("char*"))
        self.assertEqual(one("restrict char* restrict"), one("char*"))

    def test_a_top_level_qualifier_is_no_part_of_a_parameter_or_a_result(self) -> None:
        proto = ct.parse_prototype("const int32_t f(const int32_t x, char* const p, volatile uint8_t v)")
        self.assertEqual(proto.ret, one("int32_t"))
        self.assertEqual(proto.params, (one("int32_t"), one("char*"), one("uint8_t")))

    def test_a_pointee_qualifier_stays_in_a_parameter(self) -> None:
        proto = ct.parse_prototype("void f(const char* s, char* const* t)")
        self.assertTrue(proto.params[0].target.const)
        self.assertTrue(proto.params[1].target.const)

    def test_unqualified_drops_every_level(self) -> None:
        self.assertEqual(ct.unqualified(one("const char* const*")), one("char**"))
        self.assertEqual(ct.unqualified(one("int32_t (* const)(const char*)")), one("int32_t (*)(char*)"))


class Declarators(unittest.TestCase):
    def test_pointers_of_pointers(self) -> None:
        self.assertEqual(one("char**"), ct.pointer(ct.pointer(one("char"))))
        self.assertEqual(one("void*"), ct.pointer(ct.NO_VALUE))
        self.assertEqual(one("char * * "), one("char**"))

    def test_a_function_pointer(self) -> None:
        ty = one("int32_t (*)(int32_t, int32_t)")
        self.assertEqual(ty.kind, ct.PTR)
        self.assertEqual(ty.target.kind, ct.FUNC)
        self.assertEqual(ty.target.target, one("int32_t"))
        self.assertEqual(ty.target.params, (one("int32_t"), one("int32_t")))
        self.assertEqual(one("int32_t(*)(int32_t,int32_t)"), ty)
        self.assertNotEqual(one("int32_t (*)(int32_t)"), ty)
        self.assertNotEqual(one("int32_t (*)(int32_t, uint32_t)"), ty)
        self.assertNotEqual(one("uint32_t (*)(int32_t, int32_t)"), ty)

    def test_a_function_pointer_with_no_parameters_or_a_variadic_tail(self) -> None:
        self.assertEqual(one("void (*)(void)"), one("void (*)()"))
        self.assertEqual(one("void (*)(void)").target.params, ())
        self.assertTrue(one("int (*)(const char*, ...)").target.variadic)
        self.assertEqual(one("int (*)(const char*, ...)").target.params, (one("const char*"),))
        self.assertNotEqual(one("int (*)(const char*, ...)"), one("int (*)(const char*)"))

    def test_nested_function_pointers(self) -> None:
        ty = one("void (*(*)(int32_t))(int32_t)")
        self.assertEqual(ty.kind, ct.PTR)
        function = ty.target
        self.assertEqual((function.kind, function.params), (ct.FUNC, (one("int32_t"),)))
        self.assertEqual(function.target, one("void (*)(int32_t)"))
        self.assertEqual(one("int (**)(int)").target, one("int (*)(int)"))
        self.assertEqual(one("int ((*)(int))"), one("int (*)(int)"))
        self.assertEqual(one("int (((*)))(int)"), one("int (*)(int)"))

    def test_arrays_and_pointers_to_arrays(self) -> None:
        self.assertEqual(one("int32_t [4]"), ct.CType(ct.ARRAY, target=one("int32_t"), count=4))
        self.assertEqual(one("int32_t [2][3]").target.count, 3)
        self.assertEqual(one("int32_t [2][3]").count, 2)
        pointer = one("int32_t (*)[4]")
        self.assertEqual((pointer.kind, pointer.target.kind, pointer.target.count), (ct.PTR, ct.ARRAY, 4))
        self.assertEqual(one("int32_t *[4]").kind, ct.ARRAY)
        self.assertEqual(one("int32_t *[4]").target, one("int32_t*"))
        self.assertIsNone(one("char []").count)

    def test_a_function_pointer_array_parameter_is_a_pointer_to_a_function_pointer(self) -> None:
        proto = ct.parse_prototype("int deref_cb(int (*cbs[2])(int, int), int a)")
        self.assertEqual(proto.params[0], one("int (**)(int, int)"))
        self.assertEqual(proto.params[1], one("int"))

    def test_a_parameter_array_or_function_decays(self) -> None:
        proto = ct.parse_prototype("void f(int a[4][4], int b[], int c(int), char* d[3])")
        self.assertEqual(proto.params[0], one("int (*)[4]"))
        self.assertEqual(proto.params[1], one("int*"))
        self.assertEqual(proto.params[2], one("int (*)(int)"))
        self.assertEqual(proto.params[3], one("char**"))


class Prototypes(unittest.TestCase):
    def test_the_spelling_r2s_prints(self) -> None:
        proto = ct.parse_prototype("uint32_t fnv1a32(const uint8_t* p, uint64_t n)")
        self.assertEqual((proto.name, proto.ret), ("fnv1a32", one("uint32_t")))
        self.assertEqual(proto.params, (one("const uint8_t*"), one("uint64_t")))
        self.assertFalse(proto.variadic)

    def test_a_result_that_is_a_function_pointer_is_read_not_refused(self) -> None:
        # r2s writes the result as one type name and then the name: no C declaration, a prototype all the same.
        for text, ret, name, params in [
            ("int32_t(*)(int32_t, int32_t) pick(int32_t sel)", "int32_t (*)(int32_t, int32_t)", "pick", ["int32_t"]),
            ("void(*)(int32_t) set_sigint_handler(void)", "void (*)(int32_t)", "set_sigint_handler", []),
            ("void(*)(int32_t) set_signal_handler(int32_t sig, void (*handler)(int32_t))", "void (*)(int32_t)",
             "set_signal_handler", ["int32_t", "void (*)(int32_t)"]),
            ("int32_t(*)(struct word_list*) find_shell_builtin(char* name)", "int32_t (*)(struct word_list*)",
             "find_shell_builtin", ["char*"]),
            ("void(*(*)(int32_t))(int32_t) chain(void)", "void (*(*)(int32_t))(int32_t)", "chain", []),
            ("char*(*)(void) h(char (*vt)[16])", "char*(*)(void)", "h", ["char (*)[16]"]),
        ]:
            with self.subTest(text=text):
                proto = ct.parse_prototype(text)
                self.assertEqual((ct.spell(proto.ret), proto.name, [ct.spell(p) for p in proto.params]),
                                 (ret, name, params))

    def test_no_parameters(self) -> None:
        for text in ("int main(void)", "int main()", "int main(void);"):
            with self.subTest(text=text):
                self.assertEqual(ct.parse_prototype(text).params, ())

    def test_a_variadic_tail_is_a_flag_and_no_parameter(self) -> None:
        proto = ct.parse_prototype("uint32_t fcn_e200(uint32_t arg0, uint32_t arg1, ...)")
        self.assertEqual(len(proto.params), 2)
        self.assertTrue(proto.variadic)
        self.assertEqual(ct.parse_prototype("int f(...)").params, ())

    def test_unnamed_parameters_and_storage_words(self) -> None:
        proto = ct.parse_prototype("static inline int f(int, char*, void (*)(int), struct node*)")
        self.assertEqual(proto.params, (one("int"), one("char*"), one("void (*)(int)"), one("struct node*")))
        self.assertEqual(proto.ret, one("int"))

    def test_aggregates_and_the_wide_types(self) -> None:
        proto = ct.parse_prototype("struct pair mkpair(struct pair p, union u q, long double x, unsigned long long y)")
        self.assertEqual(proto.ret, ct.CType(ct.NAMED, name="struct pair"))
        self.assertEqual(proto.params[1], ct.CType(ct.NAMED, name="union u"))
        self.assertEqual(proto.params[2], ct.CType(ct.FLOAT, width=16))
        self.assertEqual(proto.params[3], one("size_t"))

    def test_text_that_is_no_prototype_is_refused(self) -> None:
        for text in ("", "not a prototype", "int f(", "int f(int x", "int f(int x,)", "int (f", "1 f()", "int f(int $x)",
                     "int f(void) int", "int f(int [)", "struct f()", "int f(void)) ", "int a.b(void)", "const f(void)",
                     "int ( f(void)", "int f(int x y z)"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)

    def test_a_close_that_is_none_is_refused(self) -> None:
        for text in ("int f(int x]", "int f(int x[3)", "int f(int x[3}", "int f(int x)]", "int f(int (*x]))"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)

    def test_a_function_is_named_by_a_name_and_no_keyword_or_number(self) -> None:
        for text in ("int *int(void)", "int *struct(void)", "int *static(void)", "int *char(void)", "int *1(void)",
                     "int *unsigned(void)", "int *enum(void)", "int *union(void)", "int *restrict(void)",
                     "int *register(void)"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)

    def test_a_tag_is_named_by_a_name_and_no_keyword_or_number(self) -> None:
        for text in ("struct const", "struct int", "struct struct", "struct 1", "union static", "enum", "struct"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_type(text)
        self.assertEqual(one("struct _x1"), ct.CType(ct.NAMED, name="struct _x1"))

    def test_a_parameter_is_named_by_a_name_and_no_keyword(self) -> None:
        for text in ("void f(int *char)", "void f(int *struct)", "void f(int *static)", "void f(int *unsigned)",
                     "void f(int *const x y)", "void f(int *1)", "void f(int x y)"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)

    def test_a_group_holds_one_declarator_and_a_named_parameter_group_names_at_most_once(self) -> None:
        for text in ("void f(int (*x y)(int))", "void f(int (*)(int)))", "void f(int (*x)))"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)
        self.assertEqual(ct.parse_prototype("void f(int (*x)(int))").params, (one("int (*)(int)"),))

    def test_the_result_of_a_header_has_no_name_in_its_own_declarator(self) -> None:
        for text in ("int (*name)(int) f(void)", "int (*name) f(void)"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)

    def test_void_is_a_parameter_only_on_its_own(self) -> None:
        for text in ("int f(void, int)", "int f(int, void)", "int f(void, void)", "int f(void, ...)"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)
        for text in ("int f(void*)", "int f(void* p, void (*cb)(void))", "int f(void)"):
            with self.subTest(text=text):
                ct.parse_prototype(text)

    def test_a_type_that_is_not_a_type_is_refused(self) -> None:
        for text in ("", "*", "int (", "int [", "const", "struct", "int int int )"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_type(text)

    def test_the_name_may_not_be_a_type_word(self) -> None:
        for text in ("int int(void)", "int const(void)", "int struct(void)"):
            with self.subTest(text=text), self.assertRaises(ct.ParseError):
                ct.parse_prototype(text)


class Spelling(unittest.TestCase):
    CASES = [
        ("unsigned long", "uint64_t"), ("long long", "int64_t"), ("unsigned char", "uint8_t"), ("signed char", "int8_t"),
        ("char", "char"), ("_Bool", "bool"), ("float", "float"), ("double", "double"), ("long double", "long double"),
        ("short", "int16_t"), ("void", "void"), ("struct pair", "struct pair"), ("const char*", "const char*"),
        ("char* const", "char* const"), ("char const* const*", "const char* const*"), ("volatile int*", "volatile int32_t*"),
        ("const volatile int*", "const volatile int32_t*"), ("char* volatile", "char* volatile"),
        ("int32_t (*)(int32_t, int32_t)", "int32_t (*)(int32_t, int32_t)"),
        ("void (*)(void)", "void (*)(void)"), ("int (*)(const char*, ...)", "int32_t (*)(const char*, ...)"),
        ("int32_t (*)[4]", "int32_t (*)[4]"), ("int32_t [2][3]", "int32_t [2][3]"), ("char* [4]", "char*[4]"),
        ("int [ ]", "int32_t []"), ("void (*(*)(int32_t))(int32_t)", "void (*(*)(int32_t))(int32_t)"),
        ("int (**)(int)", "int32_t (**)(int32_t)"), ("int (* const)(int)", "int32_t (* const)(int32_t)"),
    ]

    def test_spelling(self) -> None:
        for text, spelled in self.CASES:
            with self.subTest(text=text):
                self.assertEqual(ct.spell(one(text)), spelled)

    def test_a_spelling_reads_back_as_the_type_it_spells(self) -> None:
        for text, _ in self.CASES:
            with self.subTest(text=text):
                self.assertEqual(one(ct.spell(one(text))), one(text))

    def test_a_named_type_spells_as_its_name(self) -> None:
        self.assertEqual(ct.spell(ct.CType(ct.NAMED, name="FILE")), "FILE")


class Classify(unittest.TestCase):
    def bucket(self, expected: str, actual: str) -> str:
        return ct.classify(one(expected), one(actual))

    def test_each_kind_of_difference_has_its_bucket(self) -> None:
        for expected, actual, bucket in [
            ("int", "size_t", "width_wider"), ("uint32_t", "uint8_t", "width_narrower"),
            ("int8_t", "uint8_t", "sign"), ("uint32_t", "int", "sign"), ("int64_t", "uint64_t", "sign"),
            ("char", "int8_t", "other"), ("char", "uint8_t", "other"), ("uint8_t", "char", "other"),
            ("const uint8_t*", "uint8_t*", "qualifier"), ("int (* const *)(int)", "int (**)(int)", "qualifier"),
            ("const char**", "char**", "qualifier"), ("char* const*", "char**", "qualifier"),
            ("volatile int*", "int*", "qualifier"), ("const char* const*", "const char**", "qualifier"),
            ("int (*)(int, int)", "int (*)(char*)", "pointee"), ("const uint8_t*", "void*", "pointee"),
            ("uint8_t*", "uint16_t*", "pointee"), ("char**", "char*", "pointee"),
            ("const uint8_t*", "size_t", "pointer_as_integer"), ("size_t", "uint8_t*", "integer_as_pointer"),
            ("void", "size_t", "void_vs_value"), ("int", "void", "void_vs_value"),
            ("void*", "size_t", "pointer_as_integer"), ("void", "void*", "void_vs_value"),
            ("float", "uint32_t", "other"), ("double", "float", "other"), ("struct pair", "uint64_t", "other"),
            ("bool", "uint8_t", "other"), ("struct a", "struct b", "other"),
        ]:
            with self.subTest(expected=expected, actual=actual):
                self.assertEqual(self.bucket(expected, actual), bucket)

    def test_widths_compare_before_signs(self) -> None:
        self.assertEqual(self.bucket("int8_t", "uint32_t"), "width_wider")
        self.assertEqual(self.bucket("uint64_t", "int8_t"), "width_narrower")

    def test_an_unknown_sign_is_not_a_sign_difference(self) -> None:
        self.assertEqual(self.bucket("char", "uint8_t"), "other")
        self.assertEqual(self.bucket("int8_t", "char"), "other")

    def test_a_spelling_difference_is_no_difference(self) -> None:
        for left, right in [("long", "long long"), ("size_t", "uintptr_t"), ("unsigned long", "uint64_t")]:
            self.assertEqual(one(left), one(right))

    def test_integer_class(self) -> None:
        for text in ("int", "uint8_t", "char", "_Bool", "void*", "int (*)(int)", "struct a*", "size_t"):
            with self.subTest(text=text):
                self.assertTrue(ct.integer_class(one(text)))
        for text in ("float", "double", "long double", "struct pair", "union u", "void", "int [4]", "__int128"):
            with self.subTest(text=text):
                self.assertFalse(ct.integer_class(ct.CType(ct.INT, width=16, signed=True) if text == "__int128"
                                                  else one(text)))


class FromDwarf(unittest.TestCase):
    """The type of every function of tests/gold/source_gold/odd.c, from `readelf --debug-dump=info` of the gcc build."""

    @classmethod
    def setUpClass(cls) -> None:
        text = (FIXTURES / "odd.txt").read_text()
        units, index = dwarf.parse_readelf(text)
        cls.dwarf = dwarf.Dwarf(units, index)
        cls.functions = {sub.name: sub for sub in cls.dwarf.subprograms()}

    def signature(self, name: str) -> tuple[str, list[str], bool]:
        sub = self.functions[name]
        return (ct.spell(ct.decay(ct.from_dwarf(self.dwarf, sub.return_type))),
                [ct.spell(ct.decay(ct.from_dwarf(self.dwarf, p.type_offset))) for p in sub.parameters], sub.variadic)

    def test_the_functions_of_odd_c(self) -> None:
        for name, expected in {
            "add": ("int32_t", ["int32_t", "int32_t"], False),
            "pick": ("int32_t (*)(int32_t, int32_t)", ["int32_t"], False),
            "pick2": ("int32_t (*)(int32_t, int32_t)", ["int32_t"], False),
            "set_handler": ("void (*)(int32_t)", ["int32_t", "void (*)(int32_t)"], False),
            "mkpair": ("struct pair", ["int64_t", "int64_t"], False),
            "sumpair": ("int64_t", ["struct pair"], False),
            "mkbig": ("struct big", ["int64_t"], False),
            "sumbig": ("int64_t", ["struct big"], False),
            "next_color": ("uint32_t", ["uint32_t"], False),
            "is_even": ("bool", ["uint8_t"], False),
            "sc": ("int8_t", ["int8_t"], False),
            "us": ("uint16_t", ["uint16_t"], False),
            "ll": ("int64_t", ["int64_t", "uint64_t"], False),
            "dbl": ("double", ["double", "float"], False),
            "flt": ("float", ["float"], False),
            "sum_va": ("int32_t", ["int32_t"], True),
            "argv_at": ("const char* const*", ["const char* const*", "uint64_t"], False),
            "vptr": ("volatile int32_t*", ["volatile int32_t*"], False),
            "arr2": ("int32_t", ["int32_t (*)[4]", "int32_t (*)[4]"], False),
            "vp": ("void*", ["void*", "uint64_t"], False),
            "deref_cb": ("int32_t", ["int32_t (**)(int32_t, int32_t)", "int32_t"], False),
            "u8": ("uint8_t", ["uint8_t"], False),
            "i16": ("int16_t", ["int16_t", "int16_t"], False),
            "bb": ("bool", ["bool", "bool"], False),
            "ip": ("int64_t", ["int64_t", "uint64_t"], False),
            "ss": ("int64_t", ["int64_t"], False),
            "wc": ("int32_t", ["int32_t"], False),
            "chr": ("char", ["char"], False),
            "nr": ("void", ["int32_t"], False),
            "main": ("int32_t", ["int32_t", "char**"], False),
        }.items():
            with self.subTest(function=name):
                self.assertEqual(self.signature(name), expected)

    def test_the_dump_holds_every_function_of_odd_c(self) -> None:
        self.assertEqual(len(self.functions), 31)
        self.assertIn("mul", self.functions)

    def test_a_type_the_gate_cannot_state_is_refused(self) -> None:
        index = {1: dwarf.Die(1, "DW_TAG_base_type", 1, {"DW_AT_byte_size": "8", "DW_AT_encoding": "3\t(complex float)"},
                              {"DW_AT_byte_size": "data1", "DW_AT_encoding": "data1"}),
                 2: dwarf.Die(2, "DW_TAG_unspecified_type", 1, {})}
        graph = dwarf.Dwarf([], index)
        for offset, message in [(1, "base type encoding 3"), (2, "DW_TAG_unspecified_type"), (99, "no DIE at 0x63")]:
            with self.subTest(offset=offset), self.assertRaises(ct.NotExpressible) as raised:
                ct.from_dwarf(graph, offset)
            self.assertIn(message, str(raised.exception))

    def test_a_void_pointer_and_a_missing_type_are_void(self) -> None:
        self.assertEqual(ct.from_dwarf(self.dwarf, None), ct.NO_VALUE)


class RoundTrip(unittest.TestCase):
    """A type written as DWARF reads back as itself, for every kind and every nesting."""

    TYPES = [
        "void", "char", "signed char", "unsigned char", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t",
        "_Bool", "float", "double", "long double", "struct pair", "union u", "void*", "char**", "const char*", "char* const",
        "volatile int*", "const volatile int*", "const char* const*", "int32_t [4]", "int32_t [2][3]", "char* [4]",
        "int32_t (*)[4]", "int32_t (*)(int32_t, int32_t)", "void (*)(void)", "int (*)(const char*, ...)",
        "const void", "const void*", "volatile void*", "void (*(*)(int32_t))(int32_t)", "struct pair*", "struct pair (*)(struct pair)", "int (**)(int)",
    ]

    def test_every_type(self) -> None:
        for text in self.TYPES:
            with self.subTest(text=text):
                graph = Graph()
                self.assertEqual(ct.from_dwarf(graph.dwarf(), graph.write(one(text))), one(text))

    def test_an_array_without_a_bound_has_no_count(self) -> None:
        graph = Graph()
        self.assertIsNone(ct.from_dwarf(graph.dwarf(), graph.write(one("char []"))).count)

    def test_a_subprogram_keeps_its_parameters_in_order(self) -> None:
        graph = Graph()
        sub = graph.subprogram(ct.parse_prototype("char* f(int8_t a, uint64_t b, void* c)"), 0x1000)
        types = [ct.from_dwarf(graph.dwarf(), p.type_offset) for p in sub.parameters]
        self.assertEqual(types, [one("int8_t"), one("uint64_t"), one("void*")])


class Resolving(unittest.TestCase):
    """What a typedef, a qualifier, an enum or an unnamed struct reads as."""

    def read(self, build) -> ct.CType:
        graph = Graph()
        return ct.from_dwarf(graph.dwarf(), build(graph))

    def test_a_typedef_is_what_it_names(self) -> None:
        def build(graph):
            unsigned_long = graph.write(one("unsigned long"))
            return graph.die("DW_TAG_typedef", name="size_t", type=graph.die("DW_TAG_typedef", name="__size_t", type=unsigned_long))
        self.assertEqual(self.read(build), one("size_t"))

    def test_qualifiers_survive_a_typedef(self) -> None:
        def build(graph):
            char = graph.write(one("char"))
            alias = graph.die("DW_TAG_typedef", name="byte", type=graph.die("DW_TAG_const_type", type=char))
            return graph.die("DW_TAG_pointer_type", type=graph.die("DW_TAG_volatile_type", type=alias))
        self.assertEqual(self.read(build), one("const volatile char*"))

    def test_restrict_and_atomic_are_not_kept(self) -> None:
        def build(graph):
            pointer = graph.die("DW_TAG_pointer_type", type=graph.write(one("char")))
            return graph.die("DW_TAG_atomic_type", type=graph.die("DW_TAG_restrict_type", type=pointer))
        self.assertEqual(self.read(build), one("char*"))

    def test_an_enum_that_states_its_size_and_underlying_type_is_that_integer(self) -> None:
        signed = self.read(lambda g: g.die("DW_TAG_enumeration_type", name="e", size=4, type=g.write(one("int"))))
        unsigned = self.read(lambda g: g.die("DW_TAG_enumeration_type", name="e", size=4, type=g.write(one("unsigned"))))
        wide = self.read(lambda g: g.die("DW_TAG_enumeration_type", name="e", size=8, type=g.write(one("long"))))
        self.assertEqual((signed, unsigned, wide), (one("int32_t"), one("uint32_t"), one("int64_t")))

    def test_a_type_that_states_itself_elsewhere_or_states_no_size_is_refused(self) -> None:
        # gcc's type-unit stub has only DW_AT_signature, DWARF 2 strict gives an enum no DW_AT_type, `enum e;` is a
        # declaration: each was read as uint32_t (`size or 4`, unsigned) or as a guess at its size.
        def enum(**attrs):
            return lambda g: g.die("DW_TAG_enumeration_type", name="e", **attrs)
        int_type = lambda g: g.write(one("int"))  # noqa: E731
        long_type = lambda g: g.write(one("long"))  # noqa: E731
        stub = enum(signature=SIGNATURE.lstrip(": "))
        cases = {
            "an enum stub of a type unit": stub,
            "an enum with no underlying type": enum(size=4),
            "an enum with no size": lambda g: g.die("DW_TAG_enumeration_type", name="e", type=long_type(g)),
            "an enum declared and not defined": enum(declaration=1),
            "an enum whose size is not its underlying type's": lambda g: g.die("DW_TAG_enumeration_type", name="e", size=4,
                                                                                  type=long_type(g)),
            "an enum declared with a size and a type": lambda g: g.die("DW_TAG_enumeration_type", name="e", size=4,
                                                                         type=int_type(g), declaration=1),
            "a typedef of an enum stub": lambda g: g.die("DW_TAG_typedef", name="neg_t", type=stub(g)),
            "a pointer to an enum stub": lambda g: g.die("DW_TAG_pointer_type", size=8, type=stub(g)),
            "a const enum with no underlying type": lambda g: g.die("DW_TAG_const_type", type=enum(size=8)(g)),
            "an enum over plain char": lambda g: g.die("DW_TAG_enumeration_type", name="e", size=1, type=g.write(one("char"))),
            "an enum over a pointer": lambda g: g.die("DW_TAG_enumeration_type", name="e", size=8, type=g.write(one("int*"))),
            "a base type with no size": lambda g: g.die("DW_TAG_base_type", name="int", encoding="5\t(signed)"),
            "a boolean with no size": lambda g: g.die("DW_TAG_base_type", name="_Bool", encoding="2\t(boolean)"),
            "a struct stub of a type unit with a tag": lambda g: g.die("DW_TAG_structure_type", name="s",
                                                                        signature="0x1234"),
            "a struct declared and not defined": lambda g: g.die("DW_TAG_structure_type", name="opaque", declaration=1),
            "a pointer to a struct declared and not defined": lambda g: g.die(
                "DW_TAG_pointer_type", size=8, type=g.die("DW_TAG_structure_type", name="opaque", declaration=1)),
            "a typedef that is a stub": lambda g: g.die("DW_TAG_typedef", name="t", signature="0x1234",
                                                         type=g.write(one("int"))),
        }
        for name, build in cases.items():
            with self.subTest(name), self.assertRaises(ct.NotExpressible):
                self.read(build)

    def test_a_size_or_a_bound_written_as_an_expression_is_no_number(self) -> None:
        # `int a[n][n]` bounds its rows by an expression: readelf prints the block's length first, which read as a count.
        def vla(graph):
            bound = graph.child("DW_TAG_subrange_type")
            bound.attrs["DW_AT_upper_bound"] = "3 byte block: 91 68 6 \t(DW_OP_fbreg: -24; DW_OP_deref)"
            bound.forms["DW_AT_upper_bound"] = "exprloc"
            return graph.die("DW_TAG_pointer_type", size=8, type=graph.die("DW_TAG_array_type", (bound,),
                                                                          type=graph.write(one("int"))))
        with self.assertRaises(ct.NotExpressible):
            self.read(vla)
        def counted(graph):
            bound = graph.child("DW_TAG_subrange_type")
            bound.attrs["DW_AT_count"] = "2 byte block: 91 68 \t(DW_OP_fbreg: -24)"
            bound.forms["DW_AT_count"] = "exprloc"
            return graph.die("DW_TAG_array_type", (bound,), type=graph.write(one("int")))
        with self.assertRaises(ct.NotExpressible):
            self.read(counted)
        def unformed(graph):
            die = graph.index[graph.write(one("int"))]
            del die.forms["DW_AT_byte_size"]
            return die.offset
        with self.assertRaises(ct.NotExpressible):
            self.read(unformed)

    def test_an_unnamed_struct_takes_its_typedef_name_and_a_tagged_one_its_tag(self) -> None:
        def anonymous(graph):
            return graph.die("DW_TAG_typedef", name="point_t", type=graph.die("DW_TAG_structure_type", size=8))
        def tagged(graph):
            return graph.die("DW_TAG_typedef", name="point_t", type=graph.die("DW_TAG_structure_type", name="point", size=8))
        self.assertEqual(self.read(anonymous), ct.CType(ct.NAMED, name="point_t"))
        self.assertEqual(self.read(tagged), ct.CType(ct.NAMED, name="struct point"))

    def test_an_aggregate_with_no_name_at_all_is_refused_and_not_spelled_anonymous(self) -> None:
        # `-fdebug-types-section` leaves a stub with a signature in the unit: two different structs would read equal.
        for build in (lambda g: g.die("DW_TAG_union_type", size=8),
                      lambda g: g.die("DW_TAG_pointer_type", type=g.die("DW_TAG_structure_type", size=8))):
            with self.assertRaises(ct.NotExpressible) as raised:
                self.read(build)
            self.assertIn("neither a tag nor a typedef name", str(raised.exception))

    def test_a_type_in_another_unit_is_refused_and_not_read_as_void(self) -> None:
        # `-fdebug-types-section`: `DW_AT_type : (ref_sig8) : 0x...` names a DIE of a type unit, which is no void.
        for build in (lambda g: g.die("DW_TAG_pointer_type", size=8, type=dwarf.UNRESOLVED),
                      lambda g: g.die("DW_TAG_typedef", name="t", type=dwarf.UNRESOLVED),
                      lambda g: g.die("DW_TAG_const_type", type=dwarf.UNRESOLVED),
                      lambda g: g.die("DW_TAG_array_type", type=dwarf.UNRESOLVED),
                      lambda g: g.die("DW_TAG_subroutine_type", type=dwarf.UNRESOLVED),
                      lambda g: g.die("DW_TAG_enumeration_type", name="e", size=4, type=dwarf.UNRESOLVED)):
            with self.assertRaises(ct.NotExpressible) as raised:
                self.read(build)
            self.assertIn("another unit", str(raised.exception))
        self.assertEqual(self.read(lambda g: g.die("DW_TAG_pointer_type", size=8)), one("void*"))

    def test_a_vector_is_no_array_and_is_refused(self) -> None:
        def vector(graph, flagged):
            bound = graph.child("DW_TAG_subrange_type", upper=3)
            return graph.die("DW_TAG_array_type", (bound,), type=graph.write(one("int")), size=16, vector=1 if flagged else None)
        self.assertEqual(self.read(lambda g: vector(g, False)), one("int [4]"))
        for build in (lambda g: vector(g, True), lambda g: g.die("DW_TAG_pointer_type", type=vector(g, True))):
            with self.assertRaises(ct.NotExpressible) as raised:
                self.read(build)
            self.assertIn("vector", str(raised.exception))

    def test_a_class_is_named(self) -> None:
        self.assertEqual(self.read(lambda g: g.die("DW_TAG_class_type", name="c", size=4)), ct.CType(ct.NAMED, name="struct c"))

    def test_a_reference_is_a_pointer(self) -> None:
        self.assertEqual(self.read(lambda g: g.die("DW_TAG_reference_type", type=g.write(one("int")))), one("int32_t*"))

    def test_the_base_type_encodings(self) -> None:
        def base(name, encoding, size):
            return lambda g: g.die("DW_TAG_base_type", name=name, size=size, encoding=f"{encoding}\t(e)")
        self.assertEqual(self.read(base("char", 8, 1)), one("char"))
        self.assertEqual(self.read(base("char", 6, 1)), one("char"))
        self.assertEqual(self.read(base("unsigned char", 8, 1)), one("unsigned char"))
        self.assertEqual(self.read(base("signed char", 6, 1)), one("signed char"))
        self.assertEqual(self.read(base("char16_t", 0x10, 2)), one("uint16_t"))
        self.assertEqual(self.read(base("_Bool", 2, 1)), one("_Bool"))
        self.assertEqual(self.read(base("float", 4, 4)), one("float"))
        self.assertEqual(self.read(base("long double", 4, 16)), one("long double"))
        self.assertEqual(self.read(base("__int128", 5, 16)), ct.integer(16, True))
        for encoding in (1, 3, 0xb):
            with self.subTest(encoding=encoding), self.assertRaises(ct.NotExpressible):
                self.read(base("x", encoding, 8))

    def test_a_chain_of_sixty_four_dies_is_read_and_one_more_is_refused(self) -> None:
        for typedefs, readable in [(63, True), (64, False), (70, False)]:
            with self.subTest(typedefs=typedefs):
                graph = Graph()
                offset = graph.write(one("int"))
                for _ in range(typedefs):
                    offset = graph.die("DW_TAG_typedef", name="t", type=offset)
                if readable:
                    self.assertEqual(ct.from_dwarf(graph.dwarf(), offset), one("int"))
                else:
                    with self.assertRaises(ct.NotExpressible):
                        ct.from_dwarf(graph.dwarf(), offset)

    def test_a_type_nested_thirty_two_levels_is_read_and_one_more_is_refused(self) -> None:
        for levels, readable in [(30, True), (32, True), (33, False), (40, False)]:
            with self.subTest(levels=levels):
                graph = Graph()
                offset = graph.write(one("int"))
                for _ in range(levels):
                    offset = graph.die("DW_TAG_pointer_type", type=offset)
                if readable:
                    self.assertEqual(ct.from_dwarf(graph.dwarf(), offset).kind, ct.PTR)
                else:
                    with self.assertRaises(ct.NotExpressible):
                        ct.from_dwarf(graph.dwarf(), offset)

    def test_the_outermost_typedef_names_an_unnamed_struct(self) -> None:
        def build(graph):
            anonymous = graph.die("DW_TAG_structure_type", size=8)
            return graph.die("DW_TAG_typedef", name="outer", type=graph.die("DW_TAG_typedef", name="inner", type=anonymous))
        self.assertEqual(self.read(build), ct.CType(ct.NAMED, name="outer"))

    def test_a_multidimensional_array_is_an_array_of_arrays_in_the_order_written(self) -> None:
        def build(graph):
            rows = graph.child("DW_TAG_subrange_type", upper=1)
            columns = graph.child("DW_TAG_subrange_type", upper=2)
            return graph.die("DW_TAG_array_type", (rows, columns), type=graph.write(one("int")))
        ty = self.read(build)
        self.assertEqual((ty.kind, ty.count, ty.target.kind, ty.target.count), (ct.ARRAY, 2, ct.ARRAY, 3))
        self.assertEqual(ty, one("int [2][3]"))

    def test_an_array_without_a_subrange_is_an_array_of_no_count(self) -> None:
        ty = self.read(lambda g: g.die("DW_TAG_array_type", type=g.write(one("int"))))
        self.assertEqual((ty.kind, ty.count, ty.target), (ct.ARRAY, None, one("int")))

    def test_a_parameter_of_a_function_type_decays_in_the_dwarf_as_in_the_text(self) -> None:
        def build(graph):
            bound = graph.child("DW_TAG_subrange_type", upper=3)
            array = graph.die("DW_TAG_array_type", (bound,), type=graph.write(one("int")))
            function = graph.write(one("int (*)(void)"))
            children = (graph.child("DW_TAG_formal_parameter", type=array),
                        graph.child("DW_TAG_formal_parameter", type=graph.write(one("const char*")), ))
            subroutine = graph.die("DW_TAG_subroutine_type", children, type=graph.write(one("void")))
            return graph.die("DW_TAG_pointer_type", type=subroutine)
        self.assertEqual(self.read(build), one("void (*)(int*, const char*)"))

    def test_a_boolean_is_a_boolean_whatever_its_size(self) -> None:
        for size in (1, 4):
            with self.subTest(size=size):
                self.assertEqual(self.read(lambda g, size=size: g.die("DW_TAG_base_type", name="_Bool", size=size,
                                                                        encoding="2\t(boolean)")), one("_Bool"))

    def test_an_array_with_a_count_and_one_with_a_bound(self) -> None:
        def counted(graph):
            bound = graph.child("DW_TAG_subrange_type", count=6)
            return graph.die("DW_TAG_array_type", (bound,), type=graph.write(one("int")))
        self.assertEqual(self.read(counted).count, 6)


if __name__ == "__main__":
    unittest.main()
