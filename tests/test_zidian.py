"""Validation suite for zidian. Run: python -m tests.test_npdict  (or pytest)."""

from __future__ import annotations

import os
import sys
import tempfile
import unicodedata
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from zidian import (  # noqa: E402
    DictionaryNameFactory,
    DictionarySpec,
    DiscoveryRules,
    NameMapper,
    apply_map_to_text,
    discover,
    extract_symbols,
    generate_dictionary,
    is_valid_identifier,
    load_dictionary,
    parse_dictionary,
    transform_archive,
    write_dictionary,
)

REF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "字典.txt")
HAVE_REF = os.path.exists(REF)


def _marks(w):
    return sum(1 for c in w if unicodedata.category(c) == "Mn")


# --- reference dictionary (skipped if the fixture isn't present) -----------
def test_reference_parses_to_1000_unique_words():
    if not HAVE_REF:
        print("  SKIP (no reference fixture)"); return
    words = load_dictionary(REF)
    assert len(words) == 1000
    assert len(set(words)) == 1000
    assert all(len(w) == 300 for w in words)
    assert all(is_valid_identifier(w) for w in words)


def test_reference_alphabet_and_marks():
    if not HAVE_REF:
        print("  SKIP (no reference fixture)"); return
    words = load_dictionary(REF)
    base, marks = set(), set()
    for w in words:
        for ch in w:
            (marks if unicodedata.category(ch) == "Mn" else base).add(ch)
    assert "".join(sorted(base)) == "BKPacehklnoptu"
    assert len(marks) == 86


def test_parser_handles_comments_and_separators():
    text = "aaa\n# a comment line\nbbb ccc\t ddd\n#trailing\naaa\n"
    # words: aaa, bbb, ccc, ddd ; the second 'aaa' is a duplicate (dropped)
    assert parse_dictionary(text) == ["aaa", "bbb", "ccc", "ddd"]


# --- generator ------------------------------------------------------------
def test_generated_dictionary_matches_reference_shape():
    words = generate_dictionary(DictionarySpec(count=1000, seed=7))
    assert len(words) == 1000 and len(set(words)) == 1000
    assert all(len(w) == 300 for w in words)
    assert all(is_valid_identifier(w) for w in words)
    # Every generated word parses back to exactly itself as one dictionary word.
    for w in words[:50]:
        assert parse_dictionary(w) == [w]


def test_generator_is_deterministic_with_seed():
    a = generate_dictionary(DictionarySpec(count=200, seed=42))
    b = generate_dictionary(DictionarySpec(count=200, seed=42))
    c = generate_dictionary(DictionarySpec(count=200, seed=43))
    assert a == b and a != c


def test_generated_is_valid_proguard_dictionary_roundtrip():
    words = generate_dictionary(DictionarySpec(count=300, seed=1))
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "字典.txt")
        write_dictionary(words, p)
        assert load_dictionary(p) == words
        with open(p, "rb") as fh:
            assert not fh.read().endswith(b"\n")  # reference has no trailing NL


# --- name factory / mapping ----------------------------------------------
def test_factory_odometer_concatenates_entries():
    # N=2 so we can hand-check: singles, then doubles in lex order, then triples.
    f = DictionaryNameFactory(["A", "B"])
    got = [f.name_at(i) for i in range(8)]
    assert got == ["A", "B", "AA", "AB", "BA", "BB", "AAA", "AAB"]
    assert len(set(got)) == len(got)  # all unique


def test_factory_matches_reference_dictionary_odometer():
    # Reproduces the rule recovered from the before/after DEX:
    #   name(N)=entry0+entry0, name(N+1)=entry0+entry1, ...
    if not HAVE_REF:
        print("  SKIP (no reference fixture)"); return
    words = load_dictionary(REF)
    f = DictionaryNameFactory(words)
    n = len(words)  # 1000
    assert f.name_at(0) == words[0]
    assert f.name_at(n - 1) == words[n - 1]
    assert f.name_at(n) == words[0] + words[0]
    assert f.name_at(n + 1) == words[0] + words[1]
    assert f.name_at(2 * n) == words[1] + words[0]
    assert all(len(f.name_at(i)) == 300 for i in range(n))      # singles: 300 cp
    assert all(len(f.name_at(n + i)) == 600 for i in range(50))  # doubles: 600 cp


def test_mapping_is_reversible():
    words = generate_dictionary(DictionarySpec(count=50, seed=5))
    mapper = NameMapper(DictionaryNameFactory(words))
    src = "class Foo { int alpha; void beta(int gamma) { alpha = gamma; } }"
    syms = extract_symbols(src)
    mapper.map_all(syms)
    obf = apply_map_to_text(src, mapper.forward)
    reverse = {v: k for k, v in mapper.forward.items()}
    assert apply_map_to_text(obf, reverse) == src


def test_only_whole_identifiers_are_renamed():
    mapping = {"cat": "DOG"}
    # 'category' must NOT be touched, only the standalone token 'cat'.
    assert apply_map_to_text("cat category .cat", mapping) == "DOG category .DOG"


# --- discovery ------------------------------------------------------------
def test_discovery_filters_and_exclusions():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "sub"))
        for rel in ["a.smali", "b.txt", "sub/c.smali", "sub/R.smali", "keep.png"]:
            open(os.path.join(d, rel), "w").close()
        rules = DiscoveryRules(recursive=True, include_exts=(".smali",),
                               exclude_globs=("*/R.smali",))
        found = {os.path.relpath(p, d) for p in discover(d, rules)}
        assert found == {"a.smali", os.path.join("sub", "c.smali")}
        nonrec = {os.path.relpath(p, d) for p in
                  discover(d, DiscoveryRules(recursive=False, include_exts=(".smali",)))}
        assert nonrec == {"a.smali"}


# --- archive handling -----------------------------------------------------
def test_archive_renames_text_preserves_binary():
    mapping = {"secret": "XYZ"}
    with tempfile.TemporaryDirectory() as d:
        jin = os.path.join(d, "in.jar")
        jout = os.path.join(d, "out.jar")
        binblob = bytes(range(256))
        with zipfile.ZipFile(jin, "w") as z:
            z.writestr("a/x.smali", "invoke secret here")
            z.writestr("a/data.bin", binblob)
        rep = transform_archive(jin, jout, mapping)
        assert rep["a/x.smali"] is True and rep["a/data.bin"] is False
        with zipfile.ZipFile(jout) as z:
            assert z.read("a/x.smali").decode() == "invoke XYZ here"
            assert z.read("a/data.bin") == binblob  # byte-identical


# --- robustness -----------------------------------------------------------
def test_missing_dictionary_raises():
    try:
        load_dictionary("/no/such/字典.txt")
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


def test_malformed_or_empty_dictionary():
    assert parse_dictionary("") == []
    assert parse_dictionary("#only comments\n#more\n") == []
    assert parse_dictionary("!!!\n@@@\n") == []  # no identifier chars at all


def test_weird_filenames_roundtrip_in_archive():
    with tempfile.TemporaryDirectory() as d:
        jin, jout = os.path.join(d, "i.zip"), os.path.join(d, "o.zip")
        names = ["dir/space file.smali", "u̷n̷i.smali", "deep/a/b/c.smali"]
        with zipfile.ZipFile(jin, "w") as z:
            for n in names:
                z.writestr(n, "x foo y")
        transform_archive(jin, jout, {"foo": "BAR"})
        with zipfile.ZipFile(jout) as z:
            assert set(z.namelist()) == set(names)
            for n in names:
                assert z.read(n).decode() == "x BAR y"


def test_homoglyph_alphabet_and_marks_are_valid_identifiers():
    from zidian.dictionary import HOMOGLYPH_ALPHABET, extended_marks
    from zidian.javaid import is_java_identifier_part, is_java_identifier_start
    # every homoglyph base letter is a valid identifier START
    assert all(is_java_identifier_start(c) for c in HOMOGLYPH_ALPHABET)
    assert len(HOMOGLYPH_ALPHABET) > 14  # strictly richer than the reference 14
    # extended marks: all valid identifier PART, none valid as a start (pure marks)
    marks = extended_marks()
    assert len(marks) > 86  # strictly more than the reference 86
    assert all(is_java_identifier_part(c) and not is_java_identifier_start(c)
               for c in marks)


def test_hardening_profiles_generate_valid_unique_dictionaries():
    from zidian.dictionary import DictionarySpec
    for prof in ("classic", "balanced", "hard", "max"):
        spec = DictionarySpec.profile(prof, seed=3)
        spec.count = 200  # keep the test fast
        words = generate_dictionary(spec)
        assert len(words) == 200 and len(set(words)) == 200
        assert all(is_valid_identifier(w) for w in words)
        # each word still parses back to exactly itself (valid ProGuard entry)
        assert parse_dictionary(words[0]) == [words[0]]


def test_balanced_is_lighter_than_classic_per_entry():
    from zidian.dictionary import DictionarySpec
    assert (DictionarySpec.profile("balanced").est_bytes_per_entry()
            < DictionarySpec.profile("classic").est_bytes_per_entry())


def test_proguard_class_filter_wildcards():
    from zidian import ClassFilter, smali_class_name
    # default '**' selects everything
    assert ClassFilter.compile(["**"]).matches("com.app.Foo")
    # '*' does NOT cross a package separator
    f = ClassFilter.compile(["com.app.*"])
    assert f.matches("com.app.Foo")
    assert not f.matches("com.app.sub.Bar")
    # '**' crosses separators
    assert ClassFilter.compile(["com.app.**"]).matches("com.app.sub.Bar")
    # '?' matches one non-separator char
    assert ClassFilter.compile(["com.app.Fo?"]).matches("com.app.Foo")
    assert not ClassFilter.compile(["com.app.Fo?"]).matches("com.app.Foxx")
    # exclusion wins by order (first match decides)
    f2 = ClassFilter.compile(["!com.app.keep.**", "com.app.**"])
    assert not f2.matches("com.app.keep.Thing")
    assert f2.matches("com.app.other.Thing")
    # extract class name from smali, accepts slash form
    assert smali_class_name(".class public Lcom/app/Secret;\n.super ...") == "com.app.Secret"


def _tiny_dex():
    """Build a minimal valid DexFile model: one class, one direct method."""
    from zidian.dex import (DexFile, ClassDef, EncMethod, MethodRef, Proto, Code)
    dex = DexFile()
    dex.version = b"035\x00"
    dex.strings = []
    m = EncMethod(
        MethodRef("Lzidian/T;", Proto("V", ()), "foo"),
        access=0x9,  # public static
        code=Code(registers=0, ins=0, outs=0,
                  insns=bytearray([0x0e, 0x00]),  # return-void
                  patches=[], tries=[], debug_off_present=False),
    )
    c = ClassDef("Lzidian/T;", 0x1, "Ljava/lang/Object;", [], None,
                 [], [], [m], [], [])
    dex.classes = [c]
    return dex


def test_dex_roundtrip_builds_valid_file():
    import hashlib, struct, zlib
    from zidian.dex import serialize_dex, parse_dex
    out = serialize_dex(_tiny_dex())
    assert out[:4] == b"dex\n"
    # signature + checksum must validate
    assert hashlib.sha1(out[32:]).digest() == out[12:32]
    assert zlib.adler32(out[12:]) & 0xFFFFFFFF == struct.unpack_from("<I", out, 8)[0]
    d2 = parse_dex(out)
    assert len(d2.classes) == 1
    c = d2.classes[0]
    assert c.descriptor == "Lzidian/T;"
    assert c.superclass == "Ljava/lang/Object;"
    assert [m.ref.name for m in c.direct_methods] == ["foo"]
    assert bytes(c.direct_methods[0].code.insns) == bytes([0x0e, 0x00])
    # idempotent
    assert serialize_dex(d2) == serialize_dex(parse_dex(serialize_dex(d2)))


def test_dex_rename_changes_names_and_stays_valid():
    from zidian.dex import serialize_dex, parse_dex
    from zidian.dexobf import obfuscate_dex, ObfOptions
    base = serialize_dex(_tiny_dex())
    words = generate_dictionary(DictionarySpec(count=10, seed=1))
    out, mapping = obfuscate_dex(base, words, ObfOptions())
    assert len(mapping) == 1                       # the one direct method 'foo'
    d2 = parse_dex(out)                            # re-parse proves consistency
    name = d2.classes[0].direct_methods[0].ref.name
    assert name != "foo" and name in set(words)


def _run_all():
    g = globals()
    tests = [k for k in g if k.startswith("test_")]
    passed = 0
    for name in sorted(tests):
        g[name]()
        print(f"  PASS {name}")
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed")


if __name__ == "__main__":
    _run_all()
