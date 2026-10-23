"""Dictionary loading, generation, and the name factory.

This module is the *verified core* of the reproduction: it both reads a
ProGuard-style obfuscation dictionary exactly the way ProGuard does, and
regenerates files byte-structurally identical to the reference ``字典.txt``.

Reference dictionary (``字典.txt``) measured facts, all reproduced below:
  * 1000 entries, every one unique.
  * Each entry is exactly 300 Unicode codepoints.
  * Base alphabet = 14 letters: ``BKPacehklnoptu``.
  * 86 distinct combining marks in U+0300..U+0360 (category Mn).
  * Every entry's first codepoint is a valid Java identifier *start*;
    every other codepoint is a valid identifier *part* (letters + marks).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Sequence

from .javaid import is_java_identifier_part, is_valid_identifier

# ---------------------------------------------------------------------------
# Reference-derived defaults (so the generator reproduces 字典.txt's style).
# ---------------------------------------------------------------------------
REF_BASE_ALPHABET = "BKPacehklnoptu"
# The reference uses 86 marks in U+0300..U+0360 (a few codepoints are absent).
REF_COMBINING_MARKS = [
    chr(c) for c in (
        0x300, 0x302, 0x303, 0x304, 0x305, 0x306, 0x307, 0x308, 0x309, 0x30a,
        0x30b, 0x30c, 0x30d, 0x30e, 0x30f, 0x310, 0x311, 0x312, 0x313, 0x314,
        0x315, 0x316, 0x317, 0x318, 0x319, 0x31a, 0x31b, 0x31c, 0x31d, 0x31e,
        0x31f, 0x320, 0x321, 0x322, 0x324, 0x325, 0x326, 0x327, 0x328, 0x329,
        0x32a, 0x32b, 0x32c, 0x32d, 0x32e, 0x32f, 0x330, 0x331, 0x332, 0x334,
        0x335, 0x336, 0x337, 0x338, 0x339, 0x33a, 0x33b, 0x33c, 0x33d, 0x33e,
        0x33f, 0x341, 0x342, 0x344, 0x345, 0x346, 0x347, 0x348, 0x349, 0x34a,
        0x34b, 0x34c, 0x34e, 0x350, 0x351, 0x352, 0x353, 0x355, 0x356, 0x357,
        0x358, 0x359, 0x35a, 0x35c, 0x35d, 0x360,
    )
]
REF_CODEPOINTS_PER_ENTRY = 300
REF_COUNT = 1000


# ---------------------------------------------------------------------------
# Hardening material.
#
# Homoglyphs: visually-identical letters from different scripts. All are valid
# Java identifier *start* characters (they are Unicode letters), so the app runs
# exactly as before, but "strip the combining marks and read the ASCII skeleton"
# — the analysis that cracked the sample — no longer yields a unique or even
# stable string, because one apparent glyph maps to several codepoints.
# Cost: ~same bytes as ASCII+marks, zero runtime cost.
# ---------------------------------------------------------------------------
HOMOGLYPH_GROUPS = {
    "a": "aа",            # Latin a / Cyrillic а
    "c": "cсϲ",      # Latin c / Cyrillic с / Greek lunate sigma ϲ
    "e": "eе",            # Latin e / Cyrillic е
    "o": "oоο",      # Latin o / Cyrillic о / Greek ο
    "p": "pр",            # Latin p / Cyrillic р
    "h": "hһ",            # Latin h / Cyrillic һ
    "k": "kк",            # Latin k / Cyrillic к
    "n": "n",
    "t": "t",
    "l": "l",
    "u": "u",
    "B": "BВΒ",      # Latin B / Cyrillic В / Greek Β
    "K": "KКΚ",      # Latin K / Cyrillic К / Greek Κ
    "P": "PРΡ",      # Latin P / Cyrillic Р / Greek Ρ
}
# Flatten to a single alphabet (all are valid identifier starts).
HOMOGLYPH_ALPHABET = "".join(sorted(set("".join(HOMOGLYPH_GROUPS.values()))))

# Combining-mark blocks beyond U+0300..036F, filtered to identifier-part chars.
_MARK_RANGES = (
    (0x0300, 0x036F),  # Combining Diacritical Marks (the reference block)
    (0x0483, 0x0489),  # Cyrillic combining marks
    (0x1AB0, 0x1AFF),  # Combining Diacritical Marks Extended
    (0x1DC0, 0x1DFF),  # Combining Diacritical Marks Supplement
    (0x20D0, 0x20F0),  # Combining Diacritical Marks for Symbols
    (0xFE20, 0xFE2F),  # Combining Half Marks
)


def extended_marks() -> List[str]:
    """Wide combining-mark pool, each guaranteed a valid Java identifier part."""
    from .javaid import is_java_identifier_part
    out: List[str] = []
    for lo, hi in _MARK_RANGES:
        for cp in range(lo, hi + 1):
            ch = chr(cp)
            # Mn/Mc only (isJavaIdentifierPart excludes enclosing marks Me).
            if is_java_identifier_part(ch) and not is_valid_identifier(ch):
                out.append(ch)
    return out


# ---------------------------------------------------------------------------
# Parsing — faithful to ProGuard's DictionaryNameFactory.
# ---------------------------------------------------------------------------
def parse_dictionary(text: str) -> List[str]:
    """Parse dictionary ``text`` into an ordered list of unique words.

    Mirrors ProGuard's ``DictionaryNameFactory``:
      * ``#`` starts a line comment (ignored to end of line).
      * A *word* is a maximal run of ``isJavaIdentifierPart`` characters.
      * Any other character (whitespace, punctuation, newline) ends a word.
      * Empty words are dropped; duplicates are dropped (first wins);
        original order is preserved.

    For ``字典.txt`` this yields exactly the 1000 lines, since each line is a
    single run of identifier-part characters separated by newlines.
    """
    words: List[str] = []
    seen = set()
    buf: List[str] = []
    in_comment = False

    def flush() -> None:
        if buf:
            w = "".join(buf)
            buf.clear()
            if w not in seen:
                seen.add(w)
                words.append(w)

    for ch in text:
        if in_comment:
            if ch == "\n":
                in_comment = False
            continue
        if ch == "#":
            flush()
            in_comment = True
        elif is_java_identifier_part(ch):
            buf.append(ch)
        else:
            flush()
    flush()
    return words


def load_dictionary(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_dictionary(fh.read())


# ---------------------------------------------------------------------------
# Generation — reproduce the reference "zalgo" dictionary style.
# ---------------------------------------------------------------------------
@dataclass
class DictionarySpec:
    """Knobs for generating a ProGuard dictionary in NP Manager's style."""

    count: int = REF_COUNT
    codepoints_per_entry: int = REF_CODEPOINTS_PER_ENTRY
    base_alphabet: str = REF_BASE_ALPHABET
    combining_marks: Sequence[str] = field(default_factory=lambda: list(REF_COMBINING_MARKS))
    max_marks_per_letter: int = 125  # reference tops out ~122
    seed: int | None = None

    def validate(self) -> None:
        if self.codepoints_per_entry < 1:
            raise ValueError("codepoints_per_entry must be >= 1")
        if not self.base_alphabet:
            raise ValueError("base_alphabet must be non-empty")
        if any(not is_valid_identifier(c) for c in self.base_alphabet):
            raise ValueError("every base letter must be a valid Java identifier start")

    # -- presets -----------------------------------------------------------
    # Rationale: identifier *length* is the only thing that costs APK size /
    # dexopt time / string-pool memory (names don't affect call speed). So
    # harder profiles add homoglyphs + more marks (≈ free) and raise the entry
    # *count* (shorter names via less concatenation) rather than the length.
    @classmethod
    def profile(cls, name: str, seed: int | None = None) -> "DictionarySpec":
        name = name.lower()
        if name == "classic":  # reproduce 字典.txt exactly in style
            return cls(count=1000, codepoints_per_entry=300, seed=seed)
        if name == "balanced":  # harder AND lighter than the reference
            return cls(count=4000, codepoints_per_entry=140,
                       base_alphabet=HOMOGLYPH_ALPHABET,
                       combining_marks=extended_marks(), max_marks_per_letter=60,
                       seed=seed)
        if name == "hard":  # same weight as the reference, much harder to read
            return cls(count=4000, codepoints_per_entry=300,
                       base_alphabet=HOMOGLYPH_ALPHABET,
                       combining_marks=extended_marks(), max_marks_per_letter=125,
                       seed=seed)
        if name == "max":  # heaviest; use only if size/startup budget allows
            return cls(count=8000, codepoints_per_entry=500,
                       base_alphabet=HOMOGLYPH_ALPHABET,
                       combining_marks=extended_marks(), max_marks_per_letter=200,
                       seed=seed)
        raise ValueError(f"unknown profile: {name!r} "
                         "(classic | balanced | hard | max)")

    def est_bytes_per_entry(self) -> int:
        """Rough UTF-8 size of one entry (marks ~2 B, homoglyph letters 2-3 B)."""
        marks = self.codepoints_per_entry - max(1, self.codepoints_per_entry // 15)
        letters = self.codepoints_per_entry - marks
        return marks * 2 + letters * 2


def _make_entry(rng: random.Random, spec: DictionarySpec) -> str:
    """Build one entry of exactly ``codepoints_per_entry`` codepoints.

    First codepoint is a base letter (identifier start). The remaining budget
    is filled by alternating "a base letter, then a random run of combining
    marks" until the exact length is reached, mirroring the reference layout
    (base letters may end up adjacent when a run length is 0).
    """
    n = spec.codepoints_per_entry
    out: List[str] = [rng.choice(spec.base_alphabet)]  # valid identifier start
    while len(out) < n:
        remaining = n - len(out)
        # Decide how many marks follow the last base letter (bounded by budget).
        marks = rng.randint(0, min(spec.max_marks_per_letter, remaining))
        for _ in range(marks):
            out.append(rng.choice(spec.combining_marks))
        if len(out) < n:
            out.append(rng.choice(spec.base_alphabet))
    return "".join(out[:n])


def generate_dictionary(spec: DictionarySpec | None = None) -> List[str]:
    """Generate ``spec.count`` unique entries following the reference style."""
    spec = spec or DictionarySpec()
    spec.validate()
    rng = random.Random(spec.seed)
    out: List[str] = []
    seen = set()
    attempts = 0
    max_attempts = spec.count * 50 + 1000
    while len(out) < spec.count:
        attempts += 1
        if attempts > max_attempts:
            raise RuntimeError("could not generate enough unique entries; widen the spec")
        e = _make_entry(rng, spec)
        if e not in seen and is_valid_identifier(e):
            seen.add(e)
            out.append(e)
    return out


def write_dictionary(words: Iterable[str], path: str, trailing_newline: bool = False) -> None:
    """Write entries newline-separated (reference has NO trailing newline)."""
    data = "\n".join(words)
    if trailing_newline:
        data += "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data)


# ---------------------------------------------------------------------------
# Name factory — assigns dictionary words to symbols, ProGuard-style.
# ---------------------------------------------------------------------------
class SimpleNameFactory:
    """Fallback generator: a, b, ..., z, aa, ab, ... (ProGuard's default)."""

    _ALPHA = "abcdefghijklmnopqrstuvwxyz"

    def __init__(self) -> None:
        self._i = 0

    def next_name(self) -> str:
        i = self._i
        self._i += 1
        name = ""
        i += 1
        while i > 0:
            i -= 1
            name = self._ALPHA[i % 26] + name
            i //= 26
        return name


class DictionaryNameFactory:
    """NP Manager's dictionary name factory (recovered from a before/after DEX).

    Names are produced by a bijective base-N numeral system (N = dictionary
    size, default 1000) whose *digits are dictionary entries*:

        name(0..N-1)         -> single entry           entry[i]
        name(N .. N+N^2-1)   -> two entries (lex order) entry[i]+entry[j]
        name(...)            -> three entries, and so on

    Concretely ``name(1000) == entry[0]+entry[0]``, ``name(1001) ==
    entry[0]+entry[1]`` ... This was verified to reproduce *exactly* the 2463
    multiple-of-300 obfuscated identifiers found in the sample after-DEX (every
    one is a concatenation of reference ``字典.txt`` lines, no exceptions).

    This replaces stock ProGuard's a/b/c fallback: NP never leaves the
    dictionary alphabet, it just makes longer words.
    """

    def __init__(self, words: Sequence[str]):
        self._words = list(words)
        if not self._words:
            raise ValueError("dictionary is empty")
        self._n = len(self._words)
        self._i = 0  # running counter

    @property
    def size(self) -> int:
        return self._n

    def name_at(self, index: int) -> str:
        """Deterministic: the obfuscated name for ordinal ``index`` (0-based)."""
        n = self._n
        length, base, block = 1, 0, n
        while index >= base + block:
            base += block
            length += 1
            block *= n
        off = index - base
        digits: List[int] = []
        for _ in range(length):
            digits.append(off % n)
            off //= n
        digits.reverse()
        return "".join(self._words[d] for d in digits)

    def next_name(self) -> str:
        name = self.name_at(self._i)
        self._i += 1
        return name

    def __iter__(self) -> Iterator[str]:
        while True:
            yield self.next_name()
