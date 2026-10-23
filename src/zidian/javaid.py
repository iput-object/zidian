"""Java identifier rules (``Character.isJavaIdentifier{Start,Part}``).

NP Manager's dictionary obfuscation is driven by ProGuard, which validates
candidate names with ``\\p{javaJavaIdentifierStart}\\p{javaJavaIdentifierPart}*``
(this exact regex and ``isJavaIdentifierPart`` are present in the APK's dex).
Python's ``re`` has no ``\\p{java...}`` classes, so we reproduce the predicates
from Unicode general categories, which is what the JDK does internally.
"""

from __future__ import annotations

import unicodedata

# Categories accepted as an identifier *start* by the JVM.
_START_CATS = {"Lu", "Ll", "Lt", "Lm", "Lo", "Nl"}
# Extra categories accepted as an identifier *part* (in addition to start cats).
_PART_EXTRA_CATS = {"Mn", "Mc", "Nd", "Pc"}


def is_java_identifier_start(ch: str) -> bool:
    if ch in ("$", "_"):
        return True
    if unicodedata.category(ch) in _START_CATS:
        return True
    # Currency symbols (Sc) are also valid starts per the JLS.
    return unicodedata.category(ch) == "Sc"


def is_java_identifier_part(ch: str) -> bool:
    if is_java_identifier_start(ch):
        return True
    if ch in ("‌", "‍"):  # ZWNJ / ZWJ
        return True
    return unicodedata.category(ch) in _PART_EXTRA_CATS


def is_valid_identifier(word: str) -> bool:
    """True if ``word`` is a non-empty, fully valid Java identifier."""
    if not word:
        return False
    if not is_java_identifier_start(word[0]):
        return False
    return all(is_java_identifier_part(c) for c in word[1:])
