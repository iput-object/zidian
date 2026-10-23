"""ProGuard-style class-name filters.

NP Manager's "Obfuscate class configuration (line by line)" box selects *which
classes* get renamed, using ProGuard filter wildcards (default ``**`` = every
class). This module compiles those patterns so the same selection can be
reproduced.

ProGuard class-filter wildcard semantics:
  ?   matches a single character in a class name, but not the package separator
  *   matches any part of a class name NOT containing the package separator
  **  matches any part of a class name, INCLUDING package separators
  !   as a line/entry prefix negates the pattern (exclusion)

Names are compared in dotted form (``com.app.Foo``). A leading ``!`` marks an
exclusion; the first matching pattern wins, which is how ProGuard resolves a
mixed include/exclude list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Sequence, Tuple


def _pattern_to_regex(pat: str) -> str:
    """Translate one ProGuard class-filter pattern to a full-match regex."""
    out: List[str] = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if i + 1 < n and pat[i + 1] == "*":
                out.append(".*")          # ** : anything incl. '.'
                i += 2
                continue
            out.append("[^.]*")           # *  : anything except '.'
        elif c == "?":
            out.append("[^.]")            # ?  : one char except '.'
        else:
            out.append(re.escape(c))
        i += 1
    return "^" + "".join(out) + "$"


@dataclass
class ClassFilter:
    """Ordered include/exclude rules; first match decides."""

    rules: List[Tuple[bool, "re.Pattern[str]"]]  # (is_exclude, regex)

    @classmethod
    def compile(cls, patterns: Sequence[str]) -> "ClassFilter":
        rules: List[Tuple[bool, "re.Pattern[str]"]] = []
        for raw in patterns:
            p = raw.strip()
            if not p or p.startswith("#"):
                continue
            exclude = p.startswith("!")
            if exclude:
                p = p[1:].strip()
            rules.append((exclude, re.compile(_pattern_to_regex(p))))
        return cls(rules)

    def matches(self, class_name: str) -> bool:
        """True if ``class_name`` (dotted) is selected for obfuscation."""
        name = class_name.replace("/", ".")
        for exclude, rx in self.rules:
            if rx.match(name):
                return not exclude
        return False  # nothing matched -> not selected


def smali_class_name(smali_text: str) -> str | None:
    """Extract the dotted class name from a smali file's ``.class`` line."""
    m = re.search(r"^\.class\b.*\bL([^;]+);", smali_text, re.MULTILINE)
    if not m:
        return None
    return m.group(1).replace("/", ".")
