"""File discovery: recursive/non-recursive, extension & glob filters, exclusions."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import List, Sequence


@dataclass
class DiscoveryRules:
    recursive: bool = True
    include_exts: Sequence[str] = field(default_factory=tuple)   # e.g. (".smali", ".txt")
    include_globs: Sequence[str] = field(default_factory=tuple)  # e.g. ("*.smali",)
    exclude_globs: Sequence[str] = field(default_factory=tuple)  # e.g. ("*/R.smali",)

    def _ext_ok(self, name: str) -> bool:
        if not self.include_exts:
            return True
        return any(name.lower().endswith(e.lower()) for e in self.include_exts)

    def _glob_ok(self, path: str) -> bool:
        if not self.include_globs:
            return True
        return any(fnmatch.fnmatch(path, g) for g in self.include_globs)

    def _excluded(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, g) for g in self.exclude_globs)

    def matches(self, path: str) -> bool:
        name = os.path.basename(path)
        return self._ext_ok(name) and self._glob_ok(path) and not self._excluded(path)


def discover(target: str, rules: DiscoveryRules) -> List[str]:
    """Return matching file paths under ``target`` (a file or directory)."""
    if os.path.isfile(target):
        return [target] if rules.matches(target) else []
    out: List[str] = []
    if rules.recursive:
        for root, _dirs, files in os.walk(target):
            for f in files:
                p = os.path.join(root, f)
                if rules.matches(p):
                    out.append(p)
    else:
        for f in sorted(os.listdir(target)):
            p = os.path.join(target, f)
            if os.path.isfile(p) and rules.matches(p):
                out.append(p)
    return sorted(out)
