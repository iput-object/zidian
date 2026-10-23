"""Applying a name map to text artifacts and to zip/jar archives.

Renaming operates on *whole Java identifiers*. A token is a maximal run of
identifier-part characters that starts with an identifier-start character
(the same rule ProGuard/NP Manager use). Only tokens present in the map are
rewritten; every other byte is preserved, so unrelated files and unrelated
tokens are untouched.
"""

from __future__ import annotations

import io
import os
import zipfile
from typing import Dict, Iterator, List, Mapping, Set, Tuple

from .javaid import is_java_identifier_part, is_java_identifier_start


def iter_identifier_tokens(text: str) -> Iterator[Tuple[int, int, str]]:
    """Yield ``(start, end, token)`` for each Java identifier in ``text``."""
    i, n = 0, len(text)
    while i < n:
        if is_java_identifier_start(text[i]):
            j = i + 1
            while j < n and is_java_identifier_part(text[j]):
                j += 1
            yield i, j, text[i:j]
            i = j
        else:
            i += 1


def extract_symbols(text: str) -> List[str]:
    """Distinct identifier tokens in first-seen order (candidate symbols)."""
    seen: Set[str] = set()
    out: List[str] = []
    for _s, _e, tok in iter_identifier_tokens(text):
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def apply_map_to_text(text: str, mapping: Mapping[str, str]) -> str:
    """Rewrite every mapped identifier token; leave everything else intact."""
    if not mapping:
        return text
    out: List[str] = []
    last = 0
    for s, e, tok in iter_identifier_tokens(text):
        repl = mapping.get(tok)
        if repl is not None:
            out.append(text[last:s])
            out.append(repl)
            last = e
    out.append(text[last:])
    return "".join(out)


def transform_text_file(path: str, mapping: Mapping[str, str], out_path: str) -> bool:
    """Apply map to a UTF-8 text file. Returns True if content changed."""
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    dst = apply_map_to_text(src, mapping)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(dst)
    return dst != src


# ---------------------------------------------------------------------------
# Archive (zip/jar/apk) handling: rewrite eligible text members, copy the rest.
# ---------------------------------------------------------------------------
def transform_archive(
    in_path: str,
    out_path: str,
    mapping: Mapping[str, str],
    eligible_exts: Tuple[str, ...] = (".smali", ".txt", ".pro", ".cfg", ".properties"),
    rename_entry_paths: bool = False,
    path_map: Mapping[str, str] | None = None,
) -> Dict[str, bool]:
    """Copy ``in_path`` to ``out_path`` applying ``mapping`` to eligible members.

    Non-eligible members (``.class``, ``.dex``, images, ...) are copied byte
    for byte, preserving archive structure and validity. Returns a per-entry
    "changed?" report.
    """
    report: Dict[str, bool] = {}
    with zipfile.ZipFile(in_path, "r") as zin:
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                name = item.filename
                changed = False
                if name.lower().endswith(eligible_exts):
                    try:
                        text = data.decode("utf-8")
                        new_text = apply_map_to_text(text, mapping)
                        if new_text != text:
                            data = new_text.encode("utf-8")
                            changed = True
                    except UnicodeDecodeError:
                        pass  # not really text -> copy untouched
                if rename_entry_paths and path_map:
                    name = path_map.get(name, name)
                report[item.filename] = changed
                zout.writestr(name, data)
    return report
