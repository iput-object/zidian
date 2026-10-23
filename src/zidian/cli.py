"""Command-line interface.

Subcommands:
  gen        generate a 字典.txt-style dictionary
  inspect    report structure of a dictionary file
  obfuscate  rename identifiers in files/folders/jars using a dictionary
  restore    undo an obfuscation using a saved mapping
  proguard   emit a ProGuard dictionary-obfuscation config (real DEX/APK path)
"""

from __future__ import annotations

import argparse
import os
import sys
import unicodedata
from typing import List

from .backends import available_backends, proguard_dictionary_config
from .dictionary import (
    DictionaryNameFactory,
    DictionarySpec,
    generate_dictionary,
    load_dictionary,
    write_dictionary,
)
from .discovery import DiscoveryRules, discover
from .rename import NameMapper
from .transform import (
    apply_map_to_text,
    extract_symbols,
    transform_archive,
    transform_text_file,
)

ARCHIVE_EXTS = (".jar", ".zip", ".apk")


def _cmd_gen(a: argparse.Namespace) -> int:
    if a.profile:
        spec = DictionarySpec.profile(a.profile, seed=a.seed)
        if a.count is not None:
            spec.count = a.count
        if a.length is not None:
            spec.codepoints_per_entry = a.length
    else:
        spec = DictionarySpec(
            count=a.count or 1000,
            codepoints_per_entry=a.length or 300,
            seed=a.seed,
        )
    words = generate_dictionary(spec)
    write_dictionary(words, a.out, trailing_newline=a.trailing_newline)
    est_kb = spec.count * spec.est_bytes_per_entry() / 1024
    print(f"wrote {len(words)} entries x {spec.codepoints_per_entry} codepoints "
          f"({len(spec.base_alphabet)}-letter alphabet, "
          f"{len(list(spec.combining_marks))} marks) -> {a.out}")
    print(f"dictionary size ~{est_kb:.0f} KB; single-entry names cover "
          f"{spec.count} symbols, two-entry up to {spec.count**2:,}")
    print("note: APK/name cost scales with entry length, not count — "
          "more entries keeps names short; homoglyphs add no runtime cost.")
    return 0


def _cmd_inspect(a: argparse.Namespace) -> int:
    words = load_dictionary(a.dict)
    lens = [len(w) for w in words]
    base, marks = set(), set()
    for w in words:
        for ch in w:
            (marks if unicodedata.category(ch) == "Mn" else base).add(ch)
    print(f"entries:            {len(words)} ({len(set(words))} unique)")
    print(f"codepoints/entry:   min={min(lens)} max={max(lens)}")
    print(f"base alphabet ({len(base)}): {''.join(sorted(base))}")
    print(f"combining marks:    {len(marks)} distinct")
    return 0


def _gather_targets(a: argparse.Namespace) -> List[str]:
    rules = DiscoveryRules(
        recursive=a.recursive,
        include_exts=tuple(a.ext or ()),
        include_globs=tuple(a.glob or ()),
        exclude_globs=tuple(a.exclude or ()),
    )
    files: List[str] = []
    for t in a.targets:
        files.extend(discover(t, rules))
    return files


def _resolve_dictionary(a: argparse.Namespace) -> list:
    """Load --dict if given; otherwise auto-generate a fresh hardened dictionary
    and save it into the output dir so the run stays reversible."""
    if a.dict:
        return load_dictionary(a.dict)
    spec = DictionarySpec.profile(a.profile or "hard", seed=a.seed)
    words = generate_dictionary(spec)
    os.makedirs(a.out, exist_ok=True)
    saved = os.path.join(a.out, "zidian.generated.dict.txt")
    write_dictionary(words, saved)
    print(f"no --dict given: generated a fresh '{a.profile or 'hard'}' dictionary "
          f"({len(words)} entries) -> {saved}")
    print("  keep this file WITH the mapping to be able to restore.")
    return words


def _obfuscate_dex_targets(a, dex_files, words) -> int:
    """Multi-dex: build ONE global rename map and apply to all .dex together."""
    from .dexobf import ObfOptions, obfuscate_dexes
    sources = [open(f, "rb").read() for f in dex_files]
    opts = ObfOptions(
        rename_virtual_methods=bool(getattr(a, "rename_virtual", False)),
        rename_classes=bool(getattr(a, "rename_classes", False)),
    )
    outs, mapping = obfuscate_dexes(sources, words, opts)
    os.makedirs(a.out, exist_ok=True)
    for f, out in zip(dex_files, outs):
        outp = os.path.join(a.out, os.path.basename(f))
        with open(outp, "wb") as fh:
            fh.write(out)
    if a.mapping:
        with open(a.mapping, "w", encoding="utf-8") as fh:
            fh.write("\n".join(f"{k}\t{v}" for k, v in mapping.items()))
    print(f"obfuscated {len(dex_files)} dex file(s); renamed {len(mapping)} symbols "
          f"(direct methods + fields; virtual={opts.rename_virtual_methods}, "
          f"classes={opts.rename_classes})")
    if a.mapping:
        print(f"mapping saved -> {a.mapping}")
    return 0


def _cmd_obfuscate(a: argparse.Namespace) -> int:
    words = _resolve_dictionary(a)

    targets = _gather_targets(a)
    dex_files = [f for f in targets if f.lower().endswith(".dex")]
    if dex_files:
        return _obfuscate_dex_targets(a, dex_files, words)

    factory = DictionaryNameFactory(words)
    mapper = NameMapper(factory)
    text_files = [f for f in targets if not f.lower().endswith(ARCHIVE_EXTS)]
    archives = [f for f in targets if f.lower().endswith(ARCHIVE_EXTS)]

    # Pass 1: collect symbols from all eligible text so the mapping is stable.
    symbols: List[str] = []
    seen = set()
    for f in text_files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                for s in extract_symbols(fh.read()):
                    if s not in seen:
                        seen.add(s)
                        symbols.append(s)
        except UnicodeDecodeError:
            pass
    if a.only:
        allow = set(a.only)
        symbols = [s for s in symbols if s in allow]
    mapper.map_all(symbols)

    os.makedirs(a.out, exist_ok=True)
    changed = 0
    for f in text_files:
        rel = os.path.relpath(f, a.base) if a.base else os.path.basename(f)
        outp = os.path.join(a.out, rel)
        try:
            if transform_text_file(f, mapper.forward, outp):
                changed += 1
        except UnicodeDecodeError:
            os.makedirs(os.path.dirname(outp) or ".", exist_ok=True)
            with open(f, "rb") as src, open(outp, "wb") as dst:
                dst.write(src.read())
    for f in archives:
        outp = os.path.join(a.out, os.path.basename(f))
        rep = transform_archive(f, outp, mapper.forward)
        changed += sum(1 for v in rep.values() if v)

    if a.mapping:
        mapper.save(a.mapping)
    print(f"mapped {len(mapper.forward)} symbols; files/members changed: {changed}")
    if a.mapping:
        print(f"mapping saved -> {a.mapping}")
    return 0


def _cmd_restore(a: argparse.Namespace) -> int:
    pairs = NameMapper.load_pairs(a.mapping)
    reverse = {obf: orig for orig, obf in pairs}
    targets = _gather_targets(a)
    os.makedirs(a.out, exist_ok=True)
    changed = 0
    for f in targets:
        rel = os.path.relpath(f, a.base) if a.base else os.path.basename(f)
        outp = os.path.join(a.out, rel)
        if transform_text_file(f, reverse, outp):
            changed += 1
    print(f"restored using {len(reverse)} names; files changed: {changed}")
    return 0


def _cmd_proguard(a: argparse.Namespace) -> int:
    cfg = proguard_dictionary_config(a.dict, a.class_dict, a.package_dict)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(cfg)
        print(f"wrote ProGuard config -> {a.out}")
    else:
        sys.stdout.write(cfg)
    print(f"# available DEX/APK backends on this machine: {available_backends() or 'none'}",
          file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zidian", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="generate a 字典.txt-style dictionary")
    g.add_argument("-o", "--out", required=True)
    g.add_argument("-p", "--profile",
                   choices=["classic", "balanced", "hard", "max"],
                   help="hardening preset (default: classic). balanced = harder+lighter")
    g.add_argument("-n", "--count", type=int, default=None)
    g.add_argument("-l", "--length", type=int, default=None, help="codepoints per entry")
    g.add_argument("--seed", type=int, default=None)
    g.add_argument("--trailing-newline", action="store_true")
    g.set_defaults(func=_cmd_gen)

    i = sub.add_parser("inspect", help="report dictionary structure")
    i.add_argument("dict")
    i.set_defaults(func=_cmd_inspect)

    def add_discovery(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("targets", nargs="+", help="files and/or folders")
        sp.add_argument("--no-recursive", dest="recursive", action="store_false")
        sp.add_argument("--ext", action="append", help="filter by extension, repeatable")
        sp.add_argument("--glob", action="append", help="include glob, repeatable")
        sp.add_argument("--exclude", action="append", help="exclude glob, repeatable")
        sp.add_argument("--base", help="base dir for relative output layout")
        sp.add_argument("-o", "--out", required=True, help="output directory")

    o = sub.add_parser("obfuscate", help="rename identifiers using a dictionary")
    o.add_argument("--dict", help="dictionary file; if omitted, a fresh hardened "
                                  "one is generated and saved to the output dir")
    o.add_argument("--profile", choices=["classic", "balanced", "hard", "max"],
                   help="profile for the auto-generated dictionary (default: hard)")
    o.add_argument("--seed", type=int, help="seed for the auto-generated dictionary")
    o.add_argument("--mapping", help="write reversible mapping here")
    o.add_argument("--only", action="append", help="map only these symbols, repeatable")
    o.add_argument("--rename-virtual", action="store_true",
                   help="(DEX) also rename virtual methods — unsafe without keep "
                        "rules; may break overrides/reflection")
    o.add_argument("--rename-classes", action="store_true",
                   help="(DEX) also rename class names — interacts with manifest/reflection")
    add_discovery(o)
    o.set_defaults(func=_cmd_obfuscate)

    r = sub.add_parser("restore", help="undo obfuscation using a saved mapping")
    r.add_argument("--mapping", required=True)
    add_discovery(r)
    r.set_defaults(func=_cmd_restore)

    pg = sub.add_parser("proguard", help="emit ProGuard dictionary-obfuscation config")
    pg.add_argument("--dict", required=True, help="method/field dictionary file")
    pg.add_argument("--class-dict")
    pg.add_argument("--package-dict")
    pg.add_argument("-o", "--out")
    pg.set_defaults(func=_cmd_proguard)
    return p


def _force_utf8_output() -> None:
    # The CLI prints CJK + combining-mark text; Windows consoles default to a
    # legacy code page (cp1252) and would raise UnicodeEncodeError. Make stdout
    # and stderr UTF-8 wherever possible.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass


def main(argv: List[str] | None = None) -> int:
    _force_utf8_output()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
