# zidian (字典)

A dictionary-based identifier obfuscator for Android/JVM artifacts. It generates
ProGuard-style obfuscation dictionaries made of "zalgo" identifiers (a small base
alphabet buried under Unicode combining marks, so every name renders as an
unreadable blob while staying a valid identifier), and can apply the rename to
smali, JAR archives, and compiled DEX files — then undo it from a saved mapping.

Ships as a single standalone binary (no Python needed to run it).

## Install / build

```bash
# Native standalone binary (no Python needed to RUN it) -> dist/zidian
./build.sh            # or: make build

# Portable single file (needs python3 to run)           -> dist/zidian.pyz
./build.sh --pyz      # or: make pyz

# Or install as a normal CLI (provides the `zidian` command)
pip install .

# Run from source without building
PYTHONPATH=src python3 -m zidian --help
```

Prebuilt binaries for Linux, Windows and macOS are produced by CI on every
tagged release.

## Usage

```bash
# Generate a dictionary (profiles: classic | balanced | hard | max)
zidian gen -o dict.txt                       # default style
zidian gen -p balanced -o dict.txt           # harder and lighter
zidian gen -p hard --seed 7 -n 4000 -o dict.txt

# Inspect a dictionary's structure
zidian inspect dict.txt

# Obfuscate smali / folders / JARs (filters, exclusions, reversible mapping)
zidian obfuscate --dict dict.txt --mapping map.tsv \
    --ext .smali --exclude '*/R.smali' --base ./project -o ./out ./project

# No --dict? A fresh hardened dictionary is generated per run and saved to the
# output dir — unique dictionaries resist cross-artifact correlation.
zidian obfuscate --ext .smali -o ./out ./project

# Compiled .dex obfuscation (no external tools). Pass all of an app's dex files
# together so cross-dex references stay consistent (multi-dex aware).
zidian obfuscate -p balanced --mapping map.tsv -o out/ classes.dex classes2.dex

# Undo it (needs the saved mapping and the same dictionary)
zidian restore --mapping map.tsv --base ./out -o ./restored ./out

# Emit a ProGuard dictionary-obfuscation config
zidian proguard --dict dict.txt --class-dict dict.txt -o dict.pro
```

## Hardening profiles

Identifier *length* is the only thing that costs artifact size / load time /
memory — names don't affect call speed. So harder profiles add homoglyphs
(visually identical letters from different scripts) and a wider combining-mark
set (near-free), and raise the entry *count* (shorter names via less
concatenation) rather than the length.

| profile  | entries | cp/entry | alphabet | notes |
|----------|---------|----------|----------|-------|
| classic  | 1000    | 300      | ASCII    | baseline style |
| balanced | 4000    | 140      | homoglyph| harder **and lighter** |
| hard     | 4000    | 300      | homoglyph| same weight, much harder |
| max      | 8000    | 500      | homoglyph| heaviest |

Homoglyphs defeat "strip the marks and read the skeleton" analysis: one rendered
glyph maps to several codepoints, so the exact name can't be recovered by eye.

> Obfuscation is not encryption: whoever holds the dictionary can rebuild the
> reverse map. Hardening raises the cost of manual/visual/OCR analysis.

## DEX engine

`zidian` includes a dependency-free DEX reader/writer that rewrites a compiled
`.dex` directly: it rebuilds the string pool and the id tables (kept sorted) and
remaps every index reference, including bytecode operands. It is multi-dex aware
(one global rename map across all input dex files, so cross-dex references stay
linked) and only renames app-defined symbols — framework references are left
alone.

Default scope is conservative: direct (static/private) methods and fields.
Virtual methods, native methods and constructors are skipped so overrides and JNI
bindings don't break. `--rename-virtual` and `--rename-classes` go further but
need whole-app keep rules (manifest entries, reflection, overrides).

> No Android runtime is involved in building; validate obfuscated output on a
> device before shipping. Residual risk is reflection-by-name and JNI string
> lookups, the same caveat any renamer has.

## Project layout

```
src/zidian/        the package (dictionary, dex, dexobf, rename, discovery,
                   classfilter, transform, backends, cli)
main.py            standalone entry point for builds
tests/             validation suite (make test)
.github/workflows/ CI: tests + cross-platform binaries + releases
```

## Tests

```bash
make test
```
