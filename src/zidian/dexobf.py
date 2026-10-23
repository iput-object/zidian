"""DEX obfuscation policy: decide what to rename, then drive the rewriter.

Correctness notes (why the defaults are what they are):
  * Names are referenced *across* DEX files by (class, name, proto) strings, so a
    symbol renamed in one DEX must be renamed in every DEX of the same app.
    Hence obfuscation is **multi-dex aware**: one global rename map is built from
    all input DEX files and applied to all of them together.
  * Only symbols *defined* in the input set are renamed; framework references
    (android.*, java.*, …) are left untouched so linking still works.
  * By default we rename **direct methods** (static/private — not vtable entries,
    so overrides never break) and **fields**, and skip **virtual methods**,
    **native methods** (JNI binds by name) and **constructors**. Class renaming
    is opt-in (it interacts with the manifest and reflection).
  * Residual risk is reflection by name (Class.forName / getDeclaredMethod / JNI
    registerNatives with literals) — the same caveat ProGuard has; keep rules or
    a narrower scope handle it. Test the result on-device.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .dex import DexFile, RenamePlan, parse_dex, serialize_dex
from .dictionary import DictionaryNameFactory

ACC_STATIC = 0x0008
ACC_PRIVATE = 0x0002
ACC_NATIVE = 0x0100
_CTORS = ("<init>", "<clinit>")

# Descriptors we never rename (framework / primitives live outside the app).
def _is_app_class(desc: str) -> bool:
    return desc.startswith("L") and not (
        desc.startswith("Landroid/") or desc.startswith("Landroidx/")
        or desc.startswith("Ljava/") or desc.startswith("Ljavax/")
        or desc.startswith("Lkotlin/") or desc.startswith("Lkotlinx/")
        or desc.startswith("Ldalvik/") or desc.startswith("Lorg/xml")
        or desc.startswith("Lorg/w3c") or desc.startswith("Lorg/json/")
        or desc.startswith("Lorg/apache/http/") or desc.startswith("Ljunit/")
    )


@dataclass
class ObfOptions:
    rename_direct_methods: bool = True
    rename_virtual_methods: bool = False   # unsafe without hierarchy analysis
    rename_fields: bool = True
    rename_classes: bool = False
    keep_classes: Tuple[str, ...] = ()     # descriptors to leave untouched


def build_global_plan(dexes: Sequence[DexFile], factory: DictionaryNameFactory,
                      opts: ObfOptions) -> RenamePlan:
    class_map: Dict[str, str] = {}
    field_names: Dict[object, str] = {}
    method_names: Dict[object, str] = {}
    keep = set(opts.keep_classes)

    # which classes are defined in this app set (and allowed to rename)
    defined = set()
    for dx in dexes:
        for c in dx.classes:
            if _is_app_class(c.descriptor) and c.descriptor not in keep:
                defined.add(c.descriptor)

    if opts.rename_classes:
        for desc in sorted(defined):
            class_map[desc] = "L" + factory.next_name() + ";"

    for dx in dexes:
        for c in dx.classes:
            if c.descriptor not in defined:
                continue
            if opts.rename_direct_methods:
                for em in c.direct_methods:
                    r = em.ref
                    if r.name in _CTORS or (em.access & ACC_NATIVE):
                        continue
                    if r not in method_names:
                        method_names[r] = factory.next_name()
            if opts.rename_virtual_methods:
                for em in c.virtual_methods:
                    r = em.ref
                    if r.name in _CTORS or (em.access & ACC_NATIVE):
                        continue
                    if r not in method_names:
                        method_names[r] = factory.next_name()
            if opts.rename_fields:
                for ef in c.static_fields + c.instance_fields:
                    if ef.ref not in field_names:
                        field_names[ef.ref] = factory.next_name()

    return RenamePlan(class_map, field_names, method_names)


def obfuscate_dexes(sources: Sequence[bytes], words: Sequence[str],
                    opts: ObfOptions | None = None
                    ) -> Tuple[List[bytes], Dict[str, str]]:
    """Rename across a whole app's DEX set. Returns (out_bytes_list, mapping)."""
    opts = opts or ObfOptions()
    dexes = [parse_dex(s) for s in sources]
    factory = DictionaryNameFactory(words)
    plan = build_global_plan(dexes, factory, opts)
    outputs = [serialize_dex(dx, plan) for dx in dexes]

    mapping: Dict[str, str] = {}
    for old, new in plan.class_map.items():
        mapping["class " + old] = new
    for ref, new in plan.method_names.items():
        mapping[f"method {ref.cls}->{ref.name}"] = new
    for ref, new in plan.field_names.items():
        mapping[f"field {ref.cls}->{ref.name}:{ref.type}"] = new
    return outputs, mapping


def obfuscate_dex(data: bytes, words: Sequence[str],
                  opts: ObfOptions | None = None) -> Tuple[bytes, Dict[str, str]]:
    outs, mapping = obfuscate_dexes([data], words, opts)
    return outs[0], mapping
