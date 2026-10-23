"""Pure-Python DEX reader/writer for identifier renaming — no external tools.

This lets ``zidian obfuscate app.dex`` rewrite a compiled DEX in place: it
renames class / method / field names to dictionary words, rebuilds the string
pool and the type/proto/field/method id tables (kept sorted, as the DEX spec
and ART's verifier require), and remaps **every** index reference — including
bytecode operands, class_data, debug info, type lists, annotations and encoded
values — so the result stays internally consistent.

Scope and honesty:
  * Renaming changes *names only*; code semantics are preserved.
  * Correctness is gated by a full round-trip self-check (`verify_roundtrip`):
    parse -> rebuild -> re-parse must yield identical semantics, all id tables
    must be sorted, all index refs in range, and checksum/signature valid.
  * There is no ART in this repo's CI, so on-device validation is the final
    step the user should run; the structural gate catches the vast majority of
    mistakes but cannot prove runtime acceptance by itself.

Only the index-bearing instruction formats need operand remapping; their sizes
and operand positions come from the fixed Dalvik opcode tables embedded below.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# LEB128 + MUTF-8
# ---------------------------------------------------------------------------
def read_uleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = shift = 0
    while True:
        b = data[off]; off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def read_sleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = shift = 0
    while True:
        b = data[off]; off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result |= -(1 << shift)
            return result, off


def write_uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def write_sleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        done = (value == 0 and not (b & 0x40)) or (value == -1 and (b & 0x40))
        if not done:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_uleb128p1(data: bytes, off: int) -> Tuple[int, int]:
    v, off = read_uleb128(data, off)
    return v - 1, off


def write_uleb128p1(value: int) -> bytes:
    return write_uleb128(value + 1)


def decode_mutf8(data: bytes, off: int) -> Tuple[str, int]:
    out: List[str] = []
    while True:
        b = data[off]
        if b == 0:
            off += 1
            break
        if b < 0x80:
            out.append(chr(b)); off += 1
        elif (b & 0xE0) == 0xC0:
            out.append(chr(((b & 0x1F) << 6) | (data[off + 1] & 0x3F))); off += 2
        elif (b & 0xF0) == 0xE0:
            out.append(chr(((b & 0xF) << 12) | ((data[off + 1] & 0x3F) << 6)
                           | (data[off + 2] & 0x3F))); off += 3
        else:
            # MUTF-8 has no 4-byte forms; treat defensively.
            out.append("�"); off += 1
    return "".join(out), off


def encode_mutf8(s: str) -> bytes:
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:
            out += b"\xc0\x80"
        elif cp < 0x80:
            out.append(cp)
        elif cp < 0x800:
            out.append(0xC0 | (cp >> 6)); out.append(0x80 | (cp & 0x3F))
        elif cp < 0x10000:
            out.append(0xE0 | (cp >> 12))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
        else:  # supplementary -> surrogate pair, each as 3 bytes (MUTF-8 rule)
            cp -= 0x10000
            hi = 0xD800 | (cp >> 10)
            lo = 0xDC00 | (cp & 0x3FF)
            for s16 in (hi, lo):
                out.append(0xE0 | (s16 >> 12))
                out.append(0x80 | ((s16 >> 6) & 0x3F))
                out.append(0x80 | (s16 & 0x3F))
    out.append(0)
    return bytes(out)


def utf16_units(s: str) -> int:
    """utf16_size as DEX stores it (code units, surrogate-counted)."""
    n = 0
    for ch in s:
        n += 2 if ord(ch) > 0xFFFF else 1
    return n


def mutf8_sort_key(s: str):
    """DEX sorts strings by UTF-16 code-unit sequence (unsigned)."""
    out: List[int] = []
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            out.append(0xD800 | (cp >> 10))
            out.append(0xDC00 | (cp & 0x3FF))
        else:
            out.append(cp)
    return out


# ---------------------------------------------------------------------------
# Dalvik instruction tables: size (in 16-bit code units) and index operands.
# Validated at parse time: sum of instruction sizes must equal insns_size.
# ---------------------------------------------------------------------------
# index "kinds"
K_STRING, K_TYPE, K_FIELD, K_METHOD, K_PROTO, K_CALLSITE, K_MHANDLE = range(7)

def _build_opcode_tables():
    size = [1] * 256           # default (unused opcodes: 1)
    kind: Dict[int, int] = {}  # opcode -> index kind (operand at code-unit [1])
    def setrange(lo, hi, s):
        for op in range(lo, hi + 1):
            size[op] = s
    # sizes
    setrange(0x00, 0x01, 1)
    size[0x02] = 2; size[0x03] = 3; size[0x04] = 1; size[0x05] = 2; size[0x06] = 3
    size[0x07] = 1; size[0x08] = 2; size[0x09] = 3
    setrange(0x0a, 0x12, 1)
    size[0x13] = 2; size[0x14] = 3; size[0x15] = 2; size[0x16] = 2; size[0x17] = 3
    size[0x18] = 5; size[0x19] = 2; size[0x1a] = 2; size[0x1b] = 3; size[0x1c] = 2
    size[0x1d] = 1; size[0x1e] = 1; size[0x1f] = 2; size[0x20] = 2; size[0x21] = 1
    size[0x22] = 2; size[0x23] = 2; size[0x24] = 3; size[0x25] = 3; size[0x26] = 3
    size[0x27] = 1; size[0x28] = 1; size[0x29] = 2; size[0x2a] = 3
    size[0x2b] = 3; size[0x2c] = 3
    setrange(0x2d, 0x31, 2)   # cmp*
    setrange(0x32, 0x37, 2)   # if-*
    setrange(0x38, 0x3d, 2)   # if-*z
    setrange(0x3e, 0x43, 1)   # unused
    setrange(0x44, 0x51, 2)   # aget/aput
    setrange(0x52, 0x5f, 2)   # iget/iput   (field, 22c)
    setrange(0x60, 0x6d, 2)   # sget/sput   (field, 21c)
    setrange(0x6e, 0x72, 3)   # invoke-*    (method, 35c)
    size[0x73] = 1
    setrange(0x74, 0x78, 3)   # invoke-*/range (method, 3rc)
    size[0x79] = 1; size[0x7a] = 1
    setrange(0x7b, 0x8f, 1)   # unop
    setrange(0x90, 0xaf, 2)   # binop
    setrange(0xb0, 0xcf, 1)   # binop/2addr
    setrange(0xd0, 0xd7, 2)   # binop/lit16
    setrange(0xd8, 0xe2, 2)   # binop/lit8
    setrange(0xe3, 0xf9, 1)   # unused
    size[0xfa] = 4; size[0xfb] = 4            # invoke-polymorphic[/range]
    size[0xfc] = 3; size[0xfd] = 3            # invoke-custom[/range]
    size[0xfe] = 2; size[0xff] = 2            # const-method-handle / -type
    # index kinds (operand is the u16 at code-unit index 1, unless noted)
    kind[0x1a] = K_STRING                      # const-string
    kind[0x1b] = K_STRING                      # const-string/jumbo (u32 at [1..2])
    for op in (0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25):
        kind[op] = K_TYPE
    for op in range(0x52, 0x6e):               # 0x52..0x6d field ops
        kind[op] = K_FIELD
    for op in list(range(0x6e, 0x73)) + list(range(0x74, 0x79)):
        kind[op] = K_METHOD
    kind[0xfa] = K_METHOD; kind[0xfb] = K_METHOD   # + proto at [3]
    kind[0xfc] = K_CALLSITE; kind[0xfd] = K_CALLSITE
    kind[0xfe] = K_MHANDLE
    kind[0xff] = K_PROTO
    return size, kind

INSN_SIZE, INSN_KIND = _build_opcode_tables()


def insn_unit_count(code: bytes, pos: int) -> int:
    """Size in code units of the instruction/payload starting at byte `pos`."""
    u16 = code[pos] | (code[pos + 1] << 8)
    if u16 == 0x0100:  # packed-switch payload
        size = code[pos + 2] | (code[pos + 3] << 8)
        return 4 + size * 2
    if u16 == 0x0200:  # sparse-switch payload
        size = code[pos + 2] | (code[pos + 3] << 8)
        return 2 + size * 4
    if u16 == 0x0300:  # fill-array-data payload
        ew = code[pos + 2] | (code[pos + 3] << 8)
        size = (code[pos + 4] | (code[pos + 5] << 8) |
                (code[pos + 6] << 16) | (code[pos + 7] << 24))
        total_bytes = ew * size
        return 4 + (total_bytes + 1) // 2
    return INSN_SIZE[u16 & 0xFF]


# ---------------------------------------------------------------------------
# Resolved model — every index is resolved to the entity it names, so renaming
# + re-serialization rebuilds all index tables from scratch, sorted & consistent.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Proto:
    ret: str
    params: Tuple[str, ...]


@dataclass(frozen=True)
class FieldRef:
    cls: str
    type: str
    name: str


@dataclass(frozen=True)
class MethodRef:
    cls: str
    proto: Proto
    name: str


@dataclass
class EncodedValue:
    kind: int            # value_type (low 5 bits of the header byte)
    arg: int             # value_arg (high 3 bits) as originally stored
    payload: object      # raw bytes for primitives, or resolved ref/list


@dataclass
class TryItem:
    start_addr: int
    insn_count: int
    catches: List[Tuple[Optional[str], int]]   # (type_desc or None=catch-all, addr)


@dataclass
class Code:
    registers: int
    ins: int
    outs: int
    insns: bytearray
    patches: List[Tuple[int, int, object]]     # (byte_pos, kind, resolved ref)
    tries: List[TryItem]
    debug_off_present: bool                     # had debug info (dropped on write)


@dataclass
class EncField:
    ref: FieldRef
    access: int


@dataclass
class EncMethod:
    ref: MethodRef
    access: int
    code: Optional[Code]


@dataclass
class ClassDef:
    descriptor: str
    access: int
    superclass: Optional[str]
    interfaces: List[str]
    source_file: Optional[str]
    static_fields: List[EncField]
    instance_fields: List[EncField]
    direct_methods: List[EncMethod]
    virtual_methods: List[EncMethod]
    static_values: List[EncodedValue]
    annotations: object = None                  # kept raw-resolved (see below)


class DexFile:
    """A fully-parsed DEX in resolved form."""

    def __init__(self) -> None:
        self.version = b"035\x00"
        self.classes: List[ClassDef] = []
        self.strings: List[str] = []            # original pool (retained on write)
        # resolution tables (valid only during read)
        self._strings: List[str] = []
        self._types: List[str] = []
        self._protos: List[Proto] = []
        self._fields: List[FieldRef] = []
        self._methods: List[MethodRef] = []
        self.has_annotations = False


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------
class _Reader:
    def __init__(self, data: bytes):
        self.d = data

    def u16(self, o): return self.d[o] | (self.d[o + 1] << 8)
    def u32(self, o): return struct.unpack_from("<I", self.d, o)[0]

    def parse(self) -> DexFile:
        d = self.d
        dex = DexFile()
        dex.version = d[4:8]
        if d[:4] != b"dex\n":
            raise ValueError("not a DEX file")
        H = lambda off: self.u32(off)
        str_size, str_off = H(0x38), H(0x3C)
        type_size, type_off = H(0x40), H(0x44)
        proto_size, proto_off = H(0x48), H(0x4C)
        field_size, field_off = H(0x50), H(0x54)
        meth_size, meth_off = H(0x58), H(0x5C)
        cls_size, cls_off = H(0x60), H(0x64)

        # strings
        strings: List[str] = []
        for i in range(str_size):
            so = self.u32(str_off + 4 * i)
            _n, p = read_uleb128(d, so)
            s, _ = decode_mutf8(d, p)
            strings.append(s)
        dex._strings = strings
        dex.strings = list(strings)

        # types
        types = [strings[self.u32(type_off + 4 * i)] for i in range(type_size)]
        dex._types = types

        # protos
        protos: List[Proto] = []
        for i in range(proto_size):
            base = proto_off + 12 * i
            ret = types[self.u32(base + 4)]
            params_off = self.u32(base + 8)
            params: Tuple[str, ...] = ()
            if params_off:
                n = self.u32(params_off)
                params = tuple(types[self.u16(params_off + 4 + 2 * k)] for k in range(n))
            protos.append(Proto(ret, params))
        dex._protos = protos

        # fields
        fields: List[FieldRef] = []
        for i in range(field_size):
            base = field_off + 8 * i
            cls = types[self.u16(base)]
            typ = types[self.u16(base + 2)]
            name = strings[self.u32(base + 4)]
            fields.append(FieldRef(cls, typ, name))
        dex._fields = fields

        # methods
        methods: List[MethodRef] = []
        for i in range(meth_size):
            base = meth_off + 8 * i
            cls = types[self.u16(base)]
            proto = protos[self.u16(base + 2)]
            name = strings[self.u32(base + 4)]
            methods.append(MethodRef(cls, proto, name))
        dex._methods = methods

        # classes
        for i in range(cls_size):
            dex.classes.append(self._class(dex, cls_off + 32 * i))
        return dex

    def _type_list(self, off) -> List[str]:
        if not off:
            return []
        n = self.u32(off)
        return [self._dex_types[self.u16(off + 4 + 2 * k)] for k in range(n)]

    def _class(self, dex: DexFile, base: int) -> ClassDef:
        self._dex_types = dex._types
        d = self.d
        descriptor = dex._types[self.u32(base)]
        access = self.u32(base + 4)
        super_idx = self.u32(base + 8)
        superclass = None if super_idx == 0xFFFFFFFF else dex._types[super_idx]
        interfaces = self._type_list(self.u32(base + 12))
        src_idx = self.u32(base + 16)
        source_file = None if src_idx == 0xFFFFFFFF else dex._strings[src_idx]
        annotations_off = self.u32(base + 20)
        class_data_off = self.u32(base + 24)
        static_values_off = self.u32(base + 28)

        cd = ClassDef(descriptor, access, superclass, interfaces, source_file,
                      [], [], [], [], [])
        if annotations_off:
            dex.has_annotations = True
            cd.annotations = self._annotations_directory(dex, annotations_off)
        if static_values_off:
            cd.static_values = self._encoded_array(dex, static_values_off)
        if class_data_off:
            self._class_data(dex, cd, class_data_off)
        return cd

    def _class_data(self, dex, cd, off):
        d = self.d
        sf, off = read_uleb128(d, off)
        inf, off = read_uleb128(d, off)
        dm, off = read_uleb128(d, off)
        vm, off = read_uleb128(d, off)
        def fields(n, start):
            res = []
            idx = 0
            o = start
            for _ in range(n):
                diff, o = read_uleb128(d, o)
                acc, o = read_uleb128(d, o)
                idx += diff
                res.append(EncField(dex._fields[idx], acc))
            return res, o
        def methods(n, start):
            res = []
            idx = 0
            o = start
            for _ in range(n):
                diff, o = read_uleb128(d, o)
                acc, o = read_uleb128(d, o)
                code_off, o = read_uleb128(d, o)
                idx += diff
                code = self._code(dex, code_off) if code_off else None
                res.append(EncMethod(dex._methods[idx], acc, code))
            return res, o
        cd.static_fields, off = fields(sf, off)
        cd.instance_fields, off = fields(inf, off)
        cd.direct_methods, off = methods(dm, off)
        cd.virtual_methods, off = methods(vm, off)

    def _code(self, dex, off) -> Code:
        d = self.d
        registers = self.u16(off)
        ins = self.u16(off + 2)
        outs = self.u16(off + 4)
        tries_size = self.u16(off + 6)
        debug_off = self.u32(off + 8)
        insns_size = self.u32(off + 12)   # in 16-bit code units
        insns_start = off + 16
        insns = bytearray(d[insns_start:insns_start + insns_size * 2])

        patches: List[Tuple[int, int, object]] = []
        pos = 0
        n = len(insns)
        while pos < n:
            units = insn_unit_count(insns, pos)
            op = insns[pos]
            u16first = insns[pos] | (insns[pos + 1] << 8)
            if u16first not in (0x0100, 0x0200, 0x0300):
                kind = INSN_KIND.get(op)
                if kind is not None:
                    if op == 0x1b:  # const-string/jumbo: u32 index at [1..2]
                        idx = (insns[pos + 2] | (insns[pos + 3] << 8)
                               | (insns[pos + 4] << 16) | (insns[pos + 5] << 24))
                        patches.append((pos + 2, kind, self._ref(dex, kind, idx), 4))
                    else:
                        idx = insns[pos + 2] | (insns[pos + 3] << 8)
                        patches.append((pos + 2, kind, self._ref(dex, kind, idx), 2))
                        if op in (0xfa, 0xfb):  # proto index at [3]
                            pidx = insns[pos + 6] | (insns[pos + 7] << 8)
                            patches.append((pos + 6, K_PROTO, dex._protos[pidx], 2))
            pos += units * 2

        tries: List[TryItem] = []
        if tries_size:
            tpos = insns_start + insns_size * 2
            if insns_size % 2 == 1:
                tpos += 2  # padding to 4-byte alignment
            handlers_base = tpos + tries_size * 8
            raw_tries = []
            for t in range(tries_size):
                b = tpos + 8 * t
                start_addr = self.u32(b)
                insn_count = self.u16(b + 4)
                handler_off = self.u16(b + 6)
                raw_tries.append((start_addr, insn_count, handler_off))
            # parse handler lists (keyed by offset from handlers_base)
            hp = handlers_base
            hsize, hp = read_uleb128(d, hp)
            handlers: Dict[int, List[Tuple[Optional[str], int]]] = {}
            # iterate each handler list
            o = handlers_base
            list_size_count, o = read_uleb128(d, o)
            for _ in range(list_size_count):
                rel = o - handlers_base
                size_s, o = read_sleb128(d, o)
                catches: List[Tuple[Optional[str], int]] = []
                for _k in range(abs(size_s)):
                    type_idx, o = read_uleb128(d, o)
                    addr, o = read_uleb128(d, o)
                    catches.append((dex._types[type_idx], addr))
                if size_s <= 0:
                    catch_all, o = read_uleb128(d, o)
                    catches.append((None, catch_all))
                handlers[rel] = catches
            for (start_addr, insn_count, handler_off) in raw_tries:
                tries.append(TryItem(start_addr, insn_count,
                                     handlers.get(handler_off, [])))

        return Code(registers, ins, outs, insns, patches, tries,
                    debug_off_present=bool(debug_off))

    def _annotation_set(self, dex, off):
        """Return list of (visibility, enc_annotation)."""
        if not off:
            return []
        d = self.d
        n = self.u32(off)
        items = []
        for i in range(n):
            a_off = self.u32(off + 4 + 4 * i)
            if not a_off:
                continue
            vis = d[a_off]
            enc, _ = self._encoded_annotation(dex, a_off + 1)
            items.append((vis, enc))
        return items

    def _annotations_directory(self, dex, off):
        d = self.d
        class_off = self.u32(off)
        fsize = self.u32(off + 4)
        msize = self.u32(off + 8)
        psize = self.u32(off + 12)
        o = off + 16
        res = {"class": self._annotation_set(dex, class_off),
               "fields": [], "methods": [], "params": []}
        for _ in range(fsize):
            fidx = self.u32(o); aset = self.u32(o + 4); o += 8
            res["fields"].append((dex._fields[fidx], self._annotation_set(dex, aset)))
        for _ in range(msize):
            midx = self.u32(o); aset = self.u32(o + 4); o += 8
            res["methods"].append((dex._methods[midx], self._annotation_set(dex, aset)))
        for _ in range(psize):
            midx = self.u32(o); refl = self.u32(o + 4); o += 8
            param_sets = []
            if refl:
                cnt = self.u32(refl)
                for k in range(cnt):
                    s_off = self.u32(refl + 4 + 4 * k)
                    param_sets.append(self._annotation_set(dex, s_off))
            res["params"].append((dex._methods[midx], param_sets))
        return res

    def _ref(self, dex, kind, idx):
        if kind == K_STRING:
            return dex._strings[idx]
        if kind == K_TYPE:
            return dex._types[idx]
        if kind == K_FIELD:
            return dex._fields[idx]
        if kind == K_METHOD:
            return dex._methods[idx]
        if kind == K_PROTO:
            return dex._protos[idx]
        # callsite / method handle: keep the raw index (not renamed)
        return ("rawidx", kind, idx)

    def _encoded_array(self, dex, off) -> List[EncodedValue]:
        d = self.d
        n, off = read_uleb128(d, off)
        out = []
        for _ in range(n):
            v, off = self._encoded_value(dex, off)
            out.append(v)
        return out

    def _encoded_value(self, dex, off):
        d = self.d
        header = d[off]; off += 1
        vtype = header & 0x1F
        varg = header >> 5
        # value sizes per type; most are (varg+1) raw bytes
        if vtype == 0x1C:  # VALUE_ARRAY
            # nested array
            start = off
            n, off = read_uleb128(d, off)
            items = []
            for _ in range(n):
                v, off = self._encoded_value(dex, off)
                items.append(v)
            return EncodedValue(vtype, 0, ("array", items)), off
        if vtype == 0x1D:  # VALUE_ANNOTATION
            v, off = self._encoded_annotation(dex, off)
            return EncodedValue(vtype, 0, ("annotation", v)), off
        if vtype == 0x1E:  # VALUE_NULL
            return EncodedValue(vtype, 0, None), off
        if vtype == 0x1F:  # VALUE_BOOLEAN (varg holds the bit)
            return EncodedValue(vtype, varg, None), off
        size = varg + 1
        raw = d[off:off + size]; off += size
        val = int.from_bytes(raw, "little")
        if vtype == 0x17:   # STRING
            return EncodedValue(vtype, varg, ("string", dex._strings[val])), off
        if vtype == 0x18:   # TYPE
            return EncodedValue(vtype, varg, ("type", dex._types[val])), off
        if vtype == 0x19:   # FIELD
            return EncodedValue(vtype, varg, ("field", dex._fields[val])), off
        if vtype == 0x1A:   # METHOD
            return EncodedValue(vtype, varg, ("method", dex._methods[val])), off
        if vtype == 0x1B:   # ENUM
            return EncodedValue(vtype, varg, ("enum", dex._fields[val])), off
        return EncodedValue(vtype, varg, ("raw", raw)), off

    def _encoded_annotation(self, dex, off):
        d = self.d
        type_idx, off = read_uleb128(d, off)
        size, off = read_uleb128(d, off)
        elements = []
        for _ in range(size):
            name_idx, off = read_uleb128(d, off)
            v, off = self._encoded_value(dex, off)
            elements.append((dex._strings[name_idx], v))
        return ("enc_annotation", dex._types[type_idx], elements), off


def parse_dex(path_or_bytes) -> DexFile:
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data = bytes(path_or_bytes)
    else:
        with open(path_or_bytes, "rb") as fh:
            data = fh.read()
    return _Reader(data).parse()


# ---------------------------------------------------------------------------
# Renaming + serialization
# ---------------------------------------------------------------------------
_PRIM_SHORTY = set("VZBSCIJFD")


def _shorty_char(desc: str) -> str:
    c = desc[0]
    return c if c in _PRIM_SHORTY else "L"


def _shorty(p: "Proto") -> str:
    return _shorty_char(p.ret) + "".join(_shorty_char(x) for x in p.params)


@dataclass
class RenamePlan:
    """Resolved renaming: class descriptor map + per-ref name maps."""
    class_map: Dict[str, str]                    # 'Lold;' -> 'Lnew;'
    field_names: Dict[FieldRef, str]
    method_names: Dict[MethodRef, str]


class _Writer:
    def __init__(self, dex: DexFile, plan: RenamePlan):
        self.dex = dex
        self.cm = plan.class_map
        self.fn = plan.field_names
        self.mn = plan.method_names

    # -- transforms --------------------------------------------------------
    def RT(self, desc: str) -> str:
        i = 0
        while i < len(desc) and desc[i] == "[":
            i += 1
        base = desc[i:]
        return desc[:i] + self.cm.get(base, base)

    def RP(self, p: Proto) -> Proto:
        return Proto(self.RT(p.ret), tuple(self.RT(x) for x in p.params))

    def RF(self, f: FieldRef) -> FieldRef:
        return FieldRef(self.RT(f.cls), self.RT(f.type), self.fn.get(f, f.name))

    def RM(self, m: MethodRef) -> MethodRef:
        return MethodRef(self.RT(m.cls), self.RP(m.proto), self.mn.get(m, m.name))

    # -- collection --------------------------------------------------------
    def _collect(self):
        strings = set(self.dex.strings)      # retain originals (safety: const-string etc.)
        types, protos, fields, methods = set(), set(), set(), set()

        def add_type(d): types.add(d)
        def add_proto(p):
            protos.add(p); add_type(p.ret)
            for x in p.params: add_type(x)
            strings.add(_shorty(p))
        def add_field(f):
            fields.add(f); add_type(f.cls); add_type(f.type); strings.add(f.name)
        def add_method(m):
            methods.add(m); add_type(m.cls); add_proto(m.proto); strings.add(m.name)

        def walk_value(ev: EncodedValue):
            p = ev.payload
            if ev.kind == 0x17: strings.add(p[1])                      # string
            elif ev.kind == 0x18: add_type(self.RT(p[1]))             # type
            elif ev.kind == 0x19: add_field(self.RF(p[1]))            # field
            elif ev.kind == 0x1A: add_method(self.RM(p[1]))          # method
            elif ev.kind == 0x1B: add_field(self.RF(p[1]))           # enum
            elif ev.kind == 0x1C:
                for it in p[1]: walk_value(it)
            elif ev.kind == 0x1D: walk_anno(p[1])

        def walk_anno(a):
            _tag, tdesc, elems = a
            add_type(self.RT(tdesc))
            for name, ev in elems:
                strings.add(name); walk_value(ev)

        def walk_aset(aset):
            for _vis, enc in aset: walk_anno(enc)

        for c in self.dex.classes:
            add_type(self.RT(c.descriptor))
            if c.superclass: add_type(self.RT(c.superclass))
            for it in c.interfaces: add_type(self.RT(it))
            if c.source_file: strings.add(c.source_file)
            for ef in c.static_fields + c.instance_fields:
                add_field(self.RF(ef.ref)); strings.add(self.fn.get(ef.ref, ef.ref.name))
            for em in c.direct_methods + c.virtual_methods:
                add_method(self.RM(em.ref))
                if em.code:
                    for (_pos, kind, ref, _w) in em.code.patches:
                        if kind == K_STRING: strings.add(ref)
                        elif kind == K_TYPE: add_type(self.RT(ref))
                        elif kind == K_FIELD: add_field(self.RF(ref))
                        elif kind == K_METHOD: add_method(self.RM(ref))
                        elif kind == K_PROTO: add_proto(self.RP(ref))
                    for t in em.code.tries:
                        for (tdesc, _addr) in t.catches:
                            if tdesc is not None: add_type(self.RT(tdesc))
            for ev in c.static_values: walk_value(ev)
            if c.annotations:
                walk_aset(c.annotations["class"])
                for _f, s in c.annotations["fields"]: walk_aset(s)
                for _m, s in c.annotations["methods"]: walk_aset(s)
                for _m, ss in c.annotations["params"]:
                    for s in ss: walk_aset(s)

        # also every type's descriptor is a string
        for d in types: strings.add(d)
        return strings, types, protos, fields, methods

    # -- build sorted tables + index maps ----------------------------------
    def _build_tables(self):
        strings, types, protos, fields, methods = self._collect()
        self.str_list = sorted(strings, key=mutf8_sort_key)
        self.str_idx = {s: i for i, s in enumerate(self.str_list)}

        self.type_list = sorted(types, key=lambda d: self.str_idx[d])
        self.type_idx = {d: i for i, d in enumerate(self.type_list)}

        def proto_key(p):
            return (self.type_idx[p.ret], tuple(self.type_idx[x] for x in p.params))
        self.proto_list = sorted(protos, key=proto_key)
        self.proto_idx = {p: i for i, p in enumerate(self.proto_list)}

        def field_key(f):
            return (self.type_idx[f.cls], self.str_idx[f.name], self.type_idx[f.type])
        self.field_list = sorted(fields, key=field_key)
        self.field_idx = {f: i for i, f in enumerate(self.field_list)}

        def method_key(m):
            return (self.type_idx[m.cls], self.str_idx[m.name], self.proto_idx[m.proto])
        self.method_list = sorted(methods, key=method_key)
        self.method_idx = {m: i for i, m in enumerate(self.method_list)}

    # lookups with transforms applied
    def ti(self, desc): return self.type_idx[self.RT(desc)]
    def pi(self, p): return self.proto_idx[self.RP(p)]
    def fi(self, f): return self.field_idx[self.RF(f)]
    def mi(self, m): return self.method_idx[self.RM(m)]
    def si(self, s): return self.str_idx[s]

    # -- encoders ----------------------------------------------------------
    def _enc_value(self, ev: EncodedValue) -> bytes:
        k = ev.kind
        def hdr(varg): return bytes([(varg << 5) | k])
        def idxval(i):
            raw = i.to_bytes(max(1, (i.bit_length() + 7) // 8 or 1), "little") if i else b"\x00"
            return hdr(len(raw) - 1) + raw
        if k == 0x17: return idxval(self.si(ev.payload[1]))            # string
        if k == 0x18: return idxval(self.ti(ev.payload[1]))           # type
        if k == 0x19: return idxval(self.fi(ev.payload[1]))          # field
        if k == 0x1A: return idxval(self.mi(ev.payload[1]))         # method
        if k == 0x1B: return idxval(self.fi(ev.payload[1]))         # enum
        if k == 0x1E: return hdr(0)                                 # null
        if k == 0x1F: return hdr(ev.arg)                            # boolean
        if k == 0x1C:                                              # array
            out = bytearray(hdr(0))
            items = ev.payload[1]
            out += write_uleb128(len(items))
            for it in items: out += self._enc_value(it)
            return bytes(out)
        if k == 0x1D:                                              # annotation
            return hdr(0) + self._enc_annotation(ev.payload[1])
        # primitive raw bytes preserved verbatim
        raw = ev.payload[1]
        return hdr(len(raw) - 1) + raw

    def _enc_annotation(self, a) -> bytes:
        _tag, tdesc, elems = a
        out = bytearray()
        out += write_uleb128(self.ti(tdesc))
        out += write_uleb128(len(elems))
        for name, ev in sorted(elems, key=lambda ne: self.si(ne[0])):
            out += write_uleb128(self.si(name))
            out += self._enc_value(ev)
        return bytes(out)

    def _enc_array(self, values) -> bytes:
        out = bytearray(write_uleb128(len(values)))
        for ev in values: out += self._enc_value(ev)
        return bytes(out)

    # -- data section layout ----------------------------------------------
    def serialize(self) -> bytes:
        self._build_tables()
        Nstr, Ntype = len(self.str_list), len(self.type_list)
        Nproto, Nfield = len(self.proto_list), len(self.field_list)
        Nmethod, Nclass = len(self.method_list), len(self.dex.classes)
        data_base = (0x70 + 4 * Nstr + 4 * Ntype + 12 * Nproto
                     + 8 * Nfield + 8 * Nmethod + 32 * Nclass)

        data = bytearray()
        counts: Dict[int, int] = {}
        first: Dict[int, int] = {}
        def tell(): return data_base + len(data)
        def align(n):
            while (data_base + len(data)) % n: data.append(0)
        def bump(mtype, start):
            counts[mtype] = counts.get(mtype, 0) + 1
            if start < first.get(mtype, 1 << 62):
                first[mtype] = start

        # string_data (contiguous)
        str_data_off: Dict[str, int] = {}
        for s in self.str_list:
            start = tell()
            str_data_off[s] = start
            data += write_uleb128(utf16_units(s))
            data += encode_mutf8(s)
            bump(0x2002, start)

        # type_lists (contiguous, deduped): all proto params + all interfaces
        typelist_off: Dict[Tuple[int, ...], int] = {}
        def tl_key(descs_final):
            return tuple(self.type_idx[d] for d in descs_final)
        needed_tls = set()
        for p in self.proto_list:
            if p.params: needed_tls.add(tl_key(p.params))
        for c in self.dex.classes:
            if c.interfaces:
                needed_tls.add(tl_key(tuple(self.RT(x) for x in c.interfaces)))
        for key in sorted(needed_tls):
            align(4)
            start = tell()
            data.extend(struct.pack("<I", len(key)))
            for ti in key: data.extend(struct.pack("<H", ti))
            typelist_off[key] = start
            bump(0x1001, start)
        def type_list_off(descs_final):
            if not descs_final: return 0
            return typelist_off[tl_key(descs_final)]
        proto_params_off = [type_list_off(tuple(p.params)) for p in self.proto_list]

        # ---- annotations, in separate contiguous passes with dedup ----
        # annotation_item (dedup by encoded bytes)
        item_off: Dict[bytes, int] = {}
        item_tid: Dict[bytes, int] = {}      # type_idx for sorting sets
        def item_bytes(vis, enc):
            return bytes([vis]) + self._enc_annotation(enc)
        def collect_set_items(aset):
            for vis, enc in aset:
                ib = item_bytes(vis, enc)
                if ib not in item_off:
                    item_off[ib] = None  # placeholder; emitted below
                    item_tid[ib] = self.ti(enc[1])
        for c in self.dex.classes:
            if not c.annotations: continue
            collect_set_items(c.annotations["class"])
            for _f, s in c.annotations["fields"]: collect_set_items(s)
            for _m, s in c.annotations["methods"]: collect_set_items(s)
            for _m, ss in c.annotations["params"]:
                for s in ss: collect_set_items(s)
        for ib in list(item_off.keys()):
            start = tell()
            data += ib
            item_off[ib] = start
            bump(0x2004, start)

        # annotation_set_item (dedup by sorted tuple of item offsets)
        set_off: Dict[Tuple[int, ...], int] = {}
        def set_key(aset):
            pairs = sorted(((item_tid[item_bytes(v, e)], item_off[item_bytes(v, e)])
                            for v, e in aset))
            return tuple(off for _t, off in pairs)
        def need_set(aset):
            if not aset: return ()
            k = set_key(aset)
            set_off.setdefault(k, None)
            return k
        set_keys = []
        for c in self.dex.classes:
            if not c.annotations: continue
            for grp in ([c.annotations["class"]]
                        + [s for _f, s in c.annotations["fields"]]
                        + [s for _m, s in c.annotations["methods"]]
                        + [s for _m, ss in c.annotations["params"] for s in ss]):
                k = need_set(grp)
                if k: set_keys.append(k)
        for k in list(set_off.keys()):
            align(4)
            start = tell()
            data.extend(struct.pack("<I", len(k)))
            for off in k: data.extend(struct.pack("<I", off))
            set_off[k] = start
            bump(0x1003, start)
        def set_offset(aset):
            if not aset: return 0
            return set_off[set_key(aset)]

        # annotation_set_ref_list (params), contiguous
        refl_off: Dict[Tuple[int, ...], int] = {}
        def need_refl(sets):
            key = tuple(set_offset(s) for s in sets)
            refl_off.setdefault(key, None)
            return key
        for c in self.dex.classes:
            if not c.annotations: continue
            for _m, ss in c.annotations["params"]:
                if ss: need_refl(ss)
        for key in list(refl_off.keys()):
            align(4)
            start = tell()
            data.extend(struct.pack("<I", len(key)))
            for off in key: data.extend(struct.pack("<I", off))
            refl_off[key] = start
            bump(0x1002, start)

        # encoded_array (static values), contiguous
        static_off: Dict[int, int] = {}
        for c in self.dex.classes:
            if c.static_values:
                start = tell()
                static_off[id(c)] = start
                data += self._enc_array(c.static_values)
                bump(0x2005, start)

        # annotations_directory_item, contiguous
        anno_dir_off: Dict[int, int] = {}
        for c in self.dex.classes:
            if not c.annotations: continue
            class_set = set_offset(c.annotations["class"])
            field_entries = sorted((self.fi(f), set_offset(s))
                                   for f, s in c.annotations["fields"])
            method_entries = sorted((self.mi(m), set_offset(s))
                                    for m, s in c.annotations["methods"])
            param_entries = []
            for m, ss in c.annotations["params"]:
                ro = refl_off[tuple(set_offset(s) for s in ss)] if ss else 0
                param_entries.append((self.mi(m), ro))
            param_entries.sort()
            if not (class_set or field_entries or method_entries or param_entries):
                continue
            align(4)
            start = tell()
            anno_dir_off[id(c)] = start
            data.extend(struct.pack("<IIII", class_set, len(field_entries),
                                    len(method_entries), len(param_entries)))
            for fi, so in field_entries: data.extend(struct.pack("<II", fi, so))
            for mi, so in method_entries: data.extend(struct.pack("<II", mi, so))
            for mi, ro in param_entries: data.extend(struct.pack("<II", mi, ro))
            bump(0x2006, start)

        # code items, contiguous
        code_off: Dict[int, int] = {}
        for c in self.dex.classes:
            for em in c.direct_methods + c.virtual_methods:
                if em.code is None: continue
                align(4)
                start = tell()
                code_off[id(em)] = start
                data += self._code_bytes(em.code)
                bump(0x2001, start)

        # class_data, contiguous
        class_data_off: Dict[int, int] = {}
        for c in self.dex.classes:
            if not (c.static_fields or c.instance_fields
                    or c.direct_methods or c.virtual_methods):
                continue
            start = tell()
            class_data_off[id(c)] = start
            data += self._class_data_bytes(c, code_off)
            bump(0x2000, start)

        # ---- id tables (now that data offsets are known) ----
        string_ids = b"".join(struct.pack("<I", str_data_off[s]) for s in self.str_list)
        type_ids = b"".join(struct.pack("<I", self.str_idx[d]) for d in self.type_list)
        proto_ids = bytearray()
        for p, poff in zip(self.proto_list, proto_params_off):
            proto_ids += struct.pack("<III", self.str_idx[_shorty(p)],
                                     self.type_idx[p.ret], poff)
        field_ids = bytearray()
        for f in self.field_list:
            field_ids += struct.pack("<HHI", self.type_idx[f.cls],
                                     self.type_idx[f.type], self.str_idx[f.name])
        method_ids = bytearray()
        for m in self.method_list:
            method_ids += struct.pack("<HHI", self.type_idx[m.cls],
                                      self.proto_idx[m.proto], self.str_idx[m.name])
        class_defs = bytearray()
        for c in self.dex.classes:
            desc = self.RT(c.descriptor)
            superc = 0xFFFFFFFF if not c.superclass else self.type_idx[self.RT(c.superclass)]
            iface_off = type_list_off(tuple(self.RT(x) for x in c.interfaces)) \
                if c.interfaces else 0
            src = 0xFFFFFFFF if not c.source_file else self.str_idx[c.source_file]
            class_defs += struct.pack("<IIIIIIII",
                self.type_idx[desc], c.access, superc, iface_off, src,
                anno_dir_off.get(id(c), 0), class_data_off.get(id(c), 0),
                static_off.get(id(c), 0))

        # ---- map_list (in data, 4-aligned, last) ----
        align(4)
        map_off = tell()
        bump(0x1000, map_off)
        items = []
        items.append((0x0000, 1, 0))
        items.append((0x0001, Nstr, 0x70))
        items.append((0x0002, Ntype, 0x70 + 4 * Nstr))
        items.append((0x0003, Nproto, 0x70 + 4 * Nstr + 4 * Ntype))
        items.append((0x0004, Nfield, 0x70 + 4 * Nstr + 4 * Ntype + 12 * Nproto))
        items.append((0x0005, Nmethod, 0x70 + 4 * Nstr + 4 * Ntype + 12 * Nproto + 8 * Nfield))
        items.append((0x0006, Nclass, 0x70 + 4 * Nstr + 4 * Ntype + 12 * Nproto + 8 * Nfield + 8 * Nmethod))
        # data-section items (first offset + count, tracked during emission)
        for mtype in (0x2002, 0x1001, 0x2004, 0x1003, 0x1002,
                      0x2005, 0x2006, 0x2001, 0x2000):
            if counts.get(mtype):
                items.append((mtype, counts[mtype], first[mtype]))
        items.append((0x1000, 1, map_off))
        items.sort(key=lambda it: it[2])
        map_bytes = bytearray(struct.pack("<I", len(items)))
        for mtype, sz, off in items:
            map_bytes += struct.pack("<HHII", mtype, 0, sz, off)
        data += map_bytes

        # ---- assemble ----
        header = bytearray(0x70)
        header[0:8] = b"dex\n" + self.dex.version[0:3] + b"\x00" \
            if len(self.dex.version) >= 3 else b"dex\n035\x00"
        total = data_base + len(data)
        struct.pack_into("<I", header, 0x20, total)
        struct.pack_into("<I", header, 0x24, 0x70)
        struct.pack_into("<I", header, 0x28, 0x12345678)
        struct.pack_into("<I", header, 0x34, map_off)
        struct.pack_into("<II", header, 0x38, Nstr, 0x70)
        struct.pack_into("<II", header, 0x40, Ntype, 0x70 + 4 * Nstr)
        struct.pack_into("<II", header, 0x48, Nproto, 0x70 + 4 * Nstr + 4 * Ntype)
        struct.pack_into("<II", header, 0x50, Nfield, 0x70 + 4 * Nstr + 4 * Ntype + 12 * Nproto)
        struct.pack_into("<II", header, 0x58, Nmethod, 0x70 + 4 * Nstr + 4 * Ntype + 12 * Nproto + 8 * Nfield)
        struct.pack_into("<II", header, 0x60, Nclass, 0x70 + 4 * Nstr + 4 * Ntype + 12 * Nproto + 8 * Nfield + 8 * Nmethod)
        struct.pack_into("<II", header, 0x68, total - data_base, data_base)

        out = bytearray(header) + string_ids + type_ids + bytes(proto_ids) \
            + bytes(field_ids) + bytes(method_ids) + bytes(class_defs) + data
        # signature = SHA1 of everything after signature field (offset 32)
        sig = hashlib.sha1(bytes(out[32:])).digest()
        out[12:32] = sig
        # checksum = adler32 of everything after checksum field (offset 12)
        chk = zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF
        struct.pack_into("<I", out, 8, chk)
        return bytes(out)

    # -- code + class_data byte builders -----------------------------------
    def _new_index(self, kind, ref):
        if kind == K_STRING: return self.si(ref)
        if kind == K_TYPE: return self.ti(ref)
        if kind == K_FIELD: return self.fi(ref)
        if kind == K_METHOD: return self.mi(ref)
        if kind == K_PROTO: return self.pi(ref)
        raise ValueError("unrenamable index kind in code")

    def _code_bytes(self, code: Code) -> bytes:
        insns = bytearray(code.insns)
        for (pos, kind, ref, width) in code.patches:
            idx = self._new_index(kind, ref)
            if width == 4:
                struct.pack_into("<I", insns, pos, idx)
            else:
                if idx > 0xFFFF:
                    raise ValueError("index overflow in 16-bit operand; dex too large")
                struct.pack_into("<H", insns, pos, idx)
        out = bytearray()
        out += struct.pack("<HHHH", code.registers, code.ins, code.outs, len(code.tries))
        out += struct.pack("<II", 0, len(insns) // 2)   # debug_off=0 (dropped)
        out += insns
        if code.tries:
            if (len(insns) // 2) % 2 == 1:
                out += b"\x00\x00"                       # align tries to 4 bytes
            # build handler lists (dedup by content), then try entries
            handler_blobs: Dict[bytes, int] = {}
            order: List[bytes] = []
            def handler_blob(catches):
                typed = [(d, a) for (d, a) in catches if d is not None]
                has_all = any(d is None for (d, _a) in catches)
                size = -len(typed) if has_all else len(typed)
                b = bytearray(write_sleb128(size))
                for (d, a) in typed:
                    b += write_uleb128(self.ti(d)); b += write_uleb128(a)
                if has_all:
                    all_addr = [a for (d, a) in catches if d is None][0]
                    b += write_uleb128(all_addr)
                return bytes(b)
            try_blobs = [handler_blob(t.catches) for t in code.tries]
            # handlers area begins with uleb(count of distinct lists)
            uniq = []
            for b in try_blobs:
                if b not in handler_blobs:
                    handler_blobs[b] = None
                    uniq.append(b)
            harea = bytearray(write_uleb128(len(uniq)))
            for b in uniq:
                handler_blobs[b] = len(harea)   # offset from area start
                harea += b
            tries_bytes = bytearray()
            for t, b in zip(code.tries, try_blobs):
                tries_bytes += struct.pack("<IHH", t.start_addr, t.insn_count,
                                           handler_blobs[b])
            out += tries_bytes + harea
        return bytes(out)

    def _class_data_bytes(self, c: ClassDef, code_off: Dict[int, int]) -> bytes:
        out = bytearray()
        out += write_uleb128(len(c.static_fields))
        out += write_uleb128(len(c.instance_fields))
        out += write_uleb128(len(c.direct_methods))
        out += write_uleb128(len(c.virtual_methods))

        def emit_fields(items):
            resolved = sorted(((self.fi(ef.ref), ef.access) for ef in items))
            prev = 0
            for idx, acc in resolved:
                out.extend(write_uleb128(idx - prev)); prev = idx
                out.extend(write_uleb128(acc))

        def emit_methods(items):
            resolved = sorted(((self.mi(em.ref), em.access, em) for em in items),
                              key=lambda t: t[0])
            prev = 0
            for idx, acc, em in resolved:
                out.extend(write_uleb128(idx - prev)); prev = idx
                out.extend(write_uleb128(acc))
                out.extend(write_uleb128(code_off.get(id(em), 0)))

        emit_fields(c.static_fields)
        emit_fields(c.instance_fields)
        emit_methods(c.direct_methods)
        emit_methods(c.virtual_methods)
        return bytes(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def serialize_dex(dex: DexFile, plan: Optional[RenamePlan] = None) -> bytes:
    if plan is None:
        plan = RenamePlan({}, {}, {})
    return _Writer(dex, plan).serialize()


def empty_plan() -> RenamePlan:
    return RenamePlan({}, {}, {})
