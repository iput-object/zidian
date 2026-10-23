"""Deterministic, reversible symbol -> obfuscated-name mapping."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .dictionary import DictionaryNameFactory


@dataclass
class NameMapper:
    """Assigns dictionary names to source symbols and records the mapping.

    The mapping is deterministic given a fixed symbol order and dictionary:
    symbols are mapped on first sight, in encounter order, to successive
    factory names. It is reversible via the stored ``mapping`` (obf -> orig).
    """

    factory: DictionaryNameFactory
    forward: Dict[str, str] = field(default_factory=dict)  # original -> obf
    reverse: Dict[str, str] = field(default_factory=dict)  # obf -> original

    def map_symbol(self, original: str) -> str:
        if original in self.forward:
            return self.forward[original]
        obf = self.factory.next_name()
        self.forward[original] = obf
        self.reverse[obf] = original
        return obf

    def map_all(self, symbols: Iterable[str]) -> Dict[str, str]:
        for s in symbols:
            self.map_symbol(s)
        return dict(self.forward)

    # --- persistence (ProGuard-style "original -> obf" mapping file) --------
    def dumps(self) -> str:
        return "\n".join(f"{orig}\t{obf}" for orig, obf in self.forward.items())

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.dumps())

    @staticmethod
    def load_pairs(path: str) -> List[tuple[str, str]]:
        pairs: List[tuple[str, str]] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh.read().split("\n"):
                if not line or "\t" not in line:
                    continue
                orig, obf = line.split("\t", 1)
                pairs.append((orig, obf))
        return pairs
