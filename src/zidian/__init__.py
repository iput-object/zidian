"""zidian (字典) — reproduce NP Manager's dictionary obfuscation.

Public API:
  parse_dictionary / load_dictionary   read a ProGuard-style dictionary
  generate_dictionary / DictionarySpec create a 字典.txt-style dictionary
  DictionaryNameFactory                 hand out names like ProGuard
  NameMapper                            reversible symbol -> name mapping
  discover / DiscoveryRules             select files/folders/patterns
  apply_map_to_text / transform_archive apply a mapping to text or jars
"""

from .dictionary import (
    DictionaryNameFactory,
    DictionarySpec,
    SimpleNameFactory,
    generate_dictionary,
    load_dictionary,
    parse_dictionary,
    write_dictionary,
)
from .classfilter import ClassFilter, smali_class_name
from .dex import parse_dex, serialize_dex
from .dexobf import ObfOptions, obfuscate_dex, obfuscate_dexes
from .discovery import DiscoveryRules, discover
from .javaid import is_valid_identifier
from .rename import NameMapper
from .transform import (
    apply_map_to_text,
    extract_symbols,
    transform_archive,
    transform_text_file,
)

__all__ = [
    "parse_dictionary", "load_dictionary", "generate_dictionary", "write_dictionary",
    "DictionarySpec", "DictionaryNameFactory", "SimpleNameFactory",
    "NameMapper", "DiscoveryRules", "discover", "ClassFilter", "smali_class_name",
    "parse_dex", "serialize_dex", "obfuscate_dex", "obfuscate_dexes", "ObfOptions",
    "apply_map_to_text", "extract_symbols", "transform_archive", "transform_text_file",
    "is_valid_identifier",
]
