"""Optional real-toolchain backends for DEX/JAR/APK obfuscation.

NP Manager's actual engine is ProGuard (the APK bundles ``proguard/*`` and the
three dictionary options ``-obfuscationdictionary`` /
``-classobfuscationdictionary`` / ``-packageobfuscationdictionary``). The
faithful way to reproduce DEX/JAR/APK renaming is therefore to hand our
generated dictionary to ProGuard, or to round-trip a DEX through
baksmali -> (our text renamer) -> smali.

These helpers emit the ProGuard config and shell out to the tools *when they
are installed*; they report clearly when a tool is missing rather than
pretending the work was done.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def proguard_dictionary_config(
    method_field_dict: str,
    class_dict: Optional[str] = None,
    package_dict: Optional[str] = None,
) -> str:
    """Build the ProGuard options that activate dictionary obfuscation."""
    lines = [f"-obfuscationdictionary {method_field_dict}"]
    if class_dict:
        lines.append(f"-classobfuscationdictionary {class_dict}")
    if package_dict:
        lines.append(f"-packageobfuscationdictionary {package_dict}")
    # Keep the dictionary deterministic and aggressive, as NP's mode does.
    lines += ["-useuniqueclassmembernames", "-dontshrink", "-dontoptimize"]
    return "\n".join(lines) + "\n"


@dataclass
class ToolResult:
    ran: bool
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    note: str = ""


def run_proguard(config_path: str, proguard_cmd: str = "proguard") -> ToolResult:
    if not tool_available(proguard_cmd):
        return ToolResult(False, note=f"{proguard_cmd} not installed")
    proc = subprocess.run(
        [proguard_cmd, f"@{config_path}"], capture_output=True, text=True
    )
    return ToolResult(True, proc.returncode, proc.stdout, proc.stderr)


def baksmali(dex_path: str, out_dir: str, cmd: str = "baksmali") -> ToolResult:
    if not tool_available(cmd):
        return ToolResult(False, note=f"{cmd} not installed")
    proc = subprocess.run(
        [cmd, "disassemble", dex_path, "-o", out_dir], capture_output=True, text=True
    )
    return ToolResult(True, proc.returncode, proc.stdout, proc.stderr)


def smali(smali_dir: str, out_dex: str, cmd: str = "smali") -> ToolResult:
    if not tool_available(cmd):
        return ToolResult(False, note=f"{cmd} not installed")
    proc = subprocess.run(
        [cmd, "assemble", smali_dir, "-o", out_dex], capture_output=True, text=True
    )
    return ToolResult(True, proc.returncode, proc.stdout, proc.stderr)


def available_backends() -> List[str]:
    return [t for t in ("proguard", "baksmali", "smali") if tool_available(t)]
