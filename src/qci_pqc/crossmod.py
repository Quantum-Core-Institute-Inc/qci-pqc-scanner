"""Follow a constant defined in another file of the same tree."""

from __future__ import annotations

import re
from pathlib import Path
from .coverage import is_binary


def collect_constants(root: Path) -> dict[str, str]:
    constants = {}
    for path in root.rglob("*"):
        if path.suffix not in {".py", ".java", ".go", ".c", ".h", ".cs", ".js", ".ts"}:
            continue
        if is_binary(path):
            continue
        if path.is_symlink():
            try:
                if not path.resolve().is_relative_to(root.resolve()):
                    continue
            except Exception:
                continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in re.finditer(r"([A-Z][A-Z0-9_]*)\s*=\s*[\"']([^\"']+)[\"']", text):
            constants[m.group(1)] = m.group(2)
        # C #define and JS/TS const
        for m in re.finditer(r"#define\s+([A-Z][A-Z0-9_]*)\s+[\"']([^\"']+)[\"']", text):
            constants[m.group(1)] = m.group(2)
        for m in re.finditer(r"(?:const|let)\s+([A-Z][A-Z0-9_]*)\s*=\s*[\"']([^\"']+)[\"']", text):
            constants[m.group(1)] = m.group(2)
    return constants


def resolve_name(name: str, constants: dict[str, str]) -> str | None:
    return constants.get(name)
