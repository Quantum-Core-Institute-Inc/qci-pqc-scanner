"""Follow a constant defined in another file of the same tree."""

from __future__ import annotations

import re
from pathlib import Path


def collect_constants(root: Path) -> dict[str, str]:
    constants = {}
    for path in root.rglob("*"):
        if path.suffix not in {".py", ".java", ".go"}:
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
    return constants


def resolve_name(name: str, constants: dict[str, str]) -> str | None:
    return constants.get(name)
