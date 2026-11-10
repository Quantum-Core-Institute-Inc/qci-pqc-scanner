"""Certificate extensions and chain length from files already parsed."""

from __future__ import annotations

from pathlib import Path


def chain_length(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return 0
    return text.count("BEGIN CERTIFICATE")


def extension_names(text: str) -> list[str]:
    names = []
    for label in ("Key Usage", "Extended Key Usage", "Subject Alternative Name", "Basic Constraints"):
        if label.lower() in text.lower():
            names.append(label)
    return names
