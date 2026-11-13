"""What the scan ran, and what it skipped."""

from __future__ import annotations

from pathlib import Path

_files = 0
_skipped: list[str] = []
_parsers: set[str] = set()


def reset() -> None:
    global _files
    _files = 0
    _skipped.clear()
    _parsers.clear()


def saw_file() -> None:
    global _files
    _files += 1


def skip(path: str, reason: str) -> None:
    _skipped.append(f"{path}: {reason}")


def used(parser: str) -> None:
    _parsers.add(parser)


def summary() -> dict:
    return {
        "files_read": _files,
        "parsers": sorted(_parsers),
        "skipped": list(dict.fromkeys(_skipped)),
        "partial": bool(_skipped),
    }


def is_binary(path: Path) -> bool:
    """A file with a null byte in the first 8 KB is not source."""
    try:
        with path.open("rb") as f:
            return b"\x00" in f.read(8192)
    except Exception:
        return False
