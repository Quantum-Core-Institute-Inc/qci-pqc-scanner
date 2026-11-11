"""What the scan ran, and what it skipped."""

from __future__ import annotations

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
        "skipped": list(_skipped),
        "partial": bool(_skipped),
    }
