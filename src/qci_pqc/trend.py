"""Score, ticket-ready, and new-versus-resolved over time."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def append(path: Path, score: float, ticket_ready: float, new: int, resolved: int) -> None:
    history = json.loads(path.read_text()) if path.exists() else []
    history.append({
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "score": score,
        "ticket_ready": ticket_ready,
        "new": new,
        "resolved": resolved,
    })
    path.write_text(json.dumps(history, indent=2) + "\n")


def summary(path: Path) -> dict:
    history = json.loads(path.read_text()) if path.exists() else []
    if not history:
        return {"points": 0}
    return {"points": len(history), "latest": history[-1], "first": history[0]}
