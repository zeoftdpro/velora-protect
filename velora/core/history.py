"""Journal des événements (scans, sauvegardes, preuves) au format JSON Lines."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from velora.core.config import Project

HISTORY_FILE = "history.jsonl"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def record(project: Project, kind: str, **data) -> dict:
    project.ensure_state()
    event = {"type": kind, "time": now_iso(), **data}
    with open(project.path(HISTORY_FILE), "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event


def events(project: Project, kind: str | None = None, limit: int | None = None) -> list[dict]:
    """Événements du plus récent au plus ancien."""
    path = project.path(HISTORY_FILE)
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if kind is None or event.get("type") == kind:
                out.append(event)
    out.reverse()
    return out[:limit] if limit else out


def last(project: Project, kind: str, **match) -> dict | None:
    for event in events(project, kind):
        if all(event.get(k) == v for k, v in match.items()):
            return event
    return None
