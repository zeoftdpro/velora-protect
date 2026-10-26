"""Configuration par projet (.velora/config.json) et registre global des projets."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

STATE_DIR = ".velora"
CONFIG_FILE = "config.json"

DEFAULT_CONFIG: dict = {
    "project_name": "",
    "author": "",
    # Motifs supplémentaires à ignorer (syntaxe .gitignore), en plus du .gitignore du projet.
    "ignore": [],
    "scan": {
        "network": True,          # interroger la base OSV.dev pour les dépendances
        "fail_on": "high",        # code de sortie ≠ 0 à partir de ce niveau (CI, hook)
        "allow_paths": [],        # chemins exclus du scan (motifs .gitignore)
    },
    "backup": {
        # Dossiers locaux (disque externe, NAS, dossier OneDrive/Dropbox…) ou « rclone:remote:chemin ».
        "destinations": [],
        "respect_gitignore": True,
        "include_git_bundle": True,
        # Ex. {"type": "sqlite", "name": "app", "path": "data/app.db"}
        #     {"type": "command", "name": "pg", "command": "pg_dump mabase", "extension": "sql"}
        "databases": [],
        "retention": {"keep_last": 10, "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 12},
    },
    "alerts": {
        # Webhook Discord, Slack, Teams, ntfy.sh… (laisser vide pour désactiver)
        "webhook_url": "",
        "stale_after_hours": 48,
    },
    "proof": {
        "tsa_urls": ["https://freetsa.org/tsr", "http://timestamp.digicert.com"],
        "opentimestamps": [
            "https://a.pool.opentimestamps.org",
            "https://b.pool.opentimestamps.org",
        ],
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Project:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.state_dir = self.root / STATE_DIR
        self.config = self._load()

    def _load(self) -> dict:
        path = self.state_dir / CONFIG_FILE
        if path.exists():
            with open(path, encoding="utf-8") as f:
                return _deep_merge(DEFAULT_CONFIG, json.load(f))
        return copy.deepcopy(DEFAULT_CONFIG)

    @property
    def initialized(self) -> bool:
        return (self.state_dir / CONFIG_FILE).exists()

    @property
    def name(self) -> str:
        return self.config.get("project_name") or self.root.name

    def path(self, *parts: str) -> Path:
        return self.state_dir.joinpath(*parts)

    def ensure_state(self) -> None:
        self.state_dir.mkdir(exist_ok=True)
        gitignore = self.state_dir / ".gitignore"
        if not gitignore.exists():
            # L'état local (historique, rapports) n'a pas à finir dans le dépôt ;
            # la config et les preuves, si : elles sont utiles à toute l'équipe.
            gitignore.write_text("history.jsonl\nlast_scan.json\nui.token\n", encoding="utf-8")

    def save_config(self) -> None:
        self.ensure_state()
        with open(self.state_dir / CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
            f.write("\n")


def find_project_root(start: str | Path) -> Path:
    """Remonte l'arborescence jusqu'à trouver un .velora/config.json ; sinon renvoie start."""
    start = Path(start).resolve()
    for candidate in (start, *start.parents):
        if (candidate / STATE_DIR / CONFIG_FILE).exists():
            return candidate
    return start


def global_dir() -> Path:
    return Path(os.environ.get("VELORA_HOME") or Path.home() / ".velora")


def registered_projects() -> list[str]:
    path = global_dir() / "projects.json"
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return [p for p in json.load(f) if (Path(p) / STATE_DIR / CONFIG_FILE).exists()]
    except (OSError, ValueError):
        return []


def register_project(root: Path) -> None:
    projects = registered_projects()
    root_str = str(Path(root).resolve())
    if root_str in projects:
        return
    projects.append(root_str)
    gdir = global_dir()
    gdir.mkdir(parents=True, exist_ok=True)
    with open(gdir / "projects.json", "w", encoding="utf-8") as f:
        json.dump(projects, f, indent=2, ensure_ascii=False)
