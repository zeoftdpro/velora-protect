"""Petits utilitaires git (tous facultatifs : Velora fonctionne sans git)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


def available() -> bool:
    return shutil.which("git") is not None


def run(root: Path, *args: str, binary: bool = False):
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout if binary else proc.stdout.decode("utf-8", "replace").strip()


def is_repo(root: Path) -> bool:
    return (Path(root) / ".git").exists() and available()


def head_commit(root: Path) -> str | None:
    return run(root, "rev-parse", "HEAD") if is_repo(root) else None


def remote_url(root: Path) -> str | None:
    url = run(root, "config", "--get", "remote.origin.url") if is_repo(root) else None
    # Ne jamais conserver d'identifiants intégrés à l'URL (https://user:token@host/…)
    return re.sub(r"//[^/@\s]+@", "//", url) if url else None


def staged_files(root: Path) -> list[str]:
    out = run(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [p for p in (out or "").split("\0") if p]


def staged_content(root: Path, rel: str) -> bytes | None:
    return run(root, "show", f":{rel}", binary=True)


def is_ignored(root: Path, rel: str) -> bool:
    if not is_repo(root):
        return False
    try:
        proc = subprocess.run(["git", "-C", str(root), "check-ignore", "-q", "--", rel],
                              capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def is_tracked(root: Path, rel: str) -> bool:
    return bool(is_repo(root) and run(root, "ls-files", "--", rel))
