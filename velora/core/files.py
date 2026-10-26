"""Parcours des fichiers d'un projet (avec prise en compte des .gitignore) et empreintes."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

# Dossiers jamais pertinents (dépendances installées, caches, état interne).
IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".velora", "node_modules", "bower_components", "__pycache__",
    ".venv", "venv", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".idea", ".gradle", ".nuxt", ".svelte-kit", ".turbo", ".cache", ".parcel-cache",
    "coverage", "htmlcov", ".terraform", ".dart_tool", "Pods", ".expo",
}
# Sorties de build : exclues par défaut, mais inspectées par l'audit d'exposition.
BUILD_DIRS = {"dist", "build", "out", ".next", "target", "_site", ".output"}

READ_LIMIT = 2 * 1024 * 1024  # on n'analyse pas le texte des fichiers > 2 Mo


def _glob_to_regex(glob: str) -> str:
    i, out = 0, []
    while i < len(glob):
        ch = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if glob.startswith("/**", i) and i + 3 == len(glob):
            out.append("/.*")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            end = glob.find("]", i + 1)
            if end == -1:
                out.append(re.escape(ch))
            else:
                body = glob[i + 1:end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end
        elif ch == "\\" and i + 1 < len(glob):
            i += 1
            out.append(re.escape(glob[i]))
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


@dataclass
class _Rule:
    base: str          # dossier (relatif, posix) contenant le .gitignore ; "" = racine
    negate: bool
    dir_only: bool
    anchored: bool
    regex: re.Pattern


def parse_ignore_lines(lines: Iterable[str], base: str = "") -> list[_Rule]:
    rules = []
    for raw in lines:
        line = raw.rstrip("\n").rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = line.rstrip()
        negate = line.startswith("!")
        if negate:
            line = line[1:]
        dir_only = line.endswith("/")
        line = line.rstrip("/")
        if not line:
            continue
        anchored = "/" in line
        line = line.lstrip("/")
        rules.append(_Rule(base, negate, dir_only, anchored, re.compile(_glob_to_regex(line) + r"\Z")))
    return rules


def is_ignored(rel: str, is_dir: bool, rules: list[_Rule]) -> bool:
    ignored = False
    for rule in rules:
        if rule.dir_only and not is_dir:
            continue
        if rule.base:
            if not rel.startswith(rule.base + "/"):
                continue
            target = rel[len(rule.base) + 1:]
        else:
            target = rel
        subject = target if rule.anchored else target.rsplit("/", 1)[-1]
        if rule.regex.match(subject):
            ignored = not rule.negate
    return ignored


def _read_gitignore(path: Path, base: str) -> list[_Rule]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return parse_ignore_lines(f, base)
    except OSError:
        return []


def iter_files(root: str | Path, *, respect_gitignore: bool = True, extra_ignore: Iterable[str] = (),
               include_build: bool = False, include_hidden_state: bool = False) -> Iterator[tuple[str, Path]]:
    """Renvoie (chemin relatif posix, chemin absolu), dans un ordre déterministe."""
    root = Path(root)
    skip_dirs = set(IGNORED_DIRS)
    if include_hidden_state:
        skip_dirs.discard(".velora")
    if not include_build:
        skip_dirs |= BUILD_DIRS
    base_rules = parse_ignore_lines(extra_ignore)
    rules_by_dir: dict[str, list[_Rule]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        parent = rel_dir.rsplit("/", 1)[0] if "/" in rel_dir else ""
        rules = list(rules_by_dir.get(parent, base_rules)) if rel_dir else list(base_rules)
        if respect_gitignore and ".gitignore" in filenames:
            rules += _read_gitignore(Path(dirpath) / ".gitignore", rel_dir)
        rules_by_dir[rel_dir] = rules

        kept = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if d in skip_dirs or os.path.islink(os.path.join(dirpath, d)):
                continue
            if is_ignored(rel, True, rules):
                continue
            kept.append(d)
        dirnames[:] = kept

        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if full.is_symlink() or not full.is_file():
                continue
            if is_ignored(rel, False, rules):
                continue
            yield rel, full


def hash_file(path: str | Path, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_binary_bytes(data: bytes) -> bool:
    return b"\0" in data[:8192]


def read_text(path: str | Path, limit: int = READ_LIMIT) -> str | None:
    """Contenu texte du fichier, ou None s'il est binaire ou trop volumineux."""
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    return decode_text(data)


def decode_text(data: bytes) -> str | None:
    if is_binary_bytes(data):
        return None
    return data.decode("utf-8", errors="replace")
