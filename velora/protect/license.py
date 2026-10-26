"""Fichier LICENSE et en-têtes de copyright dans les sources."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from velora import VeloraError
from velora.core import files as fs
from velora.core.config import Project

PROPRIETARY = """\
Copyright (c) {year} {author}. Tous droits réservés.

Le présent logiciel, y compris son code source, son code objet, sa documentation, son
architecture et ses éléments graphiques, est la propriété exclusive de {author}.

Toute reproduction, représentation, modification, adaptation, traduction, décompilation,
distribution ou exploitation, totale ou partielle, par quelque procédé que ce soit et sur
quelque support que ce soit, sans l'autorisation écrite et préalable de {author}, est
strictement interdite. Aucune licence, expresse ou implicite, n'est concédée par la mise à
disposition de ce logiciel.

Toute utilisation non autorisée constitue une contrefaçon sanctionnée notamment par les
articles L.122-4, L.122-6 et L.335-2 et suivants du Code de la propriété intellectuelle.

Pour toute demande d'autorisation : {contact}

--------------------------------------------------------------------------------------------

Copyright (c) {year} {author}. All rights reserved.

This software, including its source code, object code, documentation and design, is the
exclusive property of {author}. Any reproduction, modification, distribution, reverse
engineering or use, in whole or in part, without the prior written permission of {author}
is strictly prohibited. No license, express or implied, is granted.
"""

MIT = """\
MIT License

Copyright (c) {year} {author}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

TEMPLATES = {"proprietary": (PROPRIETARY, "LicenseRef-Proprietary"), "mit": (MIT, "MIT")}

LINE_COMMENT = {
    "#": (".py", ".rb", ".sh", ".bash", ".zsh", ".ps1", ".pl", ".r", ".yml", ".yaml", ".toml", ".ex", ".exs"),
    "//": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".scala", ".go", ".rs",
           ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".dart", ".php", ".scss", ".less", ".groovy"),
    "--": (".sql", ".lua", ".hs"),
}
BLOCK_COMMENT = {(".css",): ("/*", "*/"), (".html", ".htm", ".vue", ".svelte", ".xml"): ("<!--", "-->")}
SKIP_SUFFIXES = (".min.js", ".min.css", ".d.ts")


def write_license(project: Project, kind: str, author: str, contact: str = "", overwrite: bool = False) -> Path:
    if kind not in TEMPLATES:
        raise VeloraError(f"Licence inconnue « {kind} » (choix : {', '.join(TEMPLATES)})")
    if not author:
        raise VeloraError("Indiquez l'auteur : --author \"Votre nom\" ou velora config set author \"…\"")
    target = project.root / "LICENSE"
    if target.exists() and not overwrite:
        raise VeloraError("Un fichier LICENSE existe déjà (utilisez --force pour le remplacer).")
    text = TEMPLATES[kind][0].format(year=date.today().year, author=author, contact=contact or author)
    target.write_text(text, encoding="utf-8")
    return target


def _comment_style(rel: str):
    lower = rel.lower()
    if lower.endswith(SKIP_SUFFIXES):
        return None
    for prefix, exts in LINE_COMMENT.items():
        if lower.endswith(exts):
            return ("line", prefix, "")
    for exts, (start, end) in BLOCK_COMMENT.items():
        if lower.endswith(exts):
            return ("block", start, end)
    return None


def header_lines(author: str, kind: str) -> list[str]:
    spdx = TEMPLATES.get(kind, TEMPLATES["proprietary"])[1]
    rights = "Tous droits réservés. Voir LICENSE." if kind == "proprietary" else "Voir LICENSE."
    return [f"Copyright (c) {date.today().year} {author}. {rights}", f"SPDX-License-Identifier: {spdx}"]


def add_header(text: str, rel: str, lines: list[str]) -> str | None:
    """Renvoie le texte avec en-tête, ou None si le fichier est déjà couvert / non supporté."""
    style = _comment_style(rel)
    if style is None or not text.strip():
        return None
    head = "\n".join(text.splitlines()[:15]).lower()
    if "copyright" in head or "spdx-license-identifier" in head:
        return None
    kind, start, end = style
    block = "\n".join(f"{start} {line}" for line in lines) if kind == "line" else \
        f"{start}\n" + "\n".join(f"  {line}" for line in lines) + f"\n{end}"
    newline = "\r\n" if "\r\n" in text else "\n"
    block = block.replace("\n", newline) + newline

    keep = []
    rest = text
    # Préserver shebang, déclaration d'encodage Python, balise <?php, doctype/xml.
    for _ in range(2):
        first, sep, remainder = rest.partition("\n")
        stripped = first.strip()
        if (stripped.startswith("#!") or ("coding" in stripped and stripped.startswith("#"))
                or stripped.startswith("<?php") or stripped.lower().startswith(("<!doctype", "<?xml"))):
            keep.append(first + sep)
            rest = remainder
        else:
            break
    if keep and rel.lower().endswith(".php"):
        return "".join(keep) + block + rest
    return "".join(keep) + block + (newline if rest and not rest.startswith(("\n", "\r\n")) else "") + rest


def apply_headers(project: Project, author: str, kind: str = "proprietary", dry_run: bool = False) -> list[str]:
    if not author:
        raise VeloraError("Indiquez l'auteur : --author \"Votre nom\" ou velora config set author \"…\"")
    lines = header_lines(author, kind)
    changed = []
    for rel, path in fs.iter_files(project.root, extra_ignore=project.config.get("ignore", [])):
        text = fs.read_text(path)
        if text is None:
            continue
        new = add_header(text, rel, lines)
        if new is None:
            continue
        changed.append(rel)
        if not dry_run:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(new)
    return changed
