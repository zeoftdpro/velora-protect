"""Détection de copie par empreintes de code (« winnowing », l'algorithme de MOSS / Stanford).

Le code est réduit à une suite de jetons (commentaires et mise en forme ignorés), découpée en
k-grammes hachés ; on retient un sous-ensemble représentatif de ces hachages. Deux bases de code
qui partagent un passage d'au moins k + w − 1 jetons partagent forcément une empreinte.

Deux modes sont calculés :
  - strict : identifiants conservés → peu de faux positifs, robuste au reformatage ;
  - flou   : identifiants, chaînes et nombres normalisés → résiste au renommage de variables
             et à la minification, mais plus sensible au code « passe-partout ».
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from velora.core import files as fs
from velora.core import history
from velora.core.config import Project

K = 25          # longueur d'un k-gramme, en jetons
WINDOW = 8      # taille de la fenêtre de sélection
DB_FILE = "fingerprints.json"

CODE_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".java", ".kt", ".scala",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".dart", ".php", ".rb", ".lua",
    ".sql", ".sh", ".ps1", ".css", ".scss", ".html",
)
HASH_COMMENT_EXTS = (".py", ".rb", ".sh", ".ps1")

KEYWORDS = set("""
if else elif for while do return def class function const let var import from export default new try
catch except finally raise throw public private protected static void int float double bool boolean
string char long short struct enum interface extends implements package func go defer select case
switch break continue yield async await lambda with as in is not and or None null nil true false True
False self this super fn impl trait pub mut use mod match where type typeof instanceof delete static
final abstract override virtual namespace using template typename sizeof goto echo foreach end begin
""".split())

_STRING = r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`"
_TOKEN_SLASH = re.compile(r"(?P<c>/\*.*?\*/|//[^\n]*)|(?P<s>%s)|(?P<i>[A-Za-z_$][\w$]*)|(?P<n>\d[\w.]*)|(?P<p>\S)"
                          % _STRING, re.S)
_TOKEN_HASH = re.compile(r"(?P<c>#[^\n]*)|(?P<s>\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|%s)|(?P<i>[A-Za-z_$][\w$]*)|(?P<n>\d[\w.]*)|(?P<p>\S)"
                         % _STRING, re.S)


@dataclass
class Fingerprints:
    strict: dict[int, int]   # hachage → ligne
    fuzzy: dict[int, int]


def tokenize(text: str, rel: str) -> list[tuple[str, str, int]]:
    """Renvoie (jeton strict, jeton flou, position)."""
    regex = _TOKEN_HASH if rel.lower().endswith(HASH_COMMENT_EXTS) else _TOKEN_SLASH
    out = []
    for m in regex.finditer(text):
        kind = m.lastgroup
        if kind == "c":
            continue
        tok = m.group(0)
        if kind == "i":
            fuzzy = tok if tok in KEYWORDS else "I"
        elif kind == "s":
            fuzzy = "S"
        elif kind == "n":
            fuzzy = "N"
        else:
            fuzzy = tok
        out.append((tok, fuzzy, m.start()))
    return out


def _hash(tokens: list[str]) -> int:
    return int.from_bytes(hashlib.blake2b("\x1f".join(tokens).encode("utf-8"), digest_size=8).digest(), "big")


def winnow(hashes: list[int], window: int = WINDOW) -> list[int]:
    """Indices retenus : le minimum (le plus à droite) de chaque fenêtre."""
    if not hashes:
        return []
    if len(hashes) <= window:
        return [min(range(len(hashes)), key=lambda i: (hashes[i], -i))]
    selected, last = [], -1
    for start in range(len(hashes) - window + 1):
        best = start
        for i in range(start, start + window):
            if hashes[i] <= hashes[best]:
                best = i
        if best != last:
            selected.append(best)
            last = best
    return selected


def fingerprint_text(text: str, rel: str, k: int = K) -> Fingerprints:
    tokens = tokenize(text, rel)
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
    result = {}
    for mode, idx in (("strict", 0), ("fuzzy", 1)):
        seq = [t[idx] for t in tokens]
        if len(seq) < k:
            result[mode] = {}
            continue
        hashes = [_hash(seq[i:i + k]) for i in range(len(seq) - k + 1)]
        result[mode] = {hashes[i]: bisect.bisect_right(line_starts, tokens[i][2]) for i in winnow(hashes)}
    return Fingerprints(result["strict"], result["fuzzy"])


def fingerprint_tree(root: Path, extra_ignore=(), respect_gitignore: bool = True,
                     include_build: bool = False) -> dict[str, Fingerprints]:
    out = {}
    for rel, path in fs.iter_files(root, extra_ignore=extra_ignore, respect_gitignore=respect_gitignore,
                                   include_build=include_build):
        if not rel.lower().endswith(CODE_EXTENSIONS):
            continue
        text = fs.read_text(path)
        if text:
            fp = fingerprint_text(text, rel)
            if fp.strict or fp.fuzzy:
                out[rel] = fp
    return out


def save_db(project: Project) -> dict:
    tree = fingerprint_tree(project.root, project.config.get("ignore", []))
    data = {"version": 1, "k": K, "window": WINDOW, "created": history.now_iso(),
            "files": {rel: {"strict": sorted(fp.strict), "fuzzy": sorted(fp.fuzzy)} for rel, fp in tree.items()}}
    project.ensure_state()
    with open(project.path(DB_FILE), "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    return {"files": len(tree), "fingerprints": sum(len(fp.strict) for fp in tree.values()), "created": data["created"]}


def load_reference(project: Project, use_db: bool = True) -> tuple[dict[str, dict[str, set[int]]], str]:
    path = project.path(DB_FILE)
    if use_db and path.exists():
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return ({rel: {"strict": set(v["strict"]), "fuzzy": set(v["fuzzy"])} for rel, v in data["files"].items()},
                f"base d'empreintes du {data['created']}")
    tree = fingerprint_tree(project.root, project.config.get("ignore", []))
    return ({rel: {"strict": set(fp.strict), "fuzzy": set(fp.fuzzy)} for rel, fp in tree.items()},
            "code actuel du projet")


def compare(project: Project, suspect: Path, threshold: float = 0.15, use_db: bool = True) -> dict:
    """Compare un code suspect (dossier ou fichier) au projet de référence."""
    reference, source = load_reference(project, use_db)
    index: dict[str, dict[int, set[str]]] = {"strict": {}, "fuzzy": {}}
    for rel, modes in reference.items():
        for mode, hashes in modes.items():
            for h in hashes:
                index[mode].setdefault(h, set()).add(rel)

    suspect = Path(suspect)
    if suspect.is_file():
        text = fs.read_text(suspect) or ""
        suspects = {suspect.name: fingerprint_text(text, suspect.name)}
    else:
        # Un code suspect est souvent un build ou un dépôt sans .gitignore pertinent : on regarde tout.
        suspects = fingerprint_tree(suspect, respect_gitignore=False, include_build=True)

    matches = []
    totals = {"strict": [0, 0], "fuzzy": [0, 0]}
    matched_ref = {"strict": set(), "fuzzy": set()}
    for rel, fp in suspects.items():
        row = {"file": rel}
        for mode in ("strict", "fuzzy"):
            hashes = getattr(fp, mode)
            hit = [h for h in hashes if h in index[mode]]
            totals[mode][0] += len(hit)
            totals[mode][1] += len(hashes)
            matched_ref[mode].update(hit)
            row[mode] = len(hit) / len(hashes) if hashes else 0.0
            if mode == "strict" or "sources" not in row:
                counts: dict[str, int] = {}
                for h in hit:
                    for ref in index[mode][h]:
                        counts[ref] = counts.get(ref, 0) + 1
                if counts:
                    row["sources"] = [r for r, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:3]]
                    row["lines"] = sorted({hashes[h] for h in hit})[:10]
        if max(row["strict"], row["fuzzy"]) >= threshold:
            matches.append(row)

    ref_total = {m: len({h for modes in reference.values() for h in modes[m]}) for m in ("strict", "fuzzy")}
    return {
        "reference": source,
        "reference_files": len(reference),
        "suspect_files": len(suspects),
        "suspect_similarity": {m: (totals[m][0] / totals[m][1] if totals[m][1] else 0.0) for m in totals},
        "reference_coverage": {m: (len(matched_ref[m]) / ref_total[m] if ref_total[m] else 0.0) for m in totals},
        "matches": sorted(matches, key=lambda r: -max(r["strict"], r["fuzzy"])),
    }
