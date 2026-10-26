"""Indice de confiance /100 : à quel point le score de sécurité du code est fiable.

Il mesure ce que l'analyse a réellement pu couvrir : langages pris en charge par des règles,
dépendances vérifiées dans la base OSV.dev (et avec quelle précision), fichiers lisibles.
Plafonné à 95 : une analyse automatique ne peut jamais garantir l'absence de faille.
"""

from __future__ import annotations

from velora.scan import misconfig, mobile, web

MAX_SCORE = 95

# Langages couverts par des règles dédiées (en plus de la recherche de secrets, faite partout).
SUPPORTED = set(web.JS + web.PHP + web.PY + web.CPP + web.JVM + web.CS + web.GO + web.RB + web.MARKUP
                + mobile.MOBILE_CODE) | {ext for rule in misconfig.CODE_RULES for ext in rule[3]}
# Langages reconnus mais sans règles propres : seuls les secrets y sont recherchés.
UNSUPPORTED = {".rs": "Rust", ".lua": "Lua", ".pl": "Perl", ".pm": "Perl", ".ex": "Elixir", ".exs": "Elixir",
               ".erl": "Erlang", ".hs": "Haskell", ".clj": "Clojure", ".r": "R", ".jl": "Julia", ".zig": "Zig",
               ".nim": "Nim", ".cr": "Crystal", ".fs": "F#", ".vb": "Visual Basic", ".sol": "Solidity",
               ".groovy": "Groovy", ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".asm": "Assembleur",
               ".m": "Objective-C/MATLAB", ".elm": "Elm", ".ml": "OCaml"}
for _ext in SUPPORTED:
    UNSUPPORTED.pop(_ext, None)

LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "composer.lock",
             "poetry.lock", "pipfile.lock", "uv.lock", "cargo.lock", "go.sum", "gemfile.lock", "pubspec.lock"}


# Médias et archives : jamais lus, et c'est normal (ils ne contiennent pas de code).
MEDIA = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico", ".psd", ".woff", ".woff2", ".ttf",
         ".otf", ".eot", ".mp3", ".wav", ".ogg", ".mp4", ".webm", ".mov", ".pdf", ".zip", ".gz", ".7z", ".rar"}


def _name(rel: str) -> str:
    return rel.rsplit("/", 1)[-1].lower()


def _ext(rel: str) -> str:
    name = _name(rel)
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def compute(all_files: list[str], read_files: int, dependencies: int, network_checked: bool,
            declared: int = 0) -> dict:
    """declared : dépendances listées dans les manifestes (package.json, composer.json, requirements)."""
    factors = []

    # 1. Couverture des langages (50 points)
    supported = [f for f in all_files if _ext(f) in SUPPORTED]
    unsupported: dict[str, int] = {}
    for f in all_files:
        lang = UNSUPPORTED.get(_ext(f))
        if lang:
            unsupported[lang] = unsupported.get(lang, 0) + 1
    code_total = len(supported) + sum(unsupported.values())
    if code_total == 0:
        factors.append(("Langages analysés", 25, 50, "Aucun fichier de code reconnu : seuls secrets et configuration "
                                                     "ont été vérifiés."))
    else:
        ratio = len(supported) / code_total
        detail = (f"{len(supported)} fichier(s) de code couverts par des règles."
                  + ("" if not unsupported else " Non couverts (secrets uniquement) : "
                     + ", ".join(f"{n} {lang}" for lang, n in sorted(unsupported.items(), key=lambda x: -x[1])) + "."))
        factors.append(("Langages analysés", round(50 * ratio), 50, detail))

    # 2. Dépendances (30 points)
    names = {_name(f) for f in all_files}
    has_lock = bool(names & LOCKFILES) or any(n.startswith("requirements") and n.endswith(".txt") for n in names)
    if not dependencies and not declared:
        factors.append(("Dépendances", 30, 30, "Aucune dépendance déclarée."))
    elif not dependencies:
        factors.append(("Dépendances", 15, 30, f"{declared} dépendance(s) déclarée(s) sans version figée ni fichier de "
                                                "verrouillage : impossible de les vérifier précisément dans OSV.dev."))
    elif not network_checked:
        factors.append(("Dépendances", 5, 30, f"{dependencies} dépendance(s) non vérifiée(s) dans OSV.dev "
                                               "(analyse hors-ligne ou base injoignable)."))
    elif not has_lock:
        factors.append(("Dépendances", 15, 30, "Pas de fichier de verrouillage (package-lock.json, composer.lock, "
                                                "poetry.lock…) : les versions réellement installées sont inconnues, "
                                                "des failles peuvent échapper à l'analyse."))
    else:
        factors.append(("Dépendances", 30, 30, f"{dependencies} dépendance(s) vérifiée(s) dans OSV.dev, versions "
                                                "exactes connues."))

    # 3. Fichiers lisibles (20 points)
    total = len([f for f in all_files if _ext(f) not in MEDIA])
    read_files = min(read_files, total)
    if total == 0:
        factors.append(("Fichiers lus", 0, 20, "Aucun fichier."))
    else:
        unread = total - read_files
        factors.append(("Fichiers lus", round(20 * read_files / total), 20,
                        f"{read_files}/{total} fichiers lus" + (f" ({unread} binaire(s) ou de plus de 2 Mo ignoré(s))."
                                                                 if unread else ".")))

    raw = sum(points for _, points, _, _ in factors)
    score = min(MAX_SCORE, raw)
    level = "élevée" if score >= 80 else "moyenne" if score >= 50 else "faible"
    return {"score": score, "level": level,
            "factors": [{"label": l, "points": p, "max": m, "detail": d} for l, p, m, d in factors],
            "note": "Plafonnée à 95 : une analyse automatique repère des failles connues, elle ne prouve pas leur absence."}
