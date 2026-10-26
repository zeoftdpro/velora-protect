"""Audit d'exposition : ce que votre application livre réellement au client (navigateur, mobile).

Tout ce qui est envoyé au client peut être lu, copié et modifié — l'obfuscation ne fait que
ralentir. Cet audit repère ce qui facilite le plus la copie ou la fuite : source maps publiées,
secrets dans les bundles, configuration de build trop bavarde.
"""

from __future__ import annotations

import re
from pathlib import Path

from velora.core import files as fs
from velora.scan import secrets
from velora.scan.models import Finding, sort_findings

PUBLIC_DIRS = {"dist", "build", "out", "public", "static", "www", "_site", ".output", "wwwroot", "htdocs"}
CLIENT_EXTS = (".js", ".mjs", ".cjs", ".css", ".html", ".htm", ".json", ".map", ".txt", ".xml", ".wasm")


def _in_public(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in PUBLIC_DIRS for p in parts[:-1]) or rel.startswith(".next/static/")


def audit(root: Path) -> tuple[list[Finding], list[str]]:
    root = Path(root)
    findings: list[Finding] = []
    stack = _detect_stack(root)
    map_files = []

    for rel, path in fs.iter_files(root, respect_gitignore=False, include_build=True):
        lower = rel.lower()
        name = lower.rsplit("/", 1)[-1]
        if lower.endswith((".js", ".ts", ".mjs", ".cjs")) and re.match(r"(vite|next|webpack|nuxt|rollup|astro)\.config\.", name):
            findings += _check_bundler_config(rel, fs.read_text(path) or "")
            continue
        if not _in_public(rel):
            continue
        if lower.endswith(".map"):
            map_files.append(rel)
            continue
        if name.startswith(".env") or name in {".htpasswd", ".npmrc"}:
            findings.append(Finding("exposure", "public-secret-file", "Fichier sensible dans un dossier publié", "high",
                                    rel, fix="Retirez-le du dossier publié : il est téléchargeable par n'importe qui."))
            continue
        if lower.endswith(CLIENT_EXTS) and not lower.endswith(".wasm"):
            text = fs.read_text(path)
            if not text:
                continue
            for f in secrets.scan_text(text, rel):
                f.category = "exposure"
                f.title = f"{f.title} livré au client"
                f.severity = "critical" if f.severity in ("critical", "high") else "high"
                f.fix = ("Ce secret est lisible par tout visiteur. Révoquez-le et déplacez l'appel qui l'utilise "
                         "côté serveur (API route, fonction serverless, backend).")
                findings.append(f)

    if map_files:
        findings.append(Finding(
            "exposure", "source-maps", f"{len(map_files)} source map(s) dans les fichiers publiés", "medium",
            map_files[0], detail="Les source maps permettent de reconstituer votre code source original, "
                                 "commentaires compris." + (f" Autres : {', '.join(map_files[1:4])}…" if len(map_files) > 1 else ""),
            fix="Désactivez-les en production (Vite : build.sourcemap=false ; webpack : devtool=false ; "
                "Next.js : productionBrowserSourceMaps=false) ou envoyez-les uniquement à votre outil de suivi "
                "d'erreurs (Sentry) sans les publier."))
    return sort_findings(findings), _recommendations(stack)


def _check_bundler_config(rel: str, text: str) -> list[Finding]:
    out = []
    if re.search(r"sourcemap\s*:\s*(true|['\"](?!hidden)[\w-]+['\"])", text) or \
            re.search(r"productionBrowserSourceMaps\s*:\s*true", text) or \
            re.search(r"devtool\s*:\s*['\"](?!hidden|nosources)[\w-]*source-map['\"]", text):
        out.append(Finding("exposure", "sourcemap-config", "Source maps activées dans la configuration de build",
                           "medium", rel, fix="Utilisez « hidden » ou désactivez-les pour le build de production."))
    return out


def _detect_stack(root: Path) -> set[str]:
    stack = set()
    if (root / "package.json").exists():
        stack.add("js")
    if any((root / f).exists() for f in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")):
        stack.add("python")
    if any((root / p).exists() for p in ("android", "build.gradle", "build.gradle.kts", "app/build.gradle")):
        stack.add("android")
    if (root / "pubspec.yaml").exists():
        stack.add("flutter")
    if list(root.glob("*.csproj"))[:1]:
        stack.add("dotnet")
    return stack


def _recommendations(stack: set[str]) -> list[str]:
    recs = [
        "Principe n°1 : la logique qui a de la valeur (algorithmes, règles métier, prix, IA, accès aux données) "
        "doit s'exécuter sur votre serveur ; le client n'affiche que le résultat.",
        "Exposez une API authentifiée avec limitation de débit (rate limiting) pour empêcher l'aspiration massive.",
        "Licence : générez un LICENSE propriétaire (velora protect license) et des en-têtes de copyright "
        "(velora protect headers) — vos droits sont affirmés clairement et aucune licence ne peut être présumée.",
        "Preuve : horodatez régulièrement votre code (velora proof create --archive) et enregistrez vos "
        "empreintes (velora protect fingerprint) pour pouvoir démontrer une copie plus tard.",
    ]
    if "js" in stack:
        recs.append("JavaScript : minifiez (Terser/esbuild) et, si besoin, obfusquez le code sensible restant côté "
                    "client avec javascript-obfuscator (impact sur les performances : ciblez les modules critiques).")
    if "python" in stack:
        recs.append("Python distribué : PyArmor (obfuscation + licence liée à la machine) ou Nuitka (compilation "
                    "en binaire natif) ; ne livrez jamais les .py en clair.")
    if "android" in stack:
        recs.append("Android : activez R8/ProGuard (minifyEnabled true) et Play Integrity pour détecter les APK modifiés.")
    if "flutter" in stack:
        recs.append("Flutter : compilez avec --obfuscate --split-debug-info.")
    if "dotnet" in stack:
        recs.append(".NET : utilisez un obfuscateur (ConfuserEx, Obfuscar) ou Native AOT.")
    recs.append("Contrôle de licence côté client : utile contre l'usage non payé, jamais inviolable — vérifiez "
                "toujours les droits côté serveur.")
    return recs
