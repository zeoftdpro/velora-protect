"""Inventaire des dépendances (lockfiles) et recherche de vulnérabilités connues via OSV.dev.

OSV.dev (Google, gratuit, sans clé) agrège les avis GitHub (GHSA), PyPA, RustSec, Go, npm…
"""

from __future__ import annotations

import json
import math
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from velora.core import net
from velora.scan.models import Finding

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
MAX_VULN_DETAILS = 400


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    file: str
    approximate: bool = False   # version déduite d'une plage (^1.2.0) faute de lockfile


# --------------------------------------------------------------------------- parseurs

def _parse_requirements(text: str, rel: str) -> tuple[list[Dependency], list[str]]:
    deps, unpinned = [], []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!_\-]+)", line)
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "PyPI", rel))
        else:
            name = re.match(r"[A-Za-z0-9][A-Za-z0-9._\-]*", line)
            if name:
                unpinned.append(name.group(0))
    return deps, unpinned


def _parse_package_lock(text: str, rel: str) -> list[Dependency]:
    data = json.loads(text)
    deps = []
    if "packages" in data:
        for key, info in data["packages"].items():
            if not key or info.get("link") or "version" not in info:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            deps.append(Dependency(name, info["version"], "npm", rel))
    else:
        def walk(tree: dict) -> None:
            for name, info in (tree or {}).items():
                if "version" in info and not str(info["version"]).startswith(("file:", "git", "http")):
                    deps.append(Dependency(name, info["version"], "npm", rel))
                walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return deps


def _parse_yarn_lock(text: str, rel: str) -> list[Dependency]:
    deps, current = [], None
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            spec = line.rstrip(":").split(",")[0].strip().strip('"')
            current = spec.rsplit("@", 1)[0] if spec.count("@") >= 1 and not spec.startswith("__") else None
        elif current:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            if m:
                deps.append(Dependency(current, m.group(1), "npm", rel))
                current = None
    return deps


def _parse_package_json(text: str, rel: str) -> list[Dependency]:
    data = json.loads(text)
    deps = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            m = re.match(r"^[\^~>=v\s]*(\d+\.\d+\.\d+[\w.\-+]*)", str(spec))
            if m:
                deps.append(Dependency(name, m.group(1), "npm", rel, approximate=True))
    return deps


def _parse_pipfile_lock(text: str, rel: str) -> list[Dependency]:
    data = json.loads(text)
    deps = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = str(info.get("version", "")).lstrip("=")
            if version:
                deps.append(Dependency(name, version, "PyPI", rel))
    return deps


def _parse_toml_packages(text: str, rel: str, ecosystem: str) -> list[Dependency]:
    """poetry.lock, uv.lock, Cargo.lock : blocs [[package]] name = "…" / version = "…"."""
    deps = []
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if name and version:
            deps.append(Dependency(name.group(1), version.group(1), ecosystem, rel))
    return deps


def _parse_composer_lock(text: str, rel: str) -> list[Dependency]:
    data = json.loads(text)
    return [Dependency(p["name"], str(p["version"]).lstrip("v"), "Packagist", rel)
            for section in ("packages", "packages-dev") for p in (data.get(section) or [])
            if p.get("name") and p.get("version") and not str(p["version"]).startswith("dev-")]


def _parse_go_mod(text: str, rel: str) -> list[Dependency]:
    deps, in_block = [], False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"(?:require\s+)?(\S+)\s+(v\d[\w.\-+]*)$", line) if (in_block or line.startswith("require ")) else None
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "Go", rel))
    return deps


def _parse_gemfile_lock(text: str, rel: str) -> list[Dependency]:
    deps, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)\s]+)\)$", line) if in_specs else None
        if m:
            deps.append(Dependency(m.group(1), m.group(2).split("-")[0], "RubyGems", rel))
    return deps


LOCKFILES = {
    "package-lock.json": _parse_package_lock,
    "npm-shrinkwrap.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "Pipfile.lock": _parse_pipfile_lock,
    "poetry.lock": lambda t, r: _parse_toml_packages(t, r, "PyPI"),
    "uv.lock": lambda t, r: _parse_toml_packages(t, r, "PyPI"),
    "Cargo.lock": lambda t, r: _parse_toml_packages(t, r, "crates.io"),
    "composer.lock": _parse_composer_lock,
    "go.mod": _parse_go_mod,
    "Gemfile.lock": _parse_gemfile_lock,
}


def collect(files: list[tuple[str, Path, str]]) -> tuple[list[Dependency], list[Finding]]:
    """files : liste (chemin relatif, chemin absolu, texte). Renvoie dépendances + constats annexes."""
    deps: list[Dependency] = []
    notes: list[Finding] = []
    by_dir: dict[str, set[str]] = {}
    for rel, _, _ in files:
        d, _, name = rel.rpartition("/")
        by_dir.setdefault(d, set()).add(name)

    for rel, _, text in files:
        directory, _, name = rel.rpartition("/")
        try:
            if name in LOCKFILES:
                deps += LOCKFILES[name](text, rel)
            elif re.fullmatch(r"requirements[\w\-.]*\.txt", name):
                found, unpinned = _parse_requirements(text, rel)
                deps += found
                if unpinned:
                    notes.append(Finding(
                        "dependency", "unpinned-deps", "Dépendances Python non épinglées", "low", rel,
                        detail=f"{len(unpinned)} paquet(s) sans version exacte : {', '.join(unpinned[:8])}"
                               + ("…" if len(unpinned) > 8 else ""),
                        fix="Épinglez les versions (pip freeze, pip-tools, uv lock) pour des builds reproductibles "
                            "et un audit de vulnérabilités fiable."))
            elif name == "package.json":
                siblings = by_dir.get(directory, set())
                if not siblings & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb"}:
                    deps += _parse_package_json(text, rel)
                    notes.append(Finding(
                        "dependency", "no-lockfile", "Projet npm sans lockfile", "low", rel,
                        detail="Versions déduites des plages de package.json : l'audit est approximatif.",
                        fix="Commitez package-lock.json (npm install) ou yarn.lock."))
        except (ValueError, KeyError, TypeError, AttributeError):
            notes.append(Finding("dependency", "unreadable-lockfile", "Fichier de dépendances illisible",
                                 "info", rel, fix="Vérifiez que le fichier n'est pas corrompu."))
    return deps, notes


# --------------------------------------------------------------------------- sévérité

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_score(vector: str) -> float | None:
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS3["CIA"][m["C"]]) * (1 - _CVSS3["CIA"][m["I"]]) * (1 - _CVSS3["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = min((1.08 if changed else 1) * (impact + expl), 10)
    return math.ceil(raw * 10 - 1e-9) / 10


def vuln_severity(vuln: dict) -> str:
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    mapping = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
    if label in mapping:
        return mapping[label]
    for sev in vuln.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            score = cvss3_score(sev.get("score", ""))
            if score is not None:
                return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return "medium"


def fixed_versions(vuln: dict, dep: Dependency) -> list[str]:
    out = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name", "").lower() != dep.name.lower():
            continue
        for rng in aff.get("ranges") or []:
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(out))


# --------------------------------------------------------------------------- OSV

def query_osv(deps: list[Dependency], timeout: float = 30) -> list[Finding]:
    unique: dict[tuple, Dependency] = {}
    for d in deps:
        unique.setdefault((d.ecosystem, d.name.lower(), d.version), d)
    items = list(unique.values())
    hits: list[tuple[Dependency, list[str]]] = []
    for start in range(0, len(items), 500):
        chunk = items[start:start + 500]
        payload = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                               for d in chunk]}
        response = net.post_json(OSV_BATCH_URL, payload, timeout=timeout)
        for dep, result in zip(chunk, response.get("results", [])):
            ids = [v["id"] for v in (result or {}).get("vulns", [])]
            if ids:
                hits.append((dep, ids))

    all_ids = sorted({i for _, ids in hits for i in ids})[:MAX_VULN_DETAILS]

    def fetch(vid: str) -> tuple[str, dict]:
        try:
            return vid, net.get_json(OSV_VULN_URL.format(vid), timeout=timeout)
        except (net.NetworkError, ValueError):
            return vid, {"id": vid}

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            details = dict(pool.map(fetch, all_ids))
    except RuntimeError:  # environnement sans threads (navigateur via Pyodide)
        details = dict(map(fetch, all_ids))

    findings = []
    for dep, ids in hits:
        kept: list[dict] = []
        # Une même faille a souvent plusieurs identifiants (GHSA, PYSEC, CVE) : on dédoublonne.
        for vid in sorted(ids, key=lambda i: (not i.startswith("GHSA"), i)):
            vuln = details.get(vid, {"id": vid})
            names = {vid, *(vuln.get("aliases") or [])}
            if any(names & {k["id"], *(k.get("aliases") or [])} for k in kept):
                continue
            kept.append(vuln)
        for vuln in kept:
            fixes = fixed_versions(vuln, dep)
            cves = [a for a in vuln.get("aliases") or [] if a.startswith("CVE-")]
            ident = vuln["id"] + (f" / {cves[0]}" if cves else "")
            findings.append(Finding(
                category="dependency", rule="vulnerable-dependency",
                title=f"{dep.name} {dep.version} ({dep.ecosystem}) — {ident}",
                severity=vuln_severity(vuln), file=dep.file,
                detail=(vuln.get("summary") or vuln.get("details", "")[:200] or "Vulnérabilité connue")
                       + (" [version approximative]" if dep.approximate else ""),
                fix=(f"Mettre à jour vers {' ou '.join(fixes[-3:])} ou plus récent." if fixes
                     else "Aucun correctif publié : envisagez une alternative ou des mesures d'atténuation.")
                    + f" Détails : https://osv.dev/vulnerability/{vuln['id']}",
            ))
    return findings
