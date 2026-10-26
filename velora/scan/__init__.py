"""Scan de sécurité : secrets, dépendances vulnérables, mauvaises configurations."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from velora.core import files as fs
from velora.core import gitutil, history
from velora.core.config import Project
from velora.core.net import NetworkError
from velora.scan import confidence, deps, malware, misconfig, mobile, secrets, web
from velora.scan.models import Finding, security_score, sort_findings

LAST_SCAN_FILE = "last_scan.json"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    dependencies: int = 0
    network_checked: bool = False
    warnings: list[str] = field(default_factory=list)
    duration: float = 0.0
    stack: list[str] = field(default_factory=list)
    confidence: dict | None = None

    @property
    def score(self) -> int:
        return security_score(self.findings)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "score": self.score, "counts": self.counts(), "files_scanned": self.files_scanned,
            "dependencies": self.dependencies, "network_checked": self.network_checked,
            "warnings": self.warnings, "duration": round(self.duration, 2), "stack": self.stack,
            "confidence": self.confidence,
            "findings": [f.to_dict() for f in self.findings],
        }


def run_scan(project: Project, *, network: bool | None = None, staged: bool = False,
             save: bool = True) -> ScanResult:
    started = time.time()
    cfg = project.config["scan"]
    network = cfg.get("network", True) if network is None else network
    result = ScanResult()

    if staged:
        # Mode hook pre-commit : uniquement le contenu indexé (ce qui va réellement être commité).
        texts = []
        for rel in gitutil.staged_files(project.root):
            data = gitutil.staged_content(project.root, rel)
            text = fs.decode_text(data) if data is not None and len(data) <= fs.READ_LIMIT else None
            if text is not None:
                texts.append((rel, project.root / rel, text))
        result.findings += [f for rel, _, text in texts for f in secrets.scan_text(text, rel)]
        result.files_scanned = len(texts)
    else:
        extra = list(project.config.get("ignore", [])) + list(cfg.get("allow_paths", []))
        listed = list(fs.iter_files(project.root, extra_ignore=extra))
        texts = []
        for rel, path in listed:
            text = fs.read_text(path)
            if text is not None:
                texts.append((rel, path, text))
        result.files_scanned = len(listed)

        all_files = [rel for rel, _ in listed]
        for rel, _, text in texts:
            result.findings += secrets.scan_text(text, rel)
            result.findings += misconfig.check_file(rel, text)
            result.findings += web.check_file(rel, text)
            result.findings += mobile.check_file(rel, text)
            result.findings += malware.check_file(rel, text)
        result.findings += misconfig.check_repository(project.root, all_files)
        result.stack = web.detect_stack(texts, all_files)
        result.findings += web.check_project(texts, result.stack)
        result.findings += mobile.check_project(all_files, result.stack)
        result.findings += malware.check_project(all_files)

        dependencies, notes = deps.collect(texts)
        result.dependencies = len(dependencies)
        result.findings += notes
        if dependencies and network:
            try:
                result.findings += deps.query_osv(dependencies)
                result.network_checked = True
            except (NetworkError, ValueError) as e:
                result.warnings.append(f"Base de vulnérabilités OSV injoignable ({e}) : dépendances non vérifiées.")
        elif dependencies:
            result.warnings.append("Mode hors-ligne : vulnérabilités des dépendances non vérifiées.")
        manifests = [t for t in texts if t[0].rsplit("/", 1)[-1] in ("package.json", "composer.json")
                     or t[0].rsplit("/", 1)[-1].startswith("requirements")]
        result.confidence = confidence.compute(all_files, len(texts), result.dependencies, result.network_checked,
                                               declared=len(web._declared_deps(manifests)))

    result.findings = sort_findings(result.findings)
    result.duration = time.time() - started

    if save and not staged:
        project.ensure_state()
        with open(project.path(LAST_SCAN_FILE), "w", encoding="utf-8") as f:
            json.dump({"time": history.now_iso(), **result.to_dict()}, f, indent=2, ensure_ascii=False)
        history.record(project, "scan", score=result.score, counts=result.counts(),
                       files=result.files_scanned, dependencies=result.dependencies)
    return result


def last_scan(project: Project) -> dict | None:
    path = project.path(LAST_SCAN_FILE)
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def scan_uploaded(root, *, network: bool = True, blocked=()) -> dict:
    """Analyse complète d'un projet reçu (dossier temporaire) : rien n'est écrit dans le projet.

    La configuration éventuellement présente dans l'envoi est ignorée : elle pourrait masquer des constats.
    """
    import copy

    from velora.core.config import DEFAULT_CONFIG
    from velora.protect import exposure
    from velora.scan import hardening

    project = Project(root)
    project.config = copy.deepcopy(DEFAULT_CONFIG)
    result = run_scan(project, network=network, save=False)
    exposed, recommendations = exposure.audit(project.root)
    # Un secret dans un dossier publié est signalé une seule fois, avec la gravité « exposition ».
    exposed_at = {(f.file, f.line) for f in exposed}
    # Le dossier .git n'est jamais envoyé : « projet hors gestion de versions » serait toujours faux.
    if blocked:
        exposed.append(Finding(
            "malware", "antivirus-blocked", f"{len(blocked)} fichier(s) bloqué(s) par l'antivirus de cet ordinateur",
            "critical", blocked[0], detail=("Autres : " + ", ".join(blocked[1:6])) if len(blocked) > 1 else "",
            fix="L'antivirus a reconnu du code malveillant connu et a refusé ces fichiers : ils n'ont pas pu être "
                "analysés ici. Ne les déployez pas, identifiez leur origine et faites-les vérifier (virustotal.com)."))
    result.findings = sort_findings([f for f in result.findings
                                     if (f.file, f.line) not in exposed_at and f.rule != "no-vcs"] + exposed)
    return {**result.to_dict(), "recommendations": recommendations,
            "hardening": hardening.suggest(stack=result.stack)}
