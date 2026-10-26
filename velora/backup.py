"""Sauvegardes versionnées vers un ou plusieurs stockages externes.

Chaque sauvegarde est une archive ZIP autonome :
    files/…               les fichiers du projet
    git/repo.bundle       tout l'historique git (restaurable avec « git clone repo.bundle »)
    databases/…           dumps des bases configurées
    velora/…              configuration et preuves d'antériorité
    velora-manifest.json  empreinte SHA-256 de chaque fichier (contrôle d'intégrité)

Destinations : n'importe quel dossier (disque externe, NAS « \\\\serveur\\partage », dossier
synchronisé OneDrive/Dropbox/Google Drive) ou un remote rclone (« rclone:monremote:sauvegardes »)
pour S3, Backblaze B2, SFTP, Google Drive…
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from velora import VeloraError
from velora.core import files as fs
from velora.core import gitutil, history, notify
from velora.core.config import Project

MANIFEST_NAME = "velora-manifest.json"
STAMP_FORMAT = "%Y%m%d-%H%M%S"
_STAMP_RE = re.compile(r"_(\d{8}-\d{6})\.zip$")


def safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "-", name).strip("-") or "projet"


# --------------------------------------------------------------------------- destinations

class LocalDestination:
    def __init__(self, base: str, project_name: str):
        self.label = base
        self.dir = Path(os.path.expandvars(os.path.expanduser(base))) / safe_name(project_name)

    def put(self, src: Path, name: str) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / (name + ".part")
        shutil.copyfile(src, tmp)
        os.replace(tmp, self.dir / name)

    def verify(self, name: str, sha256: str) -> bool:
        return fs.hash_file(self.dir / name) == sha256

    def list(self) -> list[str]:
        if not self.dir.exists():
            return []
        return sorted(p.name for p in self.dir.iterdir() if p.is_file() and _STAMP_RE.search(p.name))

    def delete(self, name: str) -> None:
        (self.dir / name).unlink(missing_ok=True)

    def fetch(self, name: str, target: Path) -> Path:
        return self.dir / name


class RcloneDestination:
    def __init__(self, spec: str, project_name: str):
        self.label = spec
        self.remote = spec[len("rclone:"):].rstrip("/") + "/" + safe_name(project_name)
        if not shutil.which("rclone"):
            raise VeloraError("rclone est introuvable : installez-le (https://rclone.org) ou retirez « "
                              f"{spec} » des destinations.")

    def _run(self, *args: str) -> str:
        proc = subprocess.run(["rclone", *args], capture_output=True, text=True, timeout=3600)
        if proc.returncode != 0:
            raise VeloraError(f"rclone {args[0]} a échoué : {proc.stderr.strip()[:300]}")
        return proc.stdout

    def put(self, src: Path, name: str) -> None:
        self._run("copyto", str(src), f"{self.remote}/{name}")

    def verify(self, name: str, sha256: str) -> bool:
        out = self._run("hashsum", "sha256", f"{self.remote}/{name}")
        return out.split()[0].lower() == sha256 if out.strip() else True  # certains backends n'ont pas de hash

    def list(self) -> list[str]:
        try:
            out = self._run("lsf", "--files-only", self.remote)
        except VeloraError:
            return []
        return sorted(n for n in out.splitlines() if _STAMP_RE.search(n))

    def delete(self, name: str) -> None:
        self._run("deletefile", f"{self.remote}/{name}")

    def fetch(self, name: str, target: Path) -> Path:
        self._run("copyto", f"{self.remote}/{name}", str(target / name))
        return target / name


def destination(spec: str, project_name: str):
    return RcloneDestination(spec, project_name) if spec.startswith("rclone:") else LocalDestination(spec, project_name)


# --------------------------------------------------------------------------- rétention

def parse_stamp(name: str) -> datetime | None:
    m = _STAMP_RE.search(name)
    return datetime.strptime(m.group(1), STAMP_FORMAT) if m else None


def select_to_keep(names: list[str], keep_last: int = 10, keep_daily: int = 7,
                   keep_weekly: int = 4, keep_monthly: int = 12) -> set[str]:
    """Politique « grand-père / père / fils » : N dernières + 1 par jour / semaine / mois."""
    dated = sorted(((parse_stamp(n), n) for n in names if parse_stamp(n)), reverse=True)
    keep = {n for _, n in dated[:keep_last]}
    for count, bucket in ((keep_daily, lambda d: d.date()),
                          (keep_weekly, lambda d: d.isocalendar()[:2]),
                          (keep_monthly, lambda d: (d.year, d.month))):
        seen = set()
        for dt, name in dated:
            key = bucket(dt)
            if key not in seen and len(seen) < count:
                seen.add(key)
                keep.add(name)
    return keep


# --------------------------------------------------------------------------- création

@dataclass
class BackupResult:
    status: str              # "ok" | "skipped" | "partial" | "failed"
    archive: str = ""
    size: int = 0
    files: int = 0
    sha256: str = ""
    destinations: dict | None = None
    pruned: int = 0
    message: str = ""


def _collect(project: Project) -> list[tuple[str, Path]]:
    cfg = project.config["backup"]
    return list(fs.iter_files(project.root, respect_gitignore=cfg.get("respect_gitignore", True),
                              extra_ignore=project.config.get("ignore", [])))


def _content_fingerprint(manifest: dict) -> str:
    h = hashlib.sha256()
    for rel in sorted(manifest):
        h.update(f"{rel}\0{manifest[rel]['sha256']}\n".encode())
    return h.hexdigest()


def _dump_databases(project: Project, workdir: Path, log) -> list[tuple[Path, str]]:
    out = []
    for i, db in enumerate(project.config["backup"].get("databases", [])):
        name = safe_name(db.get("name") or f"db{i + 1}")
        try:
            if db.get("type") == "sqlite":
                src = (project.root / db["path"]).resolve()
                if not src.exists():
                    raise VeloraError(f"fichier introuvable : {src}")
                dst = workdir / f"{name}.sqlite3"
                with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as source, sqlite3.connect(dst) as target:
                    source.backup(target)  # copie cohérente même si la base est en cours d'utilisation
                out.append((dst, f"databases/{name}.sqlite3"))
            elif db.get("type") == "command":
                dst = workdir / f"{name}.{db.get('extension', 'dump')}"
                with open(dst, "wb") as f:
                    proc = subprocess.run(db["command"], shell=True, stdout=f, stderr=subprocess.PIPE,  # velora:ignore (commande choisie par l'utilisateur)
                                          cwd=project.root, timeout=3600)
                if proc.returncode != 0:
                    raise VeloraError(proc.stderr.decode("utf-8", "replace").strip()[:300] or "code de sortie ≠ 0")
                out.append((dst, f"databases/{dst.name}"))
            else:
                raise VeloraError(f"type inconnu « {db.get('type')} » (attendu : sqlite ou command)")
            log(f"Base « {name} » exportée")
        except (VeloraError, sqlite3.Error, OSError, KeyError, subprocess.TimeoutExpired) as e:
            raise VeloraError(f"Export de la base « {name} » impossible : {e}") from e
    return out


def run_backup(project: Project, *, force: bool = False, log=print) -> BackupResult:
    cfg = project.config["backup"]
    specs = cfg.get("destinations") or []
    if not specs:
        raise VeloraError("Aucune destination de sauvegarde. Ajoutez-en une : "
                          "velora config add backup.destinations \"D:\\Sauvegardes\"")
    try:
        result = _run_backup(project, specs, force, log)
    except Exception as e:
        history.record(project, "backup", status="failed", message=str(e))
        notify.send_alert(project, "Échec de la sauvegarde", str(e))
        raise
    if result.status == "partial":
        notify.send_alert(project, "Sauvegarde partielle", result.message)
    return result


def _run_backup(project: Project, specs: list[str], force: bool, log) -> BackupResult:
    cfg = project.config["backup"]
    listed = _collect(project)
    manifest = {}
    for rel, path in listed:
        manifest[rel] = {"sha256": fs.hash_file(path), "size": path.stat().st_size}
    fingerprint = _content_fingerprint(manifest)

    previous = history.last(project, "backup", status="ok")
    has_dbs = bool(cfg.get("databases"))
    head = gitutil.head_commit(project.root)
    if (not force and not has_dbs and previous and previous.get("fingerprint") == fingerprint
            and previous.get("git_head") == head):
        history.record(project, "backup", status="skipped", fingerprint=fingerprint)
        return BackupResult("skipped", files=len(listed), message="Aucun changement depuis la dernière sauvegarde.")

    stamp = datetime.now().strftime(STAMP_FORMAT)
    archive_name = f"{safe_name(project.name)}_{stamp}.zip"
    with tempfile.TemporaryDirectory(prefix="velora-") as tmp:
        tmpdir = Path(tmp)
        archive = tmpdir / archive_name
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for rel, path in listed:
                zf.write(path, f"files/{rel}")
            if cfg.get("include_git_bundle", True) and head:
                bundle = tmpdir / "repo.bundle"
                if gitutil.run(project.root, "bundle", "create", str(bundle), "--all") is not None and bundle.exists():
                    zf.write(bundle, "git/repo.bundle")
                    log("Historique git inclus (git/repo.bundle)")
                else:
                    log("! Bundle git impossible à créer (historique non inclus)")
            for dump, arcname in _dump_databases(project, tmpdir, log):
                zf.write(dump, arcname)
            for rel, path in fs.iter_files(project.state_dir, respect_gitignore=False):
                if rel.startswith("proofs/") or rel == "config.json" or rel == "fingerprints.json":
                    zf.write(path, f"velora/{rel}")
            zf.writestr(MANIFEST_NAME, json.dumps({
                "velora_backup": 1, "project": project.name, "created": history.now_iso(),
                "source": str(project.root), "git_head": head, "files": manifest,
            }, indent=1, ensure_ascii=False))

        sha = fs.hash_file(archive)
        size = archive.stat().st_size
        status_by_dest: dict[str, str] = {}
        pruned = 0
        for spec in specs:
            try:
                dest = destination(spec, project.name)
                dest.put(archive, archive_name)
                if not dest.verify(archive_name, sha):
                    raise VeloraError("l'archive copiée ne correspond pas à l'original (support défaillant ?)")
                status_by_dest[spec] = "ok"
                log(f"Copiée et vérifiée → {spec}")
                pruned += _prune(dest, project.config["backup"].get("retention", {}), archive_name)
            except (VeloraError, OSError, subprocess.SubprocessError) as e:
                status_by_dest[spec] = f"erreur : {e}"
                log(f"! Échec vers {spec} : {e}")

    successes = sum(1 for s in status_by_dest.values() if s == "ok")
    if successes == 0:
        raise VeloraError("Sauvegarde impossible vers toutes les destinations : "
                          + "; ".join(f"{k} → {v}" for k, v in status_by_dest.items()))
    status = "ok" if successes == len(specs) else "partial"
    failed = [k for k, v in status_by_dest.items() if v != "ok"]
    message = f"Échec vers : {', '.join(failed)}" if failed else ""
    history.record(project, "backup", status=status, archive=archive_name, size=size, sha256=sha,
                   files=len(listed), fingerprint=fingerprint, git_head=head, destinations=status_by_dest)
    return BackupResult(status, archive_name, size, len(listed), sha, status_by_dest, pruned, message)


def _prune(dest, retention: dict, current: str) -> int:
    names = dest.list()
    keep = select_to_keep(names, **{k: int(v) for k, v in retention.items()}) | {current}
    removed = 0
    for name in names:
        if name not in keep:
            dest.delete(name)
            removed += 1
    return removed


# --------------------------------------------------------------------------- inventaire

def list_backups(project: Project) -> list[dict]:
    out = []
    for spec in project.config["backup"].get("destinations") or []:
        try:
            dest = destination(spec, project.name)
            names = dest.list()
        except VeloraError as e:
            out.append({"destination": spec, "error": str(e), "archives": []})
            continue
        archives = []
        for name in reversed(names):
            entry = {"name": name, "date": parse_stamp(name).isoformat()}
            if isinstance(dest, LocalDestination):
                entry["path"] = str(dest.dir / name)
                entry["size"] = (dest.dir / name).stat().st_size
            archives.append(entry)
        out.append({"destination": spec, "archives": archives})
    return out


def resolve_archive(project: Project, ref: str, workdir: Path) -> Path:
    """Accepte un chemin d'archive, un nom d'archive, ou « latest »."""
    if Path(ref).exists():
        return Path(ref)
    for spec in project.config["backup"].get("destinations") or []:
        dest = destination(spec, project.name)
        names = dest.list()
        if ref == "latest" and names:
            ref_name = names[-1]
        elif ref in names:
            ref_name = ref
        else:
            continue
        return dest.fetch(ref_name, workdir)
    raise VeloraError(f"Archive introuvable : {ref}")


def verify_archive(archive: Path) -> tuple[bool, list[str]]:
    problems = []
    with zipfile.ZipFile(archive) as zf:
        bad = zf.testzip()
        if bad:
            return False, [f"Données corrompues : {bad}"]
        try:
            manifest = json.loads(zf.read(MANIFEST_NAME))
        except KeyError:
            return False, ["Manifeste absent : ce n'est pas une archive Velora."]
        names = set(zf.namelist())
        for rel, meta in manifest["files"].items():
            arc = f"files/{rel}"
            if arc not in names:
                problems.append(f"Manquant : {rel}")
                continue
            h = hashlib.sha256()
            with zf.open(arc) as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            if h.hexdigest() != meta["sha256"]:
                problems.append(f"Empreinte différente : {rel}")
    return not problems, problems


def restore_archive(archive: Path, target: Path) -> int:
    target = target.resolve()
    if target.exists() and any(target.iterdir()):
        raise VeloraError(f"Le dossier cible n'est pas vide : {target} (choisissez un dossier neuf)")
    ok, problems = verify_archive(archive)
    if not ok:
        raise VeloraError("Archive invalide : " + "; ".join(problems[:5]))
    target.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            arc = PurePosixPath(info.filename)
            if arc.parts[0] == "files":
                rel = PurePosixPath(*arc.parts[1:])
            elif arc.parts[0] in {"git", "databases", "velora"} or info.filename == MANIFEST_NAME:
                rel = PurePosixPath("_velora_restore", *arc.parts)
            else:
                continue
            dest = (target / Path(*rel.parts)).resolve()
            if target not in dest.parents:  # protection « zip slip »
                raise VeloraError(f"Chemin dangereux dans l'archive : {info.filename}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
    return count


def check_freshness(project: Project) -> tuple[bool, str]:
    hours = float(project.config["alerts"].get("stale_after_hours", 48))
    event = history.last(project, "backup", status="ok")
    if not event:
        msg = "Aucune sauvegarde réussie n'a jamais été effectuée."
        notify.send_alert(project, "Aucune sauvegarde", msg)
        return False, msg
    when = datetime.fromisoformat(event["time"])
    age = datetime.now(timezone.utc) - when
    if age > timedelta(hours=hours):
        msg = f"Dernière sauvegarde réussie il y a {age.days} j {age.seconds // 3600} h (seuil : {hours:.0f} h)."
        notify.send_alert(project, "Sauvegarde trop ancienne", msg)
        return False, msg
    return True, f"Dernière sauvegarde réussie il y a {int(age.total_seconds() // 3600)} h ({event.get('archive')})."
