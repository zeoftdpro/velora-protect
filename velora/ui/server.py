"""Tableau de bord web local.

Sécurité : écoute uniquement sur 127.0.0.1, exige un jeton aléatoire (transmis dans l'URL d'ouverture
puis via un cookie SameSite=Strict et un en-tête), et vérifie l'en-tête Host (anti DNS-rebinding).
"""

from __future__ import annotations

import io
import json
import secrets
import tempfile
import threading
import traceback
import webbrowser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from velora import VeloraError, backup, proof
from velora.cli import project_status
from velora.core import config as cfgmod
from velora.core import upload
from velora.core.config import Project

INDEX = Path(__file__).with_name("index.html")
# Fichiers communs avec la version en ligne (aucune donnée sensible : servis sans jeton).
STATIC = {"/style.css": ("style.css", "text/css; charset=utf-8"),
          "/shared.js": ("shared.js", "text/javascript; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml")}
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()
# Analyses de projets envoyés et de sites en ligne : coûteuses, on en limite le nombre simultané.
_heavy = threading.BoundedSemaphore(2)


def _lock_for(root: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(root, threading.Lock())


def _project(body: dict) -> Project:
    root = body.get("root")
    if not root:
        raise VeloraError("Projet non précisé.")
    known = {str(Path(p).resolve()) for p in cfgmod.registered_projects()}
    resolved = str(Path(root).resolve())
    if resolved not in known:
        raise VeloraError("Projet inconnu : ajoutez-le d'abord depuis le tableau de bord.")
    return Project(resolved)


def _logger():
    lines: list[str] = []
    return lines, lines.append


# --------------------------------------------------------------------------- actions

def api_projects(_body):
    out = []
    for root in cfgmod.registered_projects():
        out.append({"root": root, "name": Project(root).name})
    return out


def api_status(body):
    from velora.scan import last_scan
    project = _project(body)
    st = project_status(project)
    st["last_scan"] = last_scan(project)
    st["proof_list"] = proof.list_proofs(project)[:20]
    st["backups"] = backup.list_backups(project)
    st["config"] = {"author": project.config.get("author", ""),
                    "destinations": project.config["backup"]["destinations"],
                    "webhook_url": project.config["alerts"].get("webhook_url", ""),
                    "stale_after_hours": project.config["alerts"].get("stale_after_hours", 48)}
    return st


def api_add_project(body):
    root = Path(str(body.get("path", "")).strip().strip('"')).expanduser()
    if not root.is_dir():
        raise VeloraError(f"Dossier introuvable : {root}")
    project = Project(root)
    if not project.initialized:
        project.config["project_name"] = root.resolve().name
        project.save_config()
    cfgmod.register_project(project.root)
    return {"root": str(project.root), "name": project.name}


def api_settings(body):
    project = _project(body)
    if "author" in body:
        project.config["author"] = str(body["author"]).strip()
    if "destinations" in body:
        project.config["backup"]["destinations"] = [str(d).strip() for d in body["destinations"] if str(d).strip()]
    if "webhook_url" in body:
        project.config["alerts"]["webhook_url"] = str(body["webhook_url"]).strip()
    if "stale_after_hours" in body:
        project.config["alerts"]["stale_after_hours"] = float(body["stale_after_hours"])
    project.save_config()
    return {"saved": True}


def api_scan(body):
    from velora.scan import run_scan
    project = _project(body)
    return run_scan(project, network=not body.get("offline")).to_dict()


def api_backup(body):
    project = _project(body)
    lines, log = _logger()
    result = backup.run_backup(project, force=bool(body.get("force")), log=log)
    return {**result.__dict__, "log": lines}


def api_proof(body):
    project = _project(body)
    lines, log = _logger()
    meta = proof.create_proof(project, note=str(body.get("note") or ""), archive=bool(body.get("archive")), log=log)
    return {**meta, "log": lines}


def api_proof_verify(body):
    return proof.verify_proof(_project(body), body.get("id"))


def api_fingerprint(body):
    from velora.protect import fingerprint
    return fingerprint.save_db(_project(body))


def api_compare(body):
    from velora.protect import fingerprint
    suspect = Path(str(body.get("suspect", "")).strip().strip('"'))
    if not suspect.exists():
        raise VeloraError(f"Chemin introuvable : {suspect}")
    return fingerprint.compare(_project(body), suspect)


def api_audit(body):
    from velora.protect import exposure
    findings, recs = exposure.audit(_project(body).root)
    return {"findings": [f.to_dict() for f in findings], "recommendations": recs}


def api_license(body):
    from velora.protect import license
    project = _project(body)
    author = project.config.get("author") or ""
    path = license.write_license(project, body.get("type", "proprietary"), author, overwrite=bool(body.get("force")))
    return {"path": str(path)}


def api_live(body):
    from velora.scan import hardening, live
    # Tableau de bord local : l'utilisateur peut tester son propre site en développement (localhost).
    result = live.scan(str(body.get("url", "")), allow_private=True)
    return {**result.to_dict(), "hardening": hardening.suggest(platforms=result.platforms)}


def upload_scan(stream, length: int, offline: bool) -> dict:
    """Reçoit une archive ZIP, l'extrait dans un dossier temporaire, l'analyse puis efface tout."""
    from velora.scan import scan_uploaded
    if length <= 0:
        raise VeloraError("Envoi vide.")
    if length > upload.MAX_ARCHIVE_BYTES:
        raise VeloraError(f"Envoi trop volumineux (maximum {upload.MAX_ARCHIVE_BYTES // 1024 // 1024} Mo).")
    # L'archive reste en mémoire : écrite sur le disque, un antivirus pourrait la bloquer en entier
    # dès qu'elle contient un fichier malveillant, et rien ne serait analysé.
    data = io.BytesIO()
    remaining = length
    while remaining > 0:
        chunk = stream.read(min(remaining, 1024 * 1024))
        if not chunk:
            raise VeloraError("Envoi interrompu.")
        data.write(chunk)
        remaining -= len(chunk)
    tmp = Path(tempfile.mkdtemp(prefix="velora-upload-"))
    try:
        stats = upload.safe_extract(data, tmp / "projet")
        root = upload.project_root(tmp / "projet")
        report = scan_uploaded(root, network=not offline, blocked=stats["blocked"])
        return {**report, "upload": {**stats, "name": root.name}}
    finally:
        upload.cleanup(tmp)


ROUTES = {
    "/api/projects": (api_projects, False),
    "/api/status": (api_status, False),
    "/api/projects/add": (api_add_project, False),
    "/api/settings": (api_settings, True),
    "/api/scan": (api_scan, True),
    "/api/backup": (api_backup, True),
    "/api/proof": (api_proof, True),
    "/api/proof/verify": (api_proof_verify, False),
    "/api/fingerprint": (api_fingerprint, True),
    "/api/compare": (api_compare, False),
    "/api/audit": (api_audit, False),
    "/api/license": (api_license, True),
    "/api/live": (api_live, False),
}
HEAVY = {"/api/live"}


# --------------------------------------------------------------------------- serveur

def make_handler(token: str, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "Velora"

        def log_message(self, *_):
            pass

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                             "connect-src 'self'; frame-ancestors 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload):
            self._send(code, json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _cookie_token(self) -> str:
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return jar["velora"].value if "velora" in jar else ""

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, b"Host refuse", "text/plain")
            url = urlparse(self.path)
            if url.path in STATIC:
                name, ctype = STATIC[url.path]
                return self._send(200, Path(__file__).with_name(name).read_bytes(), ctype)
            if url.path != "/":
                return self._send(404, b"Introuvable", "text/plain")
            given = parse_qs(url.query).get("t", [""])[0]
            if not (secrets.compare_digest(given, token) or secrets.compare_digest(self._cookie_token(), token)):
                return self._send(401, "Accès refusé : ouvrez l'adresse affichée par « velora ui ».".encode("utf-8"),
                                  "text/plain; charset=utf-8")
            html = INDEX.read_text(encoding="utf-8").replace("__VELORA_TOKEN__", token)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8",
                       {"Set-Cookie": f"velora={token}; HttpOnly; SameSite=Strict; Path=/"})

        def do_POST(self):
            if not self._host_ok():
                return self._json(403, {"error": "Host refusé"})
            if not secrets.compare_digest(self.headers.get("X-Velora-Token", ""), token):
                return self._json(401, {"error": "Jeton invalide"})
            url = urlparse(self.path)
            if url.path == "/api/upload":
                return self._upload(url)
            route = ROUTES.get(url.path)
            if not route:
                return self._json(404, {"error": "Route inconnue"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(length, 1_000_000)) or b"{}")
            except ValueError:
                return self._json(400, {"error": "JSON invalide"})
            handler, exclusive = route
            if url.path in HEAVY and not _heavy.acquire(blocking=False):
                return self._json(429, {"error": "Deux analyses sont déjà en cours : patientez quelques secondes."})
            try:
                if exclusive and body.get("root"):
                    lock = _lock_for(str(Path(body["root"]).resolve()))
                    if not lock.acquire(blocking=False):
                        return self._json(409, {"error": "Une opération est déjà en cours sur ce projet."})
                    try:
                        result = handler(body)
                    finally:
                        lock.release()
                else:
                    result = handler(body)
                self._json(200, result)
            except VeloraError as e:
                self._json(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001 — renvoyer l'erreur à l'interface plutôt que couper la connexion
                traceback.print_exc()
                self._json(500, {"error": f"Erreur interne : {e}"})
            finally:
                if url.path in HEAVY:
                    _heavy.release()

        def _upload(self, url):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._json(400, {"error": "Longueur invalide"})
            if length > upload.MAX_ARCHIVE_BYTES:
                self.close_connection = True
                return self._json(413, {"error": "Envoi trop volumineux (maximum "
                                                 f"{upload.MAX_ARCHIVE_BYTES // 1024 // 1024} Mo)."})
            if not _heavy.acquire(blocking=False):
                self.close_connection = True
                return self._json(429, {"error": "Deux analyses sont déjà en cours : patientez quelques secondes."})
            try:
                offline = parse_qs(url.query).get("offline", ["0"])[0] == "1"
                self._json(200, upload_scan(self.rfile, length, offline))
            except VeloraError as e:
                self.close_connection = True
                self._json(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                self.close_connection = True
                self._json(500, {"error": f"Erreur interne : {e}"})
            finally:
                _heavy.release()

    return Handler


def serve(port: int = 8765, open_browser: bool = True, initial: str | None = None) -> None:
    if initial:
        project = Project(initial)
        if project.initialized:
            cfgmod.register_project(project.root)
    else:
        here = cfgmod.find_project_root(Path.cwd())
        if Project(here).initialized:
            cfgmod.register_project(here)
    token = secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(token, port))
    url = f"http://127.0.0.1:{port}/?t={token}"
    print(f"Tableau de bord Velora : {url}\n(Ctrl+C pour arrêter)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
