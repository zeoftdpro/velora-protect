"""Service en ligne (fonctions Vercel) : test de sites, preuve de propriété, limitation du débit.

L'analyse du code, elle, s'exécute dans le navigateur du client (Pyodide) : le code n'est jamais
envoyé au serveur. Le serveur ne fait que tester des sites en ligne, avec les protections
anti-SSRF de velora.scan.live.

Variable d'environnement requise : VELORA_SECRET (aléatoire, 32 caractères ou plus). Sans elle,
l'analyse approfondie est désactivée (refus par défaut).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import traceback
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler
from urllib.parse import quote, urlsplit

from velora import VeloraError
from velora.core import net

VERIFY_PATH = "/.well-known/velora-verification.txt"
DNS_PREFIX = "_velora"
MAX_BODY = 16 * 1024


# --------------------------------------------------------------------------- preuve de propriété

def _secret() -> bytes | None:
    value = os.environ.get("VELORA_SECRET", "")
    return value.encode() if len(value) >= 32 else None


def hostname_of(url: str) -> str:
    from velora.scan.live import normalize_url
    host = urlsplit(normalize_url(url)).hostname or ""
    return host.encode("idna").decode("ascii").lower().rstrip(".")


def verification_token(host: str) -> str:
    """Jeton propre à un nom de domaine, recalculable sans base de données (HMAC du secret serveur)."""
    secret = _secret()
    if secret is None:
        raise VeloraError("Analyse approfondie indisponible : service mal configuré (VELORA_SECRET).")
    return "velora-verify=" + hmac.new(secret, host.encode(), hashlib.sha256).hexdigest()[:40]


def instructions(url: str) -> dict:
    host = hostname_of(url)
    token = verification_token(host)
    return {"host": host, "token": token,
            "file": {"url": f"https://{host}{VERIFY_PATH}", "content": token},
            "dns": {"name": f"{DNS_PREFIX}.{host}", "type": "TXT", "value": token}}


def _file_ok(host: str, token: str) -> bool:
    from velora.scan.live import Fetcher, LiveScanError
    try:
        resp = Fetcher(max_requests=4, deadline=20).fetch(f"https://{host}{VERIFY_PATH}", limit=4096)
    except (LiveScanError, OSError, ValueError):
        return False
    return resp.status == 200 and token in resp.text


def _dns_ok(host: str, token: str) -> bool:
    # DNS sur HTTPS : la bibliothèque standard ne sait pas lire les enregistrements TXT.
    url = f"https://cloudflare-dns.com/dns-query?name={quote(f'{DNS_PREFIX}.{host}')}&type=TXT"
    try:
        data = json.loads(net.request(url, headers={"Accept": "application/dns-json"}, timeout=10, max_bytes=65536))
    except (net.NetworkError, ValueError):
        return False
    return any(token in str(a.get("data", "")) for a in data.get("Answer") or [])


def is_verified(url: str) -> tuple[bool, str]:
    host = hostname_of(url)
    token = verification_token(host)
    if _dns_ok(host, token):
        return True, "dns"
    if _file_ok(host, token):
        return True, "file"
    return False, ""


# --------------------------------------------------------------------------- limitation du débit

class RateLimiter:
    """Fenêtre glissante par adresse IP, en mémoire de l'instance.

    Fluid Compute réutilise les instances, ce qui rend ce garde-fou utile, mais il ne remplace pas une
    règle de limitation dans le pare-feu Vercel (partagée entre toutes les instances)."""

    def __init__(self, limit: int, window: float):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self.hits) > 10_000:  # ne pas laisser la mémoire grossir indéfiniment
                for k in [k for k, v in self.hits.items() if not v][:5000]:
                    del self.hits[k]
            return True


# --------------------------------------------------------------------------- gestion HTTP commune

class JsonHandler(BaseHTTPRequestHandler):
    """Base des fonctions Vercel : POST JSON uniquement, réponses jamais mises en cache."""

    limiter: RateLimiter | None = None

    def log_message(self, *_):
        pass

    def respond(self, code: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def client_ip(self) -> str:
        # Sur Vercel, x-real-ip est fixé par la plateforme (non falsifiable par le client).
        return self.headers.get("x-real-ip") or self.client_address[0]

    def do_GET(self):
        self.respond(405, {"error": "Méthode non autorisée"})

    def do_POST(self):
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self.respond(415, {"error": "JSON attendu"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            return self.respond(413, {"error": "Requête invalide"})
        try:
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self.respond(400, {"error": "JSON invalide"})
        if self.limiter and not self.limiter.allow(self.client_ip()):
            return self.respond(429, {"error": "Trop d'analyses en peu de temps : réessayez dans quelques minutes."})
        try:
            self.respond(200, self.handle_json(body))
        except VeloraError as e:
            self.respond(400, {"error": str(e)})
        except Exception:  # noqa: BLE001 — ne jamais renvoyer de trace au client
            traceback.print_exc()
            self.respond(500, {"error": "Erreur interne, réessayez plus tard."})

    def handle_json(self, body: dict):
        raise NotImplementedError


def handle_live(body: dict) -> dict:
    from velora.scan import hardening, live
    url = str(body.get("url", ""))[:2048]
    deep = bool(body.get("deep"))
    method = ""
    if deep:
        verified, method = is_verified(url)
        if not verified:
            raise VeloraError("Propriété du site non vérifiée : publiez le jeton (fichier ou DNS) puis réessayez.")
    result = live.scan(url, allow_private=False, deep=deep)
    return {**result.to_dict(), "verified_by": method, "hardening": hardening.suggest(platforms=result.platforms)}


def handle_verify(body: dict) -> dict:
    url = str(body.get("url", ""))[:2048]
    info = instructions(url)
    if body.get("check"):
        info["verified"], info["method"] = is_verified(url)
    return info
