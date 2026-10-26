"""Analyse d'un site en ligne, vu de l'extérieur : HTTPS, certificat, en-têtes, cookies, CORS,
fichiers exposés, source maps et secrets dans les scripts publiés.

Uniquement des requêtes de lecture (GET), en nombre limité, identifiées par l'User-Agent :
rien qui ressemble à une attaque. Protégé contre le SSRF : seules les adresses publiques sont
contactées (sauf allow_private, réservé à un usage local), l'adresse IP vérifiée est celle
réellement utilisée (pas de DNS rebinding) et chaque redirection est revalidée.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import secrets as pysecrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from velora import VeloraError
from velora.core.net import USER_AGENT
from velora.scan import secrets
from velora.scan.models import Finding, security_score, sort_findings

PUBLIC_PORTS = {80, 443, 8080, 8443}
TIMEOUT = 10
MAX_REQUESTS = 45
DEADLINE = 120
PAGE_LIMIT = 2 * 1024 * 1024
PROBE_LIMIT = 16 * 1024
MAX_SCRIPTS = 6


class LiveScanError(VeloraError):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: http.client.HTTPMessage
    body: bytes
    tls: dict | None = None

    def header(self, name: str) -> str:
        return self.headers.get(name, "") or ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def is_html(self) -> bool:
        return "html" in self.header("Content-Type").lower() or self.body[:200].lstrip().lower().startswith(
            (b"<!doctype html", b"<html"))


@dataclass
class LiveResult:
    url: str
    final_url: str = ""
    findings: list[Finding] = field(default_factory=list)
    info: dict = field(default_factory=dict)
    platforms: list[str] = field(default_factory=list)
    requests: int = 0
    duration: float = 0.0

    @property
    def score(self) -> int:
        return security_score(self.findings)

    def to_dict(self) -> dict:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {"url": self.url, "final_url": self.final_url, "score": self.score, "counts": counts,
                "info": self.info, "platforms": self.platforms, "requests": self.requests,
                "duration": round(self.duration, 2), "findings": [f.to_dict() for f in self.findings]}


# --------------------------------------------------------------------------- réseau sûr

def check_address(ip: str, allow_private: bool = False) -> None:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if allow_private:
        return
    if not addr.is_global or addr.is_multicast:
        raise LiveScanError(f"Adresse non publique refusée ({addr}) : seuls les sites accessibles sur Internet "
                            "peuvent être analysés.")


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise LiveScanError("Adresse du site manquante.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise LiveScanError("Seules les adresses http:// et https:// sont acceptées.")
    if not parts.hostname:
        raise LiveScanError(f"Adresse invalide : {raw}")
    if parts.username or parts.password:
        raise LiveScanError("Les identifiants dans l'adresse ne sont pas acceptés.")
    try:
        parts.port
    except ValueError as e:
        raise LiveScanError(f"Adresse invalide : {raw}") from e
    return raw


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class Fetcher:
    def __init__(self, allow_private: bool = False, max_requests: int = MAX_REQUESTS, deadline: float = DEADLINE):
        self.allow_private = allow_private
        self.max_requests = max_requests
        self.requests = 0
        self.stop_at = time.time() + deadline
        self.verify = True

    def _resolve(self, host: str, port: int) -> str:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise LiveScanError(f"Nom de domaine introuvable : {host}") from e
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
        # Toutes les adresses doivent être publiques : sinon un domaine piégé pourrait alterner.
        for ip in addresses:
            check_address(ip, self.allow_private)
        return addresses[0]

    def fetch(self, url: str, *, headers: dict | None = None, follow: bool = True,
              limit: int = PAGE_LIMIT) -> Response:
        for _ in range(6):
            if self.requests >= self.max_requests or time.time() > self.stop_at:
                raise LiveScanError("Limite de requêtes ou de durée atteinte.")
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise LiveScanError(f"Redirection vers une adresse non prise en charge : {url}")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            if not self.allow_private and port not in PUBLIC_PORTS:
                raise LiveScanError(f"Port {port} refusé (ports acceptés : {', '.join(map(str, sorted(PUBLIC_PORTS)))}).")
            ip = self._resolve(parts.hostname, port)
            self.requests += 1
            if parts.scheme == "https":
                ctx = ssl.create_default_context()
                if not self.verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = _PinnedHTTPS(parts.hostname, ip, port, TIMEOUT, ctx)
            else:
                conn = _PinnedHTTP(parts.hostname, ip, port, TIMEOUT)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            try:
                conn.request("GET", path, headers={"User-Agent": f"{USER_AGENT} (analyse de sécurité)",
                                                   "Accept": "*/*", "Accept-Encoding": "identity",
                                                   **(headers or {})})
                resp = conn.getresponse()
                body = resp.read(limit)
                tls = None
                if parts.scheme == "https" and conn.sock is not None:
                    tls = {"version": conn.sock.version(), "cert": conn.sock.getpeercert() or {}}
            finally:
                conn.close()
            result = Response(url, resp.status, resp.headers, body, tls)
            location = resp.headers.get("Location")
            if follow and resp.status in (301, 302, 303, 307, 308) and location:
                url = urljoin(url, location)
                continue
            return result
        raise LiveScanError("Trop de redirections.")


# --------------------------------------------------------------------------- analyse

def scan(url: str, *, allow_private: bool = False, deep: bool = True, log=lambda _m: None) -> LiveResult:
    """deep=False saute la recherche de fichiers exposés (/.env, /.git…) : à réserver aux sites dont
    le demandeur a prouvé la propriété, car c'est la seule partie qui sort de la navigation normale."""
    started = time.time()
    url = normalize_url(url)
    result = LiveResult(url)
    f = Fetcher(allow_private=allow_private)
    parts = urlsplit(url)
    add = result.findings.append

    page = _main_page(f, url, parts, result, log)
    result.final_url = page.url
    final = urlsplit(page.url)
    origin = f"{final.scheme}://{final.netloc}"
    result.info.update({"status": page.status, "server": page.header("Server"),
                        "powered_by": page.header("X-Powered-By")})
    if page.tls:
        result.info["tls_version"] = page.tls["version"]
        _check_certificate(page.tls, result)
    if final.scheme == "https":
        port = final.port or 443
        _check_old_tls(final.hostname, port, f._resolve(final.hostname, port), result, f)

    log("En-têtes de sécurité et cookies")
    _check_headers(page, final.scheme == "https", add)
    _check_cookies(page, final.scheme == "https", add)
    if page.is_html:
        _check_html(page, origin, add)
    result.platforms = _platforms(page)

    steps = [("CORS", lambda: _check_cors(f, page.url, add)),
             ("Scripts publiés", lambda: _check_scripts(f, page, origin, add))]
    if deep:
        steps.append(("Fichiers exposés", lambda: _check_exposed(f, origin, page, add)))
    else:
        result.info.setdefault("notes", []).append(
            "Fichiers exposés (/.env, /.git, sauvegardes…) non testés : prouvez que le site vous appartient pour "
            "l'analyse approfondie.")
    result.info["deep"] = deep
    for label, step in steps:
        log(label)
        try:
            step()
        except LiveScanError as e:
            result.info.setdefault("notes", []).append(f"{label} : {e}")
        except (OSError, http.client.HTTPException) as e:
            result.info.setdefault("notes", []).append(f"{label} : {e}")

    result.findings = sort_findings(result.findings)
    result.requests = f.requests
    result.duration = time.time() - started
    return result


def _main_page(f: Fetcher, url: str, parts, result: LiveResult, log) -> Response:
    add = result.findings.append
    https_url = url if parts.scheme == "https" else (
        f"https://{parts.hostname}{parts.path or '/'}" if parts.port in (None, 80) else None)
    page = None
    if https_url:
        log(f"Connexion HTTPS à {parts.hostname}")
        try:
            page = f.fetch(https_url)
        except ssl.SSLCertVerificationError as e:
            add(Finding("live", "invalid-certificate", "Certificat HTTPS invalide", "critical", https_url,
                        detail=str(e.verify_message or e), fix="Installez un certificat valide (Let's Encrypt est gratuit) "
                        "couvrant exactement ce nom de domaine : les visiteurs voient une alerte de sécurité."))
            f.verify = False  # velora:ignore — certificat déjà signalé comme critique ; on poursuit l'analyse
            try:
                page = f.fetch(https_url)
            except (OSError, http.client.HTTPException):
                page = None
        except (OSError, http.client.HTTPException):
            page = None
    if page is None:
        http_url = url if parts.scheme == "http" else f"http://{parts.hostname}{parts.path or '/'}"
        try:
            page = f.fetch(http_url)
        except (OSError, http.client.HTTPException) as e:
            raise LiveScanError(f"Site injoignable : {e}") from e
    if urlsplit(page.url).scheme != "https":
        add(Finding("live", "no-https", "Site servi sans HTTPS", "critical", page.url,
                    fix="Activez HTTPS (Let's Encrypt, ou automatique chez Netlify/Vercel/Cloudflare/OVH) puis redirigez "
                        "tout le HTTP vers HTTPS : sinon mots de passe et cookies circulent en clair."))
    elif parts.port in (None, 80, 443):
        try:
            plain = f.fetch(f"http://{parts.hostname}/", follow=False, limit=PROBE_LIMIT)
            location = plain.header("Location")
            if plain.status < 300 or plain.status >= 400 or not location.startswith("https://"):
                add(Finding("live", "no-https-redirect", "Le HTTP ne redirige pas vers HTTPS", "high",
                            f"http://{parts.hostname}/", detail=f"Réponse HTTP {plain.status}",
                            fix="Redirigez (301) tout le trafic http:// vers https://, puis activez HSTS."))
        except (OSError, http.client.HTTPException, LiveScanError):
            pass  # port 80 fermé : acceptable
    return page


def _check_certificate(tls: dict, result: LiveResult) -> None:
    not_after = tls.get("cert", {}).get("notAfter")
    if not not_after:
        return
    try:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    except ValueError:
        return
    days = (expires - datetime.now(timezone.utc)).days
    result.info["cert_expires"] = expires.date().isoformat()
    result.info["cert_days_left"] = days
    if days < 0:
        result.findings.append(Finding("live", "cert-expired", "Certificat HTTPS expiré", "critical",
                                       fix="Renouvelez-le et automatisez le renouvellement (certbot renew)."))
    elif days < 14:
        result.findings.append(Finding("live", "cert-expiring", f"Certificat HTTPS expirant dans {days} jour(s)", "high",
                                       fix="Renouvelez-le et vérifiez que le renouvellement automatique fonctionne."))


def _check_old_tls(host: str, port: int, ip: str, result: LiveResult, f: Fetcher) -> None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return  # l'OpenSSL local ne sait plus parler TLS 1.0/1.1 : test impossible
    f.requests += 1
    try:
        with socket.create_connection((ip, port), TIMEOUT) as sock, ctx.wrap_socket(sock, server_hostname=host) as s:
            version = s.version()
    except (OSError, ssl.SSLError):
        return
    result.findings.append(Finding("live", "old-tls", f"Protocole obsolète accepté ({version})", "medium",
                                   fix="N'autorisez que TLS 1.2 et 1.3 (Mozilla SSL Configuration Generator)."))


def _check_headers(page: Response, https: bool, add) -> None:
    h = page.header
    if https:
        hsts = h("Strict-Transport-Security")
        m = re.search(r"max-age\s*=\s*(\d+)", hsts)
        if not hsts:
            add(Finding("live", "missing-hsts", "En-tête HSTS absent", "medium",
                        fix="Strict-Transport-Security: max-age=63072000; includeSubDomains — le navigateur refusera "
                            "ensuite toute connexion non chiffrée."))
        elif not m or int(m.group(1)) < 15552000:
            add(Finding("live", "weak-hsts", "HSTS trop court (moins de 6 mois)", "low", detail=hsts,
                        fix="max-age=63072000 (2 ans)."))
    csp = h("Content-Security-Policy")
    if not csp:
        add(Finding("live", "missing-csp", "Pas de Content-Security-Policy", "medium",
                    fix="Une CSP bloque l'exécution de scripts injectés (XSS). Commencez en "
                        "Content-Security-Policy-Report-Only pour ne rien casser, puis activez-la."))
    else:
        directives = {d.strip().split(" ", 1)[0].lower(): d.strip() for d in csp.split(";") if d.strip()}
        script = directives.get("script-src") or directives.get("default-src") or ""
        if "'unsafe-inline'" in script and "'nonce-" not in script and "'sha" not in script and "'strict-dynamic'" not in script:
            add(Finding("live", "csp-unsafe-inline", "CSP autorisant les scripts inline ('unsafe-inline')", "low",
                        detail=script, fix="Remplacez 'unsafe-inline' par des nonces ou des hashes : sinon la CSP ne "
                                           "protège presque plus contre le XSS."))
        if re.search(r"(?:^|\s)(?:\*|https?:|data:)(?:\s|$)", script.split(" ", 1)[1] if " " in script else ""):
            add(Finding("live", "csp-wildcard", "CSP autorisant des scripts de n'importe quelle origine", "medium",
                        detail=script, fix="Listez précisément les domaines autorisés pour script-src."))
    if h("X-Content-Type-Options").lower() != "nosniff":
        add(Finding("live", "missing-nosniff", "En-tête X-Content-Type-Options absent", "low",
                    fix="X-Content-Type-Options: nosniff"))
    if not h("X-Frame-Options") and "frame-ancestors" not in csp:
        add(Finding("live", "clickjacking", "Site intégrable dans une iframe (clickjacking)", "medium",
                    fix="X-Frame-Options: DENY ou Content-Security-Policy: frame-ancestors 'none'."))
    if not h("Referrer-Policy"):
        add(Finding("live", "missing-referrer-policy", "Pas de Referrer-Policy", "low",
                    fix="Referrer-Policy: strict-origin-when-cross-origin (évite de divulguer les URL complètes)."))
    if not h("Permissions-Policy"):
        add(Finding("live", "missing-permissions-policy", "Pas de Permissions-Policy", "info",
                    fix="Permissions-Policy: camera=(), microphone=(), geolocation=()"))
    leaks = [f"{name}: {h(name)}" for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")
             if h(name) and (name != "Server" or re.search(r"\d", h(name)))]
    if leaks:
        add(Finding("live", "version-disclosure", "Versions logicielles annoncées", "low", detail=" · ".join(leaks),
                    fix="Masquez-les (server_tokens off, expose_php=Off, app.disable('x-powered-by')) : elles aident à "
                        "cibler les failles connues."))


_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|login|remember|PHPSESSID|laravel_session|connect\.sid", re.I)


def _check_cookies(page: Response, https: bool, add) -> None:
    for raw in page.headers.get_all("Set-Cookie") or []:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
        problems = []
        if https and "secure" not in attrs:
            problems.append("Secure")
        if "httponly" not in attrs and _SESSION_COOKIE.search(name):
            problems.append("HttpOnly")
        if "samesite" not in attrs:
            problems.append("SameSite")
        if problems:
            sev = "medium" if ("Secure" in problems or "HttpOnly" in problems) and _SESSION_COOKIE.search(name) else "low"
            add(Finding("live", "cookie-flags", f"Cookie « {name} » sans {', '.join(problems)}", sev,
                        fix="Cookies de session : Secure; HttpOnly; SameSite=Lax (ou Strict)."))


def _check_html(page: Response, origin: str, add) -> None:
    text = page.text
    if re.search(r"<title>\s*Index of /", text, re.I):
        add(Finding("live", "directory-listing", "Listing de répertoire visible", "medium", page.url,
                    fix="Désactivez l'index automatique (Options -Indexes / autoindex off)."))
    if urlsplit(page.url).scheme == "https":
        mixed = re.findall(r"<(?:script|iframe|link|img|source)\b[^>]*\b(?:src|href)\s*=\s*[\"'](http://[^\"']+)", text, re.I)
        if mixed:
            add(Finding("live", "mixed-content", f"{len(mixed)} ressource(s) chargée(s) en HTTP", "medium",
                        detail=", ".join(mixed[:3]), fix="Chargez tout en https://."))
    forms = re.findall(r"<form\b[^>]*action\s*=\s*[\"'](http://[^\"']+)", text, re.I)
    if forms:
        add(Finding("live", "form-over-http", "Formulaire envoyé en HTTP", "high", detail=forms[0],
                    fix="Utilisez https:// pour l'action du formulaire."))
    host = urlsplit(origin).hostname
    no_sri = [src for tag, src in re.findall(r"(<script\b[^>]*\bsrc\s*=\s*[\"']((?:https?:)?//[^\"']+)[\"'][^>]*>)", text, re.I)
              if urlsplit(src if "://" in src else "https:" + src).hostname != host and "integrity" not in tag.lower()]
    if no_sri:
        add(Finding("live", "missing-sri", f"{len(no_sri)} script(s) tiers sans contrôle d'intégrité (SRI)", "low",
                    detail=", ".join(no_sri[:3]), fix="Ajoutez integrity=\"sha384-…\" crossorigin=\"anonymous\"."))


def _check_cors(f: Fetcher, url: str, add) -> None:
    evil = "https://velora-cors-test.example"
    resp = f.fetch(url, headers={"Origin": evil}, follow=False, limit=PROBE_LIMIT)
    acao = resp.header("Access-Control-Allow-Origin")
    creds = resp.header("Access-Control-Allow-Credentials").lower() == "true"
    if acao == evil or acao == "null":
        add(Finding("live", "cors-reflection", "CORS accepte n'importe quelle origine", "high" if creds else "medium",
                    detail=f"Access-Control-Allow-Origin: {acao}" + (" + Allow-Credentials: true" if creds else ""),
                    fix="N'acceptez que vos propres domaines (liste blanche) : sinon n'importe quel site peut lire les "
                        "réponses de votre API" + (" avec la session de vos visiteurs." if creds else ".")))


def _check_scripts(f: Fetcher, page: Response, origin: str, add) -> None:
    if not page.is_html:
        return
    host = urlsplit(origin).hostname
    srcs = []
    for src in re.findall(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", page.text, re.I):
        full = urljoin(page.url, src)
        if urlsplit(full).hostname == host and full not in srcs:
            srcs.append(full)
    maps, leaked = [], []
    for src in srcs[:MAX_SCRIPTS]:
        js = f.fetch(src, limit=PAGE_LIMIT)
        if js.status != 200:
            continue
        text = js.text
        for finding in secrets.scan_text(text, urlsplit(src).path):
            if not finding.rule.startswith("generic"):
                leaked.append(finding)
        m = re.search(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*$", text[-600:], re.M)
        map_url = urljoin(src, m.group(1)) if m and not m.group(1).startswith("data:") else None
        if map_url is None and js.header("SourceMap"):
            map_url = urljoin(src, js.header("SourceMap"))
        if map_url and len(maps) < 2:
            sm = f.fetch(map_url, limit=PROBE_LIMIT)
            if sm.status == 200 and sm.body.lstrip().startswith(b"{") and b'"sources"' in sm.body:
                maps.append(urlsplit(map_url).path)
    if maps:
        add(Finding("live", "public-source-maps", "Source maps publiées (code source reconstituable)", "medium",
                    detail=", ".join(maps),
                    fix="Ne publiez pas les fichiers .map en production (Vite : build.sourcemap=false ; Next.js : "
                        "productionBrowserSourceMaps=false) ; envoyez-les seulement à Sentry si besoin."))
    for finding in leaked:
        finding.category = "live"
        finding.title = f"{finding.title} dans un script public"
        finding.severity = "critical"
        finding.fix = ("Tout visiteur peut lire ce secret : révoquez-le immédiatement et déplacez l'appel qui "
                       "l'utilise côté serveur.")
        add(finding)


def _not_html(r: Response) -> bool:
    return r.status == 200 and not r.is_html


_EXPOSED = [
    ("/.git/HEAD", "exposed-git", "Dépôt git téléchargeable (/.git)", "critical",
     lambda r: _not_html(r) and re.match(rb"(ref: refs/|[0-9a-f]{40}\s*$)", r.body) is not None,
     "Tout le code source et son historique sont récupérables (git-dumper). Bloquez l'accès à /.git et ne déployez pas ce dossier."),
    ("/.env", "exposed-env", "Fichier .env public", "critical",
     lambda r: _not_html(r) and len(re.findall(rb"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", r.body)) >= 2,
     "Mots de passe et clés sont lisibles par tous : supprimez-le du dossier public et révoquez TOUS les secrets qu'il contient."),
    ("/.env.local", "exposed-env", "Fichier .env.local public", "critical",
     lambda r: _not_html(r) and len(re.findall(rb"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", r.body)) >= 2,
     "Supprimez-le du dossier public et révoquez les secrets qu'il contient."),
    ("/.env.production", "exposed-env", "Fichier .env.production public", "critical",
     lambda r: _not_html(r) and len(re.findall(rb"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", r.body)) >= 2,
     "Supprimez-le du dossier public et révoquez les secrets qu'il contient."),
    ("/.svn/wc.db", "exposed-svn", "Dépôt SVN téléchargeable", "high",
     lambda r: r.status == 200 and r.body.startswith(b"SQLite format 3"), "Bloquez l'accès à /.svn."),
    ("/.DS_Store", "exposed-ds-store", "Fichier .DS_Store public (liste des fichiers)", "low",
     lambda r: r.status == 200 and r.body[4:8] == b"Bud1", "Supprimez les .DS_Store du serveur."),
    ("/.htpasswd", "exposed-htpasswd", "Fichier .htpasswd public", "high",
     lambda r: _not_html(r) and re.match(rb"[\w.\-]+:\$?[\w./$]{8,}", r.body) is not None,
     "Bloquez l'accès aux fichiers .ht* et changez les mots de passe."),
    ("/.npmrc", "exposed-npmrc", "Fichier .npmrc public", "critical",
     lambda r: _not_html(r) and b"_authToken" in r.body, "Révoquez le jeton npm et retirez le fichier."),
    ("/wp-config.php.bak", "exposed-backup", "Copie de wp-config.php téléchargeable", "critical",
     lambda r: _not_html(r) and b"DB_PASSWORD" in r.body, "Supprimez-la et changez le mot de passe de la base."),
    ("/wp-config.php~", "exposed-backup", "Copie de wp-config.php téléchargeable", "critical",
     lambda r: _not_html(r) and b"DB_PASSWORD" in r.body, "Supprimez-la et changez le mot de passe de la base."),
    ("/config.php.bak", "exposed-backup", "Copie de config.php téléchargeable", "critical",
     lambda r: _not_html(r) and b"<?php" in r.body, "Supprimez-la et changez les secrets qu'elle contient."),
    ("/backup.zip", "exposed-backup", "Archive de sauvegarde téléchargeable", "critical",
     lambda r: r.status == 200 and r.body.startswith(b"PK\x03\x04"), "Retirez les sauvegardes du dossier public."),
    ("/backup.sql", "exposed-dump", "Export de base de données téléchargeable", "critical",
     lambda r: _not_html(r) and re.search(rb"CREATE TABLE|INSERT INTO", r.body) is not None,
     "Retirez-le immédiatement : c'est toute la base (utilisateurs compris)."),
    ("/dump.sql", "exposed-dump", "Export de base de données téléchargeable", "critical",
     lambda r: _not_html(r) and re.search(rb"CREATE TABLE|INSERT INTO", r.body) is not None,
     "Retirez-le immédiatement : c'est toute la base (utilisateurs compris)."),
    ("/phpinfo.php", "exposed-phpinfo", "Page phpinfo() publique", "medium",
     lambda r: r.status == 200 and b"phpinfo()" in r.body, "Supprimez cette page : elle détaille toute la configuration."),
    ("/info.php", "exposed-phpinfo", "Page phpinfo() publique", "medium",
     lambda r: r.status == 200 and b"phpinfo()" in r.body, "Supprimez cette page : elle détaille toute la configuration."),
    ("/server-status", "exposed-server-status", "Page server-status Apache publique", "medium",
     lambda r: r.status == 200 and b"Apache Server Status" in r.body, "Restreignez /server-status à 127.0.0.1."),
    ("/docker-compose.yml", "exposed-compose", "docker-compose.yml public", "medium",
     lambda r: _not_html(r) and re.search(rb"(?m)^services:", r.body) is not None,
     "Retirez-le du dossier public : il révèle l'architecture et parfois des mots de passe."),
]


def _check_exposed(f: Fetcher, origin: str, page: Response, add) -> None:
    # Réponse de référence pour une page inexistante : évite les faux positifs des sites qui renvoient
    # 200 + la page d'accueil pour n'importe quelle adresse.
    baseline = f.fetch(f"{origin}/velora-{pysecrets.token_hex(6)}", follow=False, limit=PROBE_LIMIT)
    probes = list(_EXPOSED)
    if b"wp-content" in page.body:
        probes += [
            ("/wp-json/wp/v2/users", "wp-user-enum", "Liste des utilisateurs WordPress publique", "medium",
             lambda r: r.status == 200 and r.body.lstrip().startswith(b"[") and b'"slug"' in r.body,
             "Les identifiants de connexion sont devinables : restreignez /wp-json/wp/v2/users (extension de sécurité)."),
            ("/xmlrpc.php", "wp-xmlrpc", "xmlrpc.php actif (force brute amplifiée)", "low",
             lambda r: b"XML-RPC server accepts POST requests only" in r.body,
             "Désactivez XML-RPC si vous ne l'utilisez pas (Jetpack et l'app mobile en ont besoin)."),
        ]
    for path, rid, title, sev, test, fix in probes:
        r = f.fetch(origin + path, follow=False, limit=PROBE_LIMIT)
        if r.status == 200 and baseline.status == 200 and r.body[:512] == baseline.body[:512]:
            continue
        if test(r):
            add(Finding("live", rid, title, sev, origin + path, fix=fix))
    sec = f.fetch(f"{origin}/.well-known/security.txt", follow=False, limit=PROBE_LIMIT)
    if not (sec.status == 200 and b"Contact:" in sec.body):
        add(Finding("live", "no-security-txt", "Pas de fichier security.txt", "info",
                    fix="Publiez /.well-known/security.txt (Contact: mailto:…) pour que les chercheurs puissent "
                        "vous signaler une faille (securitytxt.org)."))


def _platforms(page: Response) -> list[str]:
    h = {k.lower(): v.lower() for k, v in page.headers.items()}
    out = []
    server, powered = h.get("server", ""), h.get("x-powered-by", "")
    for label, test in [
        ("vercel", "x-vercel-id" in h or "vercel" in server), ("netlify", "x-nf-request-id" in h or "netlify" in server),
        ("cloudflare", "cf-ray" in h), ("nginx", "nginx" in server), ("apache", "apache" in server or "litespeed" in server),
        ("iis", "iis" in server or "asp.net" in powered), ("express", "express" in powered),
        ("nextjs", "next.js" in powered or "x-nextjs-cache" in h), ("php", "php" in powered),
    ]:
        if test:
            out.append(label)
    return out
