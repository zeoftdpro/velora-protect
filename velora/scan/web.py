"""Sécurité des sites et applications web, toutes technologies (analyse du code source).

Règles par langage (XSS, injections SQL/commande, inclusion de fichiers, redirections ouvertes,
SSRF, cookies, jetons…), contrôles HTML (formulaires, contenu mixte, SRI) et contrôles à l'échelle
du projet pour les applications avec comptes (limitation des tentatives, hachage, CSRF, en-têtes).
"""

from __future__ import annotations

import json
import re

from velora.scan.models import Finding

JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
PHP = (".php", ".phtml", ".inc")
PY = (".py",)
CPP = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh")
JVM = (".java", ".kt", ".kts", ".scala")
CS = (".cs", ".cshtml", ".razor")
GO = (".go",)
RB = (".rb", ".erb")
MARKUP = (".html", ".htm", ".php", ".phtml", ".twig", ".jinja", ".jinja2", ".j2", ".ejs", ".hbs",
          ".handlebars", ".erb", ".cshtml", ".razor", ".vue", ".svelte", ".astro", ".njk", ".liquid")
SERVER_CONF = (".htaccess", ".conf", "web.config", ".ini")

_USER_PHP = r"\$_(?:GET|POST|REQUEST|COOKIE)"
_USER_JS = r"req\.(?:query|params|body)"
_USER_PY = r"request\.(?:args|form|values|json|GET|POST|data|files|query_params)"

_FIX_XSS = ("Échappez toute donnée affichée (htmlspecialchars en PHP, échappement automatique du moteur de "
            "templates) ou assainissez le HTML avec DOMPurify / bleach avant de l'injecter.")
_FIX_SQL = "Utilisez des requêtes préparées (placeholders ? ou :nom) : jamais de concaténation avec une entrée utilisateur."
_FIX_CMD = ("N'exécutez jamais de commande construite à partir d'une entrée utilisateur ; passez les arguments en "
            "liste (execFile, subprocess.run([...])) et validez-les par liste blanche.")
_FIX_REDIRECT = "N'acceptez que des chemins relatifs ou une liste blanche de domaines pour les redirections."
_FIX_SSRF = ("Ne laissez pas l'utilisateur choisir l'URL appelée par votre serveur, ou validez-la par liste blanche "
             "et bloquez les adresses internes (127.0.0.1, 10.x, 169.254.169.254…).")
_FIX_STORAGE = ("Tout script de la page (extension, dépendance compromise, faille XSS) peut lire ce stockage : "
                "placez le jeton dans un cookie HttpOnly; Secure; SameSite=Lax.")

# (id, titre, sévérité, extensions, regex, conseil)
CODE_RULES = [
    # ----- JavaScript / TypeScript / React / Vue / Svelte
    ("xss-dangerous-html", "HTML injecté sans échappement (dangerouslySetInnerHTML)", "medium", JS,
     r"dangerouslySetInnerHTML", _FIX_XSS),
    ("xss-inner-html", "Affectation de innerHTML / outerHTML", "medium", JS,
     r"\.(?:inner|outer)HTML\s*\+?=(?!\s*[\"'][^\"'`$]*[\"']\s*;?\s*$)|\.insertAdjacentHTML\(", _FIX_XSS),
    ("xss-document-write", "Utilisation de document.write", "low", JS + (".html", ".htm"),
     r"document\.write(?:ln)?\(", "Construisez le DOM avec textContent / createElement plutôt que document.write."),
    ("xss-v-html", "HTML brut dans un template (v-html / {@html})", "medium", (".vue", ".svelte", ".html"),
     r"\bv-html\s*=|\{@html\s", _FIX_XSS),
    ("code-from-string", "Code exécuté depuis une chaîne (new Function / setTimeout)", "low", JS,
     r"new\s+Function\s*\(|set(?:Timeout|Interval)\(\s*[\"'`]", "Passez une fonction, jamais une chaîne de code."),
    ("token-in-web-storage", "Jeton d'authentification dans localStorage", "medium", JS,
     r"(?:localStorage|sessionStorage)\.setItem\(\s*[\"'`][^\"'`]*(?:token|jwt|auth|session|password|secret)", _FIX_STORAGE),
    ("postmessage-wildcard", "postMessage vers n'importe quelle origine (\"*\")", "medium", JS,
     r"postMessage\([^)]*,\s*[\"']\*[\"']", "Précisez l'origine exacte du destinataire, et vérifiez event.origin à la réception."),
    ("jwt-alg-none", "JWT accepté sans signature (algorithme none)", "high", JS + PY + PHP + JVM + GO,
     r"algorithms?[\"']?\s*[:=]\s*\[?\s*[\"']none[\"']", "Imposez un algorithme signé (HS256 avec un secret fort, RS256/ES256)."),
    ("cookie-insecure", "Cookie configuré sans protection (httpOnly/secure à false)", "medium", JS,
     r"\b(?:httpOnly|secure)\s*:\s*false\b", "Cookies de session : httpOnly: true, secure: true, sameSite: 'lax'."),
    ("command-injection", "Commande système construite dynamiquement", "high", JS,
     r"(?:(?<![\w.])|(?:child_process|childProcess|cp)\.)exec(?:Sync)?\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)", _FIX_CMD),
    ("reflected-xss", "Donnée de la requête renvoyée telle quelle (XSS réfléchi)", "high", JS,
     r"res\.(?:send|write|end)\(\s*[^)]*" + _USER_JS, _FIX_XSS),
    ("open-redirect", "Redirection vers une adresse fournie par l'utilisateur", "medium", JS,
     r"res\.redirect\(\s*(?:\d{3}\s*,\s*)?" + _USER_JS, _FIX_REDIRECT),
    ("nosql-injection", "Requête NoSQL construite depuis la requête HTTP", "high", JS,
     r"\.(?:find|findOne|updateOne|deleteOne|deleteMany|updateMany|countDocuments)\(\s*" + _USER_JS + r"|\$where\s*:",
     "Validez le type des champs (pas d'objet là où une chaîne est attendue) : express-mongo-sanitize, zod, joi."),
    ("ssrf", "URL appelée par le serveur choisie par l'utilisateur (SSRF)", "high", JS,
     r"(?:fetch|axios(?:\.\w+)?|got|request|http\.get|https\.get)\(\s*" + _USER_JS, _FIX_SSRF),
    ("weak-random-token", "Jeton ou code généré avec un aléa prévisible", "medium", JS,
     r"(?:token|secret|password|otp|salt|nonce|reset|code)\w*\s*[:=][^;\n]*Math\.random\(",
     "Utilisez crypto.randomUUID() / crypto.getRandomValues() (navigateur) ou crypto.randomBytes() (Node)."),

    # ----- PHP
    ("reflected-xss", "Entrée utilisateur affichée sans échappement (XSS)", "high", PHP,
     r"(?:\becho\b|\bprint\b|<\?=)\s*\(?\s*(?:" + _USER_PHP + r"|\$_SERVER\[\s*[\"'](?:PHP_SELF|REQUEST_URI|QUERY_STRING))",
     _FIX_XSS),
    ("sql-injection", "Requête SQL construite avec une entrée utilisateur", "critical", PHP,
     r"(?:mysqli?_query|pg_query|->query|->exec|->prepare)\s*\([^;]*" + _USER_PHP
     + r"|[\"'](?:SELECT|INSERT|UPDATE|DELETE)\b[^;]*" + _USER_PHP, _FIX_SQL),
    ("command-injection", "Commande système avec une entrée utilisateur", "critical", PHP,
     r"(?<![>:])(?:\bsystem|\bexec|shell_exec|passthru|popen|proc_open)\s*\([^;]*" + _USER_PHP + r"|`[^`]*" + _USER_PHP, _FIX_CMD),
    ("file-inclusion", "Inclusion de fichier contrôlée par l'utilisateur (LFI/RFI)", "critical", PHP,
     r"\b(?:include|require)(?:_once)?\b\s*\(?[^;]*" + _USER_PHP,
     "N'incluez jamais un chemin issu de la requête : utilisez une table de correspondance (liste blanche)."),
    ("unsafe-deserialization", "unserialize() sur une entrée utilisateur", "high", PHP,
     r"unserialize\s*\([^;]*" + _USER_PHP, "Utilisez json_decode : unserialize permet l'exécution de code (POP chains)."),
    ("php-extract", "extract() sur les variables de la requête", "high", PHP,
     r"extract\s*\(\s*" + _USER_PHP, "extract() permet d'écraser n'importe quelle variable : lisez les champs un par un."),
    ("ssrf", "URL ou fichier ouvert depuis une entrée utilisateur", "high", PHP,
     r"(?:file_get_contents|curl_init|fopen|readfile|simplexml_load_file)\s*\([^;]*" + _USER_PHP, _FIX_SSRF),
    ("open-redirect", "Redirection vers une adresse fournie par l'utilisateur", "medium", PHP,
     r"header\s*\(\s*[\"']Location:[^;]*" + _USER_PHP, _FIX_REDIRECT),
    ("php-mysql-legacy", "Extension mysql_* obsolète", "medium", PHP,
     r"\bmysql_(?:query|connect|real_escape_string)\s*\(", "Passez à PDO ou mysqli avec requêtes préparées (mysql_* est retiré depuis PHP 7)."),
    ("display-errors", "Affichage des erreurs PHP activé", "medium", PHP + SERVER_CONF,
     r"ini_set\(\s*[\"']display_errors[\"']\s*,\s*[\"']?(?:1|on|true)|^\s*(?:php_flag\s+)?display_errors\s*=?\s*on\b",
     "Les erreurs révèlent chemins, requêtes SQL et versions : display_errors=Off en production, log_errors=On."),
    ("cookie-insecure", "Cookie de session PHP sans protection", "medium", PHP + SERVER_CONF,
     r"session\.cookie_(?:secure|httponly)[\"']?\s*[,=]\s*[\"']?(?:0|false|off)\b",
     "session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax."),

    # ----- Python (Flask, Django, FastAPI)
    ("template-injection", "render_template_string (injection de template)", "medium", PY,
     r"render_template_string\(", "Utilisez des fichiers de template ; ne construisez jamais un template avec une entrée utilisateur."),
    ("xss-mark-safe", "Échappement HTML désactivé (mark_safe / Markup)", "low", PY,
     r"\bmark_safe\(|\bMarkup\(", _FIX_XSS),
    ("csrf-disabled", "Protection CSRF désactivée", "medium", PY,
     r"@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False",  # velora:ignore
     "Gardez la protection CSRF sur toute route qui modifie des données avec une session par cookie."),
    ("cookie-insecure", "Cookie de session sans Secure/HttpOnly", "medium", PY,
     r"(?:SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE)\s*=\s*False",
     "En production : SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True, CSRF_COOKIE_SECURE = True."),
    ("jwt-no-verify", "JWT décodé sans vérification de signature", "high", PY,
     r"jwt\.decode\([^)]*verify\s*=\s*False|[\"']verify_signature[\"']\s*:\s*False",
     "Vérifiez toujours la signature (jwt.decode(token, cle, algorithms=[\"HS256\"]))."),
    ("command-injection", "Commande système avec une donnée de la requête", "high", PY,
     r"(?:subprocess\.\w+|os\.system|os\.popen)\([^)\n]*" + _USER_PY, _FIX_CMD),
    ("ssrf", "URL appelée par le serveur choisie par l'utilisateur (SSRF)", "high", PY,
     r"(?:requests|httpx|urllib\.request)\.(?:get|post|put|delete|head|request|urlopen)\(\s*" + _USER_PY, _FIX_SSRF),
    ("path-traversal", "Fichier ouvert depuis un chemin fourni par l'utilisateur", "high", PY,
     r"(?<!\w)(?:send_file|open|FileResponse)\(\s*[^)\n]*" + _USER_PY,
     "Utilisez send_from_directory / un identifiant interne, jamais un chemin brut venant de la requête."),
    ("open-redirect", "Redirection vers une adresse fournie par l'utilisateur", "medium", PY,
     r"(?:redirect|RedirectResponse|HttpResponseRedirect)\(\s*" + _USER_PY, _FIX_REDIRECT),
    ("weak-random-token", "Jeton ou code généré avec un aléa prévisible", "medium", PY,
     r"(?:token|secret|password|otp|salt|nonce|reset|code)\w*\s*=[^\n]*\brandom\.(?:random|randint|choice|choices|getrandbits)\(",
     "Utilisez le module secrets (secrets.token_urlsafe())."),

    # ----- Templates
    ("xss-unescaped-template", "Sortie non échappée dans un template", "medium",
     (".ejs", ".hbs", ".handlebars", ".twig", ".jinja", ".jinja2", ".j2", ".html", ".njk", ".erb", ".cshtml", ".liquid"),
     r"<%-|<%==|\{\{\{|\|\s*raw\b|\|\s*safe\b|\{%\s*autoescape\s+(?:off|false)|\.html_safe\b|@Html\.Raw\(",
     _FIX_XSS),

    # ----- C / C++
    ("buffer-overflow", "gets() : débordement de tampon garanti", "high", CPP,
     r"\bgets\s*\(", "Utilisez fgets(buf, sizeof buf, stdin) ou std::getline."),
    ("buffer-overflow", "Copie de chaîne sans limite (strcpy / strcat / sprintf)", "medium", CPP,
     r"\b(?:strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat)\s*\(",
     "Utilisez snprintf, strlcpy/strncpy avec la taille du tampon, ou std::string."),
    ("buffer-overflow", "scanf(\"%s\") sans largeur maximale", "medium", CPP,
     r"\bscanf\s*\(\s*\"[^\"]*%s", "Indiquez une largeur (%63s) ou lisez avec fgets."),
    ("format-string", "Chaîne de format contrôlable (printf(variable))", "medium", CPP,
     r"\b(?:printf|syslog\s*\(\s*\w+\s*,)\s*\(?\s*[A-Za-z_][\w\->.\[\]]*\s*\)\s*;",
     "Écrivez printf(\"%s\", variable) : une chaîne contenant %n ou %x permet lecture/écriture mémoire."),
    ("command-injection", "Commande système exécutée depuis une variable", "medium", CPP,
     r"\b(?:system|popen)\s*\(\s*(?!\")", "Utilisez execve/posix_spawn avec arguments séparés, ou validez par liste blanche."),

    # ----- Java / Kotlin / C# / Go / Ruby
    ("sql-injection", "Requête SQL construite par concaténation", "high", JVM + CS,
     r"(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|SqlCommand|FromSqlRaw|ExecuteSqlRaw)"
     r"\s*\(\s*(?:\$?\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*(?:\"\s*\+|\{))", _FIX_SQL),
    ("sql-injection", "Requête SQL construite avec fmt.Sprintf", "high", GO,
     r"\.(?:Query|QueryRow|Exec)(?:Context)?\([^)\n]*(?:fmt\.Sprintf\(|\"(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+)", _FIX_SQL),
    ("command-injection", "Commande système (Runtime.exec)", "medium", JVM,
     r"Runtime\.getRuntime\(\)\.exec\(", "Utilisez ProcessBuilder avec une liste d'arguments validés."),
    ("xss-unescaped-template", "Sortie HTML non échappée", "medium", RB + CS,
     r"\.html_safe\b|\braw\(|Html\.Raw\(", _FIX_XSS),
    ("sql-injection", "Requête SQL avec interpolation de params", "high", RB,
     r"\.(?:where|find_by_sql|order|joins)\(\s*\"[^\"]*#\{params", _FIX_SQL),

    # ----- Configuration serveur (Apache, Nginx, IIS)
    ("directory-listing", "Listing des répertoires activé", "medium", SERVER_CONF,
     r"^\s*autoindex\s+on\b|^\s*Options\b(?![^\n]*-Indexes)[^\n]*\bIndexes\b|directoryBrowse\s+enabled=\"true\"",
     "Désactivez-le (autoindex off / Options -Indexes) : il expose tous les fichiers d'un dossier."),
    ("server-version", "Version du serveur annoncée", "low", SERVER_CONF,
     r"^\s*server_tokens\s+on\b|^\s*ServerSignature\s+On\b|^\s*ServerTokens\s+(?:Full|OS)\b|^\s*expose_php\s*=\s*On\b",
     "server_tokens off / ServerTokens Prod / expose_php=Off : ne facilitez pas la recherche de failles connues."),
    ("weak-tls", "Protocole TLS obsolète autorisé", "high", SERVER_CONF,
     r"ssl_protocols[^;\n]*\b(?:SSLv[23]|TLSv1(?:\.1)?)(?![.\d])|SSLProtocol[^\n]*[+\s](?:SSLv3|TLSv1(?:\.1)?)(?![.\d])",
     "N'autorisez que TLS 1.2 et 1.3 (ssl_protocols TLSv1.2 TLSv1.3;)."),
    ("debug-enabled", "Erreurs détaillées ou débogage activés (IIS/ASP.NET)", "medium", ("web.config",),
     r"<customErrors\s+mode=\"Off\"|<compilation[^>]*debug=\"true\"",
     "customErrors mode=\"RemoteOnly\" et compilation debug=\"false\" en production."),
]


def _compile():
    out = []
    for rid, title, sev, exts, rx, fix in CODE_RULES:
        flags = re.M if rid in {"weak-tls", "directory-listing", "server-version"} else re.M | re.I
        out.append((rid, title, sev, exts, re.compile(rx, flags), fix))
    return out


_COMPILED = _compile()


def _matches_ext(lower: str, exts: tuple[str, ...]) -> bool:
    name = lower.rsplit("/", 1)[-1]
    return lower.endswith(exts) or name in exts


def check_file(rel: str, text: str) -> list[Finding]:
    lower = rel.lower()
    lines = text.splitlines()
    findings = []
    for rid, title, sev, exts, regex, fix in _COMPILED:
        if not _matches_ext(lower, exts):
            continue
        hits = []
        for m in regex.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            if line <= len(lines) and "velora:ignore" in lines[line - 1]:
                continue
            if not hits or hits[-1] != line:
                hits.append(line)
        if hits:
            findings.append(Finding("web", rid, title, sev, rel, hits[0], detail=_occurrences(hits), fix=fix))
    if lower.endswith(MARKUP):
        findings += _check_markup(rel, text)
    return findings


def _occurrences(lines: list[int]) -> str:
    if len(lines) == 1:
        return ""
    shown = ", ".join(map(str, lines[:8])) + ("…" if len(lines) > 8 else "")
    return f"{len(lines)} occurrences (lignes {shown})"


# --------------------------------------------------------------------------- HTML

_FORM = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']((?:https?:)?//[^\"']+)[\"'][^>]*>", re.I)
_MIXED = re.compile(r"<(?:script|iframe|link|img|source|video|audio|embed)\b[^>]*\b(?:src|href)\s*=\s*[\"']"
                    r"(http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\"']+)", re.I)
_CSRF_HINT = re.compile(r"csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|wp_nonce|_wpnonce|"
                        r"nonce|@csrf|csrf_field|csrf_token|antiforgery", re.I)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _check_markup(rel: str, text: str) -> list[Finding]:
    out = []
    insecure_actions, missing_csrf = [], []
    for m in _FORM.finditer(text):
        attrs, body = m.group(1), m.group(2)
        if re.search(r"action\s*=\s*[\"']http://(?!localhost|127\.0\.0\.1)", attrs, re.I):
            insecure_actions.append(_line(text, m.start()))
        if re.search(r"method\s*=\s*[\"']?post", attrs, re.I) and not _CSRF_HINT.search(body + attrs):
            missing_csrf.append(_line(text, m.start()))
    if insecure_actions:
        out.append(Finding("web", "form-over-http", "Formulaire envoyé en HTTP non chiffré", "high", rel,
                           insecure_actions[0], detail=_occurrences(insecure_actions),
                           fix="Envoyez les formulaires en https:// : sinon identifiants et données circulent en clair."))
    if missing_csrf:
        out.append(Finding("web", "form-no-csrf", "Formulaire POST sans jeton anti-CSRF visible", "low", rel,
                           missing_csrf[0], detail=_occurrences(missing_csrf),
                           fix="Ajoutez un jeton CSRF (@csrf, {% csrf_token %}, csurf…) ou des cookies SameSite=Lax/Strict "
                               "si le formulaire modifie des données d'un utilisateur connecté."))
    mixed = [_line(text, m.start()) for m in _MIXED.finditer(text)]
    if mixed:
        out.append(Finding("web", "mixed-content", "Ressource chargée en HTTP (contenu mixte)", "medium", rel,
                           mixed[0], detail=_occurrences(mixed),
                           fix="Chargez toutes les ressources en https:// : un script en HTTP peut être remplacé en route."))
    no_sri = [_line(text, m.start()) for m in _SCRIPT_SRC.finditer(text) if "integrity" not in m.group(0).lower()]
    if no_sri:
        out.append(Finding("web", "missing-sri", "Script externe sans contrôle d'intégrité (SRI)", "low", rel,
                           no_sri[0], detail=_occurrences(no_sri),
                           fix="Ajoutez integrity=\"sha384-…\" crossorigin=\"anonymous\" (srihash.org), ou hébergez le "
                               "script vous-même : si le CDN est compromis, votre site l'est aussi."))
    return out


# --------------------------------------------------------------------------- projet

STACK_RULES = [
    ("React", lambda f, d: "react" in d and "react-native" not in d),
    ("Next.js", lambda f, d: "next" in d),
    ("Vue", lambda f, d: "vue" in d or any(p.endswith(".vue") for p in f)),
    ("Nuxt", lambda f, d: "nuxt" in d),
    ("Svelte", lambda f, d: "svelte" in d or "@sveltejs/kit" in d),
    ("Angular", lambda f, d: "@angular/core" in d),
    ("Express", lambda f, d: "express" in d),
    ("Fastify", lambda f, d: "fastify" in d),
    ("NestJS", lambda f, d: "@nestjs/core" in d),
    ("React Native", lambda f, d: "react-native" in d),
    ("Expo", lambda f, d: "expo" in d),
    ("Electron", lambda f, d: "electron" in d),
    ("PHP", lambda f, d: any(p.endswith(PHP) for p in f)),
    ("WordPress", lambda f, d: any(p.endswith("wp-config.php") or "/wp-content/" in "/" + p for p in f)),
    ("Laravel", lambda f, d: "artisan" in f or "laravel/framework" in d),
    ("Symfony", lambda f, d: "symfony/framework-bundle" in d),
    ("Django", lambda f, d: "django" in d or any(p.endswith("manage.py") for p in f)),
    ("Flask", lambda f, d: "flask" in d),
    ("FastAPI", lambda f, d: "fastapi" in d),
    ("C / C++", lambda f, d: any(p.endswith(CPP) for p in f)),
    ("Java / Kotlin", lambda f, d: any(p.endswith((".java", ".kt")) for p in f)),
    (".NET", lambda f, d: any(p.endswith((".csproj", ".cs")) for p in f)),
    ("Go", lambda f, d: "go.mod" in f),
    ("Ruby", lambda f, d: "Gemfile" in f),
    ("Android", lambda f, d: any(p.endswith("AndroidManifest.xml") for p in f)),
    ("iOS", lambda f, d: any(p.endswith("Info.plist") or ".xcodeproj/" in p for p in f)),
    ("Flutter", lambda f, d: "pubspec.yaml" in f),
    ("HTML / CSS", lambda f, d: any(p.endswith((".html", ".htm")) for p in f)),
]


def _declared_deps(texts: list[tuple[str, object, str]]) -> set[str]:
    names: set[str] = set()
    for rel, _, text in texts:
        name = rel.rsplit("/", 1)[-1]
        if name in ("package.json", "composer.json"):
            try:
                data = json.loads(text)
            except ValueError:
                continue
            for key in ("dependencies", "devDependencies", "require", "require-dev"):
                if isinstance(data.get(key), dict):
                    names |= {k.lower() for k in data[key]}
        elif name.startswith("requirements") and name.endswith(".txt") or name in ("pyproject.toml", "Pipfile"):
            names |= {m.group(1).lower() for m in re.finditer(r"^\s*[\"']?([A-Za-z][\w.\-]*)", text, re.M)}
        elif name == "pubspec.yaml":
            names.add("flutter")
    return names


def detect_stack(texts: list[tuple[str, object, str]], all_files: list[str]) -> list[str]:
    deps = _declared_deps(texts)
    files = set(all_files) | {p.rsplit("/", 1)[-1] for p in all_files}
    return [label for label, test in STACK_RULES if test(files, deps)]


_SERVER_CODE = JS + PHP + PY + JVM + CS + GO + RB
# Indices qu'un serveur traite lui-même des identifiants (route de connexion, lecture d'un mot de passe).
_AUTH = re.compile(r"(?:app|router|server|fastify)\.post\(\s*[\"'`][^\"'`]*(?:login|signin|sign-in|auth|register|signup)|"
                   r"@(?:app|bp|router|\w+)\.(?:route|post)\(\s*[\"'][^\"']*(?:login|signin|auth|register|signup)|"
                   r"Route::post\(\s*[\"'][^\"']*(?:login|register)|"
                   r"(?:req\.body|request\.(?:form|json|data|POST)|\$_POST)\s*(?:\.|\[\s*[\"'])pass(?:word)?|"
                   r"password_verify|check_password|passport\.authenticate|signInWithPassword|"
                   r"PasswordEncoder|UsernamePasswordAuthentication", re.I)
_AUTH_PROVIDER = re.compile(r"next-auth|@auth/|@clerk/|auth0|firebase/auth|firebase_auth|@supabase/|supabase\.auth|"
                            r"keycloak|amazon-cognito|aws-amplify|lucia|better-auth|django-allauth|social_django", re.I)
_RATE_LIMIT = re.compile(r"express-rate-limit|rate-limiter-flexible|@nestjs/throttler|express-slow-down|"
                         r"flask[_-]limiter|slowapi|django[_-]ratelimit|django-axes|axes\.|ratelimit|RateLimiter|"
                         r"throttle:|ThrottleRequests|limit_req|rack-attack|Bucket4j|AddRateLimiter|fail2ban|@fastify/rate-limit",
                         re.I)
_STRONG_HASH = re.compile(r"bcrypt|argon2|scrypt|pbkdf2|password_hash\s*\(|make_password|generate_password_hash|"
                          r"passlib|Hash::make|PasswordEncoder|PasswordHasher|has_secure_password|hashpw|crypt\(", re.I)
_SESSION = re.compile(r"express-session|cookie-session|@fastify/session|@fastify/secure-session", re.I)
_CSRF_LIB = re.compile(r"csurf|csrf-csrf|lusca|tiny-csrf|@fastify/csrf|csrf-sync|double-csrf", re.I)


def check_project(texts: list[tuple[str, object, str]], stack: list[str]) -> list[Finding]:
    """Contrôles transverses : ce qui manque dans le projet plutôt que ce qui est mal écrit."""
    findings = []
    code = [(rel, text) for rel, _, text in texts if rel.lower().endswith(_SERVER_CODE)
            and not re.search(r"(^|/)(tests?|__tests__|spec|e2e|fixtures?)/|\.(test|spec)\.", rel)]
    corpus = "\n".join(text for _, _, text in texts)
    server_side = [(rel, t) for rel, t in code if not rel.lower().endswith((".jsx", ".tsx", ".vue", ".svelte"))]
    has_auth = any(_AUTH.search(t) for _, t in server_side)
    uses_provider = bool(_AUTH_PROVIDER.search(corpus))

    if has_auth and not _RATE_LIMIT.search(corpus):
        findings.append(Finding(
            "web", "no-rate-limit", "Aucune limitation des tentatives de connexion détectée",
            "low" if uses_provider else "medium",
            detail="Sans limite, un attaquant peut tester des milliers de mots de passe (force brute, credential stuffing).",
            fix="Express : express-rate-limit · Flask : Flask-Limiter · Django : django-axes · Laravel : middleware "
                "throttle · ou limite au niveau du proxy (Nginx limit_req, Cloudflare)."))
    if has_auth and not uses_provider and not _STRONG_HASH.search(corpus):
        findings.append(Finding(
            "web", "no-password-hashing", "Aucun hachage de mot de passe robuste détecté", "medium",
            detail="Le projet gère des connexions mais aucune bibliothèque bcrypt / Argon2 / scrypt n'apparaît.",
            fix="Hachez les mots de passe avec Argon2id ou bcrypt (password_hash en PHP, bcrypt/argon2 en Node, "
                "argon2-cffi ou make_password en Python). Jamais en clair, jamais en MD5/SHA-1."))
    if "Express" in stack and "helmet" not in corpus.lower():
        findings.append(Finding(
            "web", "no-security-headers", "Express sans en-têtes de sécurité (helmet absent)", "low",
            fix="npm install helmet puis app.use(helmet()) : CSP, HSTS, anti-clickjacking, nosniff en une ligne."))
    if _SESSION.search(corpus) and not _CSRF_LIB.search(corpus) and "sameSite" not in corpus:
        findings.append(Finding(
            "web", "no-csrf", "Sessions par cookie sans protection CSRF", "medium",
            fix="Ajoutez csrf-csrf / csrf-sync, ou au minimum cookie: { sameSite: 'lax' } sur la session."))
    for rel, text in code:
        if rel.endswith("settings.py") and "INSTALLED_APPS" in text:
            missing = [k for k in ("SECURE_HSTS_SECONDS", "SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE",
                                   "SECURE_SSL_REDIRECT") if k not in text]
            if missing:
                findings.append(Finding(
                    "web", "django-https", "Réglages de sécurité Django absents", "low", rel,
                    detail="Manquants : " + ", ".join(missing),
                    fix="Ajoutez-les pour la production (voir « python manage.py check --deploy »)."))
    return findings
