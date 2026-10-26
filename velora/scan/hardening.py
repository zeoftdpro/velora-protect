"""Configurations de durcissement prêtes à copier (en-têtes HTTP de sécurité), par plateforme."""

from __future__ import annotations

import json

HEADERS = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; object-src 'none'; "
                                "base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
]

CSP_NOTE = ("La Content-Security-Policy proposée est stricte : adaptez-la à vos scripts, polices et API tierces. "
            "Testez-la d'abord sous le nom Content-Security-Policy-Report-Only pour voir ce qu'elle bloquerait.")


def _nginx() -> str:
    lines = [f'add_header {k} "{v}" always;' for k, v in HEADERS]
    return ("# Dans le bloc server { … } (HTTPS)\nserver_tokens off;\nssl_protocols TLSv1.2 TLSv1.3;\n"
            + "\n".join(lines) + "\n\n# Redirection HTTP → HTTPS\nserver {\n    listen 80;\n    server_name exemple.fr;\n"
            "    return 301 https://$host$request_uri;\n}\n\n# Fichiers sensibles\nlocation ~ /\\.(?!well-known) { deny all; }")


def _apache() -> str:
    lines = [f'    Header always set {k} "{v}"' for k, v in HEADERS]
    return ("# .htaccess à la racine du site\nOptions -Indexes\nServerSignature Off\n\nRewriteEngine On\n"
            "RewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n"
            "<IfModule mod_headers.c>\n" + "\n".join(lines) + "\n    Header unset X-Powered-By\n</IfModule>\n\n"
            "# Bloque .env, .git, sauvegardes…\n<FilesMatch \"^\\.|\\.(bak|sql|zip|log|ini|sh)$\">\n    Require all denied\n"
            "</FilesMatch>")


def _netlify() -> str:
    return "# Fichier _headers à la racine du dossier publié\n/*\n" + "\n".join(f"  {k}: {v}" for k, v in HEADERS)


def _vercel() -> str:
    conf = {"headers": [{"source": "/(.*)", "headers": [{"key": k, "value": v} for k, v in HEADERS]}]}
    return "// vercel.json\n" + json.dumps(conf, indent=2)


def _nextjs() -> str:
    items = ",\n".join(f"          {{ key: '{k}', value: \"{v}\" }}" for k, v in HEADERS)
    return ("// next.config.js\nmodule.exports = {\n  poweredByHeader: false,\n  productionBrowserSourceMaps: false,\n"
            "  async headers() {\n    return [{\n      source: '/(.*)',\n      headers: [\n" + items
            + "\n      ],\n    }];\n  },\n};")


def _express() -> str:
    return ("// npm install helmet express-rate-limit\nconst helmet = require('helmet');\n"
            "const rateLimit = require('express-rate-limit');\n\napp.disable('x-powered-by');\napp.use(helmet());\n"
            "app.use('/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 }));\n"
            "app.use(session({\n  secret: process.env.SESSION_SECRET,\n"
            "  cookie: { httpOnly: true, secure: true, sameSite: 'lax' },\n  resave: false, saveUninitialized: false,\n}));")


def _php() -> str:
    lines = [f"header(\"{k}: {v}\");" for k, v in HEADERS]
    return ("<?php\n// Au début de chaque page (ou dans un fichier inclus partout)\nheader_remove('X-Powered-By');\n"
            + "\n".join(lines) + "\n\nini_set('display_errors', '0');\nini_set('session.cookie_secure', '1');\n"
            "ini_set('session.cookie_httponly', '1');\nini_set('session.cookie_samesite', 'Lax');\n\n"
            "// Mots de passe : password_hash($mdp, PASSWORD_ARGON2ID) / password_verify()\n"
            "// SQL : $pdo->prepare('SELECT * FROM users WHERE email = ?')->execute([$email]);")


def _django() -> str:
    return ("# settings.py (production)\nDEBUG = False\nALLOWED_HOSTS = ['exemple.fr']\nSECURE_SSL_REDIRECT = True\n"
            "SECURE_HSTS_SECONDS = 63072000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSESSION_COOKIE_SECURE = True\n"
            "CSRF_COOKIE_SECURE = True\nSECURE_CONTENT_TYPE_NOSNIFF = True\nX_FRAME_OPTIONS = 'DENY'\n"
            "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'\n# Vérification : python manage.py check --deploy")


def _flask() -> str:
    return ("# pip install flask-talisman flask-limiter flask-wtf\nfrom flask_talisman import Talisman\n"
            "from flask_limiter import Limiter\nfrom flask_limiter.util import get_remote_address\n"
            "from flask_wtf.csrf import CSRFProtect\n\nTalisman(app, force_https=True, strict_transport_security=True)\n"
            "CSRFProtect(app)\nlimiter = Limiter(get_remote_address, app=app)\n"
            "app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')\n\n"
            "@app.post('/login')\n@limiter.limit('10 per 15 minutes')\ndef login(): ...")


def _iis() -> str:
    lines = "\n".join(f'        <add name="{k}" value="{v}" />' for k, v in HEADERS)
    return ("<!-- web.config -->\n<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n"
            "        <remove name=\"X-Powered-By\" />\n" + lines + "\n    </customHeaders>\n  </httpProtocol>\n"
            "  <directoryBrowse enabled=\"false\" />\n</system.webServer>")


def _cloudflare() -> str:
    lines = "\n".join(f"  Définir (statique)  {k} = {v}" for k, v in HEADERS)
    return ("# Tableau de bord Cloudflare → votre domaine\n# SSL/TLS → Certificats Edge : « Toujours utiliser HTTPS » = activé,\n"
            "#   « Version TLS minimale » = TLS 1.2, HSTS = activé (6 mois minimum)\n"
            "# Règles → Transform Rules → Modifier l'en-tête de réponse → toutes les requêtes :\n" + lines)


PLATFORMS = {
    "cloudflare": ("Cloudflare", "Transform Rules", _cloudflare),
    "nginx": ("Nginx", "nginx.conf", _nginx),
    "apache": ("Apache / hébergement mutualisé (OVH, o2switch, Hostinger…)", ".htaccess", _apache),
    "netlify": ("Netlify", "_headers", _netlify),
    "vercel": ("Vercel", "vercel.json", _vercel),
    "nextjs": ("Next.js", "next.config.js", _nextjs),
    "express": ("Node.js / Express", "app.js", _express),
    "php": ("PHP", "securite.php", _php),
    "django": ("Django", "settings.py", _django),
    "flask": ("Flask", "app.py", _flask),
    "iis": ("IIS / ASP.NET", "web.config", _iis),
}

# Correspondance entre les technologies détectées dans le code et les plateformes ci-dessus.
STACK_TO_PLATFORM = {"Next.js": "nextjs", "Express": "express", "PHP": "php", "WordPress": "apache",
                     "Laravel": "php", "Django": "django", "Flask": "flask", ".NET": "iis", "HTML / CSS": "netlify"}


def suggest(platforms=(), stack=()) -> list[dict]:
    keys = [p for p in platforms if p in PLATFORMS]
    keys += [STACK_TO_PLATFORM[s] for s in stack if s in STACK_TO_PLATFORM]
    if not keys:
        keys = ["nginx", "apache", "netlify"]
    out, seen = [], set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        label, filename, build = PLATFORMS[key]
        out.append({"platform": key, "label": label, "filename": filename, "content": build()})
    return out
