"""Détection de mauvaises configurations et de pratiques de code risquées."""

from __future__ import annotations

import re
from pathlib import Path

from velora.core import gitutil
from velora.scan.models import Finding

SENSITIVE_FILE_PATTERNS = [
    (re.compile(r"(^|/)\.env(\.[\w\-]+)?$"), "Fichier .env"),
    (re.compile(r"\.(pem|key|p12|pfx|jks|keystore|ppk)$", re.I), "Clé ou certificat privé"),
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), "Clé SSH privée"),
    (re.compile(r"(^|/)(credentials|service[-_]account)[\w\-]*\.json$", re.I), "Fichier d'identifiants"),
    (re.compile(r"\.(sqlite3?|db)$", re.I), "Base de données"),
    (re.compile(r"(^|/)\.(npmrc|pypirc|netrc|htpasswd)$"), "Fichier d'authentification"),
]
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")

# (id, titre, sévérité, extensions concernées, regex, conseil)
CODE_RULES = [
    ("tls-verify-disabled", "Vérification TLS désactivée", "high", (".py",),
     r"verify\s*=\s*False", "Ne désactivez jamais la vérification des certificats en production."),
    ("tls-verify-disabled", "Vérification TLS désactivée", "high", (".js", ".ts", ".mjs", ".cjs"),
     r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
     "Ne désactivez jamais la vérification des certificats en production."),
    ("tls-verify-disabled", "Vérification TLS désactivée", "high", (".go",),
     r"InsecureSkipVerify\s*:\s*true", "Ne désactivez jamais la vérification des certificats en production."),
    ("debug-enabled", "Mode debug activé", "medium", (".py",),
     r"^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True",
     "Le mode debug expose des traces et parfois une console d'exécution : lisez-le depuis l'environnement."),
    ("allowed-hosts-wildcard", "ALLOWED_HOSTS ouvert à tous", "medium", (".py",),
     r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]", "Listez explicitement les domaines autorisés."),
    ("cors-wildcard", "CORS ouvert à toutes les origines", "medium",
     (".py", ".js", ".ts", ".mjs", ".cjs", ".go", ".php", ".java", ".cs", ".conf", ".rb"),
     r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]|CORS_(ORIGIN|ALLOW)_ALL(_ORIGINS)?\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*",
     "Restreignez les origines autorisées, surtout si des cookies/identifiants sont envoyés."),
    ("unsafe-yaml-load", "yaml.load sans chargeur sûr", "medium", (".py",),
     r"yaml\.load\((?![^)]*Loader\s*=\s*yaml\.(Safe|CSafe)Loader)(?![^)]*SafeLoader)",
     "Utilisez yaml.safe_load() : yaml.load peut exécuter du code arbitraire."),
    ("pickle-load", "Désérialisation pickle", "low", (".py",),
     r"pickle\.loads?\(", "Ne désérialisez jamais de données pickle non fiables (exécution de code)."),
    ("shell-injection", "Commande shell (risque d'injection)", "low", (".py",),
     r"shell\s*=\s*True|os\.system\(", "Passez les arguments en liste sans shell=True."),  # velora:ignore
    ("eval-usage", "Utilisation de eval()", "low", (".py", ".js", ".ts", ".php"),  # velora:ignore
     r"(?<![\w.])eval\s*\(", "Évitez eval() sur des données externes (exécution de code)."),
    ("sql-concat", "Requête SQL construite par concaténation", "medium", (".py", ".js", ".ts", ".php"),
     r"(execute|query)\s*\(\s*f?['\"](SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*(\+|%\s|\.format\()|execute\s*\(\s*f['\"](SELECT|INSERT|UPDATE|DELETE)[^'\"]*\{",
     "Utilisez des requêtes paramétrées (placeholders) pour éviter l'injection SQL."),
    ("weak-hash", "Hachage faible pour un mot de passe", "medium", (".py", ".js", ".ts", ".php"),
     r"(md5|sha1)\s*\([^)]*pass(word)?", "Utilisez bcrypt, scrypt ou Argon2 pour les mots de passe."),
]


def _rule_list():
    return [(rid, t, s, exts, re.compile(rx, re.I | re.M if rid != "debug-enabled" else re.M), fix)
            for rid, t, s, exts, rx, fix in CODE_RULES]


_COMPILED = _rule_list()


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def check_repository(root: Path, all_files: list[str]) -> list[Finding]:
    findings = []
    has_code = any(f.endswith((".py", ".js", ".ts", ".go", ".php", ".java", ".rb", ".rs", ".cs")) for f in all_files)
    if has_code and not (root / ".gitignore").exists():
        findings.append(Finding("config", "no-gitignore", "Aucun .gitignore à la racine", "medium",
                                fix="Ajoutez un .gitignore (modèles : github.com/github/gitignore) incluant .env, "
                                    "clés, bases locales et dossiers de build."))
    if has_code and not gitutil.is_repo(root):
        findings.append(Finding("config", "no-vcs", "Projet hors gestion de versions", "low",
                                fix="Initialisez git (git init) : historique, retour arrière et preuve d'évolution."))

    for rel in all_files:
        name = rel.rsplit("/", 1)[-1]
        if name.endswith(SAFE_ENV_SUFFIXES):
            continue
        for pattern, label in SENSITIVE_FILE_PATTERNS:
            if pattern.search(rel):
                tracked = gitutil.is_tracked(root, rel)
                findings.append(Finding(
                    "config", "sensitive-file", f"{label} non ignoré par git", "high" if tracked else "medium",
                    rel, detail="Déjà commité dans le dépôt !" if tracked else "Risque de commit accidentel.",
                    fix=f"Ajoutez « {rel} » au .gitignore" + (" puis : git rm --cached \"" + rel + "\" et révoquez "
                                                               "les secrets qu'il contient." if tracked else ".")))
                break

    for rel in all_files:
        parts = rel.split("/")
        if len(parts) > 2 and parts[-2] == ".git" and parts[0] in {"public", "static", "www", "htdocs", "wwwroot"}:
            findings.append(Finding("config", "exposed-git", "Dossier .git dans un répertoire public", "high", rel,
                                    fix="Supprimez-le : tout le code source et l'historique seraient téléchargeables."))
            break
    return findings


def check_file(rel: str, text: str) -> list[Finding]:
    findings = []
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]

    for rid, title, sev, exts, regex, fix in _COMPILED:
        if not lower.endswith(exts):
            continue
        m = regex.search(text)
        if m:
            line = _line_of(text, m.start())
            if "velora:ignore" in text.splitlines()[line - 1]:
                continue
            findings.append(Finding("config", rid, title, sev, rel, line, fix=fix))

    if name == "dockerfile" or name.endswith(".dockerfile") or name.startswith("dockerfile."):
        findings += _check_dockerfile(rel, text)
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        findings += _check_compose(rel, text)
    return findings


def _check_dockerfile(rel: str, text: str) -> list[Finding]:
    out = []
    lines = text.splitlines()
    if not re.search(r"^\s*USER\s+(?!root\b|0\b)\S+", text, re.M | re.I):
        out.append(Finding("config", "docker-root", "Conteneur exécuté en root", "medium", rel,
                           fix="Ajoutez un utilisateur non privilégié : RUN adduser … puis USER app."))
    for i, line in enumerate(lines, 1):
        m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.I)
        if m and m.group(1).lower() != "scratch" and "$" not in m.group(1):
            image = m.group(1)
            if image.endswith(":latest") or (":" not in image.rsplit("/", 1)[-1] and "@" not in image):
                out.append(Finding("config", "docker-latest", f"Image de base non versionnée ({image})", "low",
                                   rel, i, fix="Fixez une version précise (ex. python:3.12-slim) voire un digest."))
        if re.match(r"\s*(ENV|ARG)\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY)\S*[\s=]+\S+", line, re.I):
            out.append(Finding("config", "docker-secret", "Secret défini dans le Dockerfile", "high", rel, i,
                               fix="Les ENV/ARG restent lisibles dans l'image : utilisez les secrets BuildKit "
                                   "(--mount=type=secret) ou injectez-les à l'exécution."))
        if re.match(r"\s*ADD\s+https?://", line, re.I):
            out.append(Finding("config", "docker-add-url", "ADD depuis une URL distante", "low", rel, i,
                               fix="Préférez RUN curl + vérification de somme de contrôle, ou COPY."))
    return out


def _check_compose(rel: str, text: str) -> list[Finding]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"\s*privileged:\s*true", line, re.I):
            out.append(Finding("config", "compose-privileged", "Conteneur en mode privileged", "high", rel, i,
                               fix="Retirez privileged et n'accordez que les capabilities nécessaires (cap_add)."))
        m = re.match(r"""\s*-\s*["']?(?:0\.0\.0\.0:)?(5432|3306|27017|6379|9200|11211|5672):\d+""", line)
        if m:
            out.append(Finding("config", "compose-db-exposed", f"Port de base de données {m.group(1)} exposé", "medium",
                               rel, i, fix="Ne publiez pas ce port, ou liez-le à 127.0.0.1 (\"127.0.0.1:5432:5432\")."))
    return out
