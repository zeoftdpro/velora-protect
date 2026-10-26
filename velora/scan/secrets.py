"""Détection de secrets (clés API, tokens, mots de passe, clés privées) dans le code."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from velora.scan.models import Finding

# Ajouter ce marqueur en commentaire sur une ligne pour l'exclure (faux positif assumé).
IGNORE_MARKER = "velora:ignore"

CONFIG_EXTENSIONS = (".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml")

_PLACEHOLDER_HINTS = (
    "xxx", "your", "example", "changeme", "change_me", "change-me", "placeholder", "dummy",
    "sample", "<", ">", "${", "{{", "%s", "{0}", "process.env", "os.environ", "getenv",
    "****", "...", "redacted", "todo", "here", "fake", "insert", "replace", "lorem",
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def looks_like_real_secret(value: str) -> bool:
    low = value.lower()
    if any(hint in low for hint in _PLACEHOLDER_HINTS) or value.startswith("$"):
        return False
    if len(set(value)) <= 3:
        return False
    # Un identifiant ou une constante (ex. "password_field", "API_KEY") n'est pas un secret.
    if re.fullmatch(r"[a-z_.\-]+", value) or re.fullmatch(r"[A-Z_.\-]+", value):
        return False
    if value.startswith(("/", "./", "http://", "https://")) and "@" not in value:
        return False
    return entropy(value) >= 3.0


def mask(secret: str) -> str:
    if len(secret) <= 8:
        return secret[:2] + "…"
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} car.)"


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    regex: re.Pattern
    group: int = 0
    validator: Callable[[str], bool] | None = None
    config_only: bool = False
    generic: bool = False


def _r(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


_KEY = r"[\w.\-]*?(?:secret|passwd|password|pwd|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|access[_\-]?token|token|private[_\-]?key|client[_\-]?secret|credentials?)(?:[_\-.]?(?:key|value|prod|dev|live|test))?"

RULES: list[Rule] = [
    Rule("private-key", "Clé privée", "critical",
         _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    Rule("aws-access-key", "Clé d'accès AWS", "critical", _r(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("github-token", "Token GitHub", "critical", _r(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    Rule("github-pat", "Token GitHub (fine-grained)", "critical", _r(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    Rule("gitlab-token", "Token GitLab", "critical", _r(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    Rule("anthropic-key", "Clé API Anthropic", "critical", _r(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    Rule("openai-key", "Clé API OpenAI", "critical",
         _r(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    Rule("stripe-live", "Clé secrète Stripe (live)", "critical", _r(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    Rule("stripe-test", "Clé secrète Stripe (test)", "medium", _r(r"\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b")),
    Rule("google-api-key", "Clé API Google", "high", _r(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule("slack-token", "Token Slack", "high", _r(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
    Rule("slack-webhook", "Webhook Slack", "high",
         _r(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+")),
    Rule("discord-webhook", "Webhook Discord", "medium",
         _r(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+")),
    Rule("sendgrid-key", "Clé API SendGrid", "high", _r(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    Rule("npm-token", "Token npm", "high", _r(r"\bnpm_[A-Za-z0-9]{36}\b")),
    Rule("pypi-token", "Token PyPI", "high", _r(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    Rule("telegram-bot", "Token de bot Telegram", "high", _r(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
    Rule("jwt", "Jeton JWT", "medium",
         _r(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    Rule("db-url-password", "URL de base de données avec mot de passe", "high",
         _r(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql)://[^\s:/@'\"]+:([^\s@'\"]{3,})@[^\s'\"]+"),
         group=1, validator=lambda v: looks_like_real_secret(v) or len(v) >= 6 and not v.startswith("$")),
    Rule("generic-secret", "Secret codé en dur", "medium",
         _r(r"""(?i)(?<![\w])(%s)["']?\s*(?:=|:|=>|:=)\s*[rbfu]{0,2}(["'`])([^"'`\s]{8,200})\2""" % _KEY),
         group=3, validator=looks_like_real_secret, generic=True),
    Rule("generic-secret-config", "Secret dans un fichier de configuration", "medium",
         _r(r"""(?i)^\s*(?:export\s+)?(%s)\s*[=:]\s*([^\s#'"]{8,200})\s*$""" % _KEY),
         group=2, validator=looks_like_real_secret, config_only=True, generic=True),
]

_FIX = ("Révoquez/régénérez ce secret immédiatement, retirez-le du code et chargez-le depuis une variable "
        "d'environnement ou un coffre (Vault, Doppler, secrets GitHub…). S'il a été commité, il reste dans "
        "l'historique git : la révocation est indispensable.")


def is_config_file(rel_path: str) -> bool:
    name = rel_path.rsplit("/", 1)[-1].lower()
    return name.startswith(".env") or name.endswith(CONFIG_EXTENSIONS)


def scan_text(text: str, rel_path: str) -> list[Finding]:
    findings: list[Finding] = []
    config_file = is_config_file(rel_path)
    for lineno, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARKER in line:
            continue
        line_hit = False
        for rule in RULES:
            if rule.config_only and not config_file:
                continue
            if rule.generic and line_hit:
                continue  # les règles génériques ne doublonnent pas une détection déjà faite
            for m in rule.regex.finditer(line):
                secret = m.group(rule.group)
                if rule.validator and not rule.validator(secret):
                    continue
                findings.append(Finding(
                    category="secret", rule=rule.id, title=rule.title, severity=rule.severity,
                    file=rel_path, line=lineno, detail=f"Valeur : {mask(secret)}", fix=_FIX,
                ))
                line_hit = True
                break  # une occurrence par règle et par ligne suffit
    return findings
