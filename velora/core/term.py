"""Affichage console : couleurs ANSI (désactivables via NO_COLOR) et libellés."""

from __future__ import annotations

import os
import sys

_CODES = {
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "grey": "90", "bold": "1",
}
_enabled: bool | None = None

SEVERITY_LABELS = {
    "critical": "CRITIQUE", "high": "ÉLEVÉ", "medium": "MOYEN", "low": "FAIBLE", "info": "INFO",
}
SEVERITY_STYLES = {
    "critical": ("red", "bold"), "high": ("red",), "medium": ("yellow",),
    "low": ("cyan",), "info": ("grey",),
}


def _color_supported() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not getattr(sys.stdout, "isatty", lambda: False)():
        return False
    if os.name == "nt":
        os.system("")  # active le mode VT100 de la console Windows  velora:ignore
    return True


def c(text: object, *styles: str) -> str:
    global _enabled
    if _enabled is None:
        _enabled = _color_supported()
    if not _enabled or not styles:
        return str(text)
    return f"\033[{';'.join(_CODES[s] for s in styles)}m{text}\033[0m"


def severity(sev: str) -> str:
    return c(f"[{SEVERITY_LABELS.get(sev, sev.upper())}]", *SEVERITY_STYLES.get(sev, ()))


def ok(msg: str) -> None:
    print(c("✔ ", "green") + msg)


def warn(msg: str) -> None:
    print(c("! ", "yellow") + msg)


def err(msg: str) -> None:
    print(c("✖ ", "red") + msg, file=sys.stderr)


def info(msg: str) -> None:
    print(c("· ", "grey") + msg)


def title(msg: str) -> None:
    print("\n" + c(msg, "bold"))


def human_size(n: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} To"
