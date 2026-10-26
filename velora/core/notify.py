"""Alertes par webhook (Discord, Slack, Teams, ntfy.sh ou tout endpoint JSON)."""

from __future__ import annotations

import json
import socket

from velora.core import net
from velora.core.config import Project


def send_alert(project: Project, subject: str, message: str) -> bool:
    url = (project.config.get("alerts") or {}).get("webhook_url", "").strip()
    if not url:
        return False
    text = f"[Velora · {project.name} · {socket.gethostname()}] {subject}\n{message}"
    try:
        if "ntfy" in url:
            net.request(url, text.encode("utf-8"), {"Title": f"Velora : {subject}"}, timeout=15)
        else:
            # « content » pour Discord, « text » pour Slack/Teams/Mattermost.
            body = json.dumps({"content": text[:1900], "text": text}).encode("utf-8")
            net.request(url, body, {"Content-Type": "application/json"}, timeout=15)
        return True
    except net.NetworkError:
        return False
