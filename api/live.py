"""Fonction Vercel : POST /api/live {"url": "...", "deep": false} — test de sécurité d'un site en ligne."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from velora.cloud import JsonHandler, RateLimiter, handle_live  # noqa: E402


class handler(JsonHandler):
    limiter = RateLimiter(limit=6, window=600)

    def handle_json(self, body):
        return handle_live(body)
