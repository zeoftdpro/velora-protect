"""Fonction Vercel : POST /api/verify {"url": "...", "check": false} — jeton de preuve de propriété."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from velora.cloud import JsonHandler, RateLimiter, handle_verify  # noqa: E402


class handler(JsonHandler):
    limiter = RateLimiter(limit=20, window=600)

    def handle_json(self, body):
        return handle_verify(body)
