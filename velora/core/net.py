"""Requêtes HTTP minimales (bibliothèque standard uniquement)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from velora import __version__

USER_AGENT = f"velora-protect/{__version__}"


class NetworkError(Exception):
    pass


def request(url: str, data: bytes | None = None, headers: dict | None = None,
            timeout: float = 30, max_bytes: int = 20 * 1024 * 1024) -> bytes:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        raise NetworkError(f"{url} : HTTP {e.code}") from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise NetworkError(f"{url} : {getattr(e, 'reason', e)}") from e


def post_json(url: str, payload: dict, timeout: float = 30) -> dict:
    body = json.dumps(payload).encode("utf-8")
    raw = request(url, body, {"Content-Type": "application/json"}, timeout)
    return json.loads(raw.decode("utf-8")) if raw else {}


def get_json(url: str, timeout: float = 30) -> dict:
    return json.loads(request(url, timeout=timeout).decode("utf-8"))
