"""Aperçu local du site Vercel : sert public/ avec les en-têtes de vercel.json et les fonctions api/*.py.

    python tools/build_web.py && python tools/preview.py [port]

Fidèle à la production pour la CSP et les fonctions ; la limitation du débit et VELORA_SECRET se
comportent comme en ligne (définissez VELORA_SECRET pour tester l'analyse approfondie).
"""

import importlib.util
import json
import mimetypes
import re
import sys
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
CONFIG = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"api_{name}", ROOT / "api" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.handler


FUNCTIONS = {f"/api/{p.stem}": _load(p.stem) for p in (ROOT / "api").glob("*.py")}


RULES = [(re.compile("^" + rule["source"].replace("(.*)", ".*") + "$"), rule["headers"]) for rule in CONFIG["headers"]]


def config_headers(path):
    out = {}
    for regex, headers in RULES:
        if regex.match(path):
            out.update({h["key"]: h["value"] for h in headers})
    return out


_wrapped = {}


def _with_config_headers(handler):
    if handler not in _wrapped:
        def end_headers(self):
            for key, value in config_headers(self.path.split("?")[0]).items():
                self.send_header(key, value)
            BaseHTTPRequestHandler.end_headers(self)
        _wrapped[handler] = type("Function", (handler,), {"end_headers": end_headers})
    return _wrapped[handler]


class Preview(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC), **kwargs)

    def end_headers(self):
        for key, value in config_headers(self.path.split("?")[0]).items():
            self.send_header(key, value)
        super().end_headers()

    def _function(self):
        handler = FUNCTIONS.get(self.path.split("?")[0])
        if not handler:
            return False
        # La requête (déjà lue) est confiée à la classe de la fonction, augmentée des en-têtes de vercel.json.
        self.__class__ = _with_config_headers(handler)
        (self.do_POST if self.command == "POST" else self.do_GET)()
        return True

    def do_POST(self):
        if not self._function():
            self.send_error(404)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in FUNCTIONS:
            return self._function()
        if CONFIG.get("cleanUrls") and path != "/" and "." not in path.rsplit("/", 1)[-1] \
                and (PUBLIC / (path.lstrip("/") + ".html")).exists():
            self.path = path + ".html"
        super().do_GET()

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s\n" % (fmt % args))


mimetypes.add_type("text/javascript", ".js")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    if not PUBLIC.exists():
        sys.exit("Lancez d'abord : python tools/build_web.py")
    print(f"Aperçu du site : http://localhost:{port}  (Ctrl+C pour arrêter)")
    ThreadingHTTPServer(("127.0.0.1", port), Preview).serve_forever()
