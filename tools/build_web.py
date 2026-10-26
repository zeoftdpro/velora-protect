"""Construit le site public (dossier public/) pour Vercel.

- copie les pages de web/ et les fichiers communs de velora/ui/ (style.css, shared.js) ;
- empaquette le moteur d'analyse Python (public/engine.zip), exécuté dans le navigateur via Pyodide.

Volontairement compatible avec un Python ancien (image de build Vercel).
"""

import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "public"
# Inutile dans le navigateur : interface locale, ligne de commande, sauvegardes, preuves, service serveur.
ENGINE_EXCLUDE = {"ui", "proof", "__pycache__", ".velora"}
ENGINE_EXCLUDE_FILES = {"cli.py", "__main__.py", "backup.py", "cloud.py"}


def build():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()
    for src in sorted((ROOT / "web").iterdir()):
        if src.is_file():
            shutil.copy2(src, OUT / src.name)
    for name in ("style.css", "shared.js", "favicon.svg"):
        shutil.copy2(ROOT / "velora" / "ui" / name, OUT / name)

    count = 0
    with zipfile.ZipFile(OUT / "engine.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted((ROOT / "velora").rglob("*.py")):
            rel = path.relative_to(ROOT)
            if ENGINE_EXCLUDE & set(rel.parts) or path.name in ENGINE_EXCLUDE_FILES:
                continue
            zf.write(path, rel.as_posix())
            count += 1
    size = (OUT / "engine.zip").stat().st_size
    print("public/ construit : moteur de %d modules (%d Ko)" % (count, size // 1024))


if __name__ == "__main__":
    build()
    sys.exit(0)
