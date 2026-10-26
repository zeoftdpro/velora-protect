"""Réception d'un projet envoyé (archive ZIP) : extraction sûre pour un service exposé.

Rien n'est exécuté : le projet est seulement lu. L'extraction refuse les chemins qui sortent du
dossier (../, chemins absolus, lecteurs Windows), les liens symboliques, les noms réservés Windows
et les bombes de décompression (taille totale, nombre de fichiers, taux de compression).
"""

from __future__ import annotations

import re
import shutil
import stat
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from velora import VeloraError
from velora.core.files import IGNORED_DIRS

MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_TOTAL_BYTES = 600 * 1024 * 1024
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_FILES = 30_000
MAX_RATIO = 200  # au-delà, une entrée de plus de 1 Mo est considérée comme une bombe de décompression

_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$", re.I)


class UploadError(VeloraError):
    pass


def _safe_parts(name: str) -> tuple[str, ...] | None:
    """Composants du chemin si l'entrée peut être extraite sans danger, sinon None."""
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = tuple(p for p in PurePosixPath(name).parts if p not in ("", "."))
    if not parts or any(p == ".." or ":" in p or _WINDOWS_RESERVED.match(p) or p.endswith((" ", "."))
                        for p in parts):
        return None
    return parts


def safe_extract(archive: str | Path | BinaryIO, dest: str | Path) -> dict:
    """Extrait l'archive (chemin ou flux en mémoire) dans dest.

    Renvoie {"files", "bytes", "skipped", "blocked"} ; « blocked » liste les fichiers qu'un antivirus a
    refusé d'écrire ou a retirés aussitôt : un signal fort de code malveillant connu."""
    dest = Path(dest)
    if isinstance(archive, (str, Path)):
        archive = Path(archive)
        size = archive.stat().st_size
    else:
        size = archive.seek(0, 2)
        archive.seek(0)
    if size > MAX_ARCHIVE_BYTES:
        raise UploadError(f"Archive trop volumineuse (maximum {MAX_ARCHIVE_BYTES // 1024 // 1024} Mo).")
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as e:
        raise UploadError("Fichier invalide : envoyez un dossier ou une archive .zip.") from e

    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    files = total = skipped = 0
    blocked: list[str] = []
    with zf:
        entries = zf.infolist()
        if len(entries) > MAX_FILES * 2:
            raise UploadError(f"Trop de fichiers dans l'archive (maximum {MAX_FILES}).")
        for info in entries:
            if info.is_dir():
                continue
            parts = _safe_parts(info.filename)
            mode = info.external_attr >> 16
            if parts is None or stat.S_ISLNK(mode) or info.flag_bits & 0x1:  # 0x1 : entrée chiffrée
                skipped += 1
                continue
            if any(p in IGNORED_DIRS for p in parts[:-1]):
                continue  # dépendances installées, caches : inutiles à l'analyse
            if info.file_size > MAX_FILE_BYTES:
                skipped += 1
                continue
            if info.file_size > 1024 * 1024 and info.file_size > MAX_RATIO * max(info.compress_size, 1):
                raise UploadError("Archive refusée : taux de compression anormal (bombe de décompression ?).")
            files += 1
            if files > MAX_FILES:
                raise UploadError(f"Trop de fichiers (maximum {MAX_FILES}).")
            target = root.joinpath(*parts)
            if not target.resolve().is_relative_to(root):
                skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with zf.open(info) as src, open(target, "wb") as out:
                    # On ne fait pas confiance à la taille annoncée : on compte ce qui sort réellement.
                    for chunk in iter(lambda: src.read(1024 * 1024), b""):
                        written += len(chunk)
                        total += len(chunk)
                        if written > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                            raise UploadError(f"Projet trop volumineux une fois décompressé "
                                              f"(maximum {MAX_TOTAL_BYTES // 1024 // 1024} Mo).")
                        out.write(chunk)
                with open(target, "rb") as check:  # un antivirus peut retirer le fichier dès son écriture
                    check.read(1)
            except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, zlib.error):
                skipped += 1
                target.unlink(missing_ok=True)
            except OSError:
                blocked.append("/".join(parts))
                try:
                    target.unlink(missing_ok=True)
                except OSError:
                    pass
    if not files:
        raise UploadError("Aucun fichier exploitable dans l'envoi.")
    return {"files": files, "bytes": total, "skipped": skipped, "blocked": blocked}


def project_root(dest: str | Path) -> Path:
    """Si l'archive contient un unique dossier de premier niveau (cas d'un dossier glissé), c'est lui la racine."""
    dest = Path(dest)
    entries = [p for p in dest.iterdir() if p.name not in ("__MACOSX",)]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def cleanup(path: str | Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
