"""Preuve d'antériorité : empreinte de chaque fichier + horodatage par des tiers indépendants.

Une preuve = un dossier .velora/proofs/<horodatage>/ contenant :
    manifest.json        liste des fichiers et de leurs empreintes SHA-256
    manifest.<tsa>.tsr   jeton d'horodatage RFC 3161 signé par une autorité (FreeTSA, DigiCert…)
    manifest.json.ots    preuve OpenTimestamps ancrée dans Bitcoin (à compléter après confirmation)
    sources.zip          (option --archive) copie exacte des fichiers, indispensable pour prouver le contenu
    CERTIFICAT.txt       résumé lisible et procédure de vérification
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from velora import VeloraError, __version__
from velora.core import files as fs
from velora.core import gitutil, history, net
from velora.core.config import Project
from velora.core.term import human_size
from velora.proof import ots, tsa

PROOFS_DIR = "proofs"
FREETSA_CA_URL = "https://freetsa.org/files/cacert.pem"


def _tsa_label(url: str) -> str:
    host = urlparse(url).hostname or "tsa"
    parts = host.split(".")
    return parts[-2] if len(parts) >= 2 else host


def build_manifest(project: Project, note: str = "") -> tuple[dict, list[tuple[str, Path]]]:
    listed = list(fs.iter_files(project.root, extra_ignore=project.config.get("ignore", [])))
    entries = [{"path": rel, "sha256": fs.hash_file(p), "size": p.stat().st_size} for rel, p in listed]
    manifest = {
        "velora_proof": 1,
        "generator": f"velora-protect {__version__}",
        "project": project.name,
        "author": project.config.get("author") or "",
        "created_utc": history.now_iso(),
        "note": note,
        "git": {"commit": gitutil.head_commit(project.root), "remote": gitutil.remote_url(project.root)},
        "file_count": len(entries),
        "total_size": sum(e["size"] for e in entries),
        "files": entries,
    }
    return manifest, listed


def create_proof(project: Project, *, note: str = "", archive: bool = False, network: bool = True,
                 log=print) -> dict:
    manifest, listed = build_manifest(project, note)
    if not listed:
        raise VeloraError("Aucun fichier à horodater dans ce projet.")
    proof_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    pdir = project.path(PROOFS_DIR, proof_id)
    pdir.mkdir(parents=True, exist_ok=False)

    raw = json.dumps(manifest, indent=1, ensure_ascii=False, sort_keys=True).encode("utf-8")
    (pdir / "manifest.json").write_bytes(raw)
    digest = hashlib.sha256(raw).digest()
    log(f"Manifeste : {len(listed)} fichiers, empreinte {digest.hex()[:16]}…")

    timestamps = []
    if network:
        for url in project.config["proof"].get("tsa_urls", []):
            label = _tsa_label(url)
            try:
                token, info = tsa.request_timestamp(url, digest)
                (pdir / f"manifest.{label}.tsr").write_bytes(token)
                timestamps.append({"type": "rfc3161", "authority": label, "url": url, "file": f"manifest.{label}.tsr",
                                   "time": info.gen_time.isoformat(), "serial": info.serial})
                log(f"Horodatage RFC 3161 obtenu auprès de {label} : {info.gen_time:%d/%m/%Y %H:%M:%S} UTC")
                if label == "freetsa" and not (pdir / "freetsa-cacert.pem").exists():
                    try:
                        (pdir / "freetsa-cacert.pem").write_bytes(net.request(FREETSA_CA_URL, timeout=20))
                    except net.NetworkError:
                        pass
            except (net.NetworkError, tsa.TSAError, IndexError, ValueError) as e:
                log(f"! Autorité {label} indisponible : {e}")
        calendars = project.config["proof"].get("opentimestamps", [])
        if calendars:
            ots_bytes, ok_cals, errors = ots.stamp(digest, calendars)
            if ots_bytes:
                (pdir / "manifest.json.ots").write_bytes(ots_bytes)
                timestamps.append({"type": "opentimestamps", "file": "manifest.json.ots", "calendars": ok_cals,
                                   "status": "en attente d'ancrage Bitcoin (quelques heures)"})
                log(f"Preuve OpenTimestamps soumise à {len(ok_cals)} calendrier(s)")
            for e in errors:
                log(f"! OpenTimestamps : {e}")

    if archive:
        with zipfile.ZipFile(pdir / "sources.zip", "w", zipfile.ZIP_DEFLATED) as zf:
            for rel, path in listed:
                zf.write(path, rel)
        log("Copie des sources archivée (sources.zip)")

    meta = {"id": proof_id, "sha256": digest.hex(), "files": len(listed), "timestamps": timestamps,
            "archive": archive, "note": note}
    (pdir / "proof.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    (pdir / "CERTIFICAT.txt").write_text(_certificate(project, manifest, meta), encoding="utf-8")
    history.record(project, "proof", id=proof_id, sha256=digest.hex(), files=len(listed),
                   timestamps=len(timestamps))
    return meta


def _certificate(project: Project, manifest: dict, meta: dict) -> str:
    author = manifest["author"] or '(non renseigné — velora config set author "Nom")'
    lines = [
        "CERTIFICAT D'EMPREINTE ET D'HORODATAGE",
        "Généré par Velora Protect",
        "=" * 60,
        f"Projet             : {manifest['project']}",
        f"Auteur déclaré     : {author}",
        f"Date (horloge PC)  : {manifest['created_utc']} (UTC)",
        f"Fichiers           : {manifest['file_count']} ({human_size(manifest['total_size'])})",
        f"Commit git         : {manifest['git']['commit'] or '—'}",
        f"Empreinte SHA-256 du manifeste :",
        f"    {meta['sha256']}",
    ]
    if meta["note"]:
        lines.append(f"Note               : {meta['note']}")
    lines += ["", "HORODATAGES PAR DES TIERS"]
    if not meta["timestamps"]:
        lines.append("  Aucun (mode hors-ligne) : seule la date de l'ordinateur est indiquée, elle n'a pas de valeur probante.")
    for t in meta["timestamps"]:
        if t["type"] == "rfc3161":
            lines.append(f"  - {t['authority']} (RFC 3161) : {t['time']} — {t['file']}")
        else:
            lines.append(f"  - OpenTimestamps (Bitcoin) : {t['status']} — {t['file']}")
    lines += [
        "",
        "COMMENT VÉRIFIER",
        "  1. Avec Velora (recalcule les empreintes et lit les jetons) :",
        f"       velora proof verify {meta['id']}",
        "  2. Indépendamment, avec OpenSSL (FreeTSA) :",
        "       openssl ts -verify -data manifest.json -in manifest.freetsa.tsr -CAfile freetsa-cacert.pem",
        "  3. OpenTimestamps : déposez manifest.json et manifest.json.ots sur https://opentimestamps.org",
        "     (ou « ots upgrade » puis « ots verify » avec le client officiel).",
        "  4. Le contenu d'un fichier se prouve en montrant que son SHA-256 figure dans manifest.json :",
        "       certutil -hashfile <fichier> SHA256     (Windows)",
        "       sha256sum <fichier>                       (Linux/macOS)",
        "",
        "À SAVOIR",
        "  - Cette preuve établit qu'un ensemble de fichiers précis existait au plus tard à la date indiquée.",
        "    Elle ne dit pas qui en est l'auteur : conservez aussi l'historique git, vos échanges et brouillons.",
        "  - Conservez une copie EXACTE des fichiers (option --archive ou sauvegarde) : sans eux, l'empreinte",
        "    seule ne permet pas de montrer le contenu protégé.",
        "  - Pour une valeur probante renforcée en France : enveloppe e-Soleau (INPI), dépôt auprès de l'APP",
        "    (Agence pour la Protection des Programmes), ou constat par un commissaire de justice. Les horodatages",
        "    ci-dessus sont un complément gratuit, pas un horodatage « qualifié » au sens du règlement eIDAS.",
    ]
    return "\n".join(lines) + "\n"


def list_proofs(project: Project) -> list[dict]:
    base = project.path(PROOFS_DIR)
    if not base.exists():
        return []
    out = []
    for d in sorted(base.iterdir(), reverse=True):
        meta_file = d / "proof.json"
        if meta_file.exists():
            try:
                out.append(json.loads(meta_file.read_text(encoding="utf-8")))
            except ValueError:
                continue
    return out


def verify_proof(project: Project, proof_id: str | None = None) -> dict:
    proofs = list_proofs(project)
    if not proofs:
        raise VeloraError("Aucune preuve dans ce projet (velora proof create).")
    meta = next((p for p in proofs if p["id"] == proof_id), None) if proof_id else proofs[0]
    if meta is None:
        raise VeloraError(f"Preuve introuvable : {proof_id}")
    pdir = project.path(PROOFS_DIR, meta["id"])
    raw = (pdir / "manifest.json").read_bytes()
    digest = hashlib.sha256(raw).digest()
    report = {"id": meta["id"], "manifest_intact": digest.hex() == meta["sha256"], "timestamps": [],
              "modified": [], "missing": [], "added": [], "archive": None}

    for token_file in sorted(pdir.glob("*.tsr")):
        entry = {"file": token_file.name}
        try:
            info = tsa.parse_response(token_file.read_bytes())
            entry.update(time=info.gen_time.isoformat(), digest_match=info.digest == digest)
        except (tsa.TSAError, IndexError, ValueError) as e:
            entry.update(error=str(e), digest_match=False)
        ca = pdir / "freetsa-cacert.pem"
        openssl = tsa.find_openssl()
        if "freetsa" in token_file.name and ca.exists() and openssl:
            proc = subprocess.run([openssl, "ts", "-verify", "-data", str(pdir / "manifest.json"),
                                   "-in", str(token_file), "-CAfile", str(ca)], capture_output=True, text=True)
            entry["openssl"] = "OK" if proc.returncode == 0 and "OK" in proc.stdout else (proc.stdout + proc.stderr).strip()[:200]
        report["timestamps"].append(entry)
    if (pdir / "manifest.json.ots").exists():
        report["timestamps"].append({"file": "manifest.json.ots", "note": "à vérifier sur https://opentimestamps.org"})

    try:
        manifest = json.loads(raw)
        expected = {e["path"]: e["sha256"] for e in manifest["files"]}
    except (ValueError, KeyError, TypeError):
        report["manifest_intact"] = False  # manifeste illisible ou falsifié : rien à comparer
        return report
    current = {rel: p for rel, p in fs.iter_files(project.root, extra_ignore=project.config.get("ignore", []))}
    for rel, sha in expected.items():
        if rel not in current:
            report["missing"].append(rel)
        elif fs.hash_file(current[rel]) != sha:
            report["modified"].append(rel)
    report["added"] = sorted(set(current) - set(expected))

    sources = pdir / "sources.zip"
    if sources.exists():
        bad = []
        with zipfile.ZipFile(sources) as zf:
            names = set(zf.namelist())
            for rel, sha in expected.items():
                if rel not in names or hashlib.sha256(zf.read(rel)).hexdigest() != sha:
                    bad.append(rel)
        report["archive"] = {"ok": not bad, "problems": bad}
    return report
