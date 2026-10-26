"""OpenTimestamps : ancrage gratuit d'une empreinte dans la blockchain Bitcoin.

On soumet l'empreinte SHA-256 à des serveurs « calendrier » publics, puis on écrit un fichier
.ots standard. Après quelques heures (confirmation Bitcoin), le fichier peut être complété et
vérifié avec l'outil officiel (« ots upgrade » / « ots verify ») ou sur https://opentimestamps.org.
"""

from __future__ import annotations

from velora.core import net

# En-tête officiel d'un DetachedTimestampFile (python-opentimestamps, core/timestamp.py).
HEADER_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
MAJOR_VERSION = b"\x01"
OP_SHA256 = b"\x08"
FORK = b"\xff"


def submit(calendar: str, digest: bytes, timeout: float = 20) -> bytes:
    return net.request(calendar.rstrip("/") + "/digest", digest,
                       {"Accept": "application/vnd.opentimestamps.v1"}, timeout=timeout, max_bytes=10000)


def build_ots_file(digest: bytes, responses: list[bytes]) -> bytes:
    """Fusionne les réponses des calendriers en un seul arbre de preuves (embranchements 0xff).

    Chaque réponse est un Timestamp sérialisé pour le message `digest`. Toutes sauf la dernière
    doivent commencer par une opération unique (pas d'embranchement de premier niveau).
    """
    if not responses:
        raise ValueError("aucune réponse de calendrier")
    single = [r for r in responses if r and r[:1] != FORK]
    multi = [r for r in responses if r and r[:1] == FORK]
    ordered = single + multi[:1]
    body = b"".join(FORK + r for r in ordered[:-1]) + ordered[-1]
    return HEADER_MAGIC + MAJOR_VERSION + OP_SHA256 + digest + body


def stamp(digest: bytes, calendars: list[str]) -> tuple[bytes | None, list[str], list[str]]:
    responses, ok, errors = [], [], []
    for cal in calendars:
        try:
            responses.append(submit(cal, digest))
            ok.append(cal)
        except net.NetworkError as e:
            errors.append(str(e))
    return (build_ots_file(digest, responses) if responses else None), ok, errors
