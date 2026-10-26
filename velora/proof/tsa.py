"""Horodatage RFC 3161 : construction de la requête et lecture de la réponse (ASN.1 DER minimal).

La vérification cryptographique complète de la signature est déléguée à OpenSSL
(« openssl ts -verify »), qui est l'outil de référence reconnu en cas d'expertise.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from velora.core import net

SHA256_OID = bytes.fromhex("608648016503040201")          # 2.16.840.1.101.3.4.2.1
TSTINFO_OID = bytes.fromhex("2a864886f70d0109100104")     # 1.2.840.113549.1.9.16.1.4


class TSAError(Exception):
    pass


# --------------------------------------------------------------------------- DER

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def der_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return der(0x02, raw)


@dataclass
class Node:
    tag: int
    content: bytes
    children: list["Node"]

    def child(self, i: int) -> "Node":
        try:
            return self.children[i]
        except IndexError:
            raise TSAError("Structure ASN.1 inattendue") from None


def parse(data: bytes, pos: int = 0, end: int | None = None) -> list[Node]:
    end = len(data) if end is None else end
    nodes = []
    while pos < end:
        if pos + 2 > end:
            raise TSAError("DER tronqué")
        tag = data[pos]
        length = data[pos + 1]
        pos += 2
        if length & 0x80:
            n = length & 0x7F
            if n == 0 or n > 4:
                raise TSAError("Longueur DER non supportée")
            length = int.from_bytes(data[pos:pos + n], "big")
            pos += n
        if pos + length > end:
            raise TSAError("DER tronqué")
        content = data[pos:pos + length]
        children = parse(data, pos, pos + length) if tag & 0x20 else []
        nodes.append(Node(tag, content, children))
        pos += length
    return nodes


# --------------------------------------------------------------------------- requête / réponse

def build_request(digest: bytes, nonce: int) -> bytes:
    algorithm = der(0x30, der(0x06, SHA256_OID) + b"\x05\x00")
    imprint = der(0x30, algorithm + der(0x04, digest))
    return der(0x30, der_int(1) + imprint + der_int(nonce) + der(0x01, b"\xff"))


@dataclass
class TimestampInfo:
    status: int
    gen_time: datetime
    digest: bytes
    nonce: int | None
    serial: int


def _parse_time(raw: bytes) -> datetime:
    text = raw.decode("ascii").rstrip("Z")
    main, _, frac = text.partition(".")
    dt = datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    return dt


def parse_response(data: bytes) -> TimestampInfo:
    """Lit un TimeStampResp (RFC 3161 §2.4.2) et en extrait le TSTInfo."""
    resp = parse(data)[0]
    status = int.from_bytes(resp.child(0).child(0).content, "big", signed=True)
    if status not in (0, 1) or len(resp.children) < 2:
        raise TSAError(f"Horodatage refusé par l'autorité (statut PKI {status})")
    token = resp.child(1)                                   # ContentInfo
    signed_data = token.child(1).child(0)                   # [0] EXPLICIT SignedData
    encap = next((n for n in signed_data.children if n.tag == 0x30 and n.children
                  and n.children[0].tag == 0x06 and n.children[0].content == TSTINFO_OID), None)
    if encap is None:
        raise TSAError("TSTInfo introuvable dans le jeton")
    tst = parse(encap.child(1).child(0).content)[0]       # [0] EXPLICIT OCTET STRING → TSTInfo
    imprint = tst.child(2)
    digest = imprint.child(1).content
    serial = int.from_bytes(tst.child(3).content, "big")
    gen_time = _parse_time(tst.child(4).content)
    nonce = next((int.from_bytes(n.content, "big", signed=True) for n in tst.children[5:] if n.tag == 0x02), None)
    return TimestampInfo(status, gen_time, digest, nonce, serial)


def request_timestamp(url: str, digest: bytes, timeout: float = 30) -> tuple[bytes, TimestampInfo]:
    nonce = secrets.randbits(63)
    body = build_request(digest, nonce)
    raw = net.request(url, body, {"Content-Type": "application/timestamp-query"}, timeout=timeout)
    info = parse_response(raw)
    if info.digest != digest:
        raise TSAError("L'autorité a horodaté une autre empreinte que celle demandée")
    if info.nonce is not None and info.nonce != nonce:
        raise TSAError("Nonce incorrect dans la réponse (rejeu ?)")
    return raw, info


def find_openssl() -> str | None:
    import shutil
    found = shutil.which("openssl")
    if found:
        return found
    for candidate in (r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\Git\mingw64\bin\openssl.exe",
                      r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"):
        if os.path.exists(candidate):
            return candidate
    return None
