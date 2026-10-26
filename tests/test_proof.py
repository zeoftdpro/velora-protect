import hashlib
import json
import unittest
from datetime import datetime, timezone

from velora import proof
from velora.proof import ots, tsa
from velora.proof.tsa import der, der_int

from tests.helpers import TempProjectCase

SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")


def fake_response(digest: bytes, nonce: int, status: int = 0, when: str = "20261015101530.25Z") -> bytes:
    """Construit un TimeStampResp RFC 3161 minimal (sans signature réelle) pour tester le parseur."""
    algorithm = der(0x30, der(0x06, tsa.SHA256_OID) + b"\x05\x00")
    tst_info = der(0x30, der_int(1) + der(0x06, bytes.fromhex("2a0304")) + der(0x30, algorithm + der(0x04, digest))
                   + der_int(123456789) + der(0x18, when.encode()) + der_int(nonce))
    encap = der(0x30, der(0x06, tsa.TSTINFO_OID) + der(0xA0, der(0x04, tst_info)))
    signed_data = der(0x30, der_int(3) + der(0x31, algorithm) + encap + der(0x31, b""))
    token = der(0x30, der(0x06, SIGNED_DATA_OID) + der(0xA0, signed_data))
    return der(0x30, der(0x30, der_int(status)) + token)


class TSATest(unittest.TestCase):
    def test_request_structure(self):
        digest = hashlib.sha256(b"x").digest()
        req = tsa.parse(tsa.build_request(digest, 2 ** 62 + 5))[0]
        self.assertEqual(req.child(0).content, b"\x01")
        self.assertEqual(req.child(1).child(1).content, digest)
        self.assertEqual(int.from_bytes(req.child(2).content, "big"), 2 ** 62 + 5)
        self.assertEqual(req.child(3).content, b"\xff")

    def test_long_lengths(self):
        blob = der(0x04, b"a" * 70000)
        node = tsa.parse(blob)[0]
        self.assertEqual(len(node.content), 70000)

    def test_parse_response(self):
        digest = hashlib.sha256(b"manifest").digest()
        info = tsa.parse_response(fake_response(digest, 987654321))
        self.assertEqual(info.digest, digest)
        self.assertEqual(info.nonce, 987654321)
        self.assertEqual(info.serial, 123456789)
        self.assertEqual(info.gen_time, datetime(2026, 10, 15, 10, 15, 30, 250000, tzinfo=timezone.utc))

    def test_rejected_status(self):
        rejected = der(0x30, der(0x30, der_int(2)))
        with self.assertRaises(tsa.TSAError):
            tsa.parse_response(rejected)


class OTSTest(unittest.TestCase):
    def test_file_layout_and_fork_merge(self):
        digest = b"\x11" * 32
        r1, r2 = b"\xf0\x01A\x08\x00" + b"p" * 9, b"\xf1\x01B\x08\x00" + b"q" * 9
        data = ots.build_ots_file(digest, [r1, r2])
        self.assertTrue(data.startswith(ots.HEADER_MAGIC + b"\x01\x08" + digest))
        self.assertEqual(data[len(ots.HEADER_MAGIC) + 34:], b"\xff" + r1 + r2)
        self.assertEqual(ots.build_ots_file(digest, [r1]), ots.HEADER_MAGIC + b"\x01\x08" + digest + r1)


class ProofFlowTest(TempProjectCase):
    def test_offline_proof_and_verification(self):
        self.write("src/a.py", "print(1)\n")
        self.write("src/b.py", "print(2)\n")
        project = self.project()
        meta = proof.create_proof(project, note="v1", archive=True, network=False, log=lambda m: None)
        pdir = project.path("proofs", meta["id"])
        manifest = json.loads((pdir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual([f["path"] for f in manifest["files"]], ["src/a.py", "src/b.py"])
        self.assertEqual(manifest["author"], "Ada Test")
        self.assertTrue((pdir / "CERTIFICAT.txt").exists())

        report = proof.verify_proof(project)
        self.assertTrue(report["manifest_intact"])
        self.assertTrue(report["archive"]["ok"])
        self.assertEqual(report["modified"] + report["missing"] + report["added"], [])

        self.write("src/a.py", "print('changé')\n")
        self.write("src/c.py", "x\n")
        report = proof.verify_proof(project, meta["id"])
        self.assertEqual(report["modified"], ["src/a.py"])
        self.assertEqual(report["added"], ["src/c.py"])

        (pdir / "manifest.json").write_text("{}", encoding="utf-8")
        self.assertFalse(proof.verify_proof(project)["manifest_intact"])

    def test_tsr_digest_checked(self):
        self.write("a.py", "1\n")
        project = self.project()
        meta = proof.create_proof(project, network=False, log=lambda m: None)
        pdir = project.path("proofs", meta["id"])
        good = hashlib.sha256((pdir / "manifest.json").read_bytes()).digest()
        (pdir / "manifest.good.tsr").write_bytes(fake_response(good, 1))
        (pdir / "manifest.bad.tsr").write_bytes(fake_response(b"\0" * 32, 1))
        stamps = {t["file"]: t["digest_match"] for t in proof.verify_proof(project)["timestamps"]}
        self.assertEqual(stamps, {"manifest.bad.tsr": False, "manifest.good.tsr": True})


if __name__ == "__main__":
    unittest.main()
