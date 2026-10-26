import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from velora import VeloraError, cloud

SECRET = "s" * 40


def post(port, path, payload, content_type="application/json"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(payload).encode(),
                                 method="POST", headers={"Content-Type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


class VerificationTest(unittest.TestCase):
    def test_token_is_stable_and_per_host(self):
        with mock.patch.dict(os.environ, {"VELORA_SECRET": SECRET}):
            a = cloud.verification_token("exemple.fr")
            self.assertEqual(a, cloud.verification_token("exemple.fr"))
            self.assertNotEqual(a, cloud.verification_token("autre.fr"))
            self.assertEqual(cloud.hostname_of("HTTPS://Exemple.FR/page"), "exemple.fr")
            info = cloud.instructions("exemple.fr")
            self.assertEqual(info["dns"]["name"], "_velora.exemple.fr")
            self.assertEqual(info["file"]["url"], "https://exemple.fr/.well-known/velora-verification.txt")

    def test_fails_closed_without_secret(self):
        with mock.patch.dict(os.environ, {"VELORA_SECRET": ""}):
            with self.assertRaises(VeloraError):
                cloud.verification_token("exemple.fr")

    def test_deep_scan_requires_verification(self):
        with mock.patch.dict(os.environ, {"VELORA_SECRET": SECRET}), \
                mock.patch.object(cloud, "is_verified", return_value=(False, "")), \
                mock.patch("velora.scan.live.scan") as scan:
            with self.assertRaises(VeloraError):
                cloud.handle_live({"url": "https://exemple.fr", "deep": True})
            scan.assert_not_called()


class RateLimiterTest(unittest.TestCase):
    def test_sliding_window(self):
        limiter = cloud.RateLimiter(limit=2, window=60)
        self.assertTrue(limiter.allow("a"))
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))


class Echo(cloud.JsonHandler):
    limiter = cloud.RateLimiter(limit=3, window=60)

    def handle_json(self, body):
        if body.get("boom"):
            raise RuntimeError("détail interne à ne pas divulguer")
        return cloud.handle_live(body) if "url" in body else {"ok": True}


class HandlerTest(unittest.TestCase):
    def setUp(self):
        Echo.limiter = cloud.RateLimiter(limit=4, window=60)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_rejects_internal_targets_and_bad_requests(self):
        code, body = post(self.port, "/", {"url": "http://169.254.169.254/latest/meta-data/"})
        self.assertEqual(code, 400)
        self.assertIn("refus", body["error"])
        self.assertEqual(post(self.port, "/", {"a": 1}, content_type="text/plain")[0], 415)
        code, body = post(self.port, "/", {"boom": True})
        self.assertEqual(code, 500)
        self.assertNotIn("détail interne", body["error"])

    def test_rate_limited(self):
        codes = [post(self.port, "/", {"x": i})[0] for i in range(6)]
        self.assertEqual(codes[:4], [200] * 4)
        self.assertEqual(codes[4:], [429, 429])


if __name__ == "__main__":
    unittest.main()
