import io
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from velora.core import upload
from velora.scan import hardening, live, mobile, run_scan, web

from tests.helpers import TempProjectCase

AWS = "AKIA" + "Z7XQ2LMN4PRT6VWY"


def web_rules(path, text):
    return {f.rule for f in web.check_file(path, text)}


def mobile_rules(path, text):
    return {f.rule for f in mobile.check_file(path, text)}


class WebRulesTest(unittest.TestCase):
    def test_javascript(self):
        self.assertIn("xss-dangerous-html", web_rules("App.jsx", "<div dangerouslySetInnerHTML={{__html: x}} />"))
        self.assertIn("xss-inner-html", web_rules("a.js", "el.innerHTML = userInput;"))
        self.assertNotIn("xss-inner-html", web_rules("a.js", 'el.innerHTML = "";'))
        self.assertIn("token-in-web-storage", web_rules("auth.ts", "localStorage.setItem('access_token', t)"))
        self.assertIn("reflected-xss", web_rules("server.js", "res.send('Bonjour ' + req.query.name)"))
        self.assertIn("command-injection", web_rules("server.js", "exec(`ping ${req.query.host}`)"))
        self.assertNotIn("command-injection", web_rules("a.js", "const m = /a/.exec(`x${y}`)"))

    def test_php(self):
        self.assertIn("reflected-xss", web_rules("index.php", "<?php echo $_GET['q']; ?>"))
        self.assertNotIn("reflected-xss", web_rules("index.php", "<?php echo htmlspecialchars($_GET['q']); ?>"))
        self.assertIn("sql-injection", web_rules("u.php", "$r = mysqli_query($db, \"SELECT * FROM u WHERE id=\" . $_GET['id']);"))
        self.assertNotIn("sql-injection", web_rules("u.php", "$s = $pdo->prepare('SELECT * FROM u WHERE id = ?');\n"
                                                             "$s->execute([$_GET['id']]);"))
        self.assertIn("file-inclusion", web_rules("p.php", "include($_GET['page'] . '.php');"))

    def test_python_cpp_and_markup(self):
        self.assertIn("template-injection", web_rules("app.py", "return render_template_string(tpl)"))  # velora:ignore
        self.assertIn("csrf-disabled", web_rules("views.py", "@csrf_exempt\ndef pay(request): ..."))  # velora:ignore
        self.assertTrue({"buffer-overflow", "format-string"} <= web_rules("main.c", "gets(buf);\nprintf(buf);\n"))
        html = '<form method="post" action="http://exemple.fr/login"><input name="pw"></form>' \
               '<script src="https://cdn.exemple.com/lib.js"></script>'
        self.assertTrue({"form-over-http", "form-no-csrf", "missing-sri"} <= web_rules("index.html", html))
        safe = '<form method="post">{% csrf_token %}</form><script src="https://cdn.x/a.js" integrity="sha384-x"></script>'
        self.assertEqual(web_rules("index.html", safe), set())

    def test_server_config(self):
        self.assertIn("directory-listing", web_rules("site/.htaccess", "Options +Indexes +FollowSymLinks"))
        self.assertNotIn("directory-listing", web_rules("site/.htaccess", "Options -Indexes"))
        self.assertIn("weak-tls", web_rules("nginx.conf", "ssl_protocols TLSv1 TLSv1.2;"))
        self.assertNotIn("weak-tls", web_rules("nginx.conf", "ssl_protocols TLSv1.2 TLSv1.3;"))

    def test_ignore_marker(self):
        self.assertEqual(web_rules("a.js", "el.innerHTML = html; // velora:ignore"), set())


class ProjectChecksTest(TempProjectCase):
    def test_login_without_rate_limit_or_hashing(self):
        self.write("package.json", '{"dependencies": {"express": "4.19.0", "react": "18.3.1"}}')
        self.write("server.js", "const app = express();\napp.post('/login', (req, res) => {\n"
                                "  if (req.body.password === user.password) res.send('ok');\n});\n")
        result = run_scan(self.project(), network=False, save=False)
        self.assertTrue({"Express", "React"} <= set(result.stack))
        found = {f.rule for f in result.findings}
        self.assertTrue({"no-rate-limit", "no-password-hashing", "no-security-headers"} <= found)

    def test_protected_login(self):
        self.write("package.json", '{"dependencies": {"express": "4", "helmet": "7", "express-rate-limit": "7", "bcrypt": "5"}}')
        self.write("server.js", "app.use(helmet());\napp.post('/login', limiter, async (req, res) => {\n"
                                "  await bcrypt.compare(req.body.password, hash);\n});\n")
        found = {f.rule for f in run_scan(self.project(), network=False, save=False).findings}
        self.assertFalse({"no-rate-limit", "no-password-hashing", "no-security-headers"} & found)


class MobileTest(unittest.TestCase):
    def test_android_manifest(self):
        manifest = """<manifest><uses-permission android:name="android.permission.READ_SMS"/>
<application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="true">
  <activity android:name=".Main" android:exported="true"><intent-filter>
    <category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
  <service android:name=".Sync" android:exported="true"/>
  <receiver android:name=".Safe" android:exported="true" android:permission="x.PERM"/>
</application></manifest>"""
        findings = {f.rule: f for f in mobile.check_file("app/src/main/AndroidManifest.xml", manifest)}
        self.assertTrue({"android-debuggable", "android-cleartext", "android-backup", "android-exported",
                         "android-permissions"} <= set(findings))
        self.assertIn("service .Sync", findings["android-exported"].detail)
        self.assertNotIn(".Main", findings["android-exported"].detail)
        self.assertNotIn(".Safe", findings["android-exported"].detail)

    def test_ios_gradle_and_code(self):
        plist = "<dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict>"
        self.assertIn("ios-ats-disabled", mobile_rules("ios/App/Info.plist", plist))
        gradle = "android {\n  buildTypes {\n    release {\n      minifyEnabled false\n    }\n  }\n}\n"
        self.assertIn("android-no-minify", mobile_rules("app/build.gradle", gradle))
        self.assertIn("insecure-storage", mobile_rules("src/api.ts", "await AsyncStorage.setItem('userToken', t)"))
        self.assertIn("trust-all-certificates", mobile_rules("lib/api.dart",
                                                             "client.badCertificateCallback = (cert, host, port) => true;"))
        self.assertIn("trust-all-certificates", mobile_rules("Net.java",
                                                             "public void checkServerTrusted(X509Certificate[] c, String a) {}"))

    def test_network_security_config_debug_overrides(self):
        xml = ('<network-security-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors>'
               '</debug-overrides></network-security-config>')
        self.assertEqual(mobile_rules("res/xml/network_security_config.xml", xml), set())


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, *mode in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if mode:
                info.external_attr = mode[0] << 16
            zf.writestr(info, data)
    return buf.getvalue()


class UploadTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def extract(self, data):
        archive = self.tmp / "a.zip"
        archive.write_bytes(data)
        return upload.safe_extract(archive, self.tmp / "out")

    def test_rejects_dangerous_paths(self):
        stats = self.extract(make_zip([
            ("../evil.txt", "x"), ("/abs.txt", "x"), ("C:/win.txt", "x"), ("a/../../up.txt", "x"),
            ("CON.txt", "x"), ("lien", "/etc/passwd", 0o120777), ("site/index.php", "<?php echo 1;"),
            ("site/node_modules/lib/x.js", "x"),
        ]))
        self.assertEqual(stats["files"], 1)
        self.assertEqual(stats["skipped"], 6)
        written = sorted(p.relative_to(self.tmp).as_posix() for p in self.tmp.rglob("*") if p.is_file())
        self.assertEqual(written, ["a.zip", "out/site/index.php"])
        self.assertEqual(upload.project_root(self.tmp / "out").name, "site")

    def test_rejects_zip_bomb(self):
        with self.assertRaises(upload.UploadError):
            self.extract(make_zip([("bombe.txt", b"\0" * (20 * 1024 * 1024))]))

    def test_rejects_garbage(self):
        with self.assertRaises(upload.UploadError):
            self.extract(b"ceci n'est pas un zip")

    def test_antivirus_blocked_file_is_reported(self):
        import builtins
        from unittest import mock
        from velora.ui.server import upload_scan
        real_open = builtins.open

        def guarded_open(path, *args, **kwargs):  # simule un antivirus qui refuse un fichier
            if str(path).endswith("shell.php"):
                raise PermissionError(13, "Opération refusée par l'antivirus")
            return real_open(path, *args, **kwargs)

        data = make_zip([("site/index.html", "<h1>ok</h1>"), ("site/uploads/shell.php", "<?php // x")])
        with mock.patch("velora.core.upload.open", guarded_open, create=True):
            report = upload_scan(io.BytesIO(data), len(data), offline=True)
        blocked = [f for f in report["findings"] if f["rule"] == "antivirus-blocked"]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["severity"], "critical")
        self.assertEqual(blocked[0]["file"], "site/uploads/shell.php")
        self.assertEqual(report["upload"]["blocked"], ["site/uploads/shell.php"])

    def test_upload_scan_end_to_end(self):
        from velora.ui.server import upload_scan
        data = make_zip([
            ("monsite/index.php", "<?php echo $_GET['nom']; ?>"),
            ("monsite/public/config.js", f'const key = "{AWS}";'),
            ("monsite/.velora/config.json", '{"scan": {"allow_paths": ["*"]}}'),
        ])
        report = upload_scan(io.BytesIO(data), len(data), offline=True)
        rules = {(f["category"], f["rule"]) for f in report["findings"]}
        self.assertIn(("web", "reflected-xss"), rules)
        self.assertIn(("exposure", "aws-access-key"), rules)  # signalé une seule fois, comme exposition
        self.assertNotIn(("secret", "aws-access-key"), rules)
        self.assertEqual(report["upload"]["name"], "monsite")
        self.assertIn("PHP", report["stack"])
        self.assertTrue(any(h["platform"] == "php" for h in report["hardening"]))


class SsrfGuardTest(unittest.TestCase):
    def test_private_addresses_refused(self):
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "0.0.0.0", "::1",
                   "::ffff:127.0.0.1", "fd00::1", "100.64.0.1"]:
            with self.subTest(ip=ip), self.assertRaises(live.LiveScanError):
                live.check_address(ip)
        live.check_address("8.8.8.8")
        live.check_address("127.0.0.1", allow_private=True)

    def test_url_validation(self):
        self.assertEqual(live.normalize_url("exemple.fr"), "https://exemple.fr")
        for bad in ["", "ftp://exemple.fr", "http://moi:secret@exemple.fr", "javascript:alert(1)"]:
            with self.subTest(url=bad), self.assertRaises(live.LiveScanError):
                live.normalize_url(bad)

    def test_localhost_refused_by_fetcher(self):
        with self.assertRaises(live.LiveScanError):
            live.Fetcher().fetch("http://localhost/")


class _VulnerableSite(BaseHTTPRequestHandler):
    PAGES = {
        "/": ("text/html", '<html><body><form action="http://exemple.fr/login" method="post"></form>'
                           '<script src="/app.js"></script></body></html>'),
        "/app.js": ("application/javascript", f'var k="{AWS}";\n//# sourceMappingURL=app.js.map\n'),
        "/app.js.map": ("application/json", '{"version":3,"sources":["src/secret.ts"]}'),
        "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
        "/.env": ("text/plain", "DB_PASSWORD=x\nAPI_KEY=y\n"),
    }

    def log_message(self, *_):
        pass

    def do_GET(self):
        page = self.PAGES.get(self.path)
        body = (page[1] if page else "introuvable").encode()
        self.send_response(200 if page else 404)
        self.send_header("Content-Type", page[0] if page else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/":
            self.send_header("Set-Cookie", "sessionid=abc; Path=/")
            self.send_header("X-Powered-By", "PHP/7.2.1")
            if self.headers.get("Origin"):
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)


class LiveScanTest(unittest.TestCase):
    def test_vulnerable_local_site(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableSite)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            result = live.scan(f"http://127.0.0.1:{server.server_port}/", allow_private=True)
        finally:
            server.shutdown()
            server.server_close()
        found = {f.rule: f for f in result.findings}
        expected = {"no-https", "missing-csp", "clickjacking", "cookie-flags", "cors-reflection", "exposed-git",
                    "exposed-env", "public-source-maps", "aws-access-key", "form-over-http", "version-disclosure"}
        self.assertTrue(expected <= set(found), expected - set(found))
        self.assertEqual(found["cors-reflection"].severity, "high")
        self.assertEqual(found["aws-access-key"].severity, "critical")
        self.assertNotIn("exposed-backup", found)  # les 404 ne déclenchent rien
        self.assertIn("php", result.platforms)
        self.assertTrue(any(s["platform"] == "php" for s in hardening.suggest(platforms=result.platforms)))
        self.assertLess(result.score, 30)


if __name__ == "__main__":
    unittest.main()
