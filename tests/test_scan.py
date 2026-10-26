import json
import unittest

from velora.scan import deps, misconfig, run_scan, secrets
from velora.scan.models import security_score

from tests.helpers import TempProjectCase

# Les faux secrets sont assemblés à l'exécution pour ne pas déclencher les scanners sur ce fichier.
AWS = "AKIA" + "Z7XQ2LMN4PRT6VWY"
GITHUB = "ghp_" + "x" * 36
STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def rules(text, path="app.py"):
    return [f.rule for f in secrets.scan_text(text, path)]


class SecretsTest(unittest.TestCase):
    def test_detects_provider_keys(self):
        self.assertIn("aws-access-key", rules(f'key = "{AWS}"'))
        self.assertIn("github-token", rules(f"token: {GITHUB}"))
        self.assertIn("stripe-live", rules(f"STRIPE={STRIPE}", ".env"))
        self.assertIn("private-key", rules("-----BEGIN RSA PRIVATE KEY-----"))  # velora:ignore (faux secret de test)
        self.assertIn("db-url-password", rules('url = "postgres://admin:Sup3rS3cret@db:5432/app"'))  # velora:ignore

    def test_generic_hardcoded_password(self):
        self.assertEqual(rules('DB_PASSWORD = "S3cr3t!pa55w0rd"'), ["generic-secret"])  # velora:ignore
        self.assertEqual(rules('"client_secret": "9f8Kq2LmZx7Wv4Np"', "config.json"), ["generic-secret"])  # velora:ignore

    def test_no_false_positives(self):
        for line in [
            'password_field = "password"',
            'tokenizer = "bert-base-uncased"',
            'api_key = os.environ["API_KEY"]',
            'API_KEY = "your-api-key-here"',
            'password: "${DB_PASSWORD}"',
            'secret = "{{ vault_secret }}"',
            'token_url = "/oauth/token"',
            'SECRET_KEY = "CHANGE_ME"',
        ]:
            with self.subTest(line=line):
                self.assertEqual(rules(line), [])

    def test_unquoted_values_only_in_config_files(self):
        self.assertEqual(rules("API_TOKEN=x9F2kL8qPz3VbN7m", ".env.production"), ["generic-secret-config"])
        self.assertEqual(rules("API_TOKEN=x9F2kL8qPz3VbN7m", "script.py"), [])

    def test_ignore_marker(self):
        self.assertEqual(rules(f'key = "{AWS}"  # velora:ignore'), [])

    def test_secret_is_masked(self):
        finding = secrets.scan_text(f'key = "{AWS}"', "a.py")[0]
        self.assertNotIn(AWS, finding.detail)


class DependencyParsersTest(unittest.TestCase):
    def test_requirements(self):
        found, unpinned = deps._parse_requirements("requests==2.19.0\nflask>=2\n# c\n-r other.txt\nDjango[argon2]==4.2.1", "r.txt")
        self.assertEqual([(d.name, d.version) for d in found], [("requests", "2.19.0"), ("Django", "4.2.1")])
        self.assertEqual(unpinned, ["flask"])

    def test_package_lock_v3(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/a/node_modules/@scope/b": {"version": "2.0.0"},
            "node_modules/linked": {"link": True},
        }}
        found = deps._parse_package_lock(json.dumps(lock), "package-lock.json")
        self.assertEqual({(d.name, d.version) for d in found}, {("lodash", "4.17.20"), ("@scope/b", "2.0.0")})

    def test_yarn_lock(self):
        text = ('"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n\n'
                'lodash@^4.17.0:\n  version "4.17.21"\n')
        found = deps._parse_yarn_lock(text, "yarn.lock")
        self.assertEqual([(d.name, d.version) for d in found], [("@babel/core", "7.2.0"), ("lodash", "4.17.21")])

    def test_poetry_and_cargo(self):
        text = '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n\n[[package]]\nname = "idna"\nversion = "3.1"\n'
        found = deps._parse_toml_packages(text, "poetry.lock", "PyPI")
        self.assertEqual([(d.name, d.version) for d in found], [("urllib3", "1.26.4"), ("idna", "3.1")])

    def test_go_mod(self):
        text = "module x\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/net v0.1.0 // indirect\n)\nrequire github.com/c/d v0.0.1\n"
        found = deps._parse_go_mod(text, "go.mod")
        self.assertEqual([d.name for d in found], ["github.com/a/b", "golang.org/x/net", "github.com/c/d"])

    def test_cvss3(self):
        self.assertEqual(deps.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(deps.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(deps.vuln_severity({"database_specific": {"severity": "MODERATE"}}), "medium")


class MisconfigTest(unittest.TestCase):
    def test_code_rules(self):
        found = {f.rule for f in misconfig.check_file("app.py", "DEBUG = True\nrequests.get(u, verify=False)\nyaml.load(f)\n")}  # velora:ignore
        self.assertTrue({"debug-enabled", "tls-verify-disabled", "unsafe-yaml-load"} <= found)
        safe = {f.rule for f in misconfig.check_file("app.py", "yaml.load(f, Loader=yaml.SafeLoader)\n")}
        self.assertNotIn("unsafe-yaml-load", safe)

    def test_dockerfile(self):
        found = {f.rule for f in misconfig.check_file("Dockerfile", "FROM node:latest\nENV API_TOKEN=abc123\n")}
        self.assertEqual(found, {"docker-root", "docker-latest", "docker-secret"})
        clean = misconfig.check_file("Dockerfile", "FROM python:3.12-slim\nUSER app\n")
        self.assertEqual(clean, [])


class RunScanTest(TempProjectCase):
    def test_full_scan_respects_gitignore(self):
        self.write(".gitignore", ".env\nsecrets/\n")
        self.write(".env", f"STRIPE={STRIPE}\n")
        self.write("secrets/key.txt", f"{GITHUB}\n")
        self.write("src/app.py", f'aws = "{AWS}"\n')
        result = run_scan(self.project(), network=False)
        files = {f.file for f in result.findings if f.category == "secret"}
        self.assertEqual(files, {"src/app.py"})
        self.assertEqual(result.score, security_score(result.findings))
        self.assertTrue((self.root / ".velora" / "last_scan.json").exists())


if __name__ == "__main__":
    unittest.main()
