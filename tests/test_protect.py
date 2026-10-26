import re
import unittest

from velora.protect import exposure, fingerprint, license

from tests.helpers import TempProjectCase

ORIGINAL = '''
def compute_invoice(customer, items, discount_rate):
    """Calcule le total d'une facture."""
    subtotal = 0
    for item in items:
        if item.quantity <= 0:
            continue
        subtotal += item.price * item.quantity
        if item.category == "premium":
            subtotal += item.price * 0.05
    discount = subtotal * discount_rate
    taxes = (subtotal - discount) * 0.2
    return {"customer": customer.id, "subtotal": subtotal, "discount": discount,
            "taxes": taxes, "total": subtotal - discount + taxes}


def apply_loyalty(customer, total):
    if customer.years > 5:
        return total * 0.9
    elif customer.years > 2:
        return total * 0.95
    return total
'''

UNRELATED = '''
class Graph:
    def __init__(self):
        self.edges = {}

    def add(self, a, b):
        self.edges.setdefault(a, set()).add(b)
        self.edges.setdefault(b, set()).add(a)

    def bfs(self, start):
        seen, queue = {start}, [start]
        while queue:
            node = queue.pop(0)
            for nxt in sorted(self.edges.get(node, ())):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        return seen
'''


def disguise(code: str) -> str:
    """Copie « maquillée » : renommage, suppression des commentaires et reformatage."""
    renames = {"compute_invoice": "calc", "customer": "c", "items": "lst", "item": "it",
               "subtotal": "s", "discount_rate": "r", "discount": "d", "taxes": "tx", "apply_loyalty": "loyal"}
    for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
        code = re.sub(rf"\b{old}\b", new, code)
    code = re.sub(r'"""[^"]*"""', "", code)
    return code.replace("    ", "  ")


class FingerprintTest(TempProjectCase):
    def test_detects_disguised_copy_but_not_unrelated_code(self):
        self.write("billing.py", ORIGINAL)
        project = self.project()
        fingerprint.save_db(project)

        suspect = self.tmp / "suspect"
        suspect.mkdir()
        (suspect / "copy.py").write_text(disguise(ORIGINAL), encoding="utf-8")
        (suspect / "other.py").write_text(UNRELATED, encoding="utf-8")
        result = fingerprint.compare(project, suspect)
        rows = {m["file"]: m for m in result["matches"]}
        self.assertIn("copy.py", rows)
        self.assertGreater(rows["copy.py"]["fuzzy"], 0.6)
        self.assertNotIn("other.py", rows)
        self.assertEqual(rows["copy.py"]["sources"], ["billing.py"])

    def test_exact_copy_is_strict_match(self):
        self.write("billing.py", ORIGINAL)
        project = self.project()
        target = self.tmp / "exact.py"
        target.write_text("# copie\n" + ORIGINAL, encoding="utf-8")
        result = fingerprint.compare(project, target, use_db=False)
        self.assertGreater(result["suspect_similarity"]["strict"], 0.9)

    def test_winnow_guarantee(self):
        hashes = [5, 3, 8, 3, 9, 1, 7, 7, 2, 6]
        picked = fingerprint.winnow(hashes, 4)
        for start in range(len(hashes) - 3):
            self.assertTrue(any(start <= i < start + 4 for i in picked))


class LicenseTest(TempProjectCase):
    LINES = ["Copyright (c) 2026 Ada. Tous droits réservés.", "SPDX-License-Identifier: LicenseRef-Proprietary"]

    def test_header_styles_and_idempotence(self):
        py = license.add_header("#!/usr/bin/env python\n# -*- coding: utf-8 -*-\nprint(1)\n", "a.py", self.LINES)
        self.assertTrue(py.startswith("#!/usr/bin/env python\n# -*- coding: utf-8 -*-\n# Copyright"))
        self.assertIsNone(license.add_header(py, "a.py", self.LINES))

        js = license.add_header("export const x = 1;\r\n", "a.ts", self.LINES)
        self.assertTrue(js.startswith("// Copyright"))
        self.assertIn("\r\n", js)

        html = license.add_header("<!doctype html>\n<html></html>\n", "i.html", self.LINES)
        self.assertTrue(html.startswith("<!doctype html>\n<!--"))

        php = license.add_header("<?php\necho 1;\n", "i.php", self.LINES)
        self.assertTrue(php.startswith("<?php\n// Copyright"))

        self.assertIsNone(license.add_header("{}", "data.json", self.LINES))
        self.assertIsNone(license.add_header("x", "lib.min.js", self.LINES))

    def test_apply_and_license_file(self):
        self.write("src/a.py", "print(1)\n")
        self.write("src/b.js", "// Copyright déjà là\nx()\n")
        project = self.project()
        self.assertEqual(license.apply_headers(project, "Ada"), ["src/a.py"])
        self.assertEqual(license.apply_headers(project, "Ada"), [])
        path = license.write_license(project, "proprietary", "Ada", "ada@example.org")
        self.assertIn("L.335-2", path.read_text(encoding="utf-8"))


class ExposureTest(TempProjectCase):
    def test_source_maps_and_bundle_secrets(self):
        self.write("package.json", "{}")
        self.write("dist/app.js", 'const k="AKIA' + 'Z7XQ2LMN4PRT6VWY";\n//# sourceMappingURL=app.js.map\n')
        self.write("dist/app.js.map", "{}")
        self.write("public/.env", "X=1")
        self.write("vite.config.ts", "export default { build: { sourcemap: true } }")
        findings, recs = exposure.audit(self.root)
        found = {f.rule for f in findings}
        self.assertTrue({"source-maps", "aws-access-key", "public-secret-file", "sourcemap-config"} <= found)
        self.assertTrue(any("javascript-obfuscator" in r for r in recs))


if __name__ == "__main__":
    unittest.main()
