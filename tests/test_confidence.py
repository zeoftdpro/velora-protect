import unittest

from velora.scan import confidence, run_scan

from tests.helpers import TempProjectCase


def points(result, label):
    return next(f["points"] for f in result["factors"] if f["label"] == label)


class ConfidenceTest(unittest.TestCase):
    def test_full_coverage_is_capped(self):
        files = ["index.php", "app.js", "composer.json", "composer.lock", "logo.png"]
        result = confidence.compute(files, 4, 10, network_checked=True)
        self.assertEqual(result["score"], confidence.MAX_SCORE)
        self.assertEqual(result["level"], "élevée")
        self.assertEqual(points(result, "Fichiers lus"), 20)  # l'image non lue ne pénalise pas

    def test_unsupported_language_lowers_confidence(self):
        result = confidence.compute(["main.rs", "lib.rs", "util.rs", "web.js"], 4, 0, network_checked=False)
        self.assertEqual(points(result, "Langages analysés"), 12)
        self.assertIn("3 Rust", result["factors"][0]["detail"])

    def test_dependencies(self):
        offline = confidence.compute(["a.js", "package.json", "package-lock.json"], 3, 5, network_checked=False)
        no_lock = confidence.compute(["a.js", "package.json"], 2, 5, network_checked=True)
        none = confidence.compute(["a.js", "pyproject.toml"], 2, 0, network_checked=False)
        unpinned = confidence.compute(["a.js", "package.json"], 2, 0, network_checked=True, declared=4)
        self.assertEqual([points(r, "Dépendances") for r in (offline, no_lock, none, unpinned)], [5, 15, 30, 15])
        self.assertLess(offline["score"], no_lock["score"])


class ScanConfidenceTest(TempProjectCase):
    def test_scan_reports_confidence(self):
        self.write("index.php", "<?php echo 1;")
        result = run_scan(self.project(), network=False, save=False)
        self.assertEqual(result.to_dict()["confidence"]["score"], result.confidence["score"])
        self.assertGreaterEqual(result.confidence["score"], 80)


if __name__ == "__main__":
    unittest.main()
