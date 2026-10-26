import unittest

from velora.core import files as fs

from tests.helpers import TempProjectCase


class IgnoreRulesTest(unittest.TestCase):
    def check(self, patterns, path, is_dir=False):
        return fs.is_ignored(path, is_dir, fs.parse_ignore_lines(patterns))

    def test_basename_and_anchored(self):
        self.assertTrue(self.check(["*.log"], "a/b/debug.log"))
        self.assertTrue(self.check(["/build"], "build", True))
        self.assertFalse(self.check(["/build"], "src/build", True))
        self.assertTrue(self.check(["docs/*.md"], "docs/a.md"))
        self.assertFalse(self.check(["docs/*.md"], "docs/sub/a.md"))

    def test_double_star_and_dir_only(self):
        self.assertTrue(self.check(["**/cache/"], "a/b/cache", True))
        self.assertFalse(self.check(["cache/"], "cache", False))
        self.assertTrue(self.check(["a/**/z.txt"], "a/z.txt"))
        self.assertTrue(self.check(["a/**/z.txt"], "a/b/c/z.txt"))

    def test_negation(self):
        rules = [".env*", "!.env.example"]
        self.assertTrue(self.check(rules, ".env.local"))
        self.assertFalse(self.check(rules, ".env.example"))


class WalkTest(TempProjectCase):
    def test_nested_gitignore_and_default_dirs(self):
        self.write(".gitignore", "*.tmp\n")
        self.write("sub/.gitignore", "local.txt\n")
        for rel in ["a.py", "x.tmp", "sub/local.txt", "sub/keep.txt", "local.txt",
                    "node_modules/pkg/index.js", "dist/bundle.js", ".velora/config.json"]:
            self.write(rel, "x")
        found = [rel for rel, _ in fs.iter_files(self.root)]
        self.assertEqual(found, [".gitignore", "a.py", "local.txt", "sub/.gitignore", "sub/keep.txt"])
        with_build = [rel for rel, _ in fs.iter_files(self.root, include_build=True)]
        self.assertIn("dist/bundle.js", with_build)


if __name__ == "__main__":
    unittest.main()
