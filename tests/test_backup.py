import json
import sqlite3
import unittest
import zipfile

from velora import VeloraError, backup

from tests.helpers import TempProjectCase


class RetentionTest(unittest.TestCase):
    def test_grandfather_father_son(self):
        names = [f"p_202601{d:02d}-{h:02d}0000.zip" for d in range(1, 31) for h in (9, 18)]
        keep = backup.select_to_keep(names, keep_last=3, keep_daily=5, keep_weekly=2, keep_monthly=1)
        newest_first = sorted(names, reverse=True)
        self.assertTrue(set(newest_first[:3]) <= keep)
        self.assertIn("p_20260126-180000.zip", keep)          # dernier jour retenu par la règle quotidienne
        self.assertNotIn("p_20260101-090000.zip", keep)
        self.assertLessEqual(len(keep), 3 + 5 + 2 + 1)

    def test_ignores_foreign_files(self):
        self.assertEqual(backup.select_to_keep(["notes.txt"], keep_last=5), set())


class BackupFlowTest(TempProjectCase):
    def setUp(self):
        super().setUp()
        self.dest = self.tmp / "dest"
        self.write("src/main.py", "print('bonjour')\n")
        self.write("README.md", "# Démo\n")
        db = sqlite3.connect(self.root / "data.db")
        db.execute("create table t (x)")
        db.execute("insert into t values (42)")
        db.commit()
        db.close()

    def make(self, **extra):
        return self.project(backup__destinations=[str(self.dest)], **extra)

    def test_run_verify_restore(self):
        project = self.make(backup__databases=[{"type": "sqlite", "name": "app", "path": "data.db"}])
        result = backup.run_backup(project, log=lambda m: None)
        self.assertEqual(result.status, "ok")
        archive = self.dest / "demo" / result.archive
        self.assertTrue(archive.exists())
        ok, problems = backup.verify_archive(archive)
        self.assertTrue(ok, problems)

        target = self.tmp / "restauration"
        backup.restore_archive(archive, target)
        self.assertEqual((target / "src" / "main.py").read_text(encoding="utf-8"), "print('bonjour')\n")
        restored_db = sqlite3.connect(target / "_velora_restore" / "databases" / "app.sqlite3")
        self.assertEqual(restored_db.execute("select x from t").fetchone(), (42,))
        restored_db.close()

    def test_skip_when_unchanged_and_detect_corruption(self):
        project = self.make()
        first = backup.run_backup(project, log=lambda m: None)
        self.assertEqual(backup.run_backup(project, log=lambda m: None).status, "skipped")
        self.write("src/main.py", "print('modifié')\n")
        self.assertEqual(backup.run_backup(project, log=lambda m: None).status, "ok")

        archive = self.dest / "demo" / first.archive
        tampered = self.tmp / "tampered.zip"
        with zipfile.ZipFile(archive) as src, zipfile.ZipFile(tampered, "w") as dst:
            for item in src.infolist():
                data = src.read(item)
                dst.writestr(item, b"pirate" if item.filename == "files/README.md" else data)
        ok, problems = backup.verify_archive(tampered)
        self.assertFalse(ok)
        self.assertIn("Empreinte différente : README.md", problems)

    def test_zip_slip_is_blocked(self):
        evil = self.tmp / "evil.zip"
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("files/../../evil.txt", "x")
            zf.writestr(backup.MANIFEST_NAME, json.dumps({"files": {}}))
        with self.assertRaises(VeloraError):
            backup.restore_archive(evil, self.tmp / "out")
        self.assertFalse((self.tmp / "evil.txt").exists())

    def test_refuses_non_empty_target(self):
        project = self.make()
        result = backup.run_backup(project, log=lambda m: None)
        with self.assertRaises(VeloraError):
            backup.restore_archive(self.dest / "demo" / result.archive, self.root)

    def test_no_destination(self):
        with self.assertRaises(VeloraError):
            backup.run_backup(self.project(), log=lambda m: None)

    def test_freshness(self):
        project = self.make()
        self.assertFalse(backup.check_freshness(project)[0])
        backup.run_backup(project, log=lambda m: None)
        self.assertTrue(backup.check_freshness(project)[0])


if __name__ == "__main__":
    unittest.main()
