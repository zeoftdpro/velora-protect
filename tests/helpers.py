import os
import tempfile
import unittest
from pathlib import Path

from velora.core.config import Project


class TempProjectCase(unittest.TestCase):
    """Crée un projet jetable et isole le registre global (VELORA_HOME)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="velora-test-")
        self.tmp = Path(self._tmp.name)
        self.root = self.tmp / "projet"
        self.root.mkdir()
        self._old_home = os.environ.get("VELORA_HOME")
        os.environ["VELORA_HOME"] = str(self.tmp / "home")

    def tearDown(self):
        if self._old_home is None:
            os.environ.pop("VELORA_HOME", None)
        else:
            os.environ["VELORA_HOME"] = self._old_home
        self._tmp.cleanup()

    def write(self, rel: str, content: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def project(self, **config) -> Project:
        project = Project(self.root)
        project.config["project_name"] = "demo"
        project.config["author"] = "Ada Test"
        for key, value in config.items():
            section, _, leaf = key.partition("__")
            if leaf:
                project.config[section][leaf] = value
            else:
                project.config[section] = value
        project.save_config()
        return Project(self.root)
