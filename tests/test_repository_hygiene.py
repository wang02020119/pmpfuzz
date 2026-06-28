import unittest
from pathlib import Path


class RepositoryHygieneTest(unittest.TestCase):
    def test_gitignore_excludes_generated_outputs_and_keeps_source_pocs(self):
        root = Path(__file__).resolve().parents[1]
        gitignore = (root / ".gitignore").read_text(encoding="ascii")

        for pattern in ["runs/", "tracecov_stage2/", "__pycache__/", "*.elf", "*.log", "*.cover"]:
            self.assertIn(pattern, gitignore)
        self.assertIn("experiments/*report*.md", gitignore)
        self.assertIn("!experiments/*.S", gitignore)

    def test_gitattributes_keeps_scripts_and_assembly_lf(self):
        root = Path(__file__).resolve().parents[1]
        attributes = (root / ".gitattributes").read_text(encoding="ascii")

        self.assertIn("*.sh text eol=lf", attributes)
        self.assertIn("*.S text eol=lf", attributes)


if __name__ == "__main__":
    unittest.main()
