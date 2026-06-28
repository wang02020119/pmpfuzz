import unittest
from pathlib import Path


class XiangShanBuildScriptTest(unittest.TestCase):
    def test_clean_xiangshan_build_script_uses_vanilla_goodtrap_path(self):
        script = Path("scripts/build_xiangshan_goodtrap_emu.sh")
        self.assertTrue(script.exists())
        text = script.read_text(encoding="ascii")

        self.assertIn("/home/dubhe/wjs/xiangshan_vanilla", text)
        self.assertIn("--config MinimalConfig", text)
        self.assertIn("--disable-fork", text)
        self.assertIn("CXX=/usr/bin/g++", text)
        self.assertIn("LINK=/usr/bin/g++", text)
        self.assertIn("CONFIG_NO_DIFFTEST", text)
        self.assertNotIn("cascade_xiangshan_adapt", text)


if __name__ == "__main__":
    unittest.main()
