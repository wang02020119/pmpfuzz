import unittest
from pathlib import Path


class XiangShanBuildScriptTest(unittest.TestCase):
    def test_clean_xiangshan_build_script_uses_vanilla_goodtrap_path(self):
        script = Path("scripts/build/build_xiangshan_goodtrap_emu.sh")
        self.assertTrue(script.exists())
        text = script.read_text(encoding="ascii")

        self.assertIn('XIANGSHAN_DIR="${XIANGSHAN_DIR:-$WORKSPACE_DIR/xiangshan}"', text)
        self.assertIn("--config MinimalConfig", text)
        self.assertIn("--disable-fork", text)
        self.assertIn("CXX=/usr/bin/g++", text)
        self.assertIn("LINK=/usr/bin/g++", text)
        self.assertIn('OPT_FAST="${OPT_FAST:--O0}"', text)
        self.assertIn('export NOOP_HOME="$XIANGSHAN_DIR"', text)
        self.assertIn('echo "[preflight] NOOP_HOME: $NOOP_HOME"', text)
        self.assertIn("expected generated VSimTop.mk", text)
        self.assertIn("isolation_path_leak.log", text)
        self.assertIn("isolated XiangShan build still references shared vanilla root", text)
        self.assertIn("CONFIG_NO_DIFFTEST", text)
        self.assertIn("python3 -m pmpfuzz.xiangshan_emu_diag", text)
        self.assertNotIn("cascade_xiangshan_adapt", text)


if __name__ == "__main__":
    unittest.main()
