from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pmpfuzz.off_state_cva6 import main


if __name__ == "__main__":
    raise SystemExit(main())
