"""
Orchestrates M7 (40-test suite T-01..T-40 on PostgreSQL 17),
M8 (4 demos D-01..D-04 + N=5 trade-off measurements),
and M9 (final deliverables SP-01..SP-05 + secret hygiene verification).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import run_all_tests  # noqa: E402
import run_demos_and_capture  # noqa: E402
import generate_deliverables  # noqa: E402


def main() -> int:
    rc = run_all_tests.main()
    if rc != 0:
        return rc
    run_demos_and_capture.run_demos()
    return generate_deliverables.main()


if __name__ == "__main__":
    raise SystemExit(main())

