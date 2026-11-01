# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Rewrite the golden fixtures from the current code: ``python packages/qa-fixture-app/tests/regen_golden.py``.

``golden/none`` holds every step. ``golden/<defect>`` holds only the steps whose response differs from ``none`` (the health response
always does), so the file list of a defect directory IS the list of what the defect changes. Review the diff of this directory
before committing: an unexpected file is an unintended change of behaviour.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from qa_fixture_app import create_server  # noqa: E402
import qfa_support as s  # noqa: E402


def main() -> int:
    transcripts = {}
    for mode in s.MODES:
        with create_server(mode) as server:
            transcripts[mode] = s.run_scenario(server.url)
    for mode in s.MODES:
        directory = s.GOLDEN / mode
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        for i, sid in enumerate(s.STEP_IDS):
            if mode == "none" or transcripts[mode][sid] != transcripts["none"][sid]:
                (directory / s.golden_name(i, sid)).write_bytes(transcripts[mode][sid])
        print(mode, len(list(directory.iterdir())), "files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
