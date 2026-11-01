# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A Robot launcher for the hard-kill test (``RunOptions.robot_launcher``): the REAL ``robot_guard`` around a module that hangs and leaves a stray child."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("robot_guard", HERE.parent / "src" / "qa_runner" / "robot_guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
guard.main(sys.argv[1:], module="guard_hang_module")
