# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Stands in for ``python -m robot`` in the offline tests: copies a recorded output.xml into the directory named by ``--outputdir`` and
exits with the code it was given. Usage: fake_robot.py --fixture FILE [--exit N] [--write-nothing] [robot options ...] SUITE"""
import shutil
import sys
from pathlib import Path

args = sys.argv[1:]
fixture = exit_code = None
write = True
out = None
i = 0
while i < len(args):
    a = args[i]
    if a == "--fixture":
        fixture = args[i + 1]; i += 2
    elif a == "--exit":
        exit_code = int(args[i + 1]); i += 2
    elif a == "--write-nothing":
        write = False; i += 1
    elif a == "--outputdir":
        out = args[i + 1]; i += 2
    else:
        i += 1
if write and fixture and out:
    shutil.copyfile(fixture, Path(out) / "output.xml")
print("fake robot ran")
sys.exit(0 if exit_code is None else exit_code)
