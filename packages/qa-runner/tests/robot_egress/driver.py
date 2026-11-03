# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot lane child of the experiments: ``python -s driver.py INPUT.json LAYERS``. It registers the hostile suite and then runs the lane's own ``main`` (the same code path as the real lane
child: install the layers, run the engine under the kit supervisor, write the outcome). ``LAYERS`` is a comma separated subset of the kernel layers for the experiments that show what each does
alone ('-' for the lane's own default, both)."""
import sys

from qa_runner import lane_robot, netfence, suites

suites.SUITES["hostile"] = {"files": ("hostile.robot", "HostileLib.py", "sneaky_import.py", "world.json"), "library": "HostileLib.py", "suite": "hostile.robot"}
layers = netfence.ALL_LAYERS if sys.argv[2] == "-" else tuple(x for x in sys.argv[2].split(",") if x)
sys.exit(lane_robot.main([sys.argv[1]], layers=layers))
