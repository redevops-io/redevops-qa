# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_robot``: the Robot Framework suite adapter of ReDevOps QA.

Runs an existing suite under the shared supervisor, enforces an allowlist of libraries (before and after the run), never installs a
library, and imports ``output.xml`` strictly at test level. Importing this package never imports Robot Framework.
"""
from .output_xml import ASSERT_TAG, ParsedRobot, parse_output_xml
from .policy import (DEFAULT_ALLOWED_LIBRARIES, STANDARD_LIBRARIES, RobotConfig, ScanResult, check_run, scan_suite)
from .suite import ADAPTER_ID, RobotSuiteAdapter, suite_manifest

__version__ = "0.1.0.dev0"
