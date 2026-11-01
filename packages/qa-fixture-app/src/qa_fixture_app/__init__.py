# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_fixture_app``: a small deterministic web app that is the target of the ReDevOps QA end-to-end tests.

Standard library only. Loopback only. The state is in memory and starts from the same seed in every process; the only file the
app ever writes is the request log the caller names. One defect at most is switched on, by name (``DEFECTS``).
"""
from .app import DEFECT_DESCRIPTIONS, DEFECTS, FixtureApp, Request, Response
from .server import FixtureServer, create_server

__version__ = "0.1.0.dev0"
