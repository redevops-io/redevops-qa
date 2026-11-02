# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The REAL lane code with an egress gateway that cannot start (a test double for the gateway only): the lane must fail closed, never fall back to a
browser with a direct way out."""
import sys

import qa_egress


class Down:
    def __init__(self, *a, **k):
        pass

    def start(self, *a, **k):
        raise OSError("cannot bind the gateway port")


qa_egress.GatewayServer = Down
from qa_runner import lane_browser                      # noqa: E402

sys.exit(lane_browser.main(sys.argv[1:]))
