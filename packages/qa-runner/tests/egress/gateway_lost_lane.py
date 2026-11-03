# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The REAL browser lane code (``qa_runner.lane_browser``) with one test seam: after the FIRST browser action returns (the page has loaded through the gateway) the gateway is stopped, as if it
had been killed. ``python gateway_lost_lane.py kill INPUT.json`` does that; ``python gateway_lost_lane.py keep INPUT.json`` is the control and leaves the gateway alone. Everything else, the harness
executor, the real adapter, the real Chromium, is the product's. Used by ``test_qr_egress_lane.py``."""
import sys

import qa_egress
from qa_runner import lane_browser

mode, argv = sys.argv[1], sys.argv[2:]
assert mode in ("kill", "keep"), mode

instances = []
Real = qa_egress.GatewayServer


class Recording(Real):
    def start(self, *a, **k):
        super().start(*a, **k)
        instances.append(self)
        return self


class Killing(lane_browser.RecordingAdapter):
    acts = 0

    def act(self, *a, **k):
        done = self._inner.act(*a, **k)
        Killing.acts += 1
        if mode == "kill" and Killing.acts == 1:
            for gateway in instances:
                gateway.stop()
        return done


qa_egress.GatewayServer = Recording
lane_browser.RecordingAdapter = Killing
sys.exit(lane_browser.main(argv))
