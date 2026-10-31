# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""One full scripted scenario over the fake driver; ``digest()`` is a hash of everything the adapter returned."""
from __future__ import annotations

import hashlib
import json
import sys


def digest() -> str:
    from agent_harness.qa.records import (ActionKind, AssertionSubject, CaptureKind, LocateMode, ObserveRequest, Phase,
                                          ResetScope, SubjectKind)
    from qa_pw_support import APP, desc, element_subject, locate_one, login_page, make_world, request
    from qa_playwright.testing.fake import FakeElement
    page = login_page()
    page.elements.append(FakeElement(role="button", name="Submit", key="dup-1", visible_after_ms=300))
    page.elements[3].on_click = lambda s, el: s.page.elements.append(FakeElement(role="alert", name="Done", text="All done"))
    page.subresources += [(f"{APP}/api/x", "fetch"), ("http://exfil.test/b", "fetch")]
    w = make_world(page)
    h = w.open()
    out = []
    out.append(w.adapter.act(h, request(ActionKind.NAVIGATE, value=f"{APP}/login"), None).to_json())
    out.append(w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT).to_json())
    w.clock.advance(400)
    out.append(w.adapter.observe(h, ObserveRequest(phase=Phase.BEFORE, step_id="s1")).to_json())
    out.append(w.adapter.act(h, request(ActionKind.FILL, value="a@b.test"), locate_one(w, h, desc("textbox", "Email"))).to_json())
    out.append([p.to_json() for p in w.adapter.receipt_payloads(h)])
    out.append(w.adapter.assert_(h, element_subject(desc("textbox", "Email"))).to_json())
    out.append(w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.URL)).to_json())
    out.append([r.to_json() for r in w.adapter.capture(h, [CaptureKind.NETWORK_EXCERPT, CaptureKind.CONSOLE_EXCERPT, CaptureKind.DOM_META])])
    out.append(w.adapter.reset(h, ResetScope.CONTEXT).to_json())
    out.append(w.adapter.close_session(h).to_json())
    out.append(w.adapter.egress_counts(h))
    out.append(sorted(w.blobs.digests()))
    return hashlib.sha256(json.dumps(out, sort_keys=True, default=str).encode()).hexdigest()


if __name__ == "__main__":
    sys.stdout.write(digest())
