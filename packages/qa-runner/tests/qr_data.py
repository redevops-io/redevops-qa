# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Recorded-observation builders shared by the judge and bundle tests."""
import copy

from qa_evidence.canon import dumps_canonical
from qa_runner.judge import observation_document, observation_path

RUN = "r0-test"
ORIGIN = "http://127.0.0.1:5000"


def row(aid, value, resolution="RESOLVED", match_count=1, digest=None):
    return {"assertion_id": aid, "resolution": resolution, "match_count": match_count, "value": value, "value_digest": digest}


def good_rows(notif=True):
    return [row("A-SAVED", "Settings saved"), row("A-NOTIF-ON", notif), row("A-URL", ORIGIN + "/settings?saved=1")]


def observation_bytes(rows=None, lane="browser", run=RUN, **overrides):
    doc = observation_document(lane, f"{run}.{lane}", "playwright-chromium", good_rows() if rows is None else rows)
    doc.update(overrides)
    return dumps_canonical(doc)


def files_with(data, lane="browser"):
    return {observation_path(lane): data}
