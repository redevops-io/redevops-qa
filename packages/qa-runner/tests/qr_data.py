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


# ---- real browser-lane files (from a real run; see golden/regen_browser.py) ------------------------------------------------------------------------------------------------
from pathlib import Path as _Path

from qa_evidence.build import read_files as _read_files

GOLDEN_DIR = _Path(__file__).resolve().parent / "golden"
BROWSER_RUN = {"none": "r0-golden-browser-none", "settings": "r0-golden-browser-settings"}


def browser_files(defect="none"):
    """The files the judge reads for the browser lane of a REAL run against the target with ``defect`` (bundle path -> bytes), and the run id they belong to."""
    return dict(_read_files(str(GOLDEN_DIR / f"browser-{defect}.tar")))
