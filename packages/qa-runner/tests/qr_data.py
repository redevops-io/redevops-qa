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


GOOD_TOTALS = {"order_101_total_cents": 9450, "order_102_total_cents": 9999, "order_103_total_cents": 9000, "order_104_total_cents": 9005}
DEFECT_TOTALS = {"order_101_total_cents": 10500, "order_102_total_cents": 9999, "order_103_total_cents": 10000, "order_104_total_cents": 10005}
_HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n<robot generator="Robot 7.5 (Python 3.12.16 on linux)" generated="2026-11-01T13:34:05.196569" rpa="false" schemaversion="5">\n'


def robot_xml(values=None, status="PASS", extra_tags=()):
    """A minimal valid Robot Framework 7.5 output.xml of the order-discount suite with the given recorded values (a test double of the engine's file; the real file is
    produced by the real engine in the ``real`` tests)."""
    values = GOOD_TOTALS if values is None else values
    tags = "".join(f"<tag>qa-observe:{k}={v}</tag>" for k, v in values.items()) + "".join(f"<tag>{t}</tag>" for t in extra_tags)
    passed, failed = (1, 0) if status == "PASS" else (0, 1)
    return (_HEAD + '<suite id="s1" name="Order Discount" source="/x/order_discount.robot"><test id="s1-t1" name="Order Discount Rule" line="8">' + tags
            + f'<status status="{status}" start="2026-11-01T13:34:05.2" elapsed="0.001"/></test><status status="{status}" start="2026-11-01T13:34:05.1" elapsed="0.01"/></suite>'
            + f'<statistics><total><stat pass="{passed}" fail="{failed}" skip="0">All Tests</stat></total></statistics></robot>\n').encode()


def robot_record(native=None, run=RUN, lane="robot"):
    """The observation record the importer derives from ``native`` (default: a clean run), as bytes."""
    from qa_runner.judge import derived_record
    return dumps_canonical(derived_record(robot_xml() if native is None else native, lane, f"{run}.{lane}"))


def robot_files(native=None, record=None, lane="robot"):
    native = robot_xml() if native is None else native
    return {f"lanes/{lane}/native/output.xml": native, f"lanes/{lane}/observations.json": robot_record(native, lane=lane) if record is None else record}
