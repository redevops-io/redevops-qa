# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Defect isolation: each defect changes ONLY its documented behaviour. The full response set of a defect mode is diffed against
the response set of ``none`` and the difference must be exactly the documented one, step by step and field by field."""
import json
import re

import pytest
import qfa_support as s

from qa_fixture_app import DEFECT_DESCRIPTIONS, DEFECTS, FixtureApp, Request, create_server

# What each defect changes, as scenario step ids: only the defect's own behaviour (/health is identical in every mode, see below).
# This table is the documented diff (README, "Seeded defects").
HEALTH = {"health", "head-health"}
DOCUMENTED_DIFF = {
    "discount": {"orders-page", "order-page-101", "order-page-103", "order-page-104", "api-orders", "api-order-101",
                          "api-order-103", "api-order-104", "api-discount-10000", "api-discount-10005", "api-discount-10500"},
    "settings": {"settings-saved-page", "api-settings-saved", "settings-reload"},
}
# Fields that may differ inside the JSON bodies of the changed steps.
DOCUMENTED_FIELDS = {"discount": {"discount_cents", "total_cents"}, "settings": {"notifications", "theme"}}


@pytest.fixture(scope="module")
def transcripts():
    out = {}
    for mode in s.MODES:
        with create_server(mode) as server:
            out[mode] = s.run_scenario(server.url)
    return out


def _body(raw: bytes) -> bytes:
    return raw.partition(b"\n\n")[2]


@pytest.mark.parametrize("mode", ["discount", "settings"])
def test_the_diff_against_none_is_exactly_the_documented_one(transcripts, mode):
    changed = {sid for sid in s.STEP_IDS if transcripts[mode][sid] != transcripts["none"][sid]}
    assert changed == DOCUMENTED_DIFF[mode]


@pytest.mark.parametrize("mode", ["discount", "settings"])
def test_only_the_documented_fields_differ_in_the_changed_json_bodies(transcripts, mode):
    for sid in DOCUMENTED_DIFF[mode]:
        a, b = _body(transcripts["none"][sid]), _body(transcripts[mode][sid])
        if not a.lstrip().startswith(b"{"):
            continue
        ja, jb = json.loads(a), json.loads(b)
        differing = set()

        def walk(x, y, key=None):
            if isinstance(x, dict) and isinstance(y, dict):
                assert x.keys() == y.keys(), (sid, "the set of keys changed")
                for k in x:
                    walk(x[k], y[k], k)
            elif isinstance(x, list) and isinstance(y, list):
                assert len(x) == len(y), (sid, "the length of a list changed")
                for xi, yi in zip(x, y):
                    walk(xi, yi, key)
            elif x != y:
                differing.add(key)
        walk(ja, jb)
        assert differing and differing <= DOCUMENTED_FIELDS[mode], (sid, differing)


@pytest.mark.parametrize("mode", ["discount", "settings"])
def test_headers_status_and_redirects_never_differ_except_content_length_of_changed_bodies(transcripts, mode):
    for sid in s.STEP_IDS:
        ha, hb = transcripts["none"][sid].partition(b"\n\n")[0], transcripts[mode][sid].partition(b"\n\n")[0]
        strip = lambda h: re.sub(rb"Content-Length: \d+", b"Content-Length: N", h)       # noqa: E731
        assert strip(ha) == strip(hb), (mode, sid)


@pytest.mark.parametrize("mode", ["discount", "settings"])
def test_health_get_and_head_are_byte_identical_in_every_defect_mode(transcripts, mode):
    for step in sorted(HEALTH):
        assert transcripts[mode][step] == transcripts["none"][step], (mode, step)
    assert json.loads(_body(transcripts["none"]["health"])) == {"status": "ok"}
    assert _body(transcripts["none"]["head-health"]) == b""


def _response_part(raw: bytes) -> bytes:
    """Status line, headers and body of a transcript, without the request lines that precede '--- <status>'."""
    return raw[raw.index(b"\n--- ") + 1:]


def test_no_response_reveals_which_defect_is_seeded(transcripts):
    # (1) the word "defect" appears in no response of any mode; (2) the active defect's name occurs in every response of its mode exactly
    # as often as in the same response of the defect-free app, so nothing in a header or body says which defect is on.
    for mode in s.MODES:
        for sid, raw in transcripts[mode].items():
            part = _response_part(raw).lower()
            assert b"defect" not in part, (mode, sid)
            if mode != "none":
                assert part.count(mode.encode()) == _response_part(transcripts["none"][sid]).lower().count(mode.encode()), (mode, sid)


def test_the_defect_is_visible_only_in_the_ready_line_and_the_arguments(tmp_path):
    for mode in ("discount", "settings"):
        with s.spawn(tmp_path, defect=mode) as run:
            assert run.ready["defect"] == mode
            health = s.run_scenario(run.url, [("h", "GET", "/health", None), ("o", "GET", "/", None)])
            assert mode.encode() not in _response_part(health["h"]).lower()
            assert b"defect" not in health["h"] and b"defect" not in health["o"]
            run.proc.terminate()
            run.proc.wait(timeout=30)


def test_the_discount_defect_leaves_every_orders_total_equal_to_its_subtotal_and_settings_work(transcripts):
    t = transcripts["discount"]
    for oid in ("101", "102", "103", "104"):
        o = json.loads(_body(t["api-order-" + oid]))
        assert o["discount_cents"] == 0 and o["total_cents"] == o["subtotal_cents"]
    assert _body(t["api-settings-saved"]) == _body(transcripts["none"]["api-settings-saved"])


def test_the_settings_defect_acknowledges_the_save_but_stores_nothing(transcripts):
    t = transcripts["settings"]
    assert t["settings-save"] == transcripts["none"]["settings-save"]                    # same 303 to /settings?saved=1
    assert b'data-testid="save-status">Settings saved<' in t["settings-saved-page"]
    assert json.loads(_body(t["api-settings-saved"])) == {"notifications": False, "theme": "light"}
    assert json.loads(_body(transcripts["none"]["api-settings-saved"])) == {"notifications": True, "theme": "dark"}
    assert json.loads(_body(t["api-order-101"])) == json.loads(_body(transcripts["none"]["api-order-101"]))


@pytest.mark.parametrize("subtotal,discount", [(0, 0), (1, 0), (9999, 0), (10000, 1000), (10005, 1000), (10009, 1000), (10010, 1001),
                                               (10500, 1050), (123456, 12345)])
def test_the_rule_in_isolation(subtotal, discount):
    assert FixtureApp("none").discount_cents(subtotal) == discount
    assert FixtureApp("settings").discount_cents(subtotal) == discount
    assert FixtureApp("discount").discount_cents(subtotal) == 0


def test_defects_are_listed_documented_and_validated():
    assert DEFECTS == ("none", "discount", "settings") and set(DEFECT_DESCRIPTIONS) == set(DEFECTS)
    assert set(DOCUMENTED_DIFF) == set(DEFECTS) - {"none"}
    for bad in ("", "None", "both", "discount,settings", "unknown"):
        with pytest.raises(ValueError, match="unknown defect"):
            FixtureApp(bad)
        with pytest.raises(ValueError, match="unknown defect"):
            create_server(bad)


def test_exactly_one_defect_at_a_time_the_app_has_no_combined_mode():
    app = FixtureApp("discount")
    save = app.handle(Request("POST", "/login", {"content-type": "application/x-www-form-urlencoded"}, b"email=alice%40example.test&password=correct+horse"))
    cookie = dict(save.headers)["Set-Cookie"].split(";")[0]
    app.handle(Request("POST", "/settings", {"cookie": cookie}, b"notifications=1&theme=dark"))
    stored = json.loads(app.handle(Request("GET", "/api/me/settings", {"cookie": cookie})).body)
    assert stored == {"notifications": True, "theme": "dark"}                            # the discount defect does not break settings
