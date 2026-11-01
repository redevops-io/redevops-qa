# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Every endpoint's exact response, byte for byte, in every defect mode, against the committed golden files."""
import pytest
import qfa_support as s

from qa_fixture_app import create_server


@pytest.fixture(scope="module", params=s.MODES)
def mode_run(request):
    with create_server(request.param) as server:
        yield request.param, s.run_scenario(server.url)


@pytest.mark.parametrize("step", s.STEP_IDS)
def test_response_equals_the_golden_file(mode_run, step):
    mode, transcript = mode_run
    assert transcript[step] == s.read_golden(mode)[step], "%s / %s differs from its golden file" % (mode, step)


def test_the_golden_directories_hold_nothing_stale_and_nothing_redundant():
    names = {i: s.golden_name(i, sid) for i, sid in enumerate(s.STEP_IDS)}
    base = s.GOLDEN / "none"
    assert sorted(p.name for p in base.iterdir()) == sorted(names.values())
    for mode in ("discount", "settings"):
        files = sorted((s.GOLDEN / mode).iterdir())
        assert files, mode
        for path in files:
            assert path.name in names.values(), "stale golden file %s" % path
            assert path.read_bytes() != (base / path.name).read_bytes(), "%s repeats the base response (redundant)" % path


def test_golden_files_are_text_with_unix_line_ends_and_no_clock():
    for path in s.GOLDEN.rglob("*.http"):
        raw = path.read_bytes()
        assert b"\r" not in raw, path
        assert b"\nDate:" not in raw and b"Last-Modified" not in raw, path
        raw.decode("utf-8")


def test_html_and_json_bodies_are_what_the_content_type_says():
    import json
    for i, sid in enumerate(s.STEP_IDS):
        raw = (s.GOLDEN / "none" / s.golden_name(i, sid)).read_bytes()
        head, _, body = raw.partition(b"\n\n")
        if head.startswith(b"HEAD "):
            assert body == b""                      # a HEAD response has the headers of a GET and no body
            continue
        if b"Content-Type: application/json" in head:
            assert json.loads(body) is not None
            assert body.endswith(b"}\n")
        elif b"Content-Type: text/html" in head:
            assert body.startswith(b"<!doctype html>\n") and body.endswith(b"</html>\n")
