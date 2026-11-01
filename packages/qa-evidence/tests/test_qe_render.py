# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Text and HTML rendering: one self-contained file, everything from a bundle escaped, and the integrity banner always present."""
import copy
import html.parser
import json
import re

import pytest

from qa_evidence.build import build_bundle
from qa_evidence.constants import ANCHOR_ABSENT_NOTICE, ANCHOR_DECLARED_NOTICE
from qa_evidence.inspector import inspect_bundle
from qa_evidence.render import render_html, render_text

from qe_helpers import build_base, build_forged, edit, inputs, put, rechain

HOSTILE = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'; DROP TABLE x; --", "&amp;&lt;b&gt;", "</style><style>body{display:none}</style>",
           "<!-- c -->", "javascript:alert(1)", "{{7*7}} ${7*7} %s %(x)s", "\x1b[2J\x1b]0;owned\x07", "a‮b⁦c", "x​y", "\u0085  ",
           "<svg onload=alert(1)>", "url(http://example.invalid/x.png)", "@import 'http://example.invalid/x.css';"]


@pytest.fixture(scope="module")
def hostile_location(tmp_path_factory):
    """A bundle whose every free-text field carries hostile text."""
    report, files, tools = inputs()
    report["lanes"][0]["native"]["raw_status"] = HOSTILE[0]
    report["lanes"][1]["native"]["raw_status"] = HOSTILE[8]
    report["redaction"]["rules"][0]["description"] = HOSTILE[1]
    report["redaction"]["notes"] = HOSTILE[2:9]
    report["limitations"].append({"id": "own", "text": HOSTILE[9] + HOSTILE[12]})
    report["environment"]["note"] = HOSTILE[4]
    report["extensions"] = {"label": HOSTILE[6], "other": HOSTILE[13]}
    b = build_bundle(report=report, files=files, tools=tools, producer={"name": "qa-runner", "version": "0.1.0", "motd": HOSTILE[14]}).with_anchor(
        "ci-artifact-attestation", HOSTILE[0] + HOSTILE[10])
    loc = tmp_path_factory.mktemp("hostile") / "b.tar"
    b.write_archive(str(loc))
    return str(loc)


class Tags(html.parser.HTMLParser):
    ALLOWED_TAGS = {"html", "head", "meta", "title", "style", "body", "h1", "h2", "div", "p", "table", "tr", "th", "td", "code", "ul", "li", "strong", "br"}
    ALLOWED_ATTRS = {"lang", "charset", "http-equiv", "content", "name", "class"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.text, self.in_style = [], [], [], False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [(tag, k, v) for k, v in attrs]
        self.in_style = tag == "style"

    def handle_endtag(self, tag):
        self.in_style = False

    def handle_data(self, data):
        if not self.in_style:
            self.text.append(data)


def parse(page):
    p = Tags()
    p.feed(page)
    p.close()
    return p


def test_hostile_text_never_becomes_markup(hostile_location):
    page = render_html(inspect_bundle(hostile_location))
    p = parse(page)
    assert set(p.tags) <= Tags.ALLOWED_TAGS, set(p.tags) - Tags.ALLOWED_TAGS
    assert {a for _, a, _ in p.attrs} <= Tags.ALLOWED_ATTRS
    for _, _, value in p.attrs:
        assert not any(h in (value or "") for h in HOSTILE)
    for raw in ("<script", "<img", "<svg", "<!--", "</style><style"):
        assert raw not in page.replace('<!DOCTYPE html>', ""), raw
    assert "&lt;script&gt;" in page and "&quot;&gt;&lt;img" in page


def test_the_hostile_text_is_still_shown_as_text_so_nothing_is_hidden(hostile_location):
    p = parse(render_html(inspect_bundle(hostile_location)))
    joined = "".join(p.text)
    assert "<script>alert(1)</script>" in joined and "javascript:alert(1)" in joined and "{{7*7}}" in joined and "DROP TABLE" in joined


def test_control_bidi_and_zero_width_characters_are_made_visible_in_both_renderings(hostile_location):
    ins = inspect_bundle(hostile_location)
    for out in (render_html(ins), render_text(ins)):
        for ch in ("\x1b", "\x07", "‮", "⁦", "​", "\u0085", " ", " ", "\x00"):
            assert ch not in out, repr(ch)
        assert "\\u202e" in out and "\\u001b" in out


def test_the_text_rendering_has_no_raw_escape_sequences_and_only_newlines_as_control_characters(hostile_location):
    out = render_text(inspect_bundle(hostile_location))
    assert all(c == "\n" or c.isprintable() for c in out)


def test_the_page_is_one_self_contained_file_with_no_script_and_no_external_resource(hostile_location):
    page = render_html(inspect_bundle(hostile_location))
    p = parse(page)
    assert "script" not in p.tags and not {"link", "img", "iframe", "object", "embed", "form", "a", "base", "audio", "video", "source", "svg"} & set(p.tags)
    assert not any(a in ("src", "href", "action", "style", "srcset", "poster", "data") or a.startswith("on") for _, a, _ in p.attrs)
    css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    assert "url(" not in css and "@import" not in css and "http" not in css
    assert "default-src 'none'" in page and "style-src 'unsafe-inline'" in page
    assert page.count("<style>") == 1 and page.startswith("<!DOCTYPE html>")


def test_html_and_text_are_deterministic(hostile_location):
    a, b = inspect_bundle(hostile_location), inspect_bundle(hostile_location)
    assert render_html(a) == render_html(b) and render_text(a) == render_text(b)


# ---- the integrity banner ------------------------------------------------------------------------------------------------------------------
def test_a_clean_unanchored_bundle_says_integrity_against_reforging_is_not_established():
    b = build_base()
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        b.write_archive(os.path.join(d, "b.tar"))
        ins = inspect_bundle(os.path.join(d, "b.tar"))
    assert ANCHOR_ABSENT_NOTICE == "no external anchor: integrity against deliberate re-forging NOT established"
    assert ANCHOR_ABSENT_NOTICE in render_text(ins) and html_escape(ANCHOR_ABSENT_NOTICE) in render_html(ins)
    assert ins.verification.to_json()["anchor"]["state"] == "absent"


def html_escape(text):
    import html as h
    return h.escape(text, quote=True)


def test_a_forged_rechained_bundle_looks_consistent_but_the_rendering_says_the_forgery_is_not_excluded(tmp_path):
    forged = build_forged()
    forged.write_archive(str(tmp_path / "f.tar"))
    ins = inspect_bundle(str(tmp_path / "f.tar"))
    assert ins.verification.ok and ins.verification.anchor.state == "absent"
    text, page = render_text(ins), render_html(ins)
    assert "Verification : OK - internally consistent" in text and ANCHOR_ABSENT_NOTICE in text
    assert "OK - internally consistent" in page and ANCHOR_ABSENT_NOTICE in page
    assert 'class="banner warn">External anchor: ' + ANCHOR_ABSENT_NOTICE in page


@pytest.mark.parametrize("state", ["declared", "verified", "mismatch"])
def test_each_anchor_state_has_its_own_banner(tmp_path, state):
    b = build_base().with_anchor("ci-artifact-attestation", "run-17")
    b.write_archive(str(tmp_path / "b.tar"))
    supplied = {"declared": None, "verified": b.manifest_digest, "mismatch": "sha256:" + "0" * 64}[state]
    ins = inspect_bundle(str(tmp_path / "b.tar"), anchor=supplied)
    assert ins.verification.anchor.state == state
    text, page = render_text(ins), render_html(ins)
    assert ins.verification.anchor.notice in text and html_escape(ins.verification.anchor.notice) in page
    if state == "declared":
        assert ANCHOR_DECLARED_NOTICE in text and "NOT" in text
    if state == "verified":
        assert "NOT established" not in text.split("External anchor:")[1].split("\n")[0] and 'banner ok">External anchor' in page
    if state == "mismatch":
        assert "FAILED" in text and 'banner bad">External anchor' in page


def test_native_results_and_verdicts_are_in_separate_sections():
    import os, tempfile
    with tempfile.TemporaryDirectory() as d:
        build_base().write_archive(os.path.join(d, "b.tar"))
        ins = inspect_bundle(os.path.join(d, "b.tar"))
    text, page = render_text(ins), render_html(ins)
    assert text.index("NATIVE ENGINE RESULTS") < text.index("INDEPENDENT VERDICT")
    assert "native=NATIVE_PASS" in text and "verdict=FAILED" in text and "ENGINE_VERIFIER_DISAGREE lane robot" in text
    assert page.index("Native engine results") < page.index("Independent verdict") and 'class="native"' in page and 'class="verdict"' in page
    assert ins.summary["independent_verdict"]["outcome"] == "FAILED" and ins.summary["lanes"][1]["native"]["status"] == "NATIVE_PASS"
    assert ins.summary["engine_verifier_disagreements"] == [{"code": "ENGINE_VERIFIER_DISAGREE", "lane_id": "robot", "native_status": "NATIVE_PASS",
                                                             "verdict_states": ["FAILED"]}]


def test_a_failed_bundle_is_flagged_and_its_content_is_marked_untrusted(tmp_path):
    files = dict(build_base().files)
    files["logs/orchestrator.log"] = b"orchestrator log LINE\n"
    from qa_evidence.build import write_archive
    write_archive(files, str(tmp_path / "t.tar"))
    ins = inspect_bundle(str(tmp_path / "t.tar"))
    assert not ins.content_trusted and not ins.verification.ok
    text, page = render_text(ins), render_html(ins)
    assert "FAILED" in text and "DIGEST_MISMATCH" in text and "for diagnosis only" in text
    assert "banner bad" in page and "DIGEST_MISMATCH" in page and "diagnosis only" in page


def test_an_unreadable_manifest_renders_without_a_summary(tmp_path):
    from qa_evidence.build import write_archive
    write_archive({"junk.txt": b"x"}, str(tmp_path / "j.tar"))
    ins = inspect_bundle(str(tmp_path / "j.tar"))
    assert ins.summary is None and "MANIFEST_MISSING" in render_text(ins) and "could not be read" in render_html(ins)


def test_informational_fields_are_listed_in_the_rendering():
    import os, tempfile
    report, files, tools = inputs()
    report["extensions"] = {"label": "nightly"}
    b = build_bundle(report=report, files=files, tools=tools)
    with tempfile.TemporaryDirectory() as d:
        b.write_archive(os.path.join(d, "b.tar"))
        ins = inspect_bundle(os.path.join(d, "b.tar"))
    assert "INFORMATIONAL" in render_text(ins) and "/extensions/label" in render_text(ins) and "/extensions/label" in render_html(ins)


def test_the_json_inspection_is_plain_json_without_floats(hostile_location):
    doc = json.loads(json.dumps(inspect_bundle(hostile_location).to_json()))
    assert doc["schema"] == "qa-evidence/inspection" and doc["verification"]["anchor"]["state"] == "declared"

    def no_float(x):
        if isinstance(x, float):
            raise AssertionError(x)
        if isinstance(x, dict):
            [no_float(v) for v in x.values()]
        if isinstance(x, list):
            [no_float(v) for v in x]
    no_float(doc)
