# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The output.xml importer against files recorded from real Robot Framework 7.5 runs, and against hostile ones."""
import pytest

from rb_support import FIXTURES
from qa_adapter_kit import MalformedReport, Status
from qa_robot import parse_output_xml

MIXED = (FIXTURES / "robot75-mixed.xml").read_bytes()
PASS = (FIXTURES / "robot75-pass.xml").read_bytes()


def by_name(parsed):
    return {a.name: a for a in parsed.assertions}


def test_a_recorded_mixed_run_maps_every_outcome():
    got = by_name(parse_output_xml(MIXED))
    assert {n: a.status for n, a in got.items()} == {
        "Login Works": Status.PASS, "Total Is Correct": Status.PASS, "Banner Text Is Wrong": Status.FAIL, "Untagged Pass": Status.PASS,
        "Skipped On Purpose": Status.SKIP, "Skip If Condition": Status.SKIP, "Templated": Status.FAIL, "Never Runs": Status.FAIL}


def test_tags_become_declared_assertion_ids_even_for_a_test_that_did_not_run():
    got = by_name(parse_output_xml(MIXED))
    assert got["Login Works"].declared_assertion_ids == ("A-1",) and got["Total Is Correct"].declared_assertion_ids == ("A-2", "A-3")
    assert got["Skipped On Purpose"].declared_assertion_ids == ("A-5",) and got["Never Runs"].declared_assertion_ids == ("A-6",)
    assert got["Untagged Pass"].declared_assertion_ids == ()


def test_messages_come_from_the_test_status_and_are_bounded():
    got = by_name(parse_output_xml(MIXED))
    assert got["Banner Text Is Wrong"].message == "Banner differs: Welcome != Welcome back"
    assert got["Never Runs"].message.startswith("Parent suite setup failed:") and got["Skipped On Purpose"].message == "not on this platform"


def test_native_ids_are_the_suite_path_and_the_test_name_made_safe_and_unique():
    ids = [a.native_id for a in parse_output_xml(MIXED).assertions]
    assert "Suite.Mixed.Login_Works" in ids and "Suite.Sub.Failing_Setup.Never_Runs" in ids and len(set(ids)) == len(ids)


def test_keyword_owners_and_names_are_collected_for_the_allowlist_check():
    parsed = parse_output_xml(MIXED)
    assert parsed.owners == {"BuiltIn"} and "Should Be Equal" in parsed.keyword_names
    assert len(parsed.raw_sha256) == 64 and parsed.generator.startswith("Robot 7.5")


def test_no_keyword_argument_or_log_text_reaches_a_result():
    parsed = parse_output_xml(MIXED)
    blob = repr(parsed.assertions)
    assert "PASSWORD" not in blob and "logging in" not in blob and "Create List" not in blob


def test_a_recorded_passing_run():
    parsed = parse_output_xml(PASS)
    assert [a.status for a in parsed.assertions] == [Status.PASS, Status.PASS] and [a.declared_assertion_ids for a in parsed.assertions] == [("A-1",), ("A-2",)]


def doc(body, root_attrs='generator="Robot 7.5" rpa="false" schemaversion="5"', stats='<statistics><total><stat pass="1" fail="0" skip="0">All Tests</stat></total></statistics>'):
    return f'<?xml version="1.0"?><robot {root_attrs}><suite id="s1" name="S">{body}</suite>{stats}</robot>'.encode()


OK_TEST = '<test id="s1-t1" name="T"><status status="PASS" start="x" elapsed="0.5"/></test>'


def test_a_minimal_well_formed_document_is_accepted():
    [a] = parse_output_xml(doc(OK_TEST)).assertions
    assert a.status is Status.PASS and a.duration_s == 0.5 and a.native_id == "S.T"


@pytest.mark.parametrize("data", [
    b"", b"nope", b"<robot", b"<html/>", doc(OK_TEST, root_attrs='generator="Robot 6.1" schemaversion="4"'),
    doc(OK_TEST, root_attrs='generator="Robot 7.5" rpa="true" schemaversion="5"'),
    doc(OK_TEST, root_attrs='generator="Robot 7.5" rpa="false"'),
    b'<?xml version="1.0"?><!DOCTYPE robot [<!ENTITY a "x">]><robot schemaversion="5"><suite name="S"/><statistics/></robot>',
    b'<!doctype robot><robot schemaversion="5"/>',
    b'<robot schemaversion="5" rpa="false"><statistics/></robot>',                                      # no suite
    doc(OK_TEST, stats=""),                                                                              # no statistics: possibly truncated
    doc(OK_TEST, stats='<statistics><total><stat pass="2" fail="0" skip="0">All Tests</stat></total></statistics>'),
    doc(OK_TEST, stats='<statistics><total><stat pass="x" fail="0" skip="0">All Tests</stat></total></statistics>'),
    doc('<test id="s1-t1" name="T"><status status="NOT RUN" start="x" elapsed="0"/></test>'),
    doc('<test id="s1-t1" name="T"/>'),
    doc('<test id="s1-t1"><status status="PASS" start="x" elapsed="0"/></test>'),
    doc('<test id="s1-t1" name="T"><kw name="K"><status status="PASS" start="x" elapsed="0"/></kw></test>'),    # only a keyword status
])
def test_malformed_hostile_or_unsupported_documents_are_refused(data):
    with pytest.raises(MalformedReport):
        parse_output_xml(data)


def test_the_recorded_file_cut_in_half_is_refused():
    with pytest.raises(MalformedReport):
        parse_output_xml(MIXED[: len(MIXED) // 2])


def test_a_billion_laughs_document_is_refused_before_parsing():
    with pytest.raises(MalformedReport):
        parse_output_xml(b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]><robot>&lol2;</robot>')


def test_size_and_count_limits(monkeypatch):
    import qa_robot.output_xml as ox
    monkeypatch.setattr(ox, "MAX_OUTPUT_BYTES", 10)
    with pytest.raises(MalformedReport):
        parse_output_xml(PASS)
    monkeypatch.undo()
    monkeypatch.setattr(ox, "MAX_TESTS", 1)
    with pytest.raises(MalformedReport):
        parse_output_xml(PASS)


def test_duplicate_names_get_unique_ids_and_hostile_names_valid_ones():
    body = ('<test id="a" name="Same"><status status="PASS" start="x" elapsed="0"/></test>'
            '<test id="b" name="Same"><status status="PASS" start="x" elapsed="0"/></test>'
            '<test id="c" name="x/../y;rm -rf $(z)"><status status="SKIP" start="x" elapsed="-3">why</status></test>')
    parsed = parse_output_xml(doc(body, stats='<statistics><total><stat pass="2" fail="0" skip="1">All Tests</stat></total></statistics>'))
    import re
    ids = [a.native_id for a in parsed.assertions]
    assert len(set(ids)) == 3 and all(re.match(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", i) for i in ids) and parsed.assertions[2].duration_s == 0.0


def test_an_invalid_assertion_tag_is_ignored_and_case_is_not_significant():
    body = ('<test id="a" name="T"><tag>QA-Assert:A-1</tag><tag>qa-assert:bad id</tag><tag>qa-assert:</tag><tag>other:A-2</tag>'
            '<status status="PASS" start="x" elapsed="0"/></test>')
    assert parse_output_xml(doc(body)).assertions[0].declared_assertion_ids == ("A-1",)
