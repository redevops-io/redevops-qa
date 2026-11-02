# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The JUnit importer against reports recorded from real pytest runs, and against malformed ones."""
import pytest

from sel_support import FIXTURES
from qa_adapter_kit import MalformedReport, Status
from qa_selenium import parse_junit, read_junit

REC = FIXTURES / "junit"


def by_name(assertions):
    return {a.name: a for a in assertions}


def test_a_recorded_mixed_report_maps_every_outcome():
    got = by_name(read_junit(REC / "pytest-mixed.xml"))
    assert {n: a.status for n, a in got.items()} == {
        "test_total_is_correct": Status.PASS, "test_banner_text": Status.FAIL, "test_untagged_pass": Status.PASS,
        "test_error_in_fixture": Status.ERROR, "test_skipped": Status.SKIP, "test_expected_failure": Status.SKIP, "test_inside_class": Status.PASS}


def test_properties_become_declared_assertion_ids():
    got = by_name(read_junit(REC / "pytest-mixed.xml"))
    assert got["test_total_is_correct"].declared_assertion_ids == ("A-2", "A-3")
    assert got["test_banner_text"].declared_assertion_ids == ("A-4",) and got["test_untagged_pass"].declared_assertion_ids == ()


def test_native_ids_are_unique_stable_and_valid():
    ids = [a.native_id for a in read_junit(REC / "pytest-mixed.xml")]
    assert len(set(ids)) == len(ids) and "suite.test_mini.TestGroup::test_inside_class" in ids


def test_messages_are_bounded_and_carry_no_traceback_body():
    got = by_name(read_junit(REC / "pytest-mixed.xml"))
    assert len(got["test_banner_text"].message) <= 500 and "record_property" not in got["test_banner_text"].message
    assert got["test_skipped"].message == "not on this platform" and got["test_error_in_fixture"].message.startswith("failed on setup")


def test_a_recorded_empty_report_has_no_assertions():
    assert read_junit(REC / "pytest-none.xml") == ()


def test_a_recorded_passing_report():
    got = read_junit(REC / "pytest-pass.xml")
    assert len(got) == 4 and all(a.status is Status.PASS for a in got)


def xml(body, attrs='name="s" tests="1"'):
    return f'<?xml version="1.0"?><testsuites><testsuite {attrs}>{body}</testsuite></testsuites>'.encode()


def test_an_error_beats_a_failure_beats_a_skip():
    body = '<testcase classname="c" name="t"><skipped message="s"/><failure message="f"/><error message="e"/></testcase>'
    assert parse_junit(xml(body))[0].status is Status.ERROR
    assert parse_junit(xml(body.replace('<error message="e"/>', "")))[0].status is Status.FAIL
    assert parse_junit(xml(body.replace('<error message="e"/>', "").replace('<failure message="f"/>', "")))[0].status is Status.SKIP


@pytest.mark.parametrize("data", [
    b"", b"not xml", b"<testsuite", b"<html/>", b"<root><testcase name='a'/></root>",
    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><testsuites><testsuite tests="0"/></testsuites>',
    b'<!DOCTYPE testsuites><testsuites><testsuite tests="0"/></testsuites>',
    b'<?xml version="1.0"?><!doctype x><testsuites/>',
    xml('<testcase classname="c" name="a"/>', 'name="s" tests="2"'),                       # truncated: declares two, holds one
    xml('<testcase classname="c" name="a"/>', 'name="s" tests="many"'),
    xml('<testcase classname="c"/>'),                                             # no name
])
def test_malformed_or_hostile_reports_are_refused(data):
    with pytest.raises(MalformedReport):
        parse_junit(data)


def test_a_billion_laughs_report_is_refused_before_it_is_parsed():
    lol = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>'
    with pytest.raises(MalformedReport):
        parse_junit(lol)


def test_a_report_without_declared_counts_is_accepted():
    assert len(parse_junit(xml('<testcase classname="c" name="a"/>', 'name="s"'))) == 1


def test_an_oversized_report_and_too_many_testcases_are_refused(tmp_path, monkeypatch):
    import qa_selenium.junit as j
    big = tmp_path / "big.xml"
    big.write_bytes(b"<testsuites>" + b" " * (j.MAX_REPORT_BYTES + 1) + b"</testsuites>")
    with pytest.raises(MalformedReport):
        read_junit(big)
    monkeypatch.setattr(j, "MAX_TESTCASES", 2)
    with pytest.raises(MalformedReport):
        parse_junit(xml('<testcase classname="c" name="a"/><testcase classname="c" name="b"/><testcase classname="c" name="c"/>', 'tests="3"'))


def test_a_missing_report_file_is_refused(tmp_path):
    with pytest.raises(MalformedReport):
        read_junit(tmp_path / "nope.xml")


def test_duplicate_and_hostile_names_get_valid_unique_ids():
    body = ('<testcase classname="c" name="t[a b]"/><testcase classname="c" name="t[a b]"/>'
            '<testcase classname="" name="x/../y;rm -rf"/><testcase classname="c" name="' + "n" * 400 + '"/>')
    got = parse_junit(xml(body, 'name="s" tests="4"'))
    ids = [a.native_id for a in got]
    assert len(set(ids)) == 4 and all(len(i) <= 128 for i in ids)
    import re
    assert all(re.match(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", i) for i in ids)


def test_an_invalid_declared_id_is_ignored_and_a_valid_one_kept():
    body = ('<testcase classname="c" name="t"><properties><property name="qa-assert" value="bad id"/>'
            '<property name="qa-assert" value="A-1"/><property name="other" value="A-2"/></properties></testcase>')
    assert parse_junit(xml(body))[0].declared_assertion_ids == ("A-1",)


def test_negative_or_absurd_durations_become_zero():
    got = parse_junit(xml('<testcase classname="c" name="a" time="-5"/>'))
    assert got[0].duration_s == 0.0
    assert parse_junit(xml('<testcase classname="c" name="a" time="abc"/>'))[0].duration_s == 0.0


def test_a_fifo_where_the_report_should_be_is_refused_at_once_and_a_link_or_a_huge_file_is_refused_too(tmp_path):
    """Retest round 2, L-R1: `stat` then `read_bytes` hung on a FIFO. The probe runs in a child with a hard timeout so a regression cannot hang the suite."""
    import os
    import subprocess
    import sys
    fifo = tmp_path / "report.xml"
    os.mkfifo(fifo)
    code = (f"import sys\nsys.path[:0] = {[p for p in sys.path if p]!r}\nfrom pathlib import Path\nfrom qa_adapter_kit import MalformedReport\nfrom qa_selenium import read_junit\n"
            f"try:\n    read_junit(Path({str(fifo)!r}))\nexcept MalformedReport as e:\n    print('REFUSED')\n")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert "REFUSED" in done.stdout, done.stderr[-300:]
    real = tmp_path / "real.xml"
    real.write_bytes((REC / "pytest-mixed.xml").read_bytes())
    link = tmp_path / "link.xml"
    link.symlink_to(real)
    with pytest.raises(MalformedReport):
        read_junit(link)
    big = tmp_path / "big.xml"
    with open(big, "wb") as fh:
        fh.truncate(21 * 1024 * 1024)
    with pytest.raises(MalformedReport):
        read_junit(big)
    assert read_junit(real)
