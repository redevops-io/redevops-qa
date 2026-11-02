# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Observation tags of Robot Framework 7.5 ``output.xml`` files: what is read, and what is refused."""
import hashlib
import json

import pytest

from qa_adapter_kit import MalformedReport
from qa_robot import observation_document, parse_observations, parse_output_xml
from qa_robot.observations import MAX_OBSERVATIONS, RESERVED_NAMES

HEAD = '<?xml version="1.0" encoding="UTF-8"?>\n<robot generator="Robot 7.5 (Python 3.12.16 on linux)" generated="2026-11-01T13:34:05.196569" rpa="false" schemaversion="5">\n'


def xml(tests, generator=None):
    """A minimal valid output.xml with one test per entry of ``tests``: (name, status, [tags])."""
    body = ['<suite id="s1" name="Suite" source="/x/suite.robot">']
    for i, (name, status, tags) in enumerate(tests, 1):
        body.append(f'<test id="s1-t{i}" name="{name}" line="{i}">' + "".join(f"<tag>{t}</tag>" for t in tags)
                    + f'<status status="{status}" start="2026-11-01T13:34:05.2" elapsed="0.001"/></test>')
    body.append('<status status="PASS" start="2026-11-01T13:34:05.1" elapsed="0.01"/></suite>')
    n = len(tests)
    stats = f'<statistics><total><stat pass="{sum(1 for t in tests if t[1] == "PASS")}" fail="{sum(1 for t in tests if t[1] == "FAIL")}" skip="{sum(1 for t in tests if t[1] == "SKIP")}">All Tests</stat></total></statistics>'
    head = HEAD if generator is None else HEAD.replace("Robot 7.5 (Python 3.12.16 on linux)", generator)
    return (head + "\n".join(body) + stats + "</robot>\n").encode()


GOOD = xml([("Order Rule", "PASS", ["qa-observe:order_101_total_cents=9450", "qa-observe:order_102_total_cents=9999", "qa-assert:A-1"])])


def test_observation_tags_become_typed_values_sorted_by_name():
    obs = parse_observations(GOOD)
    assert dict(obs.values) == {"order_101_total_cents": 9450, "order_102_total_cents": 9999} and list(obs.values) == ["order_101_total_cents", "order_102_total_cents"]
    assert obs.raw_sha256 == hashlib.sha256(GOOD).hexdigest() and obs.engine_release == "7.5" and [t[1] for t in obs.tests] == ["PASS"]


def test_values_are_integers_only_when_they_are_canonical_decimal_integers():
    obs = parse_observations(xml([("T", "PASS", ["qa-observe:a=007", "qa-observe:b=-5", "qa-observe:c=0", "qa-observe:d=12abc", "qa-observe:e=1234567890123456", "qa-observe:f=1.5"])]))
    assert dict(obs.values) == {"a": "007", "b": -5, "c": 0, "d": "12abc", "e": "1234567890123456", "f": "1.5"}


def test_a_run_without_observation_tags_has_an_empty_record():
    assert dict(parse_observations(xml([("T", "PASS", ["smoke", "qa-assert:A-1"])])).values) == {}


def test_observations_of_several_tests_are_merged_and_each_test_is_listed():
    obs = parse_observations(xml([("A", "PASS", ["qa-observe:x=1"]), ("B", "FAIL", ["qa-observe:y=2"]), ("C", "SKIP", [])]))
    assert dict(obs.values) == {"x": 1, "y": 2} and [t[1] for t in obs.tests] == ["PASS", "FAIL", "SKIP"]


@pytest.mark.parametrize("tag", ["qa-observe:", "qa-observe:x", "qa-observe:=1", "qa-observe:X=1", "qa-observe:1x=1", "qa-observe:x=", "qa-observe:x=a b", "qa-observe:x=a=b",
                                 "qa-observe:x=" + "a" * 129, "qa-observe:" + "n" * 65 + "=1", "QA-OBSERVE:X=1", "qa-observe:x=é", "qa-observe:x=a;b"])
def test_a_malformed_observation_tag_is_refused_never_skipped(tag):
    with pytest.raises(MalformedReport):
        parse_observations(xml([("T", "PASS", [tag])]))


@pytest.mark.parametrize("name", sorted(RESERVED_NAMES))
def test_a_name_that_reads_as_a_verdict_or_an_expected_value_is_refused(name):
    with pytest.raises(MalformedReport):
        parse_observations(xml([("T", "PASS", [f"qa-observe:{name}=1"])]))


def test_a_name_recorded_twice_is_refused_even_when_the_values_agree():
    with pytest.raises(MalformedReport):
        parse_observations(xml([("T", "PASS", ["qa-observe:x=1", "qa-observe:x=1"])]))
    with pytest.raises(MalformedReport):
        parse_observations(xml([("A", "PASS", ["qa-observe:x=1"]), ("B", "PASS", ["qa-observe:x=2"])]))


def test_more_than_the_limit_is_refused():
    tags = [f"qa-observe:n{i}={i}" for i in range(MAX_OBSERVATIONS + 1)]
    with pytest.raises(MalformedReport):
        parse_observations(xml([("T", "PASS", tags)]))
    assert len(parse_observations(xml([("T", "PASS", tags[:MAX_OBSERVATIONS])])).values) == MAX_OBSERVATIONS


@pytest.mark.parametrize("data", [b"", b"<robot/>", b"not xml", HEAD.encode() + b"<!DOCTYPE x>" + b"</robot>", GOOD.replace(b'schemaversion="5"', b'schemaversion="4"'),
                                  GOOD.replace(b'<stat pass="1"', b'<stat pass="2"')])
def test_the_same_hardening_as_the_test_importer_applies(data):
    with pytest.raises(MalformedReport):
        parse_observations(data)
    with pytest.raises(MalformedReport):
        parse_output_xml(data)


def test_the_record_is_a_reference_document_with_the_run_and_the_digest_of_the_raw_report_and_nothing_judged():
    doc = observation_document(parse_observations(GOOD), run_id="r0-x.robot", lane_id="robot")
    assert doc["apiVersion"] == "qa-checks/reference-1" and doc["kind"] == "RobotObservations" and doc["metadata"] == {"name": "robot"}
    spec = doc["spec"]
    assert spec["run_id"] == "r0-x.robot" and spec["output_xml_sha256"] == "sha256:" + hashlib.sha256(GOOD).hexdigest()
    assert spec["observations"] == {"order_101_total_cents": 9450, "order_102_total_cents": 9999}
    text = json.dumps(doc).lower()
    for word in ("expected", "verdict", "predicate", "verified", "pass"):
        assert word not in text.replace("order_", "")
    assert json.dumps(doc) == json.dumps(observation_document(parse_observations(GOOD), run_id="r0-x.robot", lane_id="robot"))


def test_a_release_the_generator_does_not_name_is_unknown_not_guessed():
    assert parse_observations(xml([("T", "PASS", [])], generator="Something else")).engine_release == "unknown"
