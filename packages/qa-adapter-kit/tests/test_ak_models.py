# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import copy
import json

import pytest

from qa_adapter_kit import (AdapterClass, AdapterManifest, AdapterResult, ErrorCode, EvidenceArtifact, HARD_CAPS, InteractiveActionRequest,
                            Limits, ModelError, NativeAssertion, Status, SuiteRunRequest, aggregate_status)
from qa_adapter_kit.models import canonical_json
from qa_adapter_kit.testing.fakes import interactive_manifest, suite_manifest


def na(status="PASS", nid="T1", **kw):
    return NativeAssertion(native_id=nid, name="n", status=Status(status), **kw)


def result(**kw):
    base = dict(run_id="r1", adapter_id="fake-suite", adapter_class=AdapterClass.SUITE, status=Status.PASS, native_assertions=(na(),))
    base.update(kw)
    return AdapterResult(**base)


# ---------------------------------------------------------------------------------------------- manifest
def test_manifest_round_trips_through_a_dict_and_json():
    m = suite_manifest(env_allowlist=("APP_URL",))
    again = AdapterManifest.from_dict(json.loads(json.dumps(m.to_dict())))
    assert again == m


def test_manifest_rejects_unknown_and_missing_fields():
    d = suite_manifest().to_dict()
    with pytest.raises(ModelError, match="unknown field"):
        AdapterManifest.from_dict({**d, "mid_test_steering": True})
    del d["adapter_id"]
    with pytest.raises(ModelError, match="missing field"):
        AdapterManifest.from_dict(d)


@pytest.mark.parametrize("cap", ["steer", "mid_test_steering", "interactive", "act", "click", "type", "navigate", "inject", "pause", "resume"])
def test_a_suite_adapter_cannot_claim_mid_test_steering_or_interactive_actions(cap):
    d = suite_manifest().to_dict()
    d["capabilities"] = ["run_suite", cap]
    with pytest.raises(ModelError, match="no mid-test steering"):
        AdapterManifest.from_dict(d)


def test_a_suite_adapter_declares_exactly_run_and_import():
    d = suite_manifest().to_dict()
    d["capabilities"] = ["run_suite", "something_else"]
    with pytest.raises(ModelError):
        AdapterManifest.from_dict(d)
    d["capabilities"] = []
    with pytest.raises(ModelError):
        AdapterManifest.from_dict(d)


def test_an_interactive_manifest_may_declare_actions():
    assert "click" in interactive_manifest().capabilities


@pytest.mark.parametrize("field,value", [("adapter_id", "Bad Id"), ("adapter_id", "x"), ("adapter_version", "latest"), ("network", "open"),
                                         ("downloads", "no"), ("allowed_executables", ["python"]), ("env_allowlist", ["lower"]),
                                         ("schema", "other/1"), ("adapter_class", "robot")])
def test_manifest_field_validation(field, value):
    d = suite_manifest().to_dict()
    d[field] = value
    with pytest.raises(ModelError):
        AdapterManifest.from_dict(d)


def test_manifest_limits_cannot_exceed_the_hard_caps():
    d = suite_manifest().to_dict()
    d["limits"]["deadline_s"] = HARD_CAPS.deadline_s + 1
    with pytest.raises(ModelError):
        AdapterManifest.from_dict(d)


def test_a_name_cannot_be_both_plain_and_secret():
    with pytest.raises(ModelError):
        suite_manifest(env_allowlist=("APP_X",), secret_env_allowlist=("APP_X",))


def test_framework_release_must_be_exact():
    d = suite_manifest().to_dict()
    d["framework"]["pinned_release"] = ">=1.0"
    with pytest.raises(ModelError):
        AdapterManifest.from_dict(d)


# ---------------------------------------------------------------------------------------------- limits
def test_clamp_never_exceeds_the_ceiling():
    ceiling = Limits(deadline_s=10, output_limit_bytes=100, max_steps=3, max_retries=1, kill_grace_s=1)
    asked = Limits(deadline_s=999, output_limit_bytes=10**6, max_steps=50, max_retries=5, kill_grace_s=20)
    got = asked.clamp(ceiling)
    assert got.deadline_s == 10 and got.output_limit_bytes == 100 and got.max_steps == 3 and got.max_retries == 1 and got.kill_grace_s == 1
    assert set(asked.exceeds(ceiling)) >= {"deadline_s", "max_steps"}
    assert Limits(deadline_s=1).clamp(ceiling).deadline_s == 1          # asking for less is honoured


@pytest.mark.parametrize("kw", [dict(deadline_s=0), dict(deadline_s=-1), dict(deadline_s=float("nan")), dict(deadline_s=float("inf")),
                                dict(deadline_s="10"), dict(max_steps=0), dict(max_steps=1.5), dict(max_retries=-1), dict(max_retries=True),
                                dict(output_limit_bytes=0), dict(max_retries=99)])
def test_limits_validation(kw):
    with pytest.raises(ModelError):
        Limits(**kw)


# ---------------------------------------------------------------------------------------------- requests
def req(**kw):
    base = dict(run_id="run-1", adapter_id="fake-suite", workspace="/tmp/ws", suite_path="suite/a", output_dir="/tmp/out")
    base.update(kw)
    return SuiteRunRequest(**base)


def test_suite_request_round_trips_and_never_serialises_a_secret_value():
    r = req(env={"APP_URL": "http://x"}, secret_env={"APP_PASSWORD": "s3cr3t-value-123"}, selectors=("smoke", "tag:fast"))
    d = r.to_dict()
    assert "s3cr3t-value-123" not in json.dumps(d) and d["secret_env"] == {"APP_PASSWORD": "[REDACTED]"}


@pytest.mark.parametrize("kw", [dict(suite_path="../x"), dict(suite_path="/etc/passwd"), dict(suite_path="a//b"), dict(suite_path="a\\b"),
                                dict(suite_path=""), dict(workspace="relative/dir"), dict(workspace="/a/../b"), dict(output_dir="out"),
                                dict(selectors=("--exec=evil",)), dict(selectors=("-k",)), dict(selectors=("a;b",)), dict(selectors=("a\nb",)),
                                dict(run_id="has space"), dict(adapter_id="NOPE"), dict(env={"lower": "x"}), dict(env={"A": 1}),
                                dict(env={"A": "x\x00y"}), dict(env={"A": "1"}, secret_env={"A": "1234"}), dict(sealed="yes"),
                                dict(required_assertions=("A-1", "A-1")), dict(assertion_mapping={"T1": "bad id"}), dict(limits={"deadline_s": 1})])
def test_suite_request_validation(kw):
    with pytest.raises(ModelError):
        req(**kw)


def test_suite_request_from_dict_rejects_unknown_fields():
    d = req().to_dict()
    with pytest.raises(ModelError, match="unknown field"):
        SuiteRunRequest.from_dict({**d, "shell": "rm -rf /"})


def test_interactive_request_hides_its_secret_everywhere():
    r = InteractiveActionRequest(session_id="s1", adapter_id="fake-interactive", step_index=0, kind="type", target="field", secret_value="hunter2hunter2")
    assert "hunter2hunter2" not in repr(r) and "hunter2hunter2" not in json.dumps(r.to_dict())


@pytest.mark.parametrize("kw", [dict(kind="Click"), dict(kind="click!"), dict(step_index=-1), dict(step_index=10_000), dict(timeout_s=0),
                                dict(timeout_s=float("nan")), dict(value="x", secret_value="yyyy"), dict(secret_value=""), dict(assertion_id="bad id"), dict(target="a\x00b")])
def test_interactive_request_validation(kw):
    base = dict(session_id="s1", adapter_id="fake-interactive", step_index=0, kind="click")
    base.update(kw)
    with pytest.raises(ModelError):
        InteractiveActionRequest(**base)


# ---------------------------------------------------------------------------------------------- results
def test_result_round_trips_and_has_a_stable_digest():
    r = result(artifacts=(EvidenceArtifact(path="a/b.txt", media_type="text/plain", sha256="0" * 64, size_bytes=3),))
    again = AdapterResult.from_dict(json.loads(json.dumps(r.to_dict())))
    assert again == r and again.digest() == r.digest()
    assert canonical_json(r) == canonical_json(copy.deepcopy(r))


def test_a_result_has_native_authority_only():
    assert result().authority == "native"
    with pytest.raises(ModelError, match="native authority"):
        result(authority="oracle")
    with pytest.raises(ModelError, match="unknown field"):
        AdapterResult.from_dict({**result().to_dict(), "oracle_status": "PASS"})


def test_a_result_is_never_unverified_and_a_framework_cannot_report_it():
    with pytest.raises(ModelError):
        result(status=Status.UNVERIFIED, native_assertions=())
    with pytest.raises(ModelError):
        na("UNVERIFIED")


def test_error_and_error_code_go_together():
    with pytest.raises(ModelError):
        result(status=Status.ERROR, native_assertions=())
    with pytest.raises(ModelError):
        result(status=Status.FAIL, native_assertions=(na("FAIL"),), error_code=ErrorCode.TIMEOUT)
    assert result(status=Status.ERROR, native_assertions=(), error_code=ErrorCode.TIMEOUT).error_code is ErrorCode.TIMEOUT


def test_a_suite_result_cannot_pass_without_a_passing_native_assertion():
    with pytest.raises(ModelError):
        result(native_assertions=())
    with pytest.raises(ModelError):
        result(native_assertions=(na("PASS"), na("FAIL", nid="T2")))


def test_native_ids_must_be_unique():
    with pytest.raises(ModelError):
        result(native_assertions=(na("PASS"), na("PASS")))


@pytest.mark.parametrize("statuses,expected", [(["PASS"], "PASS"), (["PASS", "PASS"], "PASS"), (["PASS", "FAIL"], "FAIL"), (["FAIL", "ERROR"], "ERROR"),
                                               (["PASS", "SKIP"], "SKIP"), (["SKIP", "SKIP"], "SKIP"), (["PASS", "UNKNOWN"], "UNKNOWN"),
                                               (["SKIP", "UNKNOWN"], "UNKNOWN"), ([], "UNKNOWN")])
def test_aggregate_status(statuses, expected):
    assert aggregate_status(tuple(na(s, nid=f"T{i}") for i, s in enumerate(statuses))) is Status(expected)


@pytest.mark.parametrize("kw", [dict(native_id="bad id"), dict(name=1), dict(duration_s=-1), dict(duration_s=float("nan")), dict(message="x" * 5000),
                                dict(declared_assertion_ids=("bad id",)), dict(status="PASSED")])
def test_native_assertion_validation(kw):
    base = dict(native_id="T1", name="n", status=Status.PASS)
    base.update(kw)
    with pytest.raises(ModelError):
        NativeAssertion(**base)


@pytest.mark.parametrize("kw", [dict(path="/abs"), dict(path="../x"), dict(sha256="xyz"), dict(media_type="nope"), dict(size_bytes=-1), dict(role="Bad Role")])
def test_artifact_validation(kw):
    base = dict(path="a.txt", media_type="text/plain", sha256="0" * 64, size_bytes=1)
    base.update(kw)
    with pytest.raises(ModelError):
        EvidenceArtifact(**base)


def test_an_action_can_declare_the_assertion_it_is_evidence_for():
    r = InteractiveActionRequest(session_id="s1", adapter_id="fake-interactive", step_index=0, kind="check", assertion_id="A-1")
    assert InteractiveActionRequest.from_dict(r.to_dict()) == r and r.to_dict()["assertion_id"] == "A-1"
