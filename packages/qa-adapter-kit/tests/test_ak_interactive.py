# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import json
import time

import pytest

from ak_support import fresh_secret
from qa_adapter_kit import (AdapterClass, ErrorCode, InteractiveActionRequest, InteractiveSession, Limits, ModelError, Status, REDACTED)
from qa_adapter_kit.testing.fakes import FakeInteractiveAdapter, interactive_manifest, suite_manifest


def action(step, target="ok", kind="read", **kw):
    base = dict(session_id="s1", adapter_id="fake-interactive", step_index=step, kind=kind, target=target)
    base.update(kw)
    return InteractiveActionRequest(**base)


@pytest.fixture
def session(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    adapter = FakeInteractiveAdapter()
    return InteractiveSession(adapter, output_dir=out), adapter


def test_an_action_returns_a_native_result_with_an_observation(session):
    s, adapter = session
    r = s.perform(action(0))
    assert r.status is Status.PASS and r.adapter_class is AdapterClass.INTERACTIVE and r.authority == "native"
    assert r.observations[0].summary == "page title: Home" and r.native_assertions == ()


def test_an_action_without_assertions_proves_nothing_beyond_having_run(session):
    s, _ = session
    r = s.perform(action(0))
    from qa_adapter_kit import map_to_canonical
    assert map_to_canonical(r, ("A-1",), {}).evidence[0].native_status is Status.UNVERIFIED


@pytest.mark.parametrize("target,status", [("assert_pass", Status.PASS), ("assert_fail", Status.FAIL), ("assert_error", Status.ERROR)])
def test_native_assertions_from_an_action_keep_their_status(session, target, status):
    s, _ = session
    r = s.perform(action(0, target))
    assert r.status is status and r.native_assertions[0].status is status
    assert (r.error_code is ErrorCode.NATIVE_ERROR) == (status is Status.ERROR)


def test_steps_must_be_in_order_and_cannot_be_replayed(session):
    s, adapter = session
    assert s.perform(action(0)).status is Status.PASS
    for bad in (0, 2, 5):
        r = s.perform(action(bad))
        assert r.status is Status.ERROR and r.error_code is ErrorCode.INVALID_REQUEST
    assert s.perform(action(1)).status is Status.PASS and adapter.calls == ["ok", "ok"]


def test_the_step_limit_ends_the_session(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    adapter = FakeInteractiveAdapter(interactive_manifest(limits=Limits(deadline_s=10, max_steps=2)))
    s = InteractiveSession(adapter, output_dir=out)
    assert s.perform(action(0)).status is Status.PASS and s.perform(action(1)).status is Status.PASS
    r = s.perform(action(2))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.STEP_LIMIT and len(adapter.calls) == 2
    assert s.perform(action(2)).error_code is ErrorCode.INVALID_REQUEST      # closed afterwards


def test_a_request_cannot_raise_the_step_limit(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    adapter = FakeInteractiveAdapter(interactive_manifest(limits=Limits(deadline_s=10, max_steps=1)))
    s = InteractiveSession(adapter, output_dir=out, limits=Limits(deadline_s=10, max_steps=100))
    s.perform(action(0))
    assert s.perform(action(1)).error_code is ErrorCode.STEP_LIMIT


def test_an_action_kind_the_adapter_did_not_declare_is_refused(session):
    s, adapter = session
    r = s.perform(action(0, kind="navigate"))
    assert r.error_code is ErrorCode.INVALID_REQUEST and adapter.calls == []


def test_a_request_for_another_adapter_is_refused(session):
    s, adapter = session
    r = s.perform(action(0, adapter_id="someone-else"))
    assert r.error_code is ErrorCode.INVALID_REQUEST and adapter.calls == []


def test_a_retryable_fault_is_retried_within_the_limit(session):
    s, adapter = session
    r = s.perform(action(0, "flaky:2"))
    assert r.status is Status.PASS and r.attempts == 3 and adapter.calls == ["flaky:2"] * 3


def test_a_fault_that_keeps_failing_ends_at_the_retry_limit(session):
    s, adapter = session
    r = s.perform(action(0, "always_flaky"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.RETRY_LIMIT and r.attempts == 3 and len(adapter.calls) == 3


def test_a_non_retryable_fault_is_not_retried(session):
    s, adapter = session
    r = s.perform(action(0, "fault"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.ADAPTER_CRASH and r.attempts == 1 and len(adapter.calls) == 1
    assert s.perform(action(1)).status is Status.PASS                        # a fault does not close the session


def test_an_adapter_crash_is_reported_by_class_name_only(session):
    s, _ = session
    r = s.perform(action(0, "crash"))
    assert r.error_code is ErrorCode.ADAPTER_CRASH and "RuntimeError" in r.error_message and "exploded" not in r.error_message


def test_an_unavailable_dependency_is_an_error_never_a_pass_or_a_skip(session):
    s, adapter = session
    r = s.perform(action(0, "unavailable"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE and r.attempts == 1


def test_a_timed_out_action_aborts_the_adapter_and_closes_the_session(session):
    s, adapter = session
    t0 = time.monotonic()
    r = s.perform(action(0, "slow", timeout_s=0.3))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.TIMEOUT and time.monotonic() - t0 < 5
    assert adapter.aborted and s.perform(action(1)).error_code is ErrorCode.INVALID_REQUEST


def test_the_session_deadline_bounds_the_total(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    adapter = FakeInteractiveAdapter(interactive_manifest(limits=Limits(deadline_s=0.5, max_steps=5)))
    s = InteractiveSession(adapter, output_dir=out)
    r = s.perform(action(0, "slow", timeout_s=30))
    assert r.error_code is ErrorCode.TIMEOUT


def test_malformed_adapter_output_is_an_error(session):
    s, _ = session
    assert s.perform(action(0, "bad_observation")).error_code is ErrorCode.MALFORMED_RESULT
    assert s.perform(action(1, "bad_return")).error_code is ErrorCode.MALFORMED_RESULT


def test_a_declared_artifact_that_does_not_exist_is_an_error(session):
    s, _ = session
    r = s.perform(action(0, "missing_artifact"))
    assert r.error_code is ErrorCode.MISSING_ARTIFACT


def test_a_secret_value_never_appears_in_the_result(session):
    s, _ = session
    secret = fresh_secret("pw-")
    r = s.perform(action(0, "echo_value", kind="type", secret_value=secret))
    blob = json.dumps(r.to_dict())
    assert secret not in blob and REDACTED in blob


def test_a_secret_registered_for_the_session_is_redacted_too(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    secret = fresh_secret("pw-")
    s = InteractiveSession(FakeInteractiveAdapter(), output_dir=out, secrets=[secret])
    r = s.perform(action(0, "echo_value", kind="type", value=secret))
    assert secret not in json.dumps(r.to_dict())


def test_the_interactive_session_refuses_a_suite_manifest(tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    adapter = FakeInteractiveAdapter(suite_manifest())
    with pytest.raises(ModelError):
        InteractiveSession(adapter, output_dir=out)


def test_the_output_directory_must_exist_and_be_allowed(tmp_path):
    from qa_adapter_kit import PathRefused
    with pytest.raises(PathRefused):
        InteractiveSession(FakeInteractiveAdapter(), output_dir=tmp_path / "missing")
    with pytest.raises(PathRefused):
        InteractiveSession(FakeInteractiveAdapter(), output_dir="/etc")


def test_close_calls_the_adapter_and_ends_the_session(session):
    s, adapter = session
    s.close()
    assert adapter.closed and s.perform(action(0)).error_code is ErrorCode.INVALID_REQUEST
